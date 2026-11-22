#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF 守护进程

两个监听（可同机不同端口，也可各自绑定地址）：
  1) frps httpPlugins 回调端：  POST /frp/handler?version=..&op=..
     -> 按 IP 名单/自动封禁决定 allow / reject（默认只绑 127.0.0.1）
  2) 独立管理界面 + API：       /  以及  /api/...
     -> 用默认账号（admin / 123456，首次登录强制修改）登录后管理 WAF

两者分端口 + 各自独立的并发闸门，避免「面板被慢连接打满」把回调一起拖死
（回调失败会让 frps fail-closed 拒绝全部连接）。
"""
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import traceback
import datetime
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, urlsplit, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 相对导入：无论本包以 app 还是 frpwaf_app 名字载入都能正确解析，
# 避免在面板常驻进程里与外部通用 "app" 包冲突。
from . import (__author__, __version__, ai, auth, blockpage, config, engine,  # noqa: E402
               firewall, geo, job, store, upgrade)

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

# 面板允许通过 /api/config 修改的监听地址（「允许远程访问」开关）。
# 只接受通配/回环四值：面板接口不应能把监听改到某个任意网卡/域名上，
# 否则「收紧/放开」的语义会变得不可预测（内网网卡地址仍可手改 json）。
HTTP_ADDR_ALLOWED = ("127.0.0.1", "0.0.0.0", "::1", "::")

# 内存中的当日计数器（用于概览与 /api/metrics，不落库，重启清零）
# invalid_addr：remote_addr 无法解析为 IP 的次数。它本该是 0；持续增长说明
# frps 回调格式变了，黑白名单/自动封禁正在静默失效，必须能在面板上看到。
# db_write_fail：连接日志/临时封禁写库失败次数（写不进去 = 面板看不到、封禁不生效）。
# fw_sync_fail：内核处置同步抛异常的次数（内核层封禁一直没生效的现场证据）。
# fw_sync_ms / ai_call_ms：最近一次同步 / AI 调用的耗时（毫秒，不是累计；无数据为 0）。
# ai_fail：AI 调用/审查失败次数（模型挂了 = 自动封禁静默失效）。
# db_backup_fail：自动备份数据库失败次数（备份一直失败 = 误删/误清理后没有回退点）。
# alert_fail：安全水位告警 webhook 发送失败次数（只是通知没发出去，不影响准入）。
# 全部是**进程内**计数：进程重启即归零（/api/health 的 uptime_s 就是「从哪个时刻起算」）。
_mem = {"started": int(time.time()), "engine_errors": 0, "frp_remote_denied": 0,
        "invalid_addr": 0, "db_write_fail": 0, "fw_sync_fail": 0,
        "fw_sync_ms": 0, "ai_call_ms": 0, "ai_fail": 0, "db_backup_fail": 0,
        "alert_fail": 0}
_mem_lock = threading.Lock()

# 关键失败日志的限频窗口（秒）：同类失败每 10 分钟最多记一条。
# 没有这个窗口时，写库失败/内核同步失败在每个连接、每轮后台轮询上都会刷一行，
# 日志被瞬间写满反而让真正的故障更难发现。
_FAIL_LOG_INTERVAL = 600
_fail_log = {}          # 失败类别 -> 上一次记日志的时刻（与 _mem_lock 同锁访问）

# 运行日志（写入 data/frpwaf.log，供插件「运行日志」页查看）
_log_lock = threading.Lock()
_LOG_MAX = 2 * 1024 * 1024      # 超过 2MB 时截断保留尾部 1MB
_LOG_FIELD_MAX = 64             # 不可信字段（代理名/用户/代理类型）落日志时的截断长度

# 配置回显用的掩码值。GET /api/config 把机密字段替换成该值，写入路径若收到
# 该值说明「客户端只是原样回写」，必须丢弃，否则会把真实密钥覆盖成 ******。
# 建议后续下沉到 app/config.py（MASKED_VALUE / MASKED_KEYS），三条写入路径共用。
MASKED_VALUE = "******"
MASKED_KEYS = ("ai_api_key", "admin_password", "secret")

# 日志字段里必须消除的控制字符（\r \n 在 _log_text 中先转义成字面量，故不在此列）
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# ---- AI 接口地址（SSRF）防护 ----
# 只允许 http/https；下列网段无论配置如何都拒绝（链路本地 + 云厂商元数据）。
# 私有地址（10/8、192.168/16、127/8）默认放行：AI 网关照文档就是
# http://127.0.0.1:3000 这类内网地址，一刀切禁私有地址等于废掉该功能。
_AI_DENY_NETS_ALWAYS = (
    ipaddress.ip_network("169.254.0.0/16"),       # 链路本地，含 169.254.169.254 元数据
    ipaddress.ip_network("100.100.100.200/32"),   # 阿里云元数据（经典网络）
    ipaddress.ip_network("fd00:ec2::254/128"),    # AWS IPv6 元数据
)
_HTTP_ERR_RE = re.compile(r"^HTTP\s+(\d{3})\b")


# ---------- 安全工具 ----------
def _log_text(v, maxlen=0):
    """净化一段要进日志/回显的文本：\r \n 转义为字面量，其它控制字符丢弃。

    proxy_name / proxy_type / user 来自 frpc 客户端的 NewUserConn 回调（客户端
    可控），其中含 \n 就能凭空插入一整行看似可信的日志（如伪造的 [审计] 记录），
    而 /api/syslog 与插件端「运行日志」页会原样展示 —— 取证链被污染。
    maxlen > 0 时按字符截断（不可信字段统一用 _LOG_FIELD_MAX）。
    """
    s = "" if v is None else str(v)
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    s = _CTRL_RE.sub("", s)
    if maxlen and len(s) > maxlen:
        s = s[:maxlen] + "..."
    return s


def _strip_masked(patch):
    """丢弃等于回显掩码的机密字段："读配置→改一项→整体回写"的客户端会把
    GET 拿到的 ****** 原样提交，若照写就毁掉真实密钥（AI 审查从此静默失效）。"""
    if not isinstance(patch, dict):
        return patch
    for k in MASKED_KEYS:
        if k in patch and str(patch[k]) == MASKED_VALUE:
            patch.pop(k, None)
    return patch


def _to_bool(v):
    """宽松布尔解析：字符串 "false"/"0"/"off" 判为 False（bool("false") 是 True）。"""
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "on", "yes")
    return bool(v)


def _allow_private_ai(cfg):
    """配置项 ai_allow_private（默认 True）：是否允许 AI 接口指向私有/回环地址。"""
    return _to_bool((cfg or {}).get("ai_allow_private", True))


def _v4_flat(ip_obj):
    """IPv4-mapped IPv6（::ffff:1.2.3.4）摊平为 IPv4，便于与 IPv4 网段比较。"""
    if ip_obj.version == 6 and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


def _ai_host_denied(ip_obj):
    """硬拒绝集：链路本地 / 云元数据 / 组播 / 未指定地址（不看 ai_allow_private）。"""
    ip_obj = _v4_flat(ip_obj)
    if ip_obj.is_unspecified or ip_obj.is_multicast:
        return True
    if ip_obj.version == 6 and ip_obj.is_link_local:
        return True
    for net in _AI_DENY_NETS_ALWAYS:
        if net.version == ip_obj.version and ip_obj in net:
            return True
    return False


def ai_url_guard(base_url, allow_private=True):
    """校验 AI 接口地址，返回 (ok, err)。

    守护进程以 root 运行，/api/ai/test 把请求体里的地址直接交给 urllib，
    不校验就等于「已登录用户可让 root 访问任意地址」：file:// 读本机文件、
    http://169.254.169.254/ 读云元数据（IMDSv1 可拿 STS 凭据）、内网管理口探测。

    策略（见 /api/config 注释与交付报告）：
      1. 只允许 http / https，其它 scheme 一律拒绝；
      2. 域名先解析成 IP，再按 IP 判定（否则「域名解析到内网」直接绕过）；
        所有解析结果都必须是允许的地址，任一命中拒绝即整体拒绝；
      3. 链路本地 / 元数据 / 组播 / 未指定地址永远拒绝；
      4. 私有/回环地址默认允许（AI 网关就在内网），ai_allow_private=false 时收紧。
    """
    raw = str(base_url or "").strip()
    if not raw:
        return False, "接口地址为空"
    try:
        u = urlsplit(raw)
    except ValueError:
        return False, "接口地址无法解析"
    scheme = (u.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, "只允许 http/https 接口地址"
    try:
        host = u.hostname          # 已剥离 userinfo 并小写化
        port = u.port or (443 if scheme == "https" else 80)
    except ValueError:
        return False, "接口地址端口非法"
    if not host:
        return False, "接口地址缺少主机名"
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return False, "接口地址域名无法解析"
    addrs = []
    for info in infos:
        try:
            addrs.append(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except (ValueError, IndexError, TypeError):
            continue
    if not addrs:
        return False, "接口地址域名无法解析"
    for addr in addrs:
        if _ai_host_denied(addr):
            return False, "接口地址指向链路本地/元数据网段，已拒绝"
        if not allow_private:
            flat = _v4_flat(addr)
            if flat.is_private or flat.is_loopback or flat.is_reserved:
                return False, "接口地址指向内网地址（ai_allow_private 已关闭）"
    return True, ""


def _safe_ai_error(res):
    """把 AI 调用错误转成可回显前端的摘要：不含响应体（防内网内容被外带）。

    原先直接 "连接失败：" + str(res)[:300]，会把内网/元数据响应体带回面板 ——
    SSRF 即使被拦在「访问」这一步，也能被当成读数据的通道。
    """
    s = str(res or "").strip()
    if not s:
        return "未知错误（详见运行日志）"
    m = _HTTP_ERR_RE.match(s)
    if m:
        return "HTTP %s（响应体已省略，详见运行日志）" % m.group(1)
    return _log_text(s.split("\n", 1)[0], 160) or "未知错误（详见运行日志）"


def _audit(msg):
    """操作审计：写入运行日志（data/frpwaf.log），带 [审计] 标记，便于追溯高危操作。"""
    try:
        _log("[审计] %s" % msg)
    except Exception:
        pass


def _log(msg):
    """写运行日志（_audit 也走这里）。

    入口统一净化：\r \n 转义成字面量 \\r \\n、其它控制字符丢弃。日志是安全产品
    的取证依据，任何来自请求/回调的字段都不能让调用方「一行变两行」。时间戳前缀
    照常生成，正常日志格式不变。
    """
    try:
        line = "[%s] %s\n" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), _log_text(msg))
        with _log_lock:
            with open(config.LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
            try:
                if os.path.getsize(config.LOG_PATH) > _LOG_MAX:
                    with open(config.LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                        data = f.read()
                    with open(config.LOG_PATH, "w", encoding="utf-8") as f:
                        f.write(data[-1024 * 1024:])
            except OSError:
                pass
    except Exception:
        pass


def _count_fail(key, msg, detail=""):
    """关键失败计数 + 限频日志：每次失败都累加计数进 /api/metrics，
    日志则每 10 分钟最多一条（同一 key 独立计时）。

    这批失败（写库失败、内核同步失败、AI 调用失败）原来大多是 `except: pass`：
    运维根本看不出「内核封禁其实一直没生效」。其余宽泛 except 一律不动——它们
    多数是可接受的降级（观测/归属地/日志失败不影响准入），全量改写风险大于收益。

    返回累计次数（便于调用方决定是否继续）。
    """
    now = time.time()
    with _mem_lock:
        _mem[key] = int(_mem.get(key) or 0) + 1
        n = int(_mem[key])
        if now - _fail_log.get(key, 0.0) < _FAIL_LOG_INTERVAL:
            return n
        _fail_log[key] = now
    # 锁外写日志：_log 自己持锁并做磁盘 IO，不能嵌在 _mem_lock 里
    try:
        _log("%s（累计 %d 次；同类失败 10 分钟内只记一条）%s"
             % (msg, n, ("：" + str(detail)) if detail else ""))
    except Exception:
        pass
    return n


# ---- 安全水位（/api/health）----
# 上面的失败计数本身只是裸数字：运维看到 fw_sync_fail=37 无法判断「要不要现在处理」。
# 这一段把这些数字翻成「状态 + 说明 + 建议动作」，面板直接渲染；可选告警 webhook
# 也复用同一套判断，保证面板与告警不会给出两种结论。
#
# 阈值口径：这些计数**本该恒为 0**，所以 ok 就是 0；1..warn_max 为 warn（够得上
# 「看一眼」），超过 warn_max 为 bad（防护已经在静默失效）。
# 为什么不做滑动窗口：这里的值本身是进程内累计值、重启即清零，滑动窗口要额外维护
# 时间序列；先给「累计值 + 平均速率」已足以判断量级。平均速率写进 detail，但
# **不参与定级**——否则刚启动时的个位数会被平均成很高的速率判成 bad，与下面的
# 冷启动宽限相互打架。
_HEALTH_STARTUP_GRACE = 300     # 冷启动宽限（秒）：此内的 warn 降级为 ok

# (key, 标签, warn 上限, 说明, 建议动作)
_HEALTH_SPEC = (
    ("invalid_addr", "回调来源地址解析失败", 10,
     "本该恒为 0。一旦增长说明 frps 回调的 remote_addr 格式变了，黑白名单与自动封禁"
     "正在静默失效（应用层会照常放行，面板上看着一切正常）",
     "对照 frps 版本检查 httpPlugins 回调格式；确认前可先开启 strict_addr 改为拒连"),
    ("fw_sync_fail", "内核封禁同步失败", 3,
     "内核层封禁可能一直没生效：应用层仍会拦，但被禁 IP 仍能反复建连，内核丢包这层"
     "等于没上（非 root / 缺 ipset 属于「环境不支持」，不计入本数）",
     "看运行日志里 ipset/iptables 相关报错，确认以 root 运行、内核模块与 ipset 可用"),
    ("db_write_fail", "写库失败", 5,
     "写不进库 = 面板看不到这批记录，封禁状态也不会落盘",
     "检查数据目录磁盘空间与 data/frpwaf.db 的权限/完整性"),
    ("ai_fail", "AI 审查失败", 5,
     "模型调用拿不到判定，AI 自动处置处于静默失效状态",
     "确认 AI 接口地址可达、密钥有效、额度未用尽（设置 → AI 审查）"),
    ("db_backup_fail", "数据快照备份失败", 2,
     "备份一直失败 = 误删/误清理后没有可用的回退点",
     "检查备份目录的磁盘空间与写权限；见运行日志里数据库自动备份相关条目"),
    ("engine_errors", "决策引擎异常", 3,
     "决策路径抛异常，此时按 fail-open 放行：本该拒绝的连接可能已经放过",
     "看运行日志「决策异常（fail-open）」的 traceback，结合当时命中的规则一起排查"),
)

_LEVEL_RANK = {"ok": 0, "warn": 1, "bad": 2}


def _mem_get(key):
    """读一个内存计数（与写入同锁，避免读到写了一半的状态）。"""
    with _mem_lock:
        return int(_mem.get(key) or 0)


def _uptime_s():
    """本进程已运行秒数（计数是从这个时刻开始记的）。"""
    return max(0, int(time.time()) - int(_mem.get("started") or 0))


def _health_level(value, warn_max):
    """0 = ok；1..warn_max = warn；> warn_max = bad。"""
    if value <= 0:
        return "ok"
    return "warn" if value <= warn_max else "bad"


def _health_ai_active(cfg):
    """AI 审查是否真会被调用：开关打开且地址与密钥都配齐。"""
    return (bool(cfg.get("ai_enabled"))
            and bool(str(cfg.get("ai_base_url") or "").strip())
            and bool(str(cfg.get("ai_api_key") or "").strip()))


def _health_rate_text(value, uptime):
    """平均速率说明（每分钟次数），用于判断「涨得快不快」。"""
    if value <= 0 or uptime <= 0:
        return ""
    rate = value * 60.0 / uptime
    if rate < 0.01:
        return "，不足 0.01 次/分钟"
    return "，约 %.2f 次/分钟" % rate


def health_data(cfg=None):
    """计算安全水位：items 逐项定级，level 取最差值，summary 一句话结论。

    两个必须处理的误报场景：
      1) AI 审查没开（开关关闭或地址/密钥没配全）时 AI 根本不会被调用，
         ai_fail 只可能来自手动的「测试连接」或手动审查，与自动处置是否失效无关
         → 一律不参与定级（仍返回真实 value，并在 detail 里说明来源）。
         注意计数是进程内计数、启动即归零（见 _mem 注释），不存在「重启前的
         历史值」被带进来，所以这里只需要看当前开关状态。
      2) 进程刚启动（不足 _HEALTH_STARTUP_GRACE 秒）时，warn 降级为 ok：
         启动初期的一次性失败（初始化/首次同步）不该立刻把面板变黄。
         **bad 不降级**：刚启动就到 bad 量级说明不是瞬时问题。
    """
    cfg = config.get() if cfg is None else cfg
    uptime = _uptime_s()
    startup = uptime < _HEALTH_STARTUP_GRACE
    ai_active = _health_ai_active(cfg)
    items = []
    for key, label, warn_max, detail, action in _HEALTH_SPEC:
        value = _mem_get(key)
        level = _health_level(value, warn_max)
        extra = []
        if key == "ai_fail" and not ai_active:
            level = "ok"
            extra.append("AI 审查未启用或未配置完整，自动审查不会运行；"
                         "该计数只来自手动测试/手动审查，不影响准入")
        if startup and value > 0:
            if level == "warn":
                level = "ok"
                extra.append("服务刚启动 %d 秒（不足 %d 秒），启动期的少量失败先观察"
                             % (uptime, _HEALTH_STARTUP_GRACE))
            elif level == "bad":
                extra.append("服务刚启动 %d 秒，仍判为 bad：这个量级不是启动瞬时问题"
                             % uptime)
        text = detail
        if value > 0:
            text += "（累计 %d 次%s）" % (value, _health_rate_text(value, uptime))
        if extra:
            text += "；" + "；".join(extra)
        items.append({"key": key, "value": value, "level": level,
                      "label": label, "detail": text, "action": action})
    level = "ok"
    for it in items:
        if _LEVEL_RANK[it["level"]] > _LEVEL_RANK[level]:
            level = it["level"]
    top = [i for i in items if i["level"] == level] if level != "ok" else []
    if level != "ok":
        summary = "%s，%s" % (
            "、".join("%s %d 次" % (i["label"], i["value"]) for i in top[:3]),
            "需要处理" if level == "bad" else "建议观察")
    elif startup:
        summary = "各项安全指标正常（刚启动 %d 秒，启动期告警已宽限）" % uptime
    else:
        summary = "各项安全指标正常（已运行 %d 分钟）" % max(1, uptime // 60)
    return {"level": level, "since": int(_mem.get("started") or 0),
            "uptime_s": uptime, "items": items, "summary": summary}


# ---- 可选告警 webhook ----
# 语义：level 从非 bad 变成 bad 时发一次，从 bad 恢复成非 bad 时再发一次；
# 同类事件 _ALERT_INTERVAL 内不重复（一次故障只打扰一次，不随 30s 后台轮询刷屏）。
# 发送放独立线程 + 短超时，失败只计数（alert_fail）不抛出：告警通路不能拖慢
# 后台循环，更不能影响准入判定。
_ALERT_INTERVAL = 1800      # 同类告警最小间隔（秒）
_ALERT_TIMEOUT = 5          # 单次 POST 超时（秒）
_ALERT_STATE = {"level": "ok", "url": "", "at": {}}
_ALERT_LOCK = threading.Lock()


def _alert_payload(health, event):
    """告警 body：只带非 ok 项（接收端不需要知道哪些指标是好的）。"""
    return {"event": event, "level": health["level"], "summary": health["summary"],
            "items": [i for i in health["items"] if i["level"] != "ok"],
            "since": health["since"], "uptime_s": health["uptime_s"],
            "ts": int(time.time())}


def _alert_post(url, payload):
    """发送一次告警（在独立线程里跑）。任何异常只计数，不上溯。"""
    try:
        # 发送前再校验一次地址：配置可能被手改，或 DNS 解析结果已变
        ok, err = ai_url_guard(url, _allow_private_ai(config.get()))
        if not ok:
            raise ValueError(err)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        # 地址协议（scheme）已由 ai_url_guard 限定为 http/https（且拒链路本地/云元数据
        # 地址），此处固定 method=POST、不跟随自定义协议，故忽略 S310 的协议告警。
        req = urllib.request.Request(  # noqa: S310
            url, data=body, method="POST",
            headers={"Content-Type": "application/json; charset=utf-8",
                     "User-Agent": "frpwaf-alert/" + str(__version__)})
        with urllib.request.urlopen(req, timeout=_ALERT_TIMEOUT) as resp:  # noqa: S310
            resp.read(256)      # 只读一小段，不把接收端的响应体拉回来
    except Exception:
        _count_fail("alert_fail",
                    "告警 webhook 发送失败（只是通知没发出去，不影响准入与面板）",
                    traceback.format_exc()[-200:])


def _alert_check(cfg=None):
    """后台每一轮调用：判断 level 是否发生跨 bad 的跳变，必要时发一次告警。

    返回本次发出的 body（未发送则为 None），便于测试直接断言而不用起网络。
    """
    cfg = config.get() if cfg is None else cfg
    url = str(cfg.get("alert_webhook") or "").strip()
    health = health_data(cfg)
    level = health["level"]
    with _ALERT_LOCK:
        prev = _ALERT_STATE["level"]
        prev_url = _ALERT_STATE["url"]
        _ALERT_STATE["level"] = level
        _ALERT_STATE["url"] = url
        if not url:
            return None
        # 刚填/刚换地址时把基线重置为 ok：否则「保存 webhook 时系统已经异常」
        # 这种情况永远等不到一次跳变，用户会以为 webhook 没生效。
        if url != prev_url:
            prev = "ok"
        if level == "bad" and prev != "bad":
            event = "bad"
        elif level != "bad" and prev == "bad":
            event = "recover"
        else:
            return None
        now = time.time()
        if now - float(_ALERT_STATE["at"].get(event) or 0.0) < _ALERT_INTERVAL:
            return None
        _ALERT_STATE["at"][event] = now
    payload = _alert_payload(health, event)
    threading.Thread(target=_alert_post, args=(url, payload),
                     name="frpwaf-alert", daemon=True).start()
    return payload


# ---- 统一安全响应头（面板与回调的全部响应）----
# CSP 取舍：两个前端都是**单文件 SPA**——内联 <script>、内联 on* 事件属性、
# 内联 <style> 与 style= 属性。因此 script-src 与 style-src 都必须带
# 'unsafe-inline'，否则整片脚本/样式被拦，页面直接白屏（这不是理论风险：
# 面板有 73 个 on*= 与 205 个 style=，独立 Web 端 34 个 on*= 与 64 个 style=）。
# default-src 'self' 仍然生效：内联是显式放行的例外，外部域一律不许加载；
# frame-ancestors 'none' + X-Frame-Options 双重禁掉点击劫持。
_SEC_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'self'; script-src 'self' 'unsafe-inline'; "
     "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
     "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
)


# 登录失败限速：来源 IP 维度 + 全局总量维度。
# - 来源 IP：窗口内失败达 _LOGIN_MAX_FAIL 次则锁定，重复触发时锁定时间指数退避；
# - 全局：窗口内失败总数达 _GLOBAL_MAX_FAIL 次则进入全局冷却，冷却期内所有
#   非本机来源一律拒绝——这是为了堵住「换 IP 就绕过单 IP 限速」的分布式爆破
#   （5000 个 IP × 每个 10 次 = 5 万次尝试，单 IP 维度永远不触发）。冷却时长
#   同样指数增长，直到有人从本机成功登录（说明攻击已结束）才清零。
# - 本机（127.0.0.1 / ::1）始终不参与全局冷却，避免把自己（宝塔面板、SSH
#   隧道）锁在门外。
# 失败计数落盘到 data/login_guard.json：重启不清零（旧实现是纯内存，
# 攻击者只要能把服务打重启就拿到了新一轮配额）。
_login_fail = {}          # ip -> (窗口起点, 窗口内失败数, 锁定到, 触发次数)
_login_lock = threading.Lock()
_LOGIN_WINDOW = 300       # 统计窗口（秒）
_LOGIN_MAX_FAIL = 10      # 窗口内最大失败次数
_LOGIN_LOCK = 300         # 首次触发的锁定时长（秒），之后按触发次数翻倍
_LOGIN_LOCK_MAX = 3600    # 锁定/冷却时长封顶
_LOCAL_IPS = ("127.0.0.1", "::1", "::ffff:127.0.0.1")

_GLOBAL_MAX_FAIL = 300    # 全局窗口内失败总数阈值
_global_fail = {"start": 0.0, "count": 0, "level": 0, "until": 0.0}

_GUARD_PATH = os.path.join(config.DATA_DIR, "login_guard.json")
_guard_io = {"at": 0.0}


def _is_local_ip(ip):
    return ip in _LOCAL_IPS


def _backoff(base, times):
    """指数退避：第 1 次 base，第 2 次 2×base … 封顶 _LOGIN_LOCK_MAX。"""
    times = max(1, int(times))
    try:
        return min(base * (2 ** (times - 1)), _LOGIN_LOCK_MAX)
    except OverflowError:
        return _LOGIN_LOCK_MAX


def _login_locked(ip):
    """返回还需等待的秒数（0=可尝试登录）：全局冷却优先，其次来源 IP 锁定。"""
    now = time.time()
    with _login_lock:
        if not _is_local_ip(ip) and _global_fail["until"] > now:
            return int(_global_fail["until"] - now) or 1
        rec = _login_fail.get(ip)
        if not rec:
            return 0
        if rec[2] > now:
            return int(rec[2] - now) or 1
        return 0


def _login_record(ip, ok):
    """记一次登录结果（ok=False 同时累加来源 IP 与全局两个维度）。"""
    now = time.time()
    force = False
    with _login_lock:
        if ok:
            _login_fail.pop(ip, None)
            # 本机登录成功 = 攻击已停，清零全局等级（否则冷却时间会永远翻倍）
            if _is_local_ip(ip):
                _global_fail.update({"start": now, "count": 0, "level": 0, "until": 0.0})
                force = True
        else:
            start, cnt, lock, times = _login_fail.get(ip, (now, 0, 0.0, 0))
            if now - start > _LOGIN_WINDOW:
                start, cnt, lock = now, 0, 0.0
            # 退避等级衰减：上一次锁定已是 1 小时前则重新从 300s 开始算。
            # 否则偶发输错（一个月两三次）会永久积累等级，最终变成 1 小时锁定。
            if lock and lock < now - _LOGIN_LOCK_MAX:
                times = 0
            cnt += 1
            if cnt >= _LOGIN_MAX_FAIL:
                times += 1
                lock = now + _backoff(_LOGIN_LOCK, times)
                cnt, start = now, 0
                _log("登录失败过多：来源 %s 锁定 %d 秒（第 %d 次触发）"
                     % (ip, int(lock - now), times))
            _login_fail[ip] = (start, cnt, lock, times)
            # 有界增长：先清过期项；仍超硬上限时按窗口起点淘汰最旧的一半，
            # 防止「持续换 IP 攻击」时字典无界膨胀（旧实现仅清过期，不设硬上限）。
            if len(_login_fail) > 5000:
                for k in [k for k, v in _login_fail.items() if now - v[0] > _LOGIN_WINDOW]:
                    _login_fail.pop(k, None)
            if len(_login_fail) > 5000:
                oldest = sorted(_login_fail.items(), key=lambda kv: kv[1][0])
                for k, _ in oldest[:len(oldest) // 2]:
                    _login_fail.pop(k, None)
            # ---- 全局维度 ----
            if now - _global_fail["start"] > _LOGIN_WINDOW:
                _global_fail["start"] = now
                _global_fail["count"] = 0
            _global_fail["count"] += 1
            if _global_fail["count"] >= _GLOBAL_MAX_FAIL:
                _global_fail["level"] += 1
                _global_fail["count"] = 0
                penalty = _backoff(60, _global_fail["level"])
                _global_fail["until"] = now + penalty
                force = True
                _log("登录失败总数触发全局冷却 %d 秒（第 %d 次触发，非本机来源全部拒绝）"
                     % (penalty, _global_fail["level"]))
            force = True
    _guard_save(force)


def _guard_save(force=False):
    """把登录失败状态落盘（按 2 秒节流，避免爆破时把磁盘写爆）。"""
    now = time.time()
    if not force and now - _guard_io["at"] < 2.0:
        return
    _guard_io["at"] = now
    with _login_lock:
        payload = {
            "ts": int(now),
            "global": dict(_global_fail),
            "ips": {k: list(v) for k, v in _login_fail.items()
                    if v[2] > now or now - v[0] <= _LOGIN_WINDOW},
        }
    # 只保留最近的一批来源，文件体积封顶（攻击时可能有上千条）
    if len(payload["ips"]) > 500:
        newest = sorted(payload["ips"].items(), key=lambda kv: kv[1][0], reverse=True)
        payload["ips"] = dict(newest[:500])
    tmp = "%s.tmp.%d" % (_GUARD_PATH, os.getpid())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, _GUARD_PATH)
        try:
            os.chmod(_GUARD_PATH, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _guard_load():
    """读取上次运行留下的失败计数（重启不清零）；过期数据直接丢弃。"""
    try:
        with open(_GUARD_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
    except Exception:
        return
    now = time.time()
    try:
        g = data.get("global") or {}
        with _login_lock:
            _global_fail["start"] = float(g.get("start") or 0)
            _global_fail["count"] = max(0, int(g.get("count") or 0))
            _global_fail["level"] = max(0, int(g.get("level") or 0))
            _global_fail["until"] = float(g.get("until") or 0)
            ips = data.get("ips") or {}
            if isinstance(ips, dict):
                for k, v in list(ips.items())[:500]:
                    try:
                        start, cnt, lock, times = (float(v[0]), int(v[1]),
                                                  float(v[2]), int(v[3]))
                    except (TypeError, ValueError, IndexError):
                        continue
                    if lock > now or now - start <= _LOGIN_WINDOW:
                        _login_fail[str(k)] = (start, cnt, lock, times)
    except Exception:
        pass
    if _global_fail["until"] > now:
        _log("登录失败计数（已落盘恢复）：全局冷却剩余 %d 秒"
             % int(_global_fail["until"] - now))


_V4_PORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
_V6_BRACKET_RE = re.compile(r"^\[([^\]]+)\](?::(\d{1,5}))?$")


def _norm_ip(text):
    """严格解析 IP 文本，返回归一化字符串；失败返回 ""。

    IPv4-mapped IPv6（::ffff:1.2.3.4）归一为 IPv4：否则 ip_list 里的 1.2.3.4
    匹配不上 `ipaddress.ip_address("::ffff:1.2.3.4")`，黑名单对该形态静默失效。
    归一化必须在进决策前完成（engine.decide 不归本模块改）。
    """
    s = str(text or "").strip()
    if not s:
        return ""
    try:
        ip_obj = ipaddress.ip_address(s)
    except ValueError:
        return ""
    return str(_v4_flat(ip_obj))


def _split_addr(remote_addr):
    """基于严格解析的 remote_addr 拆分，返回 (ip, port)；无法解析返回 ("", 0)。

    接受的形式（frps 目前输出带方括号的 IPv6）：
      '1.2.3.4:5678' / '[::1]:5678' / '[::1]' / '1.2.3.4' / '::1'
    原先 `addr.count(":") == 1` 才拆、否则当纯 IPv6 整串返回：任何非 IP 串都会
    原样传给 engine，engine 解析失败后 **直接放行**（invalid-ip-pass），且无告警。
    这里改成「解析不出来就是解析不出来」，由调用方决定放行还是拒连。
    """
    s = str(remote_addr or "").strip()
    if not s:
        return "", 0
    m = _V6_BRACKET_RE.match(s)          # [v6] / [v6]:port
    if m:
        ip = _norm_ip(m.group(1))
        return (ip, _int(m.group(2))) if ip else ("", 0)
    m = _V4_PORT_RE.match(s)             # v4:port（方括号写法已被上面吃下）
    if m:
        ip = _norm_ip(m.group(1))
        return (ip, _int(m.group(2))) if ip else ("", 0)
    ip = _norm_ip(s)                     # 裸 IP（含不带方括号的 IPv6）
    return (ip, 0) if ip else ("", 0)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ---------- /api 入参校验 ----------
# 入参原先是直接透传的：传个 dict/小数/乱字符串就在业务函数里抛 TypeError，
# 变成 500 + traceback 进日志（日志是取证依据，不能被客户端输入灌满）。
# 现在统一用下面几个小工具函数：非法就抛 _ApiError，由 _route 集中转成
# 400 + {"code": 1, "msg": "..."}，且**不进 traceback 日志**。
class _ApiError(Exception):
    """入参非法（类型/格式/范围）。由 _route 统一转 400，不是内部故障。"""


def _type_name(v):
    """类型的中文名（只给类型、不回显原值：dict/list 可能很大）。"""
    if isinstance(v, bool):
        return "布尔值"
    if isinstance(v, dict):
        return "对象"
    if isinstance(v, (list, tuple)):
        return "数组"
    if isinstance(v, (int, float)):
        return "数字"
    if isinstance(v, str):
        return "字符串"
    return type(v).__name__


def _need_str(body, key, default=None, maxlen=0):
    """取字符串入参（自动 strip）：类型不对抛 400。"""
    v = (body or {}).get(key, None)
    if v is None:
        if default is None:
            raise _ApiError("%s 不能为空" % key)
        return default
    if isinstance(v, (dict, list, tuple)):
        raise _ApiError("%s 必须是字符串（收到%s）" % (key, _type_name(v)))
    if isinstance(v, bool):
        raise _ApiError("%s 必须是字符串（收到布尔值）" % key)
    v = str(v).strip()
    if maxlen and len(v) > maxlen:
        raise _ApiError("%s 过长（上限 %d 字符）" % (key, maxlen))
    return v


def _need_int(body, key, default=None, lo=None, hi=None):
    """取整数入参：缺失/空串用 default；类型不对或越界抛 400（不得抛 TypeError）。"""
    v = (body or {}).get(key, None)
    if v is None or (isinstance(v, str) and not v.strip()):
        if default is None:
            raise _ApiError("%s 不能为空" % key)
        return int(default)
    if isinstance(v, bool):
        raise _ApiError("%s 必须是整数（收到布尔值）" % key)
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise _ApiError("%s 必须是整数（收到%s）" % (key, _type_name(v)))
    if isinstance(v, float) and v != n:
        raise _ApiError("%s 必须是整数（收到 %r）" % (key, v))
    if lo is not None and n < lo:
        raise _ApiError("%s 不能小于 %d" % (key, lo))
    if hi is not None and n > hi:
        raise _ApiError("%s 不能大于 %d" % (key, hi))
    return n


def _need_choice(body, key, choices, default=None):
    """取枚举入参（如 list_type: black/white）。"""
    v = (body or {}).get(key, None)
    if v is None or (isinstance(v, str) and not v.strip()):
        if default is None:
            raise _ApiError("%s 不能为空（可选值：%s）" % (key, " / ".join(choices)))
        return default
    if not isinstance(v, str):
        raise _ApiError("%s 必须是字符串（收到%s）" % (key, _type_name(v)))
    v = v.strip()
    if v not in choices:
        raise _ApiError("%s 只能是 %s（收到 %r）" % (key, " / ".join(choices), v))
    return v


def _need_cidr(body, key="cidr", default=None):
    """取 IP/CIDR 入参：必须是字符串且能被 ipaddress 解析，返回规范化结果。

    单 IP 也合法（ip_network('1.2.3.4') -> 1.2.3.4/32），与 store.add_ip 的语义一致。
    """
    s = _need_str(body, key, default, maxlen=64)
    if not s:
        raise _ApiError("%s 不能为空" % key)
    try:
        return str(ipaddress.ip_network(s, strict=False))
    except ValueError:
        raise _ApiError("%s 不是合法的 IP 或 CIDR：%s" % (key, s))


def _need_addr(body, key="ip", default=None):
    """取 IP / CIDR 文本入参：校验合法但**不改写原值**。

    用于按地址解封/封禁：库里存的就是原字符串（单 IP 与 CIDR 两种形态），
    归一化成 1.2.3.4/32 反而匹配不上库里已有的 1.2.3.4。
    """
    s = _need_str(body, key, default, maxlen=64)
    if not s:
        raise _ApiError("%s 不能为空" % key)
    try:
        ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise _ApiError("%s 不是合法的 IP 或 CIDR：%s" % (key, s))
    return s


def _fw_sync_once():
    """执行一次内核处置同步：计时 + 失败计数/限频日志。

    返回 firewall.sync_from_store() 的布尔结果。注意 False 有两种含义——
    「环境不支持（非 root / 缺 ipset/iptables）」与「内核封禁和拦截页都关、
    已清理规则」，都不是异常，所以**不计入 fw_sync_fail**：把常态报成失败
    会让监控彻底失去意义。只有抛异常（命令执行失败、清单读取失败）才算失败。

    耗时记入 fw_sync_ms（最近一次，不是累计）。内核同步是决策路径之外的
    派生状态下发，它变慢不会影响准入，但值得在面板上看到。
    """
    t0 = time.time()
    ok = False
    try:
        ok = bool(firewall.sync_from_store())
    except Exception:
        _count_fail("fw_sync_fail",
                    "内核封禁同步失败（内核层可能一直没生效；应用层判定仍在工作）",
                    traceback.format_exc()[-300:])
    finally:
        with _mem_lock:
            _mem["fw_sync_ms"] = int((time.time() - t0) * 1000)
    return ok


def _fw_sync():
    """按当前配置同步内核处置（DROP / REDIRECT / 清理）。

    不再区分「开关开则 sync、关则 teardown」：sync_from_store() 内部按
    fw_sync_enabled 与 block_page_enabled 决定模式——关闭内核封禁但开启
    拦截页时需改为 nat REDIRECT（让被封 IP 看到页面），两者都关才清理。
    """
    _fw_sync_once()
    try:
        with _mem_lock:
            _mem["fw_on"] = bool(config.get().get("fw_sync_enabled", True))
    except Exception:
        pass


class _QuietHTTPServer(ThreadingHTTPServer):
    """并发闸门 + 请求线程异常噪声抑制。

    异常处理：http.server 默认的 handle_error 会把请求线程中的任何异常打印完整
    traceback 到 stderr；服务脚本以 `2>&1` 追加日志，扫描器/客户端半途断开连接
    （ConnectionResetError 等）就会刷满运行日志。此类异常与业务无关，这里静默并
    按窗口汇总一条计数日志；其余异常仍按默认方式打印，保证真实故障可排查。

    并发闸门：每连接一个线程 = 每连接一个 FD，无上限时几百条「连上不发数据」的
    慢连接就能把 root 进程打到 EMFILE，之后 accept 失败，frps 的回调也跟着失败
    （fail-closed → 全部隧道中断）。这里用 BoundedSemaphore 给进程加硬上限，
    超限**直接断开而不是排队**：排队的连接本身也占 FD，排队只会把耗尽时间推迟。
    """
    _NET_ERR_TYPES = (ConnectionResetError, ConnectionAbortedError,
                      BrokenPipeError, TimeoutError, socket.timeout)
    _QUIET_WINDOW = 600          # 汇总记录窗口（秒）
    _quiet_lock = threading.Lock()
    _quiet_count = 0
    _quiet_last = 0.0
    # 并发超限统计（同样按窗口汇总，避免扫描时刷屏）
    _over_lock = threading.Lock()
    _over_count = 0
    _over_last = 0.0

    def __init__(self, addr_port, handler_cls, max_concurrent=0):
        # 0 或负值 = 不限制（仅供本地调试；生产配置默认有限）
        self.max_concurrent = max(0, _int(max_concurrent))
        self._sem = (threading.BoundedSemaphore(self.max_concurrent)
                     if self.max_concurrent > 0 else None)
        ThreadingHTTPServer.__init__(self, addr_port, handler_cls)

    # ---- 闸门 ----
    def _slot_release(self):
        sem = self._sem
        if sem is not None:
            try:
                sem.release()
            except ValueError:      # 超量释放：只可能来自异常路径，忽略
                pass

    def _reject_overload(self, request):
        """额度耗尽：直接断开（不回 503：回包本身也要占一个请求线程与 FD）。"""
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            request.close()
        except OSError:
            pass
        now = time.time()
        with _QuietHTTPServer._over_lock:
            _QuietHTTPServer._over_count += 1
            if now - _QuietHTTPServer._over_last >= self._QUIET_WINDOW:
                _QuietHTTPServer._over_last = now
                n = _QuietHTTPServer._over_count
                _QuietHTTPServer._over_count = 0
                try:
                    _log("并发超限：本窗口内已直接断开 %d 条连接（上限 %d，调大可改配置 max_concurrent）"
                         % (n, self.max_concurrent))
                except Exception:
                    pass

    def process_request(self, request, client_address):
        sem = self._sem
        if sem is not None and not sem.acquire(False):
            self._reject_overload(request)
            return
        try:
            ThreadingHTTPServer.process_request(self, request, client_address)
        except Exception:
            self._slot_release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            ThreadingHTTPServer.process_request_thread(self, request, client_address)
        finally:
            self._slot_release()

    def handle_error(self, request, client_address):
        etype = sys.exc_info()[0]
        if etype is not None and issubclass(etype, self._NET_ERR_TYPES):
            now = time.time()
            with _QuietHTTPServer._quiet_lock:
                _QuietHTTPServer._quiet_count += 1
                if now - _QuietHTTPServer._quiet_last >= self._QUIET_WINDOW:
                    _QuietHTTPServer._quiet_last = now
                    n = _QuietHTTPServer._quiet_count
                    _QuietHTTPServer._quiet_count = 0
                    _log("已静默 %d 条客户端断连异常（扫描器/连接提前关闭，不影响防护）" % n)
            return
        ThreadingHTTPServer.handle_error(self, request, client_address)


# ---- 管理 API 路由表（/api/* 精确匹配，方法约束在此声明）----
#
# 每条：路径 -> (允许的方法集合, Handler 上的处理方法名)。
#   * 路径是精确匹配（`_api` 用 dict.get），故 /api/ai/test 与
#     /api/ai/test/status、/api/logs 与 /api/logs/proxies|summary 这类相邻
#     前缀天然不会互相吃掉，也不再依赖 if 链的先后顺序。
#   * 方法不在集合里 => 405 + Allow 头（资源存在，只是方法不允许）；
#     只有未知路径才回 404「接口不存在」。
#   * GET 集合同时覆盖 HEAD（`do_HEAD` 走 GET 路由）。
#   * 真正到达这里的只有 GET/POST：PUT/DELETE/PATCH/OPTIONS 在
#     `_method_not_allowed` 那层就被挡掉了。
_ROUTES = {
    "/api/health": ({"GET", "POST"}, "_api_health"),
    "/api/metrics": ({"GET", "POST"}, "_api_metrics"),
    "/api/overview": ({"GET", "POST"}, "_api_overview"),
    "/api/config": ({"GET", "POST"}, "_api_config"),
    "/api/password": ({"POST"}, "_api_password"),      # 收窄：原链里 GET 也会进改密分支
    "/api/iplist": ({"GET", "POST"}, "_api_iplist"),
    "/api/logs": ({"GET", "POST"}, "_api_logs"),
    "/api/logs/proxies": ({"GET", "POST"}, "_api_logs_proxies"),
    "/api/logs/summary": ({"GET", "POST"}, "_api_logs_summary"),
    "/api/burst": ({"GET", "POST"}, "_api_burst"),
    "/api/bans": ({"GET", "POST"}, "_api_bans"),
    "/api/export": ({"GET"}, "_api_export"),           # 原为 handler 内显式 405
    "/api/proxies": ({"GET", "POST"}, "_api_proxies"),
    "/api/geo": ({"GET", "POST"}, "_api_geo"),
    "/api/geo/db": ({"GET", "POST"}, "_api_geo_db"),
    "/api/kernban": ({"GET", "POST"}, "_api_kernban"),
    "/api/kernban/sync": ({"POST"}, "_api_kernban_sync"),   # 原为 if 条件里的 and method == "POST"
    "/api/ai/review": ({"GET", "POST"}, "_api_ai_review"),
    "/api/ai/review/status": ({"GET", "POST"}, "_api_ai_review_status"),
    "/api/ai/results": ({"GET", "POST"}, "_api_ai_results"),
    "/api/ai/test/status": ({"GET"}, "_api_ai_test_status"),   # 原为 and method == "GET"
    "/api/ai/test": ({"POST"}, "_api_ai_test"),           # 原为 handler 内显式 405
    "/api/blockpage": ({"GET", "POST"}, "_api_blockpage"),
    "/api/about": ({"GET", "POST"}, "_api_about"),
    "/api/upgrade/check": ({"GET", "POST"}, "_api_upgrade_check"),
    "/api/upgrade/status": ({"GET"}, "_api_upgrade_status"),   # 原为 and method == "GET"
    "/api/upgrade/apply": ({"POST"}, "_api_upgrade_apply"),   # 原为 and method == "POST"
    "/api/service": ({"POST"}, "_api_service"),           # 原为 and method == "POST"
    "/api/syslog": ({"GET", "POST"}, "_api_syslog"),
    "/api/version": ({"GET", "POST"}, "_api_version"),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "frpwaf/" + __version__
    protocol_version = "HTTP/1.1"
    # 每连接 socket 超时，缓解 slowloris 慢连接长期占用
    timeout = 30
    # True = 回调专用监听（只接受 /frp/handler，其余路径一律 404）
    _handler_only = False
    # 默认口令未改时仍可访问的 API：登录/退出/改密，以及只读的概览
    # （概览用于前端渲染「需先修改默认口令」引导，不暴露任何变更能力）
    _PWD_GATE_EXEMPT = ("/api/password", "/api/overview")

    # ---------- 工具 ----------
    def log_message(self, format, *args):  # 静音默认访问日志
        pass

    def _send(self, code, body: "bytes | str" = b"", ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # 统一安全响应头：所有出口（HTML/JSON/纯文本/204）都走本方法，
        # 这样才能保证漏掉一处也不会出现「某个响应缺防护」。
        for k, v in _SEC_HEADERS:
            self.send_header(k, v)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), headers=headers)

    def _body(self):
        n = _int(self.headers.get("Content-Length"))
        if n <= 0:
            return {}
        if n > 2 * 1024 * 1024:   # 上限 2MB，防止超大请求体耗尽内存
            raise ValueError("request body too large")
        raw = self.rfile.read(n)
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        # 只有 JSON 对象才是「请求体」；数组/数字/字符串同样能通过 json.loads，
        # 但后续 body.get(...) 会 AttributeError -> 500 + traceback。统一归空对象。
        return data if isinstance(data, dict) else {}

    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _user(self):
        return auth.verify_token(self._cookie(auth.COOKIE_NAME))

    def _require_login(self):
        if not self._user():
            self._json({"code": 401, "msg": "未登录或会话已过期"}, 401)
            return False
        return True

    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    def _is_local(self):
        """回调来源是否为本机（frps 回调固定走 127.0.0.1/::1）。"""
        ip = self._client_ip()
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _cookie_secure(self):
        """是否给会话 Cookie 加 Secure 标记。

        面板默认走明文 HTTP（7080），若给 Cookie 加 Secure，浏览器在 http://
        下不会回传该 Cookie，会出现「登录成功却立刻 401、面板不可用」。
        故默认不加：仅当请求经 HTTPS 到达（反向代理设置 X-Forwarded-Proto）
        或配置显式开启 cookie_secure 时才加。
        """
        try:
            if config.get().get("cookie_secure"):
                return "; Secure"
        except Exception:
            pass
        if (self.headers.get("X-Forwarded-Proto", "") or "").lower() == "https":
            return "; Secure"
        return ""

    # ---------- 路由 ----------
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_HEAD(self):
        """HEAD 走 GET 路由。

        http.server 默认没有 do_HEAD，会给一个 **501 错误页**，而那个响应直接由
        stdlib 写出、根本不经过 _send()，于是安全响应头全部缺失——监控/探活用 HEAD
        探测时看到的是一份没有任何防护头的 501，很容易被当成「服务异常」。
        _send() 本就会在 HEAD 时只发头不发体（原有判断），所以直接复用 GET 路由。
        """
        self._route("GET")

    def _method_not_allowed(self):
        """其余方法（PUT/DELETE/PATCH/OPTIONS）统一 405，且经过 _send()。

        理由同上：stdlib 的默认错误响应绕过 _send()，会让这些请求缺安全响应头。
        """
        self._send(405, "method not allowed", ctype="text/plain; charset=utf-8")

    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_OPTIONS = _method_not_allowed

    def _route(self, method):
        try:
            u = urlparse(self.path)
            path = u.path
            qs = parse_qs(u.query)

            # frp 插件回调（始终放行：关闭网页端不影响 WAF 防护与 frps 回调）
            # 仅接受本机来源：frps 回调固定走 127.0.0.1；否则任何可达 7080 的
            # 来源都能伪造 remote_addr 触发封禁（可把任意 IP 打入黑名单）。
            if path == "/frp/handler":
                if not self._is_local():
                    with _mem_lock:
                        _mem["frp_remote_denied"] += 1
                    return self._send(403, "forbidden", ctype="text/plain; charset=utf-8")
                return self._frp_handler(qs)

            # 回调专用监听（独立端口 + 独立并发配额）不提供面板与其它 API
            if self._handler_only:
                return self._send(404, "not found", ctype="text/plain; charset=utf-8")

            # 网页端开关：关闭时仅屏蔽网页与 /api/*，回调照常运行
            if not config.get().get("web_enabled", True):
                return self._send(403, "网页端已关闭", ctype="text/plain; charset=utf-8")

            # 静态资源
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path == "/favicon.ico":
                return self._send(204, b"")

            # 认证
            if path == "/api/login" and method == "POST":
                return self._api_login()
            if path == "/api/logout" and method == "POST":
                return self._json({"code": 0, "msg": "已退出"},
                                  headers={"Set-Cookie": "%s=; Max-Age=0; Path=/"
                                           % auth.COOKIE_NAME})

            # 需要登录的 API
            if path.startswith("/api/"):
                if not self._require_login():
                    return
                # 首次登录强制改密：默认口令未修改时，除白名单外的 API 全部 403。
                # 放在认证之后：未登录仍然只得到 401，不泄露「口令未改」这个状态。
                if not config.get().get("password_changed", False) \
                        and path not in self._PWD_GATE_EXEMPT:
                    return self._json({"code": 403,
                                       "msg": "需先修改默认口令",
                                       "password_change_required": True}, 403)
                return self._api(path, method, qs)

            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        except _ApiError as exc:
            # 入参非法：400 + {"code":1,"msg":...}，且**不进 traceback 日志**
            # （原先会在业务函数里抛 TypeError -> 500，日志被客户端的错误输入灌满）
            try:
                self._json({"code": 1, "msg": str(exc)}, 400)
            except Exception:
                pass
        except BrokenPipeError:
            pass
        except Exception:
            # 细节只进日志，不回显给请求方（未认证可达，traceback 会泄露内部结构）
            _log("请求处理异常：" + traceback.format_exc()[-500:])
            try:
                self._json({"code": 500, "msg": "服务器内部错误"}, 500)
            except Exception:
                pass

    # ---------- frp 插件回调 ----------
    def _frp_handler(self, qs):
        if self.command != "POST":
            return self._send(405, "method not allowed", ctype="text/plain")
        body = self._body()
        op = (qs.get("op", [body.get("op", "")])[0]) or ""
        content = body.get("content") or {}
        user_info = content.get("user") or {}
        user = user_info.get("user", "") if isinstance(user_info, dict) else ""

        # 目前仅对 NewUserConn 做按来源 IP 的准入控制
        if op == "NewUserConn":
            remote_addr = content.get("remote_addr", "")
            ip, port = _split_addr(remote_addr)
            proxy_name = content.get("proxy_name", "")
            proxy_type = content.get("proxy_type", "")
            # 不可信字段落日志前统一净化 + 截断（防换行伪造审计行）
            log_name = _log_text(proxy_name, _LOG_FIELD_MAX)
            log_type = _log_text(proxy_type, _LOG_FIELD_MAX)
            log_user = _log_text(user, _LOG_FIELD_MAX)
            strict = bool(config.get().get("strict_addr", False))
            if not ip:
                # 字段缺失/格式异常：计数 + 限频告警（/api/overview 可见）。
                # 默认仍放行（保持现有行为），开启 strict_addr 后改为 fail-closed。
                with _mem_lock:
                    _mem["invalid_addr"] += 1
                    n_bad = _mem["invalid_addr"]
                if n_bad <= 3 or n_bad % 100 == 0:
                    _log("回调字段异常（累计 %d 次）：remote_addr=%s 无法解析为 IP/端口，%s"
                         % (n_bad, _log_text(remote_addr, _LOG_FIELD_MAX),
                            "已按 strict_addr 拒连" if strict else "已放行"))
                if strict:
                    try:
                        store.add_log_and_bump("", port, proxy_name, proxy_type, user,
                                               "reject", "invalid-addr", rejected=True)
                    except Exception:
                        _count_fail("db_write_fail",
                                    "连接日志写入失败（reject 记录写不进库，面板看不到这批拒绝）",
                                    traceback.format_exc()[-300:])
                    _log("拒绝连接（strict_addr）：remote_addr=%s -> %s/%s%s 原因=invalid-addr"
                         % (_log_text(remote_addr, _LOG_FIELD_MAX), log_name, log_type,
                            (" user=%s" % log_user) if log_user else ""))
                    return self._json({"reject": True, "reject_reason": "invalid-addr"})
            try:
                # ip 已在 _split_addr 里严格解析并归一化（v4-mapped -> v4），
                # engine.decide 拿到的一定是可解析地址；解析失败在上一段已处理。
                allow, reason = engine.decide(ip, port, proxy_name, proxy_type, user)
            except Exception:
                # 决策异常时放行（避免 WAF 逻辑错误导致 frp 全线拒绝）；
                # 计数 + 限频日志：连续出现说明防护在静默失效，便于从概览/日志发现。
                with _mem_lock:
                    _mem["engine_errors"] += 1
                    n = _mem["engine_errors"]
                if n <= 3 or n % 100 == 0:
                    _log("决策异常（fail-open，累计 %d 次）：%s"
                         % (n, traceback.format_exc()[-300:]))
                allow, reason = True, "engine-error"
            try:
                # 日志 + 代理统计合并为单事务（原为两次独立写库，高并发下写放大）
                store.add_log_and_bump(ip, port, proxy_name, proxy_type, user,
                                       "allow" if allow else "reject", reason,
                                       rejected=not allow)
            except Exception:
                # 写不进去 = 面板看不到连接记录、代理统计也不准。原来直接 pass，
                # 磁盘满/SQLITE_BUSY 时运维毫无感知；现在计数 + 10 分钟限频告警。
                _count_fail("db_write_fail",
                            "连接日志写入失败（面板看不到这批连接记录，代理统计也会偏）",
                            traceback.format_exc()[-300:])
            if allow:
                return self._json({"reject": False, "unchange": True})
            _log("拒绝连接 %s -> %s/%s%s 原因=%s" % (
                ip, log_name, log_type,
                (" user=%s" % log_user) if log_user else "",
                _log_text(reason or "blocked", _LOG_FIELD_MAX)))
            return self._json({"reject": True, "reject_reason": reason or "blocked"})

        # 其他 op（Login / NewWorkConn / CloseProxy / Ping）暂不改动
        return self._json({"reject": False, "unchange": True})

    # ---------- 静态 ----------
    def _static(self, name):
        path = os.path.join(WEB_DIR, name)
        if not os.path.abspath(path).startswith(os.path.abspath(WEB_DIR)) or not os.path.exists(path):
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else "application/octet-stream"
        return self._send(200, data, ctype=ctype)

    # ---------- 认证 API ----------
    def _api_login(self):
        body = self._body()
        user = str(body.get("username", ""))
        pwd = str(body.get("password", ""))
        ip = self._client_ip()
        wait = _login_locked(ip)
        if wait > 0:
            _log("登录被拒（限速中）来自 %s，剩余 %d 秒" % (ip, wait))
            return self._json({"code": 429,
                               "msg": "尝试过于频繁，请 %d 秒后再试" % wait}, 429,
                              headers={"Retry-After": str(wait)})
        if not auth.check_login(user, pwd):
            _login_record(ip, False)
            _log("登录失败 来自 %s 用户名=%s" % (ip, user))
            time.sleep(0.3)
            return self._json({"code": 401, "msg": "用户名或密码错误"}, 401)
        _login_record(ip, True)
        _log("登录成功 来自 %s 用户名=%s" % (ip, user))
        token = auth.create_token(user)
        return self._json(
            {"code": 0, "msg": "登录成功", "user": user,
             "password_change_required": not config.get().get("password_changed", False)},
            headers={"Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Lax%s; Max-Age=%d"
                     % (auth.COOKIE_NAME, token, self._cookie_secure(), auth.SESSION_TTL)},
        )

    # ---------- 管理 API ----------
    def _api(self, path, method, qs):
        """按路由表分发管理 API（路径精确匹配）。

        每次请求只查一次表：未知路径 404「接口不存在」，路径存在但方法不允许
        405 + Allow 头，其余交给对应 handler。handler 统一签名
        ``(cfg, qs, method)``：cfg 是本次请求的配置快照，qs 是 parse_qs 结果，
        method 是 `_route` 判定后的方法（HEAD 也按 GET 传入），按需取用。
        """
        spec = _ROUTES.get(path)
        if spec is None:
            return self._json({"code": 404, "msg": "接口不存在"}, 404)
        allowed, handler = spec
        if method not in allowed:
            return self._api_not_allowed(allowed)
        return getattr(self, handler)(config.get(), qs, method)

    def _api_not_allowed(self, allowed):
        """405 + Allow 头（RFC 7231：405 必须带 Allow）。

        必须走 `_json`（=> `_send`）：stdlib 默认的 error 响应会绕过 `_send`，
        那样 405 就丢了统一的安全响应头。
        """
        allow = ", ".join(sorted(allowed))
        return self._json({"code": 1, "msg": "仅支持 " + allow}, 405,
                          headers={"Allow": allow})

    def _api_metrics(self, cfg, qs, method):
        # 运维可见性（P2-3.10）：纯内存计数，重启清零；需登录（走统一的 /api/* 门禁）。
        # 字段名按接口契约固定；同时镜像一份到 data 里，面板侧统一读 data 也不会踩空。
        with _mem_lock:
            m = {k: int(_mem.get(k) or 0) for k in (
                "engine_errors", "invalid_addr", "db_write_fail", "fw_sync_fail",
                "fw_sync_ms", "ai_call_ms", "frp_remote_denied", "ai_fail",
                "db_backup_fail", "alert_fail")}
        # uptime 以本进程模块加载时刻为起点（服务运行时≈进程启动时刻）
        m["uptime_s"] = max(0, int(time.time()) - int(_mem.get("started") or 0))
        out = {"code": 0}
        out.update(m)
        out["data"] = dict(m)
        return self._json(out)

    def _api_health(self, cfg, qs, method):
        """安全水位：把裸计数翻成「状态 + 说明 + 建议动作」。

        纯内存计算（无磁盘 IO、无网络），每项固定 6 个字段，`level` 取所有项
        里最差的一档。阈值与误报处理的口径见 `_HEALTH_SPEC` / `health_data()`。
        """
        return self._json({"code": 0, "data": health_data(cfg)})

    def _api_overview(self, cfg, qs, method):
        st = store.stats()
        st.update({
            "version": __version__,
            "uptime": int(time.time()) - _mem["started"],
            "http_addr": cfg["http_addr"],
            "http_port": cfg["http_port"],
            "frp_handler_addr": cfg.get("frp_handler_addr", "127.0.0.1"),
            "frp_handler_port": cfg.get("frp_handler_port", 7082),
            "max_concurrent": cfg.get("max_concurrent", 96),
            "handler_max_concurrent": cfg.get("handler_max_concurrent", 32),
            "remote_access": str(cfg.get("http_addr") or "") not in ("127.0.0.1", "::1"),
            # 默认口令未改：前端据此渲染强制改密引导（与 403 门禁同一来源）
            "password_change_required": not cfg.get("password_changed", False),
            "blacklist_enabled": cfg["blacklist_enabled"],
            "whitelist_enabled": cfg["whitelist_enabled"],
            "auto_ban_enabled": cfg["auto_ban_enabled"],
            "auto_ban_cc_enabled": bool(cfg.get("auto_ban_cc_enabled", False)),
            "auto_ban_scan_enabled": bool(cfg.get("auto_ban_scan_enabled", False)),
            "auto_ban_ssh_enabled": bool(cfg.get("auto_ban_ssh_enabled", False)),
            "rate_limit_enabled": cfg["rate_limit_enabled"],
            "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
            "admin_user": cfg.get("admin_user", "admin"),
        })
        with _mem_lock:
            st["engine_errors"] = _mem["engine_errors"]
            st["frp_remote_denied"] = _mem["frp_remote_denied"]
            # 地址解析失败计数：本该恒为 0，持续增长 = 黑白名单在静默失效
            st["invalid_addr"] = _mem["invalid_addr"]
        st["strict_addr"] = bool(cfg.get("strict_addr", False))
        st["ai_allow_private"] = _allow_private_ai(cfg)
        st["geo_available"] = geo.db_info().get("available", False)
        return self._json({"code": 0, "data": st})

    def _api_config(self, cfg, qs, method):
        if method == "GET":
            # 过滤机密字段，避免明文泄露管理密码 / AI 密钥
            safe = {k: v for k, v in cfg.items() if k not in MASKED_KEYS}
            safe["ai_api_key"] = MASKED_VALUE if cfg.get("ai_api_key") else ""
            # 前端「允许远程访问」开关靠它回显（含 ::1/:: 等手改值）
            safe["http_addr"] = str(cfg.get("http_addr") or "")
            return self._json({"code": 0, "data": safe})
        body = self._body()
        patch = {}

        # ---- 监听地址（「允许远程访问」开关）----
        # 只接受通配/回环四值。其它值（具体网卡 IP、域名、0.0.0.0 变体）一律
        # 拒绝并明确报错：面板接口不应能把监听改到不可预测的地址上。
        # 故意不静默回退——保存后监听位没变却提示成功是最坏的体验。
        if "http_addr" in body:
            _addr = str(body.get("http_addr") or "").strip()
            if _addr == "localhost":
                _addr = "127.0.0.1"
            if _addr not in HTTP_ADDR_ALLOWED:
                return self._json({"code": 1, "msg":
                                   "监听地址只能是 %s 之一（当前输入 %r）；"
                                   "其它地址请直接修改 data/frpwaf.json 后重启服务"
                                   % (" / ".join(HTTP_ADDR_ALLOWED), _addr)})
            patch["http_addr"] = _addr
        # ---- 端口（面板 / 回调）----
        for _pk in ("http_port", "frp_handler_port"):
            if _pk not in body:
                continue
            try:
                _pv = int(body.get(_pk))
            except (TypeError, ValueError):
                return self._json({"code": 1, "msg": "%s 必须是数字" % _pk})
            if not 1 <= _pv <= 65535:
                return self._json({"code": 1, "msg": "%s 需在 1~65535 之间" % _pk})
            patch[_pk] = _pv

        allowed = {
            "blacklist_enabled": bool, "whitelist_enabled": bool,
            "auto_ban_enabled": bool, "auto_ban_window": int,
            "auto_ban_threshold": int, "auto_ban_seconds": int,
            "auto_ban_cc_enabled": bool, "auto_ban_cc_window": int,
            "auto_ban_cc_threshold": int, "auto_ban_cc_seconds": int,
            "auto_ban_scan_enabled": bool, "auto_ban_scan_window": int,
            "auto_ban_scan_threshold": int, "auto_ban_scan_seconds": int,
            "auto_ban_ssh_enabled": bool, "auto_ban_ssh_window": int,
            "auto_ban_ssh_threshold": int,
            "rate_limit_enabled": bool, "rate_limit_per_sec": int,
            "log_max_rows": int, "fw_sync_enabled": bool,
            # 静态拦截页（404/封禁/风控）与 GitHub 在线升级
            "block_page_enabled": bool, "block_page_404_enabled": bool,
            "block_page_ban_enabled": bool, "block_page_risk_enabled": bool,
            "block_page_port": int, "block_page_redirect_ports": str,
            "github_repo": str,
            # 分布式突发观测与代理级冷却
            "burst_window": int, "proxy_cool_enabled": bool,
            "proxy_cool_min_conns": int, "proxy_cool_uniq_threshold": int,
            "proxy_cool_single_pct": int, "proxy_cool_seconds": int,
            "ai_enabled": bool, "ai_protocol": str, "ai_base_url": str,
            "ai_api_key": str, "ai_model": str, "ai_interval": int,
            "ai_window": int, "ai_min_conns": int, "ai_max_ips": int,
            "ai_auto_ban": bool, "ai_cdn_guard": bool, "ai_ban_seconds": int,
            "ai_suspicious_ban": bool, "ai_ssh_strict": bool,
            "ai_ssh_permanent_suspicious": bool, "ai_timeout": int,
            # 并发闸门（P0-3）：线程/FD 硬上限，可按机器调
            "max_concurrent": int, "handler_max_concurrent": int,
            # 拦截页监听地址（需 blockpage.py 改读本键后生效）
            "block_page_addr": str,
            # 安全水位告警 webhook（空 = 关闭；保存后立即生效，无需重启）
            "alert_webhook": str,
        }
        # 新增开关（不配置时保持旧行为）：宽松布尔解析，避免 "false" 被当成 True。
        #   strict_addr：地址解析失败时拒连（fail-closed）
        #   ai_allow_private：是否允许 AI 接口指向私有/回环地址（默认允许）
        for _k in ("strict_addr", "ai_allow_private"):
            if _k in body:
                patch[_k] = _to_bool(body[_k])
        # 类型不对时**必须报错**，不能静默丢弃：
        # 原来这里 except (TypeError, ValueError): pass，导致
        #   - log_max_rows={}    → int({}) 失败，但当次保存报「成功」而值没变
        #   - github_repo=12345  → str(12345) 成功，把数字存成垃圾字符串 "12345"
        # 两种都是「界面说成功、实际没生效」，事后极难排查。
        _bad = []
        for k, typ in allowed.items():
            if k not in body:
                continue
            _v = body[k]
            try:
                if typ is bool:
                    # 布尔字段只接受 bool 或能识别的字符串/number，不接受容器
                    if isinstance(_v, (dict, list)):
                        raise TypeError("期望布尔值")
                    patch[k] = _to_bool(_v)
                elif typ is int:
                    if isinstance(_v, bool):        # bool 是 int 子类，但不该当整数用
                        raise TypeError("期望整数")
                    _iv = int(_v)
                    if isinstance(_v, str) and str(_iv) != _v.strip():
                        raise ValueError("不是合法整数")
                    patch[k] = max(0, _iv)
                else:
                    if isinstance(_v, (dict, list)):
                        raise TypeError("期望字符串")
                    # 数字/布尔传给字符串字段多半是填错了（例如 github_repo 填成 12345），
                    # str() 会把它存成垃圾值 "12345"，等到真正用时才报错。
                    if isinstance(_v, (int, float, bool)):
                        raise TypeError("期望字符串，不应为数字")
                    patch[k] = str(_v).strip()
            except (TypeError, ValueError):
                _bad.append(k)
        if _bad:
            return self._json({"code": 1, "msg": "以下设置项的值类型不正确：%s"
                               % "、".join(_bad[:6])})
        # 掩码回写防护：GET 回显的 ****** 不得写回（会毁掉真实密钥）
        _strip_masked(patch)
        # SSRF 防护：接口地址变更即校验，否则可先存恶意地址、再走 /api/ai/test 绕开
        if patch.get("ai_base_url"):
            ok_url, err = ai_url_guard(patch["ai_base_url"],
                                       _allow_private_ai(dict(cfg, **patch)))
            if not ok_url:
                _log("AI 接口地址被拒绝（SSRF 防护）：%s -> %s"
                     % (_log_text(patch["ai_base_url"], 120), err))
                return self._json({"code": 1, "msg": "AI 接口地址不可用：" + err})
        # 告警 webhook 同源校验（SSRF）：空 = 关闭，不清求。
        # ai_allow_private 的语义在这里沿用：告警接收端常是内网服务
        # （ntfy / Gotify / 自建中转），一刀切禁私有地址会直接废掉该功能；
        # 无论开关如何，链路本地与云元数据地址都由 ai_url_guard 硬拒。
        if patch.get("alert_webhook"):
            ok_hook, hook_err = ai_url_guard(patch["alert_webhook"],
                                            _allow_private_ai(dict(cfg, **patch)))
            if not ok_hook:
                _log("告警 webhook 被拒绝（SSRF 防护）：%s -> %s"
                     % (_log_text(patch["alert_webhook"], 120), hook_err))
                return self._json({"code": 1, "msg": "告警 Webhook 地址不可用：" + hook_err})
        if patch.get("auto_ban_window", 60) < 1:
            patch["auto_ban_window"] = 1
        # 攻击类型封禁：窗口参数与既有 auto_ban 同样强制 ≥1 秒；
        # 开关开启时参数为「未设置形态」（阈值/时长 0、窗口 ≤1）的回退默认值，
        # 由 config.save() 内统一的 normalize_auto_ban() 完成（对所有写入路径生效）。
        for _w in ("auto_ban_cc_window", "auto_ban_scan_window", "auto_ban_ssh_window"):
            if patch.get(_w, 60) < 1:
                patch[_w] = 1
        # 突发观测/冷却：窗口与时长参数钳制；开关开启时参数为「未设置形态」
        # 的回退默认值由 config.save() 内统一的 normalize_burst_cool() 完成。
        # 冷却时长下限 10s 与引擎运行时（max(10, ...)）一致，避免显示/行为不符。
        if patch.get("burst_window", 60) < 2:
            patch["burst_window"] = 2
        if patch.get("proxy_cool_seconds", 60) < 10:
            patch["proxy_cool_seconds"] = 10
        if patch.get("proxy_cool_single_pct", 80) > 100:
            patch["proxy_cool_single_pct"] = 100
        if patch.get("ai_interval", 300) < 60:
            patch["ai_interval"] = 60
        if patch.get("ai_window", 300) < 30:
            patch["ai_window"] = 30
        # ---- 端口冲突校验（按「本次 patch 后的生效值」判，避免只改一个端口时漏判）----
        # 面板/回调/拦截页三个监听抢同一端口时：要么服务起不来，要么回调打到面板
        # 上（面板被扫就连带 fail-closed），因此直接拒绝而不是静默回退到默认值。
        _eff = dict(cfg)
        _eff.update(patch)
        try:
            _hp = int(_eff.get("http_port") or 7080)
            _hpp = int(_eff.get("frp_handler_port") or 7082)
            _bpp = int(_eff.get("block_page_port") or 7081)
        except (TypeError, ValueError):
            return self._json({"code": 1, "msg": "端口必须是数字"})
        if _hp == _hpp:
            return self._json({"code": 1, "msg": "面板端口与回调端口不能相同（均为 %d）" % _hp})
        if _hpp == _bpp:
            return self._json({"code": 1, "msg": "回调端口不能与拦截页端口相同（均为 %d）" % _hpp})
        config.save(patch)   # patch 语义：锁内合并磁盘现状，避免覆盖并发写入方字段
        _fw_sync()   # 开关/名单变化立即生效（关闭内核封禁时同步清理残留）
        blockpage.ensure()   # 拦截页端口/开关变更后立即生效
        # 监听地址/端口/并发上限变了：立即重绑（失败会回退旧监听并报错）
        return self._apply_listen(patch)

    def _api_password(self, cfg, qs, method):
        body = self._body()
        _new = str(body.get("new") or "")
        _cfg = config.get()
        # 默认口令不可作为新口令：否则 password_changed 会一直是 False，
        # 首次登录强制改密变成「改了个寂寞」
        if _new and _new == "123456":
            return self._json({"code": 1, "msg": "新口令不能继续使用默认值 123456"})
        # 支持同时修改用户名与密码（与宝塔插件端保持一致）
        ok, msg = auth.change_credentials(
            body.get("old", ""), body.get("new", ""),
            body.get("new_user", ""), body.get("old_user", ""))
        if ok:
            # 写 password_changed：解除「除改密/login 外全部 403」的门禁。
            # config.save() 里的 normalize_password_flag 会按口令实值对齐，
            # 即使这里写错也不会误放行。
            try:
                config.save({"password_changed": True})
            except ValueError:
                pass   # 磁盘配置损坏：不掩盖改密成功的事实
            _audit("Web 端修改管理员账号/口令")
        return self._json({"code": 0 if ok else 1, "msg": msg})

    def _api_iplist(self, cfg, qs, method):
        if method == "GET":
            lt = qs.get("type", [None])[0]
            # 面板展示接口：限制返回条数（缺省/非法 = 默认上限 5000，
            # 显式传入也不超过硬上限）。名单正常为几百条，此上限仅防异常增长。
            lim = _int(qs.get("limit", [0])[0])
            if lim <= 0 or lim > store.PANEL_LIST_CAP:
                lim = store.PANEL_LIST_CAP
            rows = store.list_ips(lt, limit=lim)
            for r in rows:
                # 名单条目可能是 CIDR，取网络地址做归属地查询
                base = (r.get("cidr") or "").split("/")[0]
                g = geo.lookup(base)
                r["geo"] = g.get("text", "")
            return self._json({"code": 0, "data": rows})
        if method == "POST":
            body = self._body()
            action = body.get("action")
            # 入参校验前置：类型/格式不对一律 400（原先传 dict/小数/乱串会 500+traceback）。
            # 校验后就地把 body 里的值规范化，后面的业务分支保持原样。
            if action == "add":
                body["cidr"] = _need_cidr(body, "cidr")
                body["list_type"] = _need_choice(body, "list_type",
                                                 ("black", "white"), "black")
                body["remark"] = _need_str(body, "remark", "", maxlen=500)
            elif action == "del":
                body["id"] = _need_int(body, "id", lo=1)
            elif action == "batch":
                body["text"] = _need_str(body, "text", "")
                body["list_type"] = _need_choice(body, "list_type",
                                                 ("black", "white"), "black")
            try:
                if action == "add":
                    store.add_ip(body.get("cidr", ""),
                                 body.get("list_type", "black"),
                                 body.get("remark", ""))
                    engine.invalidate_cache()
                    _fw_sync()
                    return self._json({"code": 0, "msg": "添加成功"})
                if action == "del":
                    store.del_ip(body.get("id"))
                    engine.invalidate_cache()
                    _fw_sync()
                    return self._json({"code": 0, "msg": "删除成功"})
                if action == "clear_black":
                    # 一键解封全部黑名单（误封恢复；仅黑名单，不动白名单）
                    n = store.clear_blacklist()
                    engine.invalidate_cache()
                    _fw_sync()
                    return self._json({"code": 0, "msg": "已解封全部黑名单（%d 条）" % n})
                if action == "batch":
                    # 多行文本批量导入： 每行  cidr[,备注]
                    text = body.get("text", "")
                    lt = body.get("list_type", "black")
                    ok = fail = 0
                    for line in text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",", 1)
                        cidr = parts[0].strip()
                        remark = parts[1].strip() if len(parts) > 1 else ""
                        try:
                            store.add_ip(cidr, lt, remark)
                            ok += 1
                        except ValueError:
                            fail += 1
                    engine.invalidate_cache()
                    _fw_sync()
                    return self._json({"code": 0, "msg": "导入完成：成功 %d，跳过 %d" % (ok, fail)})
            except ValueError as e:
                return self._json({"code": 1, "msg": str(e)})
            return self._json({"code": 1, "msg": "未知操作"})

    def _api_logs(self, cfg, qs, method):
        if method == "GET":
            limit = max(1, min(1000, _int(qs.get("limit", [100])[0])))
            offset = max(0, _int(qs.get("offset", [0])[0]))
            ip = qs.get("ip", [None])[0]
            action = qs.get("action", [None])[0]
            proxy = qs.get("proxy", [None])[0]
            rows = store.list_logs(limit, offset, ip, action, proxy)
            total = store.count_logs(ip, action, proxy)
            geo.enrich(rows)
            return self._json({"code": 0, "data": rows, "total": total})
        # 走到这里只剩 POST（路由表已保证）；目前仅 action=purge 一个写操作。
        body = self._body()
        if body.get("action") == "purge":
            store.purge_logs()
            return self._json({"code": 0, "msg": "日志已清空"})
        # 未知 action 的口径与 /api/iplist 对齐：资源存在、只是操作不认识，
        # 回 200 + code=1。原先直接掉到链尾回「接口不存在」，把「action 写错」
        # 报成「路径不存在」，排障时容易走错方向。
        return self._json({"code": 1, "msg": "未知操作"})

    def _api_logs_proxies(self, cfg, qs, method):
        # 连接日志中出现过的代理名（供筛选下拉框）
        return self._json({"code": 0, "data": store.log_proxy_names()})

    def _api_logs_summary(self, cfg, qs, method):
        # 按代理聚合视图（窗口钳制 60s ~ 24h；非法值回退默认 1 小时）
        window = _int(qs.get("window", [3600])[0])
        if window <= 0:
            window = 3600
        window = max(60, min(86400, window))
        res = store.summary_by_proxy(window)
        return self._json({"code": 0, "data": res["rows"], "window": window,
                           "total_proxies": res["total_proxies"]})

    def _api_burst(self, cfg, qs, method):
        # 代理级突发观测快照（纯内存）+ 冷却阈值与状态（供面板展示）
        cfg = config.get()
        return self._json({"code": 0, "data": engine.burst_snapshot(), "config": {
            "burst_window": int(cfg.get("burst_window") or 60),
            "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
            "proxy_cool_min_conns": int(cfg.get("proxy_cool_min_conns") or 300),
            "proxy_cool_uniq_threshold": int(cfg.get("proxy_cool_uniq_threshold") or 200),
            "proxy_cool_single_pct": int(cfg.get("proxy_cool_single_pct") or 80),
            "proxy_cool_seconds": int(cfg.get("proxy_cool_seconds") or 60),
        }})

    def _api_bans(self, cfg, qs, method):
        if method == "GET":
            act = store.active_bans()
            his = store.ban_history(100)
            geo.enrich(act)
            geo.enrich(his)
            return self._json({"code": 0, "data": act, "history": his})
        body = self._body()
        action = body.get("action")
        if action == "unban":
            ip = _need_addr(body, "ip")
            store.unban_ip(ip)
            firewall.remove(ip)
            _fw_sync()
            return self._json({"code": 0, "msg": "已解封"})
        if action == "unban_all":
            # 一键解封全部生效中的临时封禁（与黑名单解封独立）
            n = store.release_all_bans()
            _fw_sync()
            return self._json({"code": 0, "msg": "已解封全部临时封禁（%d 条）" % n})
        if action == "ban":
            ip = _need_addr(body, "ip")
            # 0/空 = 默认 1 小时（与旧行为一致）；非整数/越界直接 400
            secs = _need_int(body, "seconds", 3600, lo=0, hi=365 * 86400)
            if secs <= 0:
                secs = 3600
            try:
                store.add_ban(ip, "manual", secs)
            except ValueError as e:
                return self._json({"code": 1, "msg": str(e)})
            except Exception:
                # 写库失败原先只在 ValueError 之外的路径变成 500，且不留痕迹：
                # 面板提示「封禁失败」但日志里什么也没有。现在计数 + 限频告警。
                _count_fail("db_write_fail",
                            "临时封禁写入数据库失败（封禁未生效）",
                            traceback.format_exc()[-300:])
                return self._json({"code": 1, "msg": "封禁写入失败，详情见运行日志"}, 500)
            _fw_sync()
            return self._json({"code": 0, "msg": "已封禁"})
        # 未知 action：与 /api/iplist、/api/logs 同一口径（理由见 /api/logs 处）
        return self._json({"code": 1, "msg": "未知操作"})

    def _api_export(self, cfg, qs, method):
        # 名单/封禁导出（P2-3.11）：运维手工备份、跨机器迁移用。
        # 只读：走 store 的只读连接（不占全局 _lock），导出期间回调照常写入。
        # 机密字段一律掩码：否则「点一下导出」就把 AI 密钥/管理口令落到下载目录，
        # 而导出文件往往会被传来传去（聊天工具/工单附件）。
        # 方法约束（仅 GET）改由 _ROUTES 声明，405 + Allow 由 _api 统一回。
        snap = store.export_rows()
        masked = {k: v for k, v in cfg.items() if k not in MASKED_KEYS}
        for _k in MASKED_KEYS:
            # 空值保持空值（不留掩码，否则看起来像「配置了一个密钥」）
            masked[_k] = MASKED_VALUE if cfg.get(_k) else ""
        _log("导出名单与封禁历史（/api/export）")
        return self._json(
            {"ok": True, "exported_at": int(time.time()),
             "ip_list": snap["ip_list"], "bans": snap["bans"],
             "config_masked": masked},
            headers={"Content-Disposition": 'attachment; filename="%s"'
                     % ("frpwaf-export-%s.json"
                        % time.strftime("%Y%m%d-%H%M%S"))})

    def _api_proxies(self, cfg, qs, method):
        return self._json({"code": 0, "data": store.list_proxy_stat()})

    def _api_geo(self, cfg, qs, method):
        # 单 IP 归属地查询（含当日连接次数）
        ip = (qs.get("ip", [""])[0] or "").strip()
        # 缺参 / 非法 IP 属于「请求本身有问题」，用 400 而不是 200 + code=1：
        # 与 /api/iplist、/api/bans 的入参校验口径一致，也让「路径写错」与
        # 「参数写错」在状态码上就分得开。
        if not ip:
            return self._json({"code": 1, "msg": "请输入 IP"}, 400)
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            return self._json({"code": 1, "msg": "无效的 IP 地址"}, 400)
        g = geo.lookup(ip)
        try:
            conns = store.count_logs(ip=ip)
            recent = store.recent_count_by_ip(ip, 86400)
        except Exception:
            conns = recent = 0
        return self._json({"code": 0, "data": {
            "ip": ip, "geo": g.get("text", ""), "country": g.get("country", ""),
            "province": g.get("province", ""), "city": g.get("city", ""),
            "isp": g.get("isp", ""), "lat": g.get("lat"), "lon": g.get("lon"),
            "total_conns": conns, "today_conns": recent,
        }})

    def _api_geo_db(self, cfg, qs, method):
        return self._json({"code": 0, "data": geo.db_info()})

    def _api_kernban(self, cfg, qs, method):
        st = firewall.status()
        st["enabled"] = bool(cfg.get("fw_sync_enabled", True))
        return self._json({"code": 0, "data": st})

    def _api_kernban_sync(self, cfg, qs, method):
        _audit("Web 端手动同步内核封禁")
        # 走 _fw_sync_once：计时 + 失败计数/10 分钟限频日志
        # （原直接调用 firewall.sync_from_store()，抛异常就是 500 + 无人统计）
        ok = _fw_sync_once()
        st = firewall.status()
        if ok:
            return self._json({"code": 0, "msg": "已同步", "data": st})
        if st.get("mode") == "off":
            return self._json({"code": 0, "msg": "内核封禁与拦截页均已关闭，已清理内核规则",
                               "data": st})
        return self._json({"code": 1,
                           "msg": "当前环境不支持（需 root + ipset/iptables）",
                           "data": st})

    def _api_ai_review(self, cfg, qs, method):
        if method == "POST":
            _audit("Web 端手动触发 AI 审查")
            # 一次审查要送审一批 IP 并等模型回包，可能远超 Nginx 的 60s。
            # 这里只提交后台线程、立即返回，前端轮询 /api/ai/review/status。
            # ai.review() 自带 _review_lock（非阻塞获取），已有审查在跑时
            # 会被它拒掉，不会并行跑两轮。
            if ai.review_busy():
                return self._json({"code": 1, "msg": "已有审查在进行中，请稍候"})

            def _run_review():
                try:
                    res = ai.review(force=True)
                    if not res.get("ok"):
                        _count_fail("ai_fail",
                                    "AI 审查失败（拿不到判定，相关 IP 不会被处置）",
                                    _log_text(res.get("msg"), 200))
                except Exception:
                    _count_fail("ai_fail", "AI 审查异常",
                                traceback.format_exc()[-300:])

            threading.Thread(target=_run_review, name="frpwaf-ai-review",
                             daemon=True).start()
            return self._json({"code": 0, "msg": "已提交审查，正在执行…"})
        return self._json({"code": 0, "data": store.list_ai_review(200)})

    def _api_ai_review_status(self, cfg, qs, method):
        # 轮询手动审查是否已结束：ai.review() 的所有出口都会写
        # ai_last_run / ai_last_ok，直接用它们判断，不另建状态文件。
        cfg_seen = config.get()
        return self._json({"code": 0, "data": {
            "running": ai.review_busy(),
            "last_run": int(cfg_seen.get("ai_last_run") or 0),
            "last_ok": bool(cfg_seen.get("ai_last_ok")),
            "last_result": cfg_seen.get("ai_last_result") or "",
        }})

    def _api_ai_results(self, cfg, qs, method):
        return self._json({"code": 0, "data": store.list_ai_review(200)})

    def _api_ai_test_status(self, cfg, qs, method):
        # 轮询「测试连接」任务状态：提交接口立刻返回，真正的模型调用在后台线程
        return self._json({"code": 0, "data": job.status("ai_test")})

    def _api_ai_test(self, cfg, qs, method):
        # 测试 AI 连接（提交后台任务，立即返回 job_id，前端轮询上面那个状态接口）。
        # 模型调用最长 120s，同步执行会被反向代理/宝塔面板的 60s 超时先掉，
        # 用户以为失败就反复点——变成多次并发打模型，既烧额度也看不出真实结果。
        # 方法约束（仅 POST）改由 _ROUTES 声明，405 + Allow 由 _api 统一回。
        body = self._body()
        cfg = config.get()
        tmp = dict(cfg)
        for k in ("ai_protocol", "ai_base_url", "ai_api_key", "ai_model"):
            v = body.get(k)
            # 掩码值（******）表示「用户未修改」，不能用它覆盖真实密钥
            if v and str(v).strip() and str(v).strip() != MASKED_VALUE:
                tmp[k] = str(v).strip()
        if not tmp.get("ai_base_url") or not tmp.get("ai_api_key"):
            return self._json({"code": 1, "msg": "请先填写接口地址与密钥"})
        # SSRF 防护：本进程以 root 运行，地址完全来自请求体/配置，必须先校验。
        # 校验仍在请求线程里做（提交前拒绝最省事，也不让坏地址占到一次任务名额）。
        ok_url, url_err = ai_url_guard(tmp.get("ai_base_url"),
                                       _allow_private_ai(tmp))
        if not ok_url:
            _log("AI 接口地址被拒绝（SSRF 防护）：%s -> %s"
                 % (_log_text(tmp.get("ai_base_url"), 120), url_err))
            return self._json({"code": 1, "msg": "接口地址不可用：" + url_err})
        started, why, st = job.start(
            "ai_test", lambda prog: _ai_test_job(tmp, prog), "正在调用模型…")
        if not started:
            # 并发保护：同一时刻只允许一次模型测试（常见于用户连点按钮）
            return self._json({"code": 1, "msg": why})
        _log("AI 连接测试已提交后台执行（job %s）" % st.get("job_id"))
        return self._json({"code": 0, "msg": "已提交后台执行，正在调用模型…",
                           "data": {"job_id": st.get("job_id"), "started": True}})

    def _api_blockpage(self, cfg, qs, method):
        return self._json({"code": 0, "data": blockpage.status()})

    def _api_about(self, cfg, qs, method):
        return self._json({"code": 0, "data": {
            "name": "FRP WAF", "version": __version__, "author": __author__,
            "repo": str(cfg.get("github_repo") or ""), "license": "MIT",
            # 不再笼统宣称「零第三方依赖」：app/geo.py 有可选的 import maxminddb
            # （缺失时降级 available=False），如实描述才不会被使用者当成谎言。
            "runtime": "Python 3 标准库 + SQLite + 原生 JS（核心零第三方依赖；"
                       "IP 归属地为可选增强，依赖面板自带的 maxminddb）",
        }})

    def _api_upgrade_check(self, cfg, qs, method):
        # 「检查更新」允许临时指定仓库（只读：仅调 api.github.com 读 Release
        # 信息，方便对比 fork）。该 repo 绝不会被带进 apply（见下）。
        body = self._body() if method == "POST" else {}
        repo = str(body.get("repo") or cfg.get("github_repo") or "").strip()
        res = upgrade.check(repo)
        return self._json({"code": 0 if res.get("ok") else 1, "data": res,
                           "msg": _upgrade_msg(res)})

    def _api_upgrade_status(self, cfg, qs, method):
        # 轮询在线升级进度：升级已移出请求线程，前端靠它拿 running/percent/msg
        return self._json({"code": 0, "data": job.status("upgrade")})

    def _api_upgrade_apply(self, cfg, qs, method):
        # 升级目标仓库只取自配置：请求体里的 repo 一律忽略。
        # 否则任何拿到面板会话的人都能让 root 进程安装任意仓库的代码
        # （改 app/*.py 并重启），这是已确认的 root 权限失守路径。
        body = self._body() or {}
        cfg_repo = str(cfg.get("github_repo") or "").strip()
        asked = str(body.get("repo") or "").strip()
        if asked and asked != cfg_repo:
            _audit("拒绝按请求体仓库升级：请求 %s 与配置 %s 不一致，已改用配置值"
                   % (asked, cfg_repo or "未配置"))
        # 配置缺失在提交阶段就拒（快速失败），不让它占一个任务名额再在后台报错
        if not upgrade.valid_repo(cfg_repo):
            return self._json({"code": 1,
                               "msg": "未配置可用的升级仓库（github_repo），"
                                      "请先在「关于」页填写并保存"})
        # 提交后台任务后立即返回：升级要下载 + 覆盖几百个文件 + 重启，
        # 同步跑必被反向代理的 60s 超时先掉，用户看到「失败」而实际上升级成功了。
        started, why, st = job.start("upgrade", _upgrade_job, "检查更新…")
        if not started:
            # 并发保护：绝不允许两个升级并行（同时覆盖同一批文件会互相打断）
            _audit("拒绝重复的在线升级请求：%s" % why)
            return self._json({"code": 1, "msg": why})
        _audit("Web 端触发 GitHub 在线升级（仓库取自配置：%s），任务 %s，后台执行"
               % (cfg_repo, st.get("job_id")))
        return self._json({"code": 0, "msg": "升级任务已提交，正在后台执行（可轮询进度）",
                           "data": {"job_id": st.get("job_id"), "started": True}})

    def _api_service(self, cfg, qs, method):
        body = self._body()
        action = str(body.get("action") or "").strip()
        if action not in ("restart", "stop"):
            return self._json({"code": 1, "msg": "不支持的操作（仅 restart / stop）"})
        _audit("Web 端服务控制：%s" % action)
        ok = upgrade.schedule_init(action, delay=2)
        if not ok:
            return self._json({"code": 1, "msg": "无法执行（未找到服务脚本 /etc/init.d/frpwaf）"})
        return self._json({"code": 0,
                           "msg": "已提交，服务将在约 2 秒后%s" % ("重启" if action == "restart" else "停止")})

    def _api_syslog(self, cfg, qs, method):
        lim = _int(qs.get("limit", [200])[0])
        if lim <= 0 or lim > 2000:
            lim = 200
        try:
            with open(config.LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []
        return self._json({"code": 0, "data": {"lines": lines[-lim:], "total": len(lines)}})

    def _api_version(self, cfg, qs, method):
        return self._json({"code": 0, "version": __version__})

    def _apply_listen(self, patch):
        """保存后重绑监听，并把实际结果回给前端。

        patch 里没有监听相关键时为普通保存（直接成功）。重绑失败时旧监听已回退，
        故这里回 code=1 提示用户，但配置已落盘（下次重启会重试）。
        """
        _keys = ("http_addr", "http_port", "frp_handler_port",
                 "max_concurrent", "handler_max_concurrent")
        if not any(k in patch for k in _keys):
            return self._json({"code": 0, "msg": "保存成功"})
        cfg = config.get()
        errs = []
        notes = []
        for role, label, cls in (("panel", "面板", Handler),
                                 ("handler", "回调", _HandlerOnlyHandler)):
            addr, port, cap = _listener_params(cfg, role)
            if role == "handler":
                pa, pp, _pc = _listener_params(cfg, "panel")
                if (addr, port) == (pa, pp):
                    notes.append("回调与面板同地址端口，已合并监听")
                    continue
            ok, msg = _rebind_role(role, addr, port, cap, cls, label)
            if not ok:
                errs.append(msg)
        if errs:
            return self._json({"code": 1, "msg": "；".join(errs)})
        addr, port, cap = _listener_params(cfg, "panel")
        msg = "保存成功，面板当前监听 %s:%d（并发上限 %d）" % (addr, port, cap)
        if "http_addr" in patch or "http_port" in patch:
            msg += "；若监听地址已变，请用新地址访问"
        if notes:
            msg += "；" + "；".join(notes)
        return self._json({"code": 0, "msg": msg, "data": {
            "http_addr": addr, "http_port": port, "max_concurrent": cap}})


class _HandlerOnlyHandler(Handler):
    """回调专用监听（独立端口）的 Handler：只接 /frp/handler，其余一律 404。

    分端口的目的是把「frps 回调」与「面板请求」的并发额度彻底分开：
    面板被慢连接/扫描打满时，回调仍有自己的配额，不会因为面板被扫而让
    frps 因回调失败 fail-closed 拒绝全部连接。
    """
    _handler_only = True


# ---- 监听管理（面板 / 回调各自独立线程与并发配额）----
# role -> (server, thread)
_servers = {"panel": None, "handler": None}


def _listener_params(cfg, role):
    """从配置取某个监听的 (addr, port, 并发上限)。"""
    if role == "handler":
        addr = str(cfg.get("frp_handler_addr") or "127.0.0.1")
        port = _int(cfg.get("frp_handler_port")) or 7082
        cap = _int(cfg.get("handler_max_concurrent")) or 32
    else:
        addr = str(cfg.get("http_addr") or "127.0.0.1")
        port = _int(cfg.get("http_port")) or 7080
        cap = _int(cfg.get("max_concurrent")) or 96
    return addr, int(port), int(cap)


def _start_listener(role, addr, port, cap, handler_cls):
    """绑定并后台起服务（serve_forever 跑在独立线程，便于运行时重绑）。"""
    srv = _QuietHTTPServer((addr, int(port)), handler_cls, max_concurrent=cap)
    srv.daemon_threads = True
    srv.timeout = 30
    th = threading.Thread(target=srv.serve_forever, name="frpwaf-" + role, daemon=True)
    th.start()
    _servers[role] = (srv, th)
    return srv


def _stop_listener(role):
    """停掉某个监听（先 shutdown 让 serve_forever 退出，再关监听套接字）。

    已建立的连接不受影响（server_close 只关监听 fd），因此可以在处理面板请求的
    线程里安全地重绑，不会把当前响应截断。
    """
    item = _servers.get(role)
    if item is None:
        return
    srv, th = item
    _servers[role] = None
    try:
        srv.shutdown()
    except Exception:
        pass
    try:
        srv.server_close()
    except Exception:
        pass
    try:
        th.join(2.0)
    except Exception:
        pass


def _rebind_role(role, addr, port, cap, handler_cls, label):
    """把某个监听切换到新的 (addr, port, cap)；失败则回退旧监听。

    返回 (ok, msg)。先关旧后绑新是必须的：Linux 下「通配地址」与「具体地址」
    不能同时占同一端口，先绑新会在改监听地址时必失败。
    """
    item = _servers.get(role)
    old = None
    if item is not None:
        srv = item[0]
        try:
            old = (srv.server_address[0], int(srv.server_address[1]),
                   int(srv.max_concurrent))
        except Exception:
            old = None
        if old == (addr, int(port), int(cap)):
            return True, ""
        _stop_listener(role)
    try:
        _start_listener(role, addr, port, cap, handler_cls)
        _log("%s监听已切换为 %s:%d（并发上限 %d）" % (label, addr, int(port), int(cap)))
        return True, ""
    except OSError as exc:
        _log("%s监听切换失败（%s:%s）：%s" % (label, addr, port, exc))
        if old is None:
            return False, "%s监听切换失败（%s）" % (label, exc)
        try:
            _start_listener(role, old[0], old[1], old[2], handler_cls)
            return False, "%s监听切换失败（%s），已回退到原地址 %s:%s" % (
                label, exc, old[0], old[1])
        except OSError as exc2:
            _log("%s监听回退也失败：%s" % (label, exc2))
            return False, "%s监听切换失败且回退失败（%s），当前无可用监听，请重启服务" % (
                label, exc2)


def _upgrade_job(progress):
    """后台执行 GitHub 在线升级（原本跑在请求线程里的 upgrade.apply 原样搬过来）。

    语义一步没改：仓库只取自配置、发布包必须有 sha256 锚点并比对、结构校验、
    备份失败不覆盖、覆盖/重启失败自动回滚 —— 这些都在 upgrade.apply() 里，
    这里只负责换一个执行线程，并把结果写成任务状态供前端轮询。

    进度由 upgrade.apply() 的阶段回调驱动（检查 → 下载 → 校验 → 解包 →
    结构校验 → 备份 → 覆盖 → 重启），所以前端能读到 5 和 100 之间的中间态，
    不再是「卡在 5% 然后突然 100%」。
    """
    repo = str(config.get().get("github_repo") or "").strip()
    progress(5, "准备检查更新…")
    res = upgrade.apply(repo, progress=progress)
    msg = _upgrade_msg(res)
    _audit("GitHub 在线升级结果：%s" % msg)
    if res.get("ok"):
        return {"ok": True, "msg": msg,
                "from": str(res.get("from") or ""),
                "to": str(res.get("to") or ""),
                "sha256": str(res.get("sha256") or "")}
    return {"ok": False, "error": msg, "msg": msg}


def _ai_test_job(tmp, progress):
    """后台执行一次 AI 连接测试（模型调用最长 120s，不能占请求线程）。

    SSRF 校验已在提交阶段做过（daemon.ai_url_guard），此处不重复。
    ai_call_ms 统计照旧更新，只是从请求线程改成后台线程里记。
    失败原因按原口径处理：响应体摘要只进运行日志（防内网内容被外带），
    回给前端的只是一句不含响应体的摘要。
    """
    t0 = time.time()
    progress(30, "正在调用模型…")
    ok, res = ai.call_model(tmp, [{"ip": "8.8.8.8", "geo": "美国", "conns": 1,
                                   "rejected": 0, "proxies": "test"}])
    with _mem_lock:
        # 最近一次模型调用耗时（不是累计）；无调用时保持 0
        _mem["ai_call_ms"] = int((time.time() - t0) * 1000)
    if ok:
        return {"ok": True, "msg": "连接成功，模型返回正常"}
    # 失败详情（含响应体摘要）只进本地运行日志，且按 10 分钟限频：
    # 模型挂掉时自动审查会持续失败，逐次打日志会把运行日志涮成无效信息。
    _count_fail("ai_fail", "AI 模型调用失败（自动审查拿不到判定，相关 IP 不会被处置）",
                _log_text(res, 300))
    msg = "连接失败：" + _safe_ai_error(res)
    return {"ok": False, "error": msg, "msg": msg}


def _upgrade_msg(res):
    """把 upgrade 的返回压成一句可原样展示的中文（失败原因绝不能吞掉）。

    upgrade.apply() 失败时给 `error`，成功（含「已是最新版本」）给 `msg`。
    两个键都可能缺：缺了也必须给明确兜底，不能让面板把失败当成「完成」。
    典型场景：Release 既无 asset digest 也无 SHA256SUMS 时 apply 会拒绝升级，并返回『该发布缺少校验信息』——这句话必须原样回到前端。
    """
    if not isinstance(res, dict):
        return "升级模块返回异常"
    msg = str(res.get("error") or res.get("msg") or "").strip()
    if msg:
        return msg
    return "升级完成" if res.get("ok") else "升级失败（未返回原因，请查看运行日志）"


def _write_burst_snapshot(cfg):
    """把突发观测/冷却快照写入 data/burst_snapshot.json（供插件端面板进程读取）。

    观测与冷却状态都在本进程内存中，宝塔插件端运行在另一个进程，
    无法直接访问；由后台每 10s 周期落盘一次（原子替换），
    插件端 burst_status 读该文件。写失败不中断主流程，但按窗口记一次
    运行日志（磁盘满/权限问题可排查）；文件权限与配置/DB 一致收紧为 0600。
    """
    try:
        data = {
            "ts": int(time.time()),
            "data": engine.burst_snapshot(),
            "config": {
                "burst_window": int(cfg.get("burst_window") or 60),
                "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
                "proxy_cool_min_conns": int(cfg.get("proxy_cool_min_conns") or 300),
                "proxy_cool_uniq_threshold": int(cfg.get("proxy_cool_uniq_threshold") or 200),
                "proxy_cool_single_pct": int(cfg.get("proxy_cool_single_pct") or 80),
                "proxy_cool_seconds": int(cfg.get("proxy_cool_seconds") or 60),
            },
        }
        tmp = "%s.tmp.%d" % (config.BURST_SNAPSHOT_PATH, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, config.BURST_SNAPSHOT_PATH)
        try:
            os.chmod(config.BURST_SNAPSHOT_PATH, 0o600)   # 含代理名/观测指标，收紧权限
        except OSError:
            pass
    except Exception:
        # 写失败按窗口限流记日志（避免每 10s 刷屏）
        now = time.time()
        if now - _snap_fail_log["at"] >= 600:
            _snap_fail_log["at"] = now
            try:
                _log("突发观测快照写入失败（插件端将看到过期数据）：%s"
                     % traceback.format_exc()[-200:])
            except Exception:
                pass


_snap_fail_log = {"at": 0.0}


# 后台轮询间隔（秒）。
# 历史为 10s：那时内核同步每轮要 fork 多条 ipset/iptables（且每轮固定 6 条注定失败的
# iptables -D），10s 一轮开销可观。firewall 已改为状态记忆化（稳态 0 fork），
# 实时封禁也由事件驱动路径覆盖，因此这里改为 30s 兜底轮询即可：
# 到期封禁的释放粒度由 10s 变粗为 30s（临时封禁多活 ≤30s，可接受）。
_BG_INTERVAL = 30         # 秒
_BG_CHECKPOINT_EVERY = 60    # WAL checkpoint 周期（秒）
_BG_HEARTBEAT_EVERY = 600    # 心跳日志周期（秒）
# 数据快照备份周期（秒）。备份是重的 IO（几十 MB 级），一天一次就够：更频繁
# 除了多占磁盘没有额外价值（真正的回滚点是「上一个稳定快照」）。
_BG_BACKUP_EVERY = 24 * 3600
# 备份失败后的重试间隔（秒）：低磁盘/临时锁冲突都是一次性因，若像成功那样
# 排到 24 小时后，一次瞬时失败就会让当天整段数据没有快照。
_BG_BACKUP_RETRY = 600


def _bg_backup(now):
    """后台自动备份节流：返回**下次应尝试**的时刻（epoch 秒）。

    以磁盘上最新备份的 mtime 为准，而不是只靠进程内计时：这样「刚重启完就
    一直没备份」和「重启后把 24 小时重新数一遍」两个坑都不会踩（重启不丢
    「上次备份是什么时候」）。距上次备份不足 24h 时直接返回「下次到期时刻」，
    不产生任何写入。
    """
    try:
        last = store.last_backup_time()
        if last and now - last < _BG_BACKUP_EVERY:
            return last + _BG_BACKUP_EVERY
        ok, info = store.backup_db(keep=store.BACKUP_KEEP)
        if ok:
            _log("数据库自动备份完成：%s（保留最近 %d 份）"
                 % (os.path.basename(info), store.BACKUP_KEEP))
            return now + _BG_BACKUP_EVERY
        _count_fail("db_backup_fail",
                    "数据库自动备份失败（误删/误清理后将没有可用回退点）", info)
        return now + _BG_BACKUP_RETRY
    except Exception:
        # 备份是「有更好、没有也能跑」的旁路：任何异常不得上溯主循环
        _count_fail("db_backup_fail", "数据库自动备份异常",
                    traceback.format_exc()[-300:])
        return now + _BG_BACKUP_RETRY


def _bg_loop():
    """后台：释放到期封禁、裁剪日志、同步内核封禁、WAL checkpoint、数据快照备份、写心跳日志。

    周期与 checkpoint/心跳的时间阈值解耦（按秒计，而不是数 tick 次数）：
    以后再调 _BG_INTERVAL 时，checkpoint 与心跳的周期不会被连带改掉。
    """
    last_ckpt = 0.0
    last_hb = 0.0
    # 初次为 0 = 启动后第一轮就检查一次；_bg_backup 内部再按「磁盘上最新备份」
    # 判断是否真的需要做（距上次不足 24h 就只把下次到期时刻算出来）
    next_backup = 0.0
    while True:
        try:
            for b in engine.auto_release():
                _log("自动解封 %s（封禁到期）" % b["ip"])
            # 代理级冷却判定（默认关闭；开关开启时进入/续期/清理）
            for name in engine.cool_check():
                _log("代理级冷却：%s 触发分布式突发阈值，冷却期内新 IP 将被拒绝" % name)
            cfg = config.get()
            store.trim_logs(int(cfg.get("log_max_rows") or 50000))
            store.trim_bans(20000)
            store.trim_ai_review(5000)
            _fw_sync()
            # 安全水位告警：先判断是否跨 bad 跳变，再发送（未配置则直接返回）
            _alert_check(cfg)
            blockpage.ensure()   # 兜底：其它进程（宝塔插件端）改了拦截页配置也能生效
            now = time.time()
            if now - last_ckpt >= _BG_CHECKPOINT_EVERY:
                last_ckpt = now
                store.checkpoint(truncate=True)
            # 数据快照（重 IO 操作，只能放在后台线程：请求线程里绝不能做）
            if now >= next_backup:
                next_backup = _bg_backup(now)
            # 每 10 分钟写一条心跳（含内存占用），便于确认服务存活
            if now - last_hb >= _BG_HEARTBEAT_EVERY:
                last_hb = now
                try:
                    with open("/proc/self/statm") as f:
                        rss = int(f.read().split()[1]) * 4096 // 1024
                    _log("心跳：服务正常，生效封禁 %d，内存 %dKB" % (
                        len(store.active_bans()), rss))
                except Exception:
                    _log("心跳：服务正常")
        except Exception:
            _log("后台任务异常：" + traceback.format_exc()[-300:])
        time.sleep(_BG_INTERVAL)


_snap_err = {"at": 0.0, "n": 0}


def _snapshot_loop():
    """突发观测快照独立 10s 落盘。

    插件端 burst_status 用「超过 30s 未更新」判定陈旧，而后台主轮询已放慢到 30s：
    两者共用同一周期会在 30s 边界抖动，让面板把正常数据误标为「陈旧」。
    快照只是内存数据序列化（无 DB、无 fork），保持 10s 完全负担得起。

    异常隔离：本线程只服务「插件端能看到多新的观测数据」，任何异常都不得
    上溯主循环/进程；失败按 10 分钟限频记一条日志，避免磁盘满或权限异常时
    每 10s 刷一轮日志（同时保证问题不会被静默掩盖）。
    """
    while True:
        try:
            _write_burst_snapshot(config.get())
        except Exception:
            now = time.time()
            if now - _snap_err["at"] >= 600:
                _snap_err["at"] = now
                _snap_err["n"] += 1
                try:
                    _log("快照线程异常（第 %d 次记录，10 分钟限频）：%s"
                         % (_snap_err["n"], traceback.format_exc()[-300:]))
                except Exception:
                    pass   # 连日志都写不了（磁盘满）：只能静默，不能因此退出
        time.sleep(10)


def write_pid():
    try:
        with open(config.PID_PATH, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass


def _bind_firewall_logger():
    """把 firewall 模块的限频告警并入运行日志（data/frpwaf.log）。

    firewall 侧改成「按命令族 600s 限频记日志」后不再 2>/dev/null 静默；把回调指向
    _log 就能和面板/决策日志同文件，运维不用再单独看 stderr。
    这里用 getattr 探测：daemon 与 firewall 分属不同改动批次，接口未就绪时不能崩，
    也不能因此让服务起不来（日志接入只是可观测性增强，不是功能前提）。
    """
    setter = getattr(firewall, "set_logger", None)
    if not callable(setter):
        return
    try:
        setter(_log)
    except Exception:
        pass


def main():
    config.load()
    store.init()
    write_pid()
    _bind_firewall_logger()   # firewall 限频告警并入运行日志（接口缺失时静默跳过）
    _guard_load()   # 登录失败计数跨重启恢复（全局冷却不再因重启而清零）
    cfg = config.get()
    t = threading.Thread(target=_bg_loop, daemon=True)
    t.start()
    threading.Thread(target=_snapshot_loop, daemon=True).start()
    threading.Thread(target=ai.loop_forever, daemon=True).start()
    blockpage.ensure()   # 拦截页服务（独立端口，受 block_page_enabled 控制）

    # 1) 面板 + /api（并发闸门 max_concurrent）
    addr, port, cap = _listener_params(cfg, "panel")
    try:
        _start_listener("panel", addr, port, cap, Handler)
    except OSError as exc:
        # 与旧行为一致：面板起不来属于致命错误（init 脚本收 start 失败）
        msg = "面板监听失败 %s:%d：%s" % (addr, port, exc)
        _log(msg)
        print("[frpwaf] " + msg, file=sys.stderr, flush=True)
        sys.exit(1)
    print("[frpwaf] listening on %s:%d  (pid=%d, max_concurrent=%d)"
          % (addr, port, os.getpid(), cap), flush=True)
    _log("服务启动，面板监听 %s:%d（pid=%d，版本 %s，并发上限 %d）"
         % (addr, port, os.getpid(), __version__, cap))

    # 2) frps 回调独立监听（并发闸门 handler_max_concurrent）
    #    失败只告警：宁可退回「回调与面板同端口」的旧形态也不能让服务起不来。
    haddr, hport, hcap = _listener_params(cfg, "handler")
    if (haddr, hport) == (addr, port):
        _log("回调监听与面板相同（%s:%d），已合并：建议把 frp_handler_port 分出去"
             % (haddr, hport))
    else:
        try:
            _start_listener("handler", haddr, hport, hcap, _HandlerOnlyHandler)
            print("[frpwaf] callback listener on %s:%d  (max_concurrent=%d)"
                  % (haddr, hport, hcap), flush=True)
            _log("frps 回调监听 %s:%d（并发上限 %d）；frps.toml 的 httpPlugins addr "
                 "需指向该地址" % (haddr, hport, hcap))
            if haddr in ("0.0.0.0", "::"):
                _log("警告：回调监听绑定了通配地址 %s，建议改回 127.0.0.1（frps 与本服务同机）"
                     % haddr)
        except OSError as exc:
            _log("回调独立监听启动失败（%s:%d）：%s；将仅由面板监听兼任回调（面板被打满时"
                 "回调可能被饿死）" % (haddr, hport, exc))
            print("[frpwaf] callback listener failed on %s:%d: %s"
                  % (haddr, hport, exc), flush=True)

    try:
        # 监听都在各自线程里 serve_forever，主线程只负责驻留与优雅退出
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        _stop_listener("handler")
        _stop_listener("panel")
        _log("服务停止（pid=%d）" % os.getpid())


if __name__ == "__main__":
    main()
