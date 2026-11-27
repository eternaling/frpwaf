#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - AI 自动 IP 审查

周期性把最近一段时间的高频来源 IP（含归属地、连接数、命中代理）汇总后，
交给大模型判断是否恶意，并按判定分级处置：

  - 确凿（malicious）        -> 永久黑名单（ip_list black，内核 timeout=0）
  - 疑似（suspicious）       -> 临时封禁（时长 ai_ban_seconds，默认 1800 秒）
  - SSH 相关从严             -> 模型标记 SSH 爆破、或命中代理名含 ssh 时，
                                疑似也直接永久黑名单（ai_ssh_strict 控制）
  - CDN 回源                 -> 仅记录，不自动封禁（ai_cdn_guard 控制；
                                防封 CDN 边缘节点导致整站 522）
  - 白名单命中 / 已处置      -> 跳过（skipped / already_banned）

支持两种协议：
  - openai    : POST {base}/v1/chat/completions   (Authorization: Bearer)
  - anthropic : POST {base}/v1/messages           (x-api-key + anthropic-version)
仅使用标准库 urllib，无需额外依赖。
"""
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from concurrent.futures import ThreadPoolExecutor

from . import config, geo, store

SYSTEM_PROMPT = (
    "你是一名服务器安全分析师，负责审查反向代理(frp)的入站连接来源 IP。"
    "你会收到一组来源 IP 及其归属地、连接次数、命中的代理端口类型等信息。"
    "请判断每个 IP 是否属于恶意/可疑行为（例如：端口扫描、SSH 暴力破解、"
    "爬虫抓取、异常高频访问、来自高风险地区的自动化攻击等）。"
    "正常用户访问（如本人手机/公司网络的常规访问）应判为 benign。"
    "关于 CDN/反向代理回源：一个 CDN 边缘节点会代表大量真实用户发起连接，"
    "误封边缘 IP 会使经该节点访问的站点整体不可用。"
    "仅当某 IP 的归属地/ISP/组织名属于 CDN 厂商（Cloudflare、Amazon CloudFront、"
    "Fastly、Sucuri、Imperva、Incapsula、Akamai、阿里云 CDN/ESA、腾讯云 CDN/EdgeOne、"
    "百度云加速等），且只访问 http/https/tcpmux 类代理时，才可将 category 填 cdn_origin，"
    "此时 verdict 一般为 benign。"
    "通用云厂商（Amazon EC2、阿里云 ECS、腾讯云 CVM 等）上既有 CDN 也有普通云主机，"
    "不能仅凭厂商名判为 cdn_origin。"
    "访问 ssh/mysql/redis 等非 Web 服务（ptypes 含 tcp/udp 等类型）的 IP 不可能是 CDN 回源。"
    "对每个 IP 还需给出攻击类型 category（英文短语，如 ssh_bruteforce、port_scan、"
    "web_scan、crawler、rate_abuse、cdn_origin、other；正常访问填 none）。"
    "只输出 JSON，不要输出任何多余文字或 markdown 代码块。"
)


def _build_user_prompt(items):
    lines = [
        "以下是需要审查的来源 IP 列表（JSON）：",
        json.dumps(items, ensure_ascii=False),
        "",
        "请对每个 IP 给出判断，严格按如下 JSON 数组格式返回（不要 markdown 代码块）：",
        '[{"ip":"1.2.3.4","verdict":"malicious|suspicious|benign",'
        '"category":"ssh_bruteforce|port_scan|web_scan|crawler|rate_abuse|cdn_origin|other|none",'
        '"reason":"简短中文理由"}]',
        "判定规则：确凿的攻击/扫描/爆破 => malicious；可疑但不确定 => suspicious；正常 => benign。",
        "category 取上述取值之一；无法归类时填 other；正常访问填 none。",
        "cdn_origin 的适用条件：ISP/组织名属于 CDN 厂商，且 ptypes 只含 http/https/tcpmux；"
        "ptypes 含其它类型、或只有通用云厂商名时不适用 cdn_origin。",
    ]
    return "\n".join(lines)


def _collect():
    """汇总最近窗口内的高频 IP。

    聚合必须走 `_query_ro`（独立只读连接，不占全局 _lock）：
    `WHERE ts>=? GROUP BY ip ORDER BY conns DESC` 在窗口突发时（窗口内几万行）
    可能跑几十到几百毫秒，若占着全局锁，这段时间内每个 NewUserConn 的
    `add_log_and_bump` 都在排队——frps 回调超时就会被判失败（fail-closed）。
    WAL 模式下读与写互不阻塞，换成只读连接后慢查询只慢自己。
    """
    cfg = config.get()
    window = max(30, int(cfg.get("ai_window") or 300))
    min_conns = max(1, int(cfg.get("ai_min_conns") or 20))
    max_ips = max(1, int(cfg.get("ai_max_ips") or 20))
    since = int(time.time()) - window

    rows = store._query_ro(
        "SELECT ip, COUNT(*) AS conns, "
        "  SUM(CASE WHEN action!='allow' THEN 1 ELSE 0 END) AS rejected, "
        "  GROUP_CONCAT(DISTINCT proxy_name) AS proxies, "
        "  GROUP_CONCAT(DISTINCT proxy_type) AS ptypes "
        "FROM conn_log WHERE ts>=? GROUP BY ip HAVING conns>=? "
        "ORDER BY conns DESC LIMIT ?",
        (since, min_conns, max_ips),
    )
    items = []
    for r in rows:
        g = geo.lookup(r["ip"])
        items.append({
            "ip": r["ip"],
            "geo": g.get("text", ""),
            "conns": r["conns"],
            "rejected": r["rejected"] or 0,
            "proxies": (r["proxies"] or "")[:120],
            # 命中代理类型：模型据此区分 Web 回源（http/https/tcpmux）与敏感服务爆破；
            # 本地 _cdn_origin_hit 也用它做类型硬否决（非 Web 类型不可能是 CDN 回源）。
            "ptypes": (r["ptypes"] or "")[:80],
        })
    return items


def _salvage_json(text):
    """从被截断的 JSON 文本中逐对象抢救（仅整体解析失败时调用）。

    模型输出达到 max_tokens 上限时，数组尾部条目会被截断（JSON 不完整）。
    这里按 `{` 起点用 JSONDecoder.raw_decode 逐个尝试，只接受能完整解析的
    对象；缺失条目由调用方按「未返回 = 不处置」处理，安全方向不受影响。
    """
    dec = json.JSONDecoder()
    out = []
    i = text.find("{")
    while i != -1:
        try:
            obj, end = dec.raw_decode(text, i)
        except ValueError:
            i = text.find("{", i + 1)
            continue
        if isinstance(obj, dict):
            out.append(obj)
        i = text.find("{", end)
    return out


def _extract_json(text):
    """从模型回复中提取 JSON 数组（容忍 markdown 代码块/多余文字/尾部截断）。"""
    if not text:
        return None
    t = text.strip()
    # 去掉 ```json ... ``` 包裹
    m = re.search(r"```(?:json)?\s*(.*?)```", t, re.S)
    if m:
        t = m.group(1).strip()
    # 找到第一个 [ 到最后一个 ]
    a, b = t.find("["), t.rfind("]")
    if a != -1 and b != -1 and b > a:
        t = t[a:b + 1]
    try:
        return json.loads(t)
    except Exception:
        pass
    # 整体解析失败：多为输出被 max_tokens 截断。逐对象抢救，全失败仍返回 None
    salvaged = _salvage_json(t)
    return salvaged if salvaged else None


def _in_trusted_cidr(ip, cfg):
    """IP 是否落在「永不自动封禁」的可信网段里。

    两个来源（任一命中即可）：
      1. 配置 `ai_trusted_cidrs`（运维手动声明的，确定性）；
      2. **自动学习表** `trusted_cidr`（AI 判过 CDN 回源的 IP/段会自己记下）。

    为什么需要：站点前置 CDN/WAF 时，回源 IP 属于共享边缘节点，封一个等于封
    一片真实用户（2026-11 封掉阿里云 ESA 回源段 → 整站 522）。而回源 IP 段
    不是固定公开列表（owner 也拿不到），所以只能「遇到过就记住」——这就是
    第 2 个来源的意义。

    调用频率：每个送审 IP 一次（不是每个连接），一次 DB 只读查询可接受。
    """
    return bool(_in_config_cidrs(ip, cfg) or _in_learned_cidrs(ip))


def _in_config_cidrs(ip, cfg):
    """IP 是否落在**人工配置**的可信网段 `ai_trusted_cidrs` 里。

    命中返回匹配到的网段字符串，否则返回 ""。运维手动声明、确定性，不读库。
    与 _in_learned_cidrs 分开，是为了让审计与面板能区分「人工配置」和「AI 学到」。
    """
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    raw = str(cfg.get("ai_trusted_cidrs") or "").strip()
    if not raw:
        return ""
    for part in re.split(r"[,;\s]+", raw):
        if not part:
            continue
        try:
            if obj in ipaddress.ip_network(part, strict=False):
                return part
        except ValueError:
            continue
    return ""


def _in_learned_cidrs(ip):
    """IP 是否落在**自动学习表** `trusted_cidr` 里（AI 判过 CDN 回源的 IP/段会自己记下）。

    命中返回该条目的 cidr，否则返回 ""；命中时刷新 last_seen 并按来源续期
    （续期上限 created_at + 90 天）。学习表查询已过滤过期条目，误学可自愈。
    读学习表失败按未命中处理，不影响主流程。
    """
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    try:
        learned = list(store.list_trusted_cidr_strings())
    except Exception:
        return ""
    for part in learned:
        try:
            hit = obj in ipaddress.ip_network(part, strict=False)
        except ValueError:
            continue
        if hit:
            try:
                store.touch_trusted_cidr(part)
            except Exception:
                pass
            return part
    return ""


# 同段升级为整段可信（/24）所需的最小强证据 /32 个数。
# 强证据 = keyword / model / manual（口径见 store.count_trusted_in_subnet），弱证据不计。
# 为什么是 3 而不是 2：model 层的旁证允许「全 Web 类型 + >=2 个代理名」（见 _cdn_origin_hit
# 的 web_multi），所以一个多站探测的 Web 来源就能贡献一个强证据名额；门槛定在 2 时，
# 同段凑两个即整段信任 24 小时，放大器成本太低。提到 3 让「误判 + 邻近误判」需要连续三次。
# 为什么不改成「必须至少一条 keyword 证据」：2026-11 整站 522 的根因正是 ESA 回源 IP 的
# 归属地文本只写「阿里云」、不含 CDN 字样，关键字层完全落空，只有当 model 层 + 行为旁证
# 能认出来；要求 keyword 等于让那类来源永远升不了级，事故会重演。
# 为什么不做成 config.DEFAULTS 配置项：这是安全内部阈值而非运维旋钮，暴露成配置项要同步
# 两个面板的设置页与配置校验，而误配成 1 就等于把放大器开满，收益远不及代价。
_TRUST_SUBNET_MIN_IPS = 3


def _learn_trusted(ip, reason, source="behavior", review_id=0):
    """把 IP（或它所在的 /24）记入「可信回源网段」，以后不再自动封。

    这只是**观察到的经验**，不改变本次处置——本次是否跳过封禁由调用方决定。
    学习失败静默忽略：记不住也不该影响封禁/放行决策。

    source 为学习来源（keyword / model / behavior / subnet / manual），决定条目 TTL。
    调用方只应对强证据调用本函数：关键字命中，或模型判 cdn_origin 且有旁证。
    review_id 是本次处置写入的审查记录 id（0 = 无关联），一并存进学习条目，
    排障时从「学过这个网段」能直接回查是哪次审查造成的。

    自动升级：只学 /32 时，同一 /24 里未过期的强证据 /32 达到 `_TRUST_SUBNET_MIN_IPS`
    （当前 3）个，就把整个 /24 也记下（source=subnet，24 小时 TTL，命中续期，
    上限 created_at + 90 天）。
    为什么：CDN 边缘节点是成批出现的（事故里 61.241.14.x 有 26 个），
    逐个 /32 记会让每个新节点先被封一次才学会；整段信任面更大，
    所以只按强证据计数、用更高的数量门槛、并给短 TTL，不再活跃即自然过期。
    """
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    try:
        learned = store.add_trusted_cidr(str(obj), reason, source=source,
                                         ai_review_id=review_id)
        # 同段强证据回源 IP 达到门槛 -> 升级为整段可信（短 TTL）
        if obj.version == 4:
            prefix = str(ipaddress.ip_network(str(obj) + "/24", strict=False))
            try:
                n = store.count_trusted_in_subnet(prefix)
            except Exception:
                n = 0
            if n >= _TRUST_SUBNET_MIN_IPS:
                store.add_trusted_cidr(
                    prefix, "同段已学到 %d 个强证据回源 IP，升级为整段可信（%s）"
                    % (n, (reason or "")[:60]), source="subnet", ai_review_id=review_id)
        return learned
    except Exception:
        return None


def _subnet_ban_hot(ip, cfg):
    """同一 /24 是否因批量封禁而「变热」（返回 (是否熔断, 已有封禁数)）。

    动机：CDN/WAF 的回源节点往往集中在同一运营商 /24 里（事故中
    61.241.14.x 一次被封 26 个、39.91.185.x 17 个）。真实攻击者很少会在
    短时间内在同一个 /24 里凑出这么多不同 IP 去探测同一个端口。

    因此：窗口内同一 /24 已有 >= limit 个不同 IP 被自动封禁时，判定该段大概率
    是共享出口/CDN 节点，停止继续封（避免群集连坐把整段用户打挂）。

    limit <= 0 表示关闭熔断；会话错误时返回未熔断（宁可继续按模型判定处置）。
    """
    try:
        limit = int(cfg.get("ai_subnet_ban_limit") or 0)
        window = int(cfg.get("ai_subnet_ban_window") or 900)
    except (TypeError, ValueError):
        return False, 0
    if limit <= 0:
        return False, 0
    try:
        obj = ipaddress.ip_address(ip)
        if obj.version != 4:
            return False, 0          # 只对 IPv4 /24 做熔断；v6 前缀语义不同
        subnet = str(ipaddress.ip_network(str(obj) + "/24", strict=False))
    except ValueError:
        return False, 0
    try:
        n = store.count_recent_bans_in_subnet(subnet, window)
    except Exception:
        return False, 0
    return (n >= limit), n


def _is_login_trusted(ip):
    """IP 是否在「登录即信任」名单里（面板登录过，带 TTL）。

    供 AI 处置侧使用：生产上 112.48.13.214 就是被 AI 以「临时访问 MySQL/Redis
    等非 Web 服务」为由临时封的，光豁免引擎的自动封禁不够——AI 那条路也得让。

    读失败按「不在信任中」处理（宁可照常处置，不能因读库失败而全放行）。
    """
    try:
        return ip in set(store.list_trusted_login_ips())
    except Exception:
        return False


def _is_whitelisted(ip):
    """IP 是否落在白名单内（白名单优先：AI 不对其自动处置）。

    名单条目可能是 CIDR；判定失败按「不在白名单」处理，不影响主流程。
    """
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for r in store.list_ips("white"):
        try:
            if obj in ipaddress.ip_network(r.get("cidr", ""), strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_ssh_related(category, reason, proxies):
    """判断是否为 SSH 相关（模型标记 SSH 爆破 / 理由或代理名含 ssh）。

    category 缺失（旧模型输出）时用理由与代理名兜底；代理名如 `ssh_22`
    是「经 frp 暴露 SSH 隧道」的强信号，属用户要求的从严范围。
    """
    cat = (category or "").lower()
    if cat in ("ssh_bruteforce", "ssh_brute_force", "ssh_bruteforce_attempt",
               "ssh_attack", "ssh_login"):
        return True
    text = ((category or "") + " " + (reason or "") + " " + (proxies or "")).lower()
    return "ssh" in text


# 纯 CDN/反代厂商关键字（归属地/ISP 文本命中即视为 CDN 回源强特征）。
# 只收录「本身即 CDN 服务商」的名称：共享云厂商通用名（如 Amazon / Google /
# Microsoft）不收录，避免把云主机上的普通用户/误判为回源而放行。
#
# 阿里云 ESA（边缘安全加速）必须单独列：它的回源节点 IP 属于阿里云普通网段
# （实测 47.123.x.x / 8.25.82.x.x），归属地只写「阿里云」而不会带 “cdn” 字样，
# 光靠 "阿里云 cdn" 永远不命中 —— 2026-11 就因此把 ESA 回源 IP 当扫描器封了一批
# （ban_log 里模型自己写着「无法确证 CDN 回源」），造成站点短暂 522。
_CDN_KEYWORDS = (
    "cloudflare", "cloudfront", "fastly", "sucuri", "imperva", "incapsula",
    "akamai", "阿里云 cdn", "腾讯云 cdn", "百度云加速", "网宿", "chinacache",
    "keycdn", "bunnycdn", "stackpath", "edgecast", "limelight", "gcore",
    # 阿里云 ESA（边缘安全加速）及其别名/英文名。不收录裸 "esa"：
    # 子串匹配会误中 Empresa / Mesa / Telesat / Teresa / Desa 等地名与组织名。
    "阿里云 esa", "aliyun esa", "alibaba cloud esa", "alibaba cloud edge security",
    "edge security acceleration", "边缘安全加速",
    # 阿里云 CDN 的其它常见写法（归属地文本不统一）
    "aliyun cdn", "alibaba cloud cdn", "aliyuncs",
    # 腾讯云 EdgeOne
    "edgeone", "tencent cloud cdn",
)


# CDN 回源只可能经 HTTP 层或 tcpmux 代理进入；出现其它类型（tcp/udp/stcp 等）即不是回源。
_WEB_TYPES = frozenset(("http", "https", "tcpmux"))


def _ptypes(it):
    """返回代理类型集合（小写）。GROUP_CONCAT 后用逗号/空白/分号分隔。"""
    return {p.strip().lower()
            for p in re.split(r"[,;\s]+", str(it.get("ptypes") or "")) if p.strip()}


def _proxy_names(it):
    """返回命中的代理名集合（去重）。"""
    return {p for p in re.split(r"[,;\s]+", str(it.get("proxies") or "")) if p}


def _is_ascii(s):
    # str.isascii 需要 3.7+，手写以兼容老环境
    return all(ord(c) < 128 for c in s)


def _keyword_hit(text):
    """归属地/ISP 文本命中的 CDN 厂商关键字；未命中返回空串。

    4 个字符以下的 ASCII 关键字要求前后不是字母（词边界），避免子串误中更长的单词；
    其余关键字（中文、多词短语）按子串匹配。
    """
    text = (text or "").lower()
    for kw in _CDN_KEYWORDS:
        if len(kw) <= 4 and _is_ascii(kw):
            if re.search(r"(?<![a-z])" + re.escape(kw) + r"(?![a-z])", text):
                return kw
        elif kw in text:
            return kw
    return ""


def _hit_label(source, detail):
    """命中层标签：model / keyword:<kw> / behavior:<n>，写入审查记录与学习理由。"""
    if source == "model" or not detail:
        return source
    return "%s:%s" % (source, detail)


def _cdn_origin_hit(category, it, cfg):
    """CDN 回源判定，返回 (是否回源, 命中层, 明细)。

    命中层：model（模型判 cdn_origin 且有旁证）/ keyword / behavior；未命中为 (False, "", "")。

    先做类型硬否决：ptypes 非空且含 http/https/tcpmux 之外的类型 -> 不是回源，
    模型判定与关键字都不能推翻。ptypes 为空（数据缺失）时不否决，交给下面三层。

    三层判断：
      1. 模型判 category=cdn_origin，且有旁证（关键字命中，或 全 Web 类型 + 多站点），
         无旁证不认；
      2. 归属地/ISP 文本命中 CDN 厂商关键字（短关键字按词边界匹配）；
      3. 行为特征：ptypes 非空且全为 Web 类型，同时 proxies 里有 2 个以上不同代理名。
         ptypes 为空时本层不成立（证据不足，不放行）。

    第 3 层来自 2026-11 事故：ESA 回源 IP（47.123.x.x / 8.25.82.x.x）归属地只写
    「阿里云」不带 CDN 字样，模型判 suspicious，前两层落空，回源 IP 被封导致 522。
    但只看「混访多站」会把扫多个 tcp 代理的扫描器也当成回源（生产 66.132.159.18
    在 98 秒内连了 5 个 tcp 代理），所以必须叠加类型判断。

    该判断只影响「自动处置」，不影响送审与审计记录；`ai_cdn_guard` 关闭时不做任何跳过。
    """
    if not cfg.get("ai_cdn_guard", True):
        return False, "", ""
    types = _ptypes(it)
    if types and not types <= _WEB_TYPES:
        return False, "", ""      # 出现过任何非 Web 类型 -> 不可能是 CDN 回源
    names = _proxy_names(it)
    web_multi = bool(types) and len(names) >= 2
    kw = _keyword_hit(str(it.get("geo") or ""))
    if (category or "").lower() == "cdn_origin":
        # 模型判 cdn_origin 必须配合旁证：关键字命中，或 全 Web 类型 + 多站点
        if kw:
            return True, "model", "keyword:" + kw
        if web_multi:
            return True, "model", "behavior:%d" % len(names)
        return False, "", ""      # 无旁证不认
    if kw:
        return True, "keyword", kw
    if web_multi:
        return True, "behavior", str(len(names))
    return False, "", ""


def _is_cdn_origin(category, it, cfg):
    """判断某送审 IP 是否应按「CDN 回源」跳过自动封禁（bool 包装，规则见 _cdn_origin_hit）。"""
    return _cdn_origin_hit(category, it, cfg)[0]


def _apply_action(ip, verdict, category, reason, it, cfg):
    """按判定分级处置并写入审查记录，返回展示用结果字典。

    分级：
      - CDN 回源（cdn_origin / CDN 厂商强特征）-> 仅记录，不自动封禁（防 522）
      - 确凿（malicious）或 SSH 相关疑似（ai_ssh_strict）-> 永久黑名单
      - 疑似（suspicious，ai_suspicious_ban）           -> 临时封禁
      - 其余 / 已在处置中                                -> 仅记录
    安全边界：白名单命中的 IP 一律不自动处置，防止模型误判导致
    「封 IP 段连坐白名单」；写入前统一校验 IP 合法性。
    """
    ssh = _is_ssh_related(category, reason, it.get("proxies", ""))
    # 白名单优先：即使模型判恶意也不自动处置
    if _is_whitelisted(ip):
        store.add_ai_review(0, ip, verdict, "白名单命中，跳过自动处置", "skipped",
                            cfg.get("ai_model", ""))
        return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
                "action": "skipped", "mode": "whitelist", "ssh": ssh,
                "geo": it.get("geo", ""), "conns": it.get("conns", 0)}

    # CDN 回源保护：边缘节点 IP 被大量真实用户共享，一旦自动封禁会导致
    # 整站不可访问（CDN 回源被拒 → 522）。仅对「本会触发封禁」的判定生效
    # （benign/unknown 本就不处置，走常规记录即可），只记录、不写任何封禁。
    cdn_hit, cdn_src, cdn_detail = False, "", ""
    if verdict in ("malicious", "suspicious"):
        cdn_hit, cdn_src, cdn_detail = _cdn_origin_hit(category, it, cfg)
    if cdn_hit:
        label = _hit_label(cdn_src, cdn_detail)
        if cdn_src == "model" and cdn_detail:
            label = "model，旁证 " + cdn_detail
        # 先写审查记录拿到 id，再写学习条目：学习条目要指回「哪次审查学到的」，
        # 顺序反了就得学习后再回填（多一次 UPDATE，且中途失败会留下无主条目）。
        rev_id = store.add_ai_review(
            0, ip, verdict, "CDN 回源（%s），跳过自动处置" % label,
            "skipped", cfg.get("ai_model", ""))
        # 只有强证据才学习：关键字命中，或模型判 cdn_origin 且有旁证。
        # 行为层单独命中只跳过本次：「混访多站」是启发式，持久化成信任可被扫描器利用。
        if cdn_src in ("keyword", "model") and cfg.get("ai_learn_cdn", True):
            _learn_trusted(ip, "CDN 回源（%s）：%s" % (label, (reason or "")[:80]),
                           source=cdn_src, review_id=rev_id)
        return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
                "action": "skipped", "mode": "cdn", "ssh": ssh,
                "geo": it.get("geo", ""), "conns": it.get("conns", 0)}

    # 可信网段保护：确定性，不依赖模型判断。站点前置 CDN/WAF 时，源站看到的全是
    # 节点 IP，按 IP 封禁 = 封所有真实用户。两个来源分开记审计：
    #   - mode=trusted：人工配置 ai_trusted_cidrs；
    #   - mode=learned：AI 自动学习表 trusted_cidr。
    t_hit, t_mode, t_note = "", "", ""
    if verdict in ("malicious", "suspicious"):
        t_hit = _in_config_cidrs(ip, cfg)
        if t_hit:
            t_mode = "trusted"
            t_note = "命中人工配置的可信网段（ai_trusted_cidrs：%s），跳过自动处置" % t_hit
        else:
            t_hit = _in_learned_cidrs(ip)
            if t_hit:
                t_mode = "learned"
                t_note = "命中 AI 学习的可信回源网段（%s），跳过自动处置" % t_hit
    if t_hit:
        store.add_ai_review(0, ip, verdict, t_note, "skipped", cfg.get("ai_model", ""))
        return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
                "action": "skipped", "mode": t_mode, "ssh": ssh,
                "geo": it.get("geo", ""), "conns": it.get("conns", 0)}

    # 登录即信任：面板登录过的 IP 也不自动处置。
    # 为什么 AI 侧也要查：生产上 112.48.13.214 就是被 AI 以「临时访问 MySQL/Redis
    # 等非 Web 服务且无探测证据」为由临时封的（不只是引擎的自动封禁）。
    if verdict in ("malicious", "suspicious") and _is_login_trusted(ip):
        store.add_ai_review(0, ip, verdict, "登录信任 IP，跳过自动处置",
                            "skipped", cfg.get("ai_model", ""))
        return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
                "action": "skipped", "mode": "login", "ssh": ssh,
                "geo": it.get("geo", ""), "conns": it.get("conns", 0)}

    # 同段批量封禁熔断：窗口内同一 /24 已有多个 IP 被自动封禁 -> 大概率是
    # 共享出口/CDN 节点（不是独立攻击者），停止继续封，避免越封越多、整段连坐。
    if verdict in ("malicious", "suspicious"):
        hit, count = _subnet_ban_hot(ip, cfg)
        if hit:
            # 熔断只止血、不学习：同段多个 IP 被封只说明「可能」是共享出口，
            # 把止血结果持久化成信任，会让批量探测换来整段长期豁免。
            store.add_ai_review(
                0, ip, verdict,
                "【熔断待复核】同一 /24 在 %d 秒内已有 %d 个 IP 被自动封禁，疑似共享出口/CDN 段，"
                "跳过本次自动处置，未写入可信网段"
                % (int(cfg.get("ai_subnet_ban_window") or 900), count),
                "skipped", cfg.get("ai_model", ""))
            return {"ip": ip, "verdict": verdict, "category": category,
                    "reason": reason, "action": "skipped", "mode": "subnet",
                    "ssh": ssh, "geo": it.get("geo", ""), "conns": it.get("conns", 0)}

    if not cfg.get("ai_auto_ban"):
        action, mode = "none", ""
    else:
        permanent = (verdict == "malicious") or (
            verdict == "suspicious" and ssh and cfg.get("ai_ssh_strict", True)
            and cfg.get("ai_ssh_permanent_suspicious", True))
        if permanent and not cfg.get("blacklist_enabled", True):
            permanent = False
            temporary = True  # 黑名单未生效时保留临时拦截，不释放已有封禁
        else:
            temporary = (verdict == "suspicious" and not permanent
                         and cfg.get("ai_suspicious_ban", True))
        if not (permanent or temporary):
            action, mode = "none", ""
        else:
            # 处置前校验：非法 IP 不进入任何封禁集合
            try:
                ipaddress.ip_network(ip, strict=False)
            except ValueError:
                store.add_ai_review(0, ip, verdict, "IP 格式非法，跳过", "none",
                                    cfg.get("ai_model", ""))
                return {"ip": ip, "verdict": verdict, "category": category,
                        "reason": reason, "action": "none", "mode": "",
                        "ssh": ssh, "geo": it.get("geo", ""),
                        "conns": it.get("conns", 0)}
            if permanent:
                # 确凿 / SSH 从严 -> 永久黑名单（ip_list black，内核 timeout=0）
                try:
                    store.add_ip(ip, "black", ("ai: " + (reason or "malicious"))[:200])
                    action, mode = "permanent", "permanent"
                except ValueError:
                    # 已存在于黑名单（UNIQUE 约束）视为已处置
                    action, mode = "already_banned", "permanent"
                except Exception:
                    action, mode = "ban_failed", "permanent"
                if action != "ban_failed":
                    # 永久生效后释放同名临时封禁（无记录时为无副作用操作）
                    try:
                        store.unban_ip(ip)
                    except Exception:
                        pass
            else:
                # 疑似 -> 临时封禁（ban_log，到期自动释放）
                try:
                    if store.is_banned(ip):
                        action, mode = "already_banned", "temp"
                    else:
                        store.add_ban(ip, ("ai: " + (reason or "suspicious"))[:200],
                                      int(cfg.get("ai_ban_seconds") or 1800))
                        action, mode = "banned", "temp"
                except Exception:
                    action, mode = "ban_failed", "temp"

    store.add_ai_review(0, ip, verdict, reason, action, cfg.get("ai_model", ""))
    return {"ip": ip, "verdict": verdict, "category": category, "reason": reason,
            "action": action, "mode": mode, "ssh": ssh,
            "geo": it.get("geo", ""), "conns": it.get("conns", 0)}


def _endpoint(base, path):
    """智能拼接接口地址，兼容用户不同填法，避免出现 /v1/v1/...：

    path 形如 "/v1/chat/completions" 或 "/v1/messages"。
      base = http://host            -> http://host/v1/chat/completions
      base = http://host/v1         -> http://host/v1/chat/completions
      base = http://host/v1/        -> http://host/v1/chat/completions
      base = http://host/v1/chat/completions -> 原样返回
    """
    b = (base or "").strip().rstrip("/")
    if not b:
        return b
    # 只放行 http/https：防止 ai_base_url 被填成 file:// 或自定义协议，让 urlopen 读取本地文件
    if urllib.parse.urlsplit(b).scheme.lower() not in ("http", "https"):
        raise ValueError("ai_base_url 只支持 http:// 或 https://")
    if b.endswith(path):
        return b
    i = path.find("/", 1)
    version, tail = path[:i], path[i:]  # 如 "/v1", "/chat/completions"
    if b.endswith(version):
        return b + tail
    return b + path


def _max_tokens_for(n):
    """按送审条数估算输出上限：每条判定约 120 token（含 reason），另留 512 余量。

    过小会把输出截断成非法 JSON（历史故障），过大则部分网关直接拒绝；
    因此夹取 [1024, 16384]（16384 为多数模型/网关的安全上限）。
    """
    try:
        n = max(1, int(n))
    except (TypeError, ValueError):
        n = 1
    return min(16384, max(1024, n * 120 + 512))


def _call_openai(cfg, user_prompt, timeout=60, max_tokens=1500):
    url = _endpoint(cfg["ai_base_url"], "/v1/chat/completions")
    payload = {
        "model": cfg["ai_model"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": int(max_tokens),
    }
    # url 由 _endpoint 生成，已限定 http/https 协议
    req = urllib.request.Request(  # noqa: S310
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + cfg["ai_api_key"]},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _call_anthropic(cfg, user_prompt, timeout=60, max_tokens=1500):
    url = _endpoint(cfg["ai_base_url"], "/v1/messages")
    payload = {
        "model": cfg["ai_model"],
        "max_tokens": int(max_tokens),
        "temperature": 0.1,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    # url 由 _endpoint 生成，已限定 http/https 协议
    req = urllib.request.Request(  # noqa: S310
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "x-api-key": cfg["ai_api_key"],
                 "anthropic-version": "2023-06-01"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data = json.loads(resp.read().decode("utf-8"))
    parts = data.get("content") or []
    return "".join(p.get("text", "") for p in parts if p.get("type") == "text")


# 单批送审条数：控制单次请求的输出规模。100 条 × 约 120 token/条 ≈ 12k 输出
# token（动态 max_tokens 上限 16384 内），主流模型/网关可稳定完成；条数再多
# 会显著抬高输出被 max_tokens 截断的概率（历史故障：1000 条一批返回非法 JSON）。
# 用户期望「一批 IP 一起送审、一起拿回」：调大后请求数更少、总耗时更短，
# 单批失败由二分重试兜底（见 _call_batch）。
_BATCH_SIZE = 100
# 解析失败二分重试的拆分预算：防止「模型持续返回非法 JSON」时请求数失控
# （每次拆分把一批变两批，预算用完即放弃该批）。
_SPLIT_BUDGET = 16
# 二分重试的最小拆分条数：拆到该规模仍失败即放弃，不再继续拆到 1 条。
# 避免网关日志里出现大量「一条 IP 一个请求」的碎片请求（既慢又无意义）。
_MIN_SPLIT = 5
# 批次并行度：多批同时送审（「一起拿回来」），总耗时约降为串行的 1/N。
# 取 3 是稳妥值：兼顾提速与网关限流风险（并行过高易触发 429）。
_MAX_WORKERS = 3

# 并行批次共享的预算/失败列表需要线程安全（_call_batch 递归在多个线程中跑）
_budget_lock = threading.Lock()
_fail_lock = threading.Lock()
# review 互斥：自动循环与手动触发可能同时到达，同一时刻只跑一轮审查，
# 避免重复送审/重复处置（也保证 ai_review_state 状态机不被并发干扰）。
_review_lock = threading.Lock()


def _call_once(cfg, proto, items, timeout):
    """单批调用一次模型，返回 (ok, verdicts_or_error)。"""
    user_prompt = _build_user_prompt(items)
    max_tokens = _max_tokens_for(len(items))
    last_err = None
    # 网关可能较慢，超时/网络类错误重试一次
    for attempt in (1, 2):
        try:
            if proto == "anthropic":
                text = _call_anthropic(cfg, user_prompt, timeout=timeout,
                                       max_tokens=max_tokens)
            else:
                text = _call_openai(cfg, user_prompt, timeout=timeout,
                                    max_tokens=max_tokens)
            last_err = None
            break
        except urllib.error.HTTPError as e:
            # HTTP 层错误（如 4xx/5xx）不重试，直接返回
            try:
                detail = e.read().decode("utf-8")[:300]
            except Exception:
                detail = ""
            return False, "HTTP %s %s %s" % (e.code, e.reason, detail)
        except Exception as e:
            last_err = "调用失败: %s" % e
            if attempt == 1:
                time.sleep(2)
                continue
    if last_err:
        return False, last_err
    verdicts = _extract_json(text)
    if verdicts is None:
        return False, "模型返回无法解析为 JSON: %s" % (text or "")[:200]
    if not isinstance(verdicts, list):
        return False, "模型返回不是数组"
    return True, verdicts


def _take_budget(budget):
    """原子取用一次拆分预算（并行批次共享预算，必须加锁判定+扣减）。"""
    with _budget_lock:
        if budget[0] <= 0:
            return False
        budget[0] -= 1
        return True


def _call_batch(cfg, proto, items, timeout, failures, budget):
    """送审一批；失败/漏答时在预算内二分重试或补齐。

    - 解析失败（截断）或网关拒绝 max_tokens / 请求体过大 → 二分重试，
      把「整批报废」降级为「只损失个别条目」；拆到 _MIN_SPLIT 条仍失败
      即放弃该批（不再拆到单条，避免网关日志被碎片小请求刷屏）；
    - 解析成功但缺条目（截断抢救只保住前半段、或模型漏答）→ 只对缺失
      的 IP 再送一次（缺失 ≥2 条时；只缺 1 条不再补，代价大于收益）；
    鉴权、限流等错误二分无意义，直接记失败返回（由 call_model 决定是否终止）。
    """
    ok, res = _call_once(cfg, proto, items, timeout)
    if ok:
        got = {str(v.get("ip", "")).strip() for v in res
               if isinstance(v, dict)}
        missing = [it for it in items if it.get("ip") not in got]
        if 1 < len(missing) < len(items) and _take_budget(budget):
            res = res + _call_batch(cfg, proto, missing, timeout,
                                    failures, budget)
        return res
    err = str(res)
    low = err.lower()
    split = (len(items) > _MIN_SPLIT
             and ("无法解析" in err or "413" in err or "max_tokens" in low)
             and _take_budget(budget))
    if not split:
        with _fail_lock:
            failures.append(err)
        return []
    mid = len(items) // 2
    return (_call_batch(cfg, proto, items[:mid], timeout, failures, budget)
            + _call_batch(cfg, proto, items[mid:], timeout, failures, budget))


def call_model(cfg, items):
    """分批调用大模型，返回 (ok, verdicts_or_error)。

    送审量超过 _BATCH_SIZE 时自动分批（每批独立计算 max_tokens），避免单次
    输出超限被截断成非法 JSON；单批解析失败自动二分重试。批次按 _MAX_WORKERS
    并行送审（一起发出、一起拿回），总耗时约为串行的 1/N；每波内的批次相互
    独立，单批失败不影响其它批。全部批次失败才返回 ok=False；部分批次失败时
    返回已成功批次的判定（未返回的 IP 不处置，安全）。
    """
    proto = (cfg.get("ai_protocol") or "openai").lower()
    try:
        timeout = max(15, int(cfg.get("ai_timeout") or 120))
    except (TypeError, ValueError):
        timeout = 120
    items = list(items or [])
    if not items:
        return True, []
    chunks = [items[i:i + _BATCH_SIZE]
              for i in range(0, len(items), _BATCH_SIZE)]
    failures = []
    budget = [_SPLIT_BUDGET]
    out = []
    auth_error = [None]   # 鉴权/参数类错误：所有批次相同，提前终止

    def _run(chunk):
        with _fail_lock:
            before = len(failures)
        part = _call_batch(cfg, proto, chunk, timeout, failures, budget)
        # 鉴权/参数类 HTTP 错误对所有批次相同：记录后于波边界提前终止，
        # 避免无谓重复请求（同一波已发出的批次无法收回，最多浪费一波）。
        if auth_error[0] is None:
            with _fail_lock:
                new = failures[before:]
            for f in new:
                if f.startswith("HTTP ") and "413" not in f:
                    auth_error[0] = f
                    break
        return part

    if len(chunks) == 1:
        out = _run(chunks[0])
    else:
        # 按波提交（每波最多 _MAX_WORKERS 批），波内并行、波间串行：
        # 既满足「一批 IP 一起送审、一起拿回」，又能在鉴权类错误时
        # 于波边界提前终止，不把剩余批次全部发出去（最多浪费一波）。
        workers = min(_MAX_WORKERS, len(chunks))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for start in range(0, len(chunks), workers):
                for part in pool.map(_run, chunks[start:start + workers]):
                    out += part
                if auth_error[0]:
                    break
    if out:
        return True, out
    if auth_error[0]:
        return False, auth_error[0]
    return False, failures[0] if failures else "模型未返回任何判定"


def review(force=False):
    """执行一次审查。返回结果字典。

    全程持 _review_lock：自动循环与手动触发并发到达时只跑一轮，
    避免重复送审/重复处置；所有出口都更新 ai_last_run / ai_last_ok，
    供插件端轮询判断「本轮是否已结束、是否成功」。
    """
    if not _review_lock.acquire(blocking=False):
        return {"ok": False, "msg": "已有审查在进行中，请稍候"}
    try:
        return _review_locked(force=force)
    finally:
        _review_lock.release()


def _review_locked(force=False):
    # 前置校验（不置 running 标记：避免校验失败也闪一下「审查中」）
    cfg = config.get()
    if not cfg.get("ai_enabled") and not force:
        _mark_done(False, "AI 审查未启用")
        return {"ok": False, "msg": "AI 审查未启用"}
    if not cfg.get("ai_base_url") or not cfg.get("ai_api_key"):
        _mark_done(False, "未配置 AI 接口地址或密钥")
        return {"ok": False, "msg": "未配置 AI 接口地址或密钥"}

    # 标记本轮开始（插件端轮询 ai_review_state 显示进度）；无论成功、失败还是
    # 提前返回，finally 都会清除该标记，保证前端不会无限显示「审查中」。
    try:
        config.save({"ai_review_state": "running",
                     "ai_review_started": int(time.time())})
    except Exception:
        pass
    try:
        try:
            return _review_run(cfg)
        except Exception as e:
            # 兜底：未预期异常也必须更新状态，避免前端一直等待/显示旧结果
            _mark_done(False, "审查异常：%s" % e)
            return {"ok": False, "msg": "审查异常：%s" % e, "results": []}
    finally:
        try:
            config.save({"ai_review_state": ""})
        except Exception:
            pass


def _review_run(cfg):
    items = _collect()
    if not items:
        store.add_ai_review(0, "-", "none", "窗口内无达到阈值的 IP", "skip", cfg.get("ai_model", ""))
        _mark_done(True, "本次无可审查的 IP")
        return {"ok": True, "msg": "本次无可审查的 IP", "results": [], "checked": 0}

    ok, res = call_model(cfg, items)
    if not ok:
        store.add_ai_review(0, "-", "error", str(res)[:400], "error", cfg.get("ai_model", ""))
        _mark_done(False, str(res))
        return {"ok": False, "msg": str(res), "results": []}

    # 建立 IP -> 统计 映射，便于展示
    stat = {it["ip"]: it for it in items}
    results = []
    banned = 0        # 永久黑名单数
    temp_banned = 0   # 临时封禁数
    cdn_skipped = 0   # CDN 回源跳过数
    for v in res:
        if not isinstance(v, dict):
            continue
        ip = str(v.get("ip", "")).strip()
        verdict = str(v.get("verdict", "")).strip().lower()
        category = str(v.get("category", "")).strip().lower()
        reason = str(v.get("reason", "")).strip()[:300]
        if not ip:
            continue
        # 只处理本次真正送审过的 IP。模型可能因幻觉 / 提示注入返回集合外的
        # IP（例如被审查内容里诱导出的无关地址），若对其自动封禁可被滥用。
        if ip not in stat:
            continue
        if verdict not in ("malicious", "suspicious", "benign"):
            verdict = "unknown"
        r = _apply_action(ip, verdict, category, reason, stat[ip], cfg)
        if r["action"] == "permanent":
            banned += 1
        elif r["action"] == "banned" and r["mode"] == "temp":
            temp_banned += 1
        elif r["action"] == "skipped" and r.get("mode") == "cdn":
            cdn_skipped += 1
        results.append(r)

    # 永久黑名单写入后立即让决策缓存失效（名单缓存 3s TTL，改完即生效）；
    # 内核同步由 daemon 后台线程兜底，也可由此处主动触发。
    if banned:
        try:
            from . import engine
            engine.invalidate_cache()
        except Exception:
            pass
        try:
            from . import firewall
            if cfg.get("fw_sync_enabled", True):
                firewall.sync_from_store()
        except Exception:
            pass

    # 更新配置里的上次运行信息（patch 语义：锁内合并，避免覆盖面板/插件端
    # 并发修改的开关或凭据）。大批量送审时个别批次可能失败，摘要中标注
    # 未获判定数量（未获判定 = 不处置，安全方向不受影响）。
    reviewed_ips = len({r["ip"] for r in results})
    missing = max(0, len(items) - reviewed_ips)
    last_result = "审查 %d 个 IP，永久黑名单 %d 个，临时封禁 %d 个" % (
        reviewed_ips, banned, temp_banned)
    if cdn_skipped:
        last_result += "，CDN 回源跳过 %d 个" % cdn_skipped
    if missing:
        last_result += "，%d 个未获判定（不处置）" % missing
    _mark_done(True, last_result)
    return {"ok": True, "msg": last_result, "results": results,
            "checked": len(items), "banned": banned, "temp_banned": temp_banned,
            "cdn_skipped": cdn_skipped}


def _mark_done(ok, result):
    """记录本轮审查结束：更新时间戳/摘要/成功标记（patch 语义合并写入）。"""
    try:
        config.save({"ai_last_run": int(time.time()),
                     "ai_last_result": str(result)[:400],
                     "ai_last_ok": bool(ok)})
    except Exception:
        pass


def review_busy():
    """是否已有审查在进行中（供调用方决定是否提交，避免空转/重复）。"""
    return _review_lock.locked()


def loop_forever():
    """后台线程：消费「立即审查」请求，并按间隔执行自动审查。

    「立即审查」由插件端写 ai_run_requested 时间戳触发（面板请求立即返回，
    不被长审查阻塞）；本循环消费执行。有待处理请求时按 2 秒快速轮询，
    平时 20 秒一轮，保证点按后近乎立即开始。
    """
    while True:
        try:
            cfg = config.get()
            req = int(cfg.get("ai_run_requested") or 0)
            consumed = int(cfg.get("ai_run_consumed") or 0)
            last = int(cfg.get("ai_last_run") or 0)
            if req > consumed and not review_busy():
                # 先标记「已消费」再执行：即使本轮失败也不会被反复触发
                # （用独立 consumed 游标，不与自动审查的 last_run 互相干扰）
                config.save({"ai_run_consumed": req})
                res = review(force=True)
                if not res.get("ok") and "进行中" in str(res.get("msg", "")):
                    # 与另一路审查撞车（极窄竞态）：回滚游标，下轮重试
                    config.save({"ai_run_consumed": consumed})
            elif cfg.get("ai_enabled"):
                interval = max(60, int(cfg.get("ai_interval") or 300))
                if time.time() - last >= interval and not review_busy():
                    review()
        except Exception:
            pass
        # 有待处理请求时快速轮询（2s），否则常规节奏（20s）
        try:
            cfg = config.get()
            fast = (int(cfg.get("ai_run_requested") or 0)
                    > int(cfg.get("ai_run_consumed") or 0))
        except Exception:
            fast = False
        time.sleep(2 if fast else 20)
