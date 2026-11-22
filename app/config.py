#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 配置管理

配置保存在 data/frpwaf.json，首次运行自动生成（含默认管理员 admin/123456）。
"""
import copy
import json
import os
import secrets
import threading
import time

BASE = os.environ.get("FRPWAF_HOME", "/opt/frpwaf")
DATA_DIR = os.path.join(BASE, "data")
DB_PATH = os.path.join(DATA_DIR, "frpwaf.db")
CONF_PATH = os.path.join(DATA_DIR, "frpwaf.json")
LOG_PATH = os.path.join(DATA_DIR, "frpwaf.log")
PID_PATH = os.path.join(DATA_DIR, "frpwaf.pid")
# 突发观测/冷却快照（daemon 后台周期写入，插件端面板进程读取）：
# 观测数据在 daemon 进程内存中，宝塔插件端是另一个进程，必须经文件共享。
BURST_SNAPSHOT_PATH = os.path.join(DATA_DIR, "burst_snapshot.json")

# ---- 配置回显掩码 ----
# GET 回显配置时把 MASKED_KEYS 里的机密字段替换成 MASKED_VALUE；写入路径若收到
# 该值，说明客户端只是「读配置 → 改一项 → 整体回写」，必须丢弃（丢弃 = 保留
# 磁盘原值，**不是清空**）。否则真实密钥/口令会被覆盖成 ******：AI 审查从此
# 静默失效、管理员口令变成掩码字符。三条写入路径（daemon / 插件端 / 本模块
# save）共用这一份定义，不要各自硬编码副本。
MASKED_VALUE = "******"
MASKED_KEYS = ("ai_api_key", "admin_password", "secret")

DEFAULTS = {
    # 管理面板监听地址。默认仅本机：旧默认 0.0.0.0 + 默认口令 admin/123456
    # 等于把面板直接摆到公网（登录即拿到 root 级操作面）。
    # 「装完能打开面板」由 install.sh 在首次安装时显式写入本项保证；
    # 需要远程访问请在面板「设置 → 监听与安全」打开「允许远程访问」，
    # 或手改 data/frpwaf.json 后重启服务。
    "http_addr": "127.0.0.1",
    "http_port": 7080,
    # frps 回调（POST /frp/handler）的独立监听。与面板分端口的意义：面板被
    # 慢连接/扫描打满时，回调仍有独立并发配额，不会让 frps 因回调失败而
    # fail-closed 拒绝全部连接。frps 与本服务同机，回调不需要公网可达。
    # 注意：frps.toml 里 [[httpPlugins]] 的 addr 必须与「本项:端口」一致，
    # 该注入在插件端（frpwaf_main.py）完成。
    "frp_handler_addr": "127.0.0.1",
    "frp_handler_port": 7082,
    # 并发闸门（每连接一个线程，超限直接断开而不是排队——排队的连接本身占 FD）。
    # 面板与回调各自独立配额：面板被打满时回调仍保有自己的额度。
    # FD 上限由 frpwaf.init 的 `ulimit -n 8192` 保证。
    "max_concurrent": 96,
    "handler_max_concurrent": 32,
    # ---- 地址解析策略与 AI 出网策略 ----
    # strict_addr：frps 回调里的来源地址解析不出 IP 时的处置策略。
    #   False（默认）= 保持现状放行（reason=invalid-ip-pass），但计数并告警；
    #   True = 直接拒连（fail-closed，reason=invalid-ip-strict）。
    "strict_addr": False,
    # ai_allow_private：AI 接口地址是否允许私有/回环网段。
    #   True（默认）= 允许：AI 网关通常是内网自建（如 http://127.0.0.1:3000），
    #                  一刀切禁私有地址等于直接废掉该功能；
    #   False = 只允许公网地址。
    # 注意：无论取值如何，链路本地与云元数据地址（169.254.0.0/16、fe80::/10、
    # fd00:ec2::254 等）都由出网校验硬拒，不受本开关影响。
    "ai_allow_private": True,
    # ---- 安全水位告警（可选）----
    # 后台循环把 /api/health 的 level 从「非 bad」变成 bad 时向该地址 POST 一次，
    # 恢复（bad -> 非 bad）再发一次；同类事件 30 分钟内不重复。
    # 留空 = 关闭（默认关闭：多数部署没有接收端，开了只会白跑网络请求）。
    # 地址在保存时与每次发送前都过 SSRF 校验（复用 ai_url_guard）。
    "alert_webhook": "",
    # 是否启用「网页端」（WAF 管理面板）。关闭后仅停用网页访问（/ 与 /api/*），
    # frps 回调（/frp/handler）与 WAF 防护照常运行，可从宝塔插件端随时重新开启。
    "web_enabled": True,
    # 管理员账号（默认 admin / 123456）。
    # `password_changed` 控制「首次登录强制改密」：为 False 时，除登录/改密/
    # 静态页以外的所有 API 一律 403「需先修改默认口令」。旧配置没有该键 =
    # 视为未改密；其与口令实值的一致性由 normalize_password_flag() 维护
    # （改了密码就置 True，改回默认值则强制回到 False）。
    "admin_user": "admin",
    "admin_password": "123456",
    "password_changed": False,
    # 会话签名密钥（首次生成后固定）
    "secret": "",
    # 名单开关
    "blacklist_enabled": True,
    "whitelist_enabled": False,
    # 自动封禁（按来源 IP 在窗口内的连接次数）
    # 注意：frp 代理端口（尤其 HTTP/HTTPS vhost）天然会有大量并发连接，
    # 阈值过低会误封正常用户，默认关闭，按需在面板中开启并谨慎设置阈值。
    "auto_ban_enabled": False,
    "auto_ban_window": 60,
    "auto_ban_threshold": 200,
    "auto_ban_seconds": 600,
    # ---- 攻击类型自动封禁（按攻击特征分维度，独立开关，默认全部开启）----
    # 检测在内存中完成（不查库），命中后才写封禁记录；
    # 白名单保护前提：whitelist_enabled 开启时白名单 IP 才会在决策第 1 步直接放行。
    # 默认开启（用户要求开箱即用）：阈值均偏保守，误封代价由处置档位兜底
    # （CC/扫描为临时封禁可自愈；敏感服务爆破才永久，且仅非 HTTP 类高频时触发）。
    # 不需要的类型可在面板设置页单独关闭；参数留 0（或窗口 ≤1 秒）视为未设置，
    # 加载/保存时自动回退下列默认值，保证「开启即生效、无需手填参数」。
    # CC 攻击：同 IP 在窗口内对 HTTP/HTTPS 代理的新建连接数达阈值
    # -> 临时封禁（正常用户高峰可能误伤，故用临时封禁可自愈）
    "auto_ban_cc_enabled": True,
    "auto_ban_cc_window": 60,
    "auto_ban_cc_threshold": 300,
    "auto_ban_cc_seconds": 600,
    # 端口扫描：同 IP 在窗口内访问的不同代理数达阈值
    # -> 临时封禁（多服务正常用户可能误伤，故用临时封禁可自愈）
    "auto_ban_scan_enabled": True,
    "auto_ban_scan_window": 60,
    "auto_ban_scan_threshold": 20,
    "auto_ban_scan_seconds": 1800,
    # 敏感服务爆破：同 IP 在窗口内命中 ssh/mysql/redis 等敏感代理（非 HTTP 类）的连接数达阈值
    # -> 永久黑名单（正常用户不会高频新建此类连接，判定为确凿恶意）；
    #    若黑名单开关关闭则降级为临时封禁（auto_ban_seconds），保证仍被拦截
    "auto_ban_ssh_enabled": True,
    "auto_ban_ssh_window": 60,
    "auto_ban_ssh_threshold": 20,
    # 简单限速（单 IP 每秒新连接数上限，0 表示关闭）
    "rate_limit_enabled": False,
    "rate_limit_per_sec": 0,
    # ---- 分布式突发观测与代理级冷却 ----
    # 背景：海量不同 IP × 每 IP 仅 1 次的分布式爬虫/扫描，单 IP 维度检测
    # （限速/CC/扫描/基础自动封禁）按设计不触发，需按「代理」维度观测与处置。
    # 观测（burst_window）为纯内存、始终开启、无副作用；
    # 冷却拦截（proxy_cool_*）默认关闭：仅凭连接层行为无法区分恶意爬虫与
    # 出口 IP 变化的真实用户（移动网络/动态 IP/CDN 回源），确认流量性质后再开。
    "burst_window": 60,                 # 观测窗口（秒），<2 视为未设置回退默认
    "proxy_cool_enabled": False,        # 代理级冷却拦截开关（默认关闭，误伤风险见 UI 提示）
    "proxy_cool_min_conns": 300,        # 触发下限：窗口内连接数
    "proxy_cool_uniq_threshold": 200,   # 触发下限：窗口内独立 IP 数
    "proxy_cool_single_pct": 80,        # 触发下限：每 IP 仅 1 次占比（%）
    "proxy_cool_seconds": 60,           # 冷却时长（秒），最小 10
    # 日志保留条数（20 万条约 20~30MB：突发场景 5 万条数小时即被刷满，
    # 调大后突发历史不被快速裁掉，便于回看定性）
    "log_max_rows": 200000,
    # 内核级封禁：把黑名单/封禁同步到 ipset+iptables，在内核直接丢包，
    # 被禁 IP 连不到 frps，连接计数不再增长（需要 root + ipset/iptables）
    "fw_sync_enabled": True,
    # ---- 静态拦截页（404 / 封禁 / 风控）----
    # frp 回调只能返回 allow/reject、无法返回 HTML；frps 的 custom404Page 只对
    # 「Host 未匹配任何 frpc 域名」的路由失败生效。因此「被封 IP 展示页面」只能靠
    # 网络层改道：内核级封禁关闭时，用 iptables -t nat REDIRECT 把命中封禁的 IP
    # 在其访问端口上引导到本服务提供的拦截页。
    # 语义区分：内核级封禁开 = DROP（静默、无页面）；关 + 拦截页开 = REDIRECT（展示页面）。
    "block_page_enabled": True,          # 拦截页总开关（默认开启）
    "block_page_404_enabled": True,      # 404 页开关（默认开启）
    "block_page_ban_enabled": True,      # 封禁页开关（默认开启）
    "block_page_risk_enabled": True,     # 风控页开关（默认开启）
    "block_page_port": 7081,             # 拦截页服务监听端口（与 http_port 解耦，避免误挡面板）
    # 拦截页监听地址：拦截页是被封 IP 经 iptables nat REDIRECT 后的落地页，
    # 必须保持可从外部访问，因此不能跟随面板的 http_addr（面板收紧到
    # 127.0.0.1 后拦截页仍需 0.0.0.0）。app/blockpage.py 已改读本项生效。
    "block_page_addr": "0.0.0.0",
    # REDIRECT 目标端口：逗号分隔的端口列表（如 "80,8080"）；留空 = 自动读取 frps
    # 配置的 vhostHTTPPort。留空且读不到时不做 REDIRECT（拦截页功能不生效）。
    "block_page_redirect_ports": "",
    # ---- AI 自动 IP 审查 ----
    "ai_enabled": False,
    "ai_protocol": "openai",              # openai / anthropic
    "ai_base_url": "",                    # 如 http://127.0.0.1:3000
    "ai_api_key": "",
    "ai_model": "claude-haiku-4.5",
    "ai_interval": 300,                   # 审查间隔（秒），最短 60
    "ai_window": 300,                     # 每次审查分析的最近时间窗口（秒）
    "ai_min_conns": 20,                   # 窗口内连接数低于此值的 IP 不送审
    "ai_max_ips": 20,                     # 每次最多送审的 IP 数
    "ai_auto_ban": True,                  # AI 判定为恶意时是否自动处置
    "ai_cdn_guard": True,                 # CDN 回源保护：判定为 CDN 回源的 IP 不自动封禁
    "ai_ban_seconds": 1800,               # 疑似封禁时长（秒）；确凿判定走永久黑名单
    "ai_suspicious_ban": True,            # 疑似（suspicious）是否自动临时封禁
    "ai_ssh_strict": True,                # SSH 相关（SSH 爆破 / ssh 代理）是否从严
    "ai_ssh_permanent_suspicious": True,  # SSH 相关疑似是否也直接永久黑名单
    "ai_timeout": 120,                    # 单次模型调用超时（秒）
    "ai_last_run": 0,                     # 上次运行时间戳
    "ai_last_result": "",                 # 上次结果摘要
    "ai_last_ok": True,                   # 上次审查是否成功（前端轮询提示用）
    # 异步「立即审查」请求：插件端只写请求时间戳并立即返回（避免面板请求
    # 被长审查阻塞导致按钮卡死），由 daemon 的 AI 循环轮询消费执行。
    "ai_run_requested": 0,                # 请求时间戳（0=无请求）
    "ai_run_consumed": 0,                 # 已消费到的请求时间戳（req > consumed 视为待执行）
    "ai_review_state": "",                # "running"=正在审查（插件端轮询进度）
    "ai_review_started": 0,               # 本轮审查开始时间戳（判断进度是否僵死）
    # ---- GitHub 在线升级 ----
    # 仓库地址 owner/repo；默认指向本项目公开仓库（可在面板「关于」页改成自己的 fork）。
    # 置空 = 未配置（「检查更新 / 一键升级」会提示先填仓库地址）。
    "github_repo": "eternaling/frpwaf",
    "github_last_check": 0,               # 上次检查更新时间戳
    "github_last_result": "",             # 上次检查结果摘要（前端展示）
    "github_last_ok": True,               # 上次检查是否成功
}


def _ensure_dir():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except OSError as exc:
        raise OSError("无法创建数据目录 %s：%s" % (DATA_DIR, exc)) from exc
    # 目录权限收紧到 700：默认 umask 022 会得到 755，同机其它用户虽读不到文件
    # （文件是 600）却能列目录、看到文件名与数量。只改目录本身，不动已有文件。
    # chmod 失败必须忽略：Windows 等平台 chmod 语义有限，不能因为收紧权限失败
    # 把服务弄挂（目录不可用时的报错已经在上面抛出）。
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass


# 一次性迁移标记：旧版设置页缺新键时回显 0/0/0（窗口显示 1），用户点保存会把
# 「开关关闭 + 窗口 1 + 阈值 0（+ 时长 0）」的哨兵组合写进配置。该标记只在
# 迁移完成后写入，保证「升级自动恢复默认开启」只做一次，之后用户手动关闭不再被重置。
_ATTACK_MIGRATED = "_attack_defaults_migrated"


def migrate_legacy_attack(cfg):
    """一次性迁移旧版误存的哨兵配置（见 _ATTACK_MIGRATED 注释）。"""
    if cfg.get(_ATTACK_MIGRATED):
        return cfg
    for _p in ("cc", "scan", "ssh"):
        _en = "auto_ban_%s_enabled" % _p
        if cfg.get(_en) is not False:
            continue
        try:
            _th = int(cfg.get("auto_ban_%s_threshold" % _p) or 0)
            _win = int(cfg.get("auto_ban_%s_window" % _p) or 0)
        except (TypeError, ValueError):
            continue
        if _th < 1 and _win <= 1:
            cfg[_en] = True   # 疑似旧版 0/0/0 哨兵：恢复默认开启
    cfg[_ATTACK_MIGRATED] = True
    return cfg


# 一次性迁移标记：旧配置里 `github_repo` 为空（键缺失或保存过空值）时填入默认公开仓库。
# 只做一次，之后用户手动清空不再被重置。
_GITHUB_REPO_MIGRATED = "_github_repo_default_migrated"


def migrate_github_repo(cfg):
    """一次性把空 `github_repo` 填为 DEFAULTS 默认值（见 _GITHUB_REPO_MIGRATED 注释）。"""
    if cfg.get(_GITHUB_REPO_MIGRATED):
        return cfg
    if not str(cfg.get("github_repo") or "").strip():
        cfg["github_repo"] = DEFAULTS["github_repo"]
    cfg[_GITHUB_REPO_MIGRATED] = True
    return cfg


def normalize_auto_ban(cfg):
    """攻击类型封禁参数防呆：开关开启时，参数为「未设置形态」则回退 DEFAULTS 默认值。

    - 阈值/时长 <1：会让检测永不触发（阈值 0）或静默回退，视为未设置；
    - 窗口 <2 秒：1 秒级窗口对连接数/代理数统计没有参考价值，而 0/1
      正是历史「保存时强制 ≥1」写入的哨兵值（旧版设置页裸读缺键显示 0，
      用户保存后被改写成 1），视为未设置。
    回退保证「开启即生效、无需手填参数」；确实不需要的类型请关闭对应开关，
    而不是把参数留 0。就地修改并返回传入的字典（便于链式调用）。

    注意：仅覆盖三类攻击封禁（本次「开箱即用」需求的范围）；
    基础 auto_ban 保持既有语义（默认关闭、阈值 0 = 永不触发），不做改写。
    """
    groups = (
        ("auto_ban_cc_enabled", "auto_ban_cc", ("window", "threshold", "seconds")),
        ("auto_ban_scan_enabled", "auto_ban_scan", ("window", "threshold", "seconds")),
        ("auto_ban_ssh_enabled", "auto_ban_ssh", ("window", "threshold")),  # ssh 档永久黑名单，无时长键
    )
    for _en, _pre, _sufs in groups:
        if not cfg.get(_en):
            continue
        for _suf in _sufs:
            _k = "%s_%s" % (_pre, _suf)
            if _k not in DEFAULTS:
                continue
            try:
                _v = int(cfg.get(_k) or 0)
            except (TypeError, ValueError):
                _v = 0
            _bad = _v < 2 if _suf == "window" else _v < 1
            if _bad:
                cfg[_k] = DEFAULTS[_k]
    return cfg


def normalize_block_page(cfg):
    """拦截页配置防呆（load / save 双路径）。

    - `block_page_port` 非法（非数字/越界）回退默认；与 `http_port` 相同会让拦截页
      服务与面板争抢同一端口，同样回退默认，避免配置冲突导致服务起不来；
    - `block_page_redirect_ports` 只保留 1~65535 的端口，去重后按原顺序以逗号拼接。
    就地修改并返回传入字典（便于链式调用）。
    """
    try:
        _p = int(cfg.get("block_page_port") or 0)
    except (TypeError, ValueError):
        _p = 0
    try:
        _hp = int(cfg.get("http_port") or 7080)
    except (TypeError, ValueError):
        _hp = 7080
    if _p < 1 or _p > 65535 or _p == _hp:
        cfg["block_page_port"] = DEFAULTS["block_page_port"]
    raw = str(cfg.get("block_page_redirect_ports") or "")
    ports = []
    for tok in raw.replace("\uff0c", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            _v = int(tok)
        except (TypeError, ValueError):
            continue
        if 1 <= _v <= 65535 and _v not in ports:
            ports.append(_v)
    cfg["block_page_redirect_ports"] = ",".join(str(x) for x in ports)
    return cfg


def normalize_burst_cool(cfg):
    """突发观测与代理级冷却参数防呆（load / save 双路径）。

    - `burst_window`：无条件 <2 回退默认（观测始终开启，窗口无意义会让占比
      统计失真；0/1 是历史「保存时强制 ≥1」的哨兵形态）；
    - `proxy_cool_*`：仅在**开关开启**时防呆（关闭时保留原值，下次开启不丢配置）；
      连接数/独立 IP/时长 <1 回退默认，占比钳制到 [1, 100]。
    就地修改并返回传入字典（便于链式调用）。
    """
    try:
        if int(cfg.get("burst_window") or 0) < 2:
            cfg["burst_window"] = DEFAULTS["burst_window"]
    except (TypeError, ValueError):
        cfg["burst_window"] = DEFAULTS["burst_window"]
    if cfg.get("proxy_cool_enabled"):
        for _k in ("proxy_cool_min_conns", "proxy_cool_uniq_threshold"):
            try:
                _v = int(cfg.get(_k) or 0)
            except (TypeError, ValueError):
                _v = 0
            if _v < 1:
                cfg[_k] = DEFAULTS[_k]
        try:
            _s = int(cfg.get("proxy_cool_seconds") or 0)
        except (TypeError, ValueError):
            _s = 0
        # 下限与引擎运行时一致（engine.cool_check 取 max(10, ...)）：
        # 1~9 秒回退默认，避免「面板显示 1s、实际冷却 10s」的行为差异
        if _s < 10:
            cfg["proxy_cool_seconds"] = DEFAULTS["proxy_cool_seconds"]
        try:
            _p = int(cfg.get("proxy_cool_single_pct") or 0)
        except (TypeError, ValueError):
            _p = 0
        if _p < 1:
            cfg["proxy_cool_single_pct"] = DEFAULTS["proxy_cool_single_pct"]
        elif _p > 100:
            cfg["proxy_cool_single_pct"] = 100
    return cfg


def normalize_listen(cfg):
    """监听地址/端口/并发上限防呆（load / save 双路径）。

    - 端口非法（非数字/越界）回退默认；
    - `frp_handler_port` 与面板端口或拦截页端口相同 → 起服务时抢端口（或回调
      打到面板监听上），回退默认；
    - 并发上限钳制到 [8, 512]：0/1 会让面板几乎不可用，过大则失去闸门意义；
    - `http_addr` 只做「空值回退」，不限定取值形态：手工填内网网卡地址
      （如 10.0.0.5）是合法用法。面板接口侧的四值白名单由 daemon 负责。
    就地修改并返回传入字典（便于链式调用）。
    """
    if not str(cfg.get("http_addr") or "").strip():
        cfg["http_addr"] = DEFAULTS["http_addr"]
    if not str(cfg.get("frp_handler_addr") or "").strip():
        cfg["frp_handler_addr"] = DEFAULTS["frp_handler_addr"]
    if not str(cfg.get("block_page_addr") or "").strip():
        cfg["block_page_addr"] = DEFAULTS["block_page_addr"]

    def _port(key, fallback):
        try:
            _v = int(cfg.get(key) or 0)
        except (TypeError, ValueError):
            _v = 0
        return _v if 1 <= _v <= 65535 else fallback

    cfg["http_port"] = _port("http_port", DEFAULTS["http_port"])
    cfg["block_page_port"] = _port("block_page_port", DEFAULTS["block_page_port"])
    _hp = int(cfg["http_port"])
    _bp = int(cfg["block_page_port"])
    _hport = _port("frp_handler_port", DEFAULTS["frp_handler_port"])
    if _hport in (_hp, _bp):
        _hport = DEFAULTS["frp_handler_port"]
    # 默认 7082 也可能被用户改成与面板/拦截页相同，逐级兜底避免死循环
    if _hport in (_hp, _bp):
        _hport = 7083
    cfg["frp_handler_port"] = _hport

    for _k in ("max_concurrent", "handler_max_concurrent"):
        try:
            _v = int(cfg.get(_k) or 0)
        except (TypeError, ValueError):
            _v = 0
        if _v < 8 or _v > 512:
            _v = DEFAULTS[_k]
        cfg[_k] = _v
    return cfg


# 严格布尔取值表：配置文件是手改的 JSON，可能写成 "true" / 1 / "False" / null。
_TRUE_TOKENS = ("1", "true")
_FALSE_TOKENS = ("0", "false")


def _strict_bool(v, default):
    """把配置值归一化成 bool；不可识别时返回 default（**绝不静默当 False**）。

    接受：True/False、1/0（含 1.0/0.0）、"1"/"0"、"true"/"false"（大小写不敏感）。
    其它（None、""、"abc"、2、列表等）一律回退 default，因为两种误判都有实害：
      - ai_allow_private 被误判成 False，内网 AI 网关直接不可用；
      - strict_addr 被误判成 False，本想 fail-closed 的机器静默变成放行。
    """
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        _s = v.strip().lower()
        if _s in _TRUE_TOKENS:
            return True
        if _s in _FALSE_TOKENS:
            return False
    return default


def normalize_addr_policy(cfg):
    """地址解析 / AI 出网策略防呆（load / save 双路径）。

    `strict_addr` 与 `ai_allow_private` 必须是「可识别的布尔」：手写脏值
    （null、"abc"、2 等）回退 DEFAULTS，而不是被 bool() 静默转成 False/True。
    就地修改并返回传入字典（便于链式调用）。
    """
    for _k in ("strict_addr", "ai_allow_private"):
        cfg[_k] = _strict_bool(cfg.get(_k, DEFAULTS[_k]), DEFAULTS[_k])
    return cfg


def normalize_password_flag(cfg):
    """`password_changed` 与口令实值对齐（load / save 双路径）。

    该标志用于「首次登录强制改密」，必须与真实口令一致，否则会出现
    两种坏结果：
      1. 用户从宝塔插件端（或手改 json）改了密码，网页端却一直 403；
      2. 用户把密码改回默认值，标志仍是 True，强制改密形同虚设。
    故不直接采信存储值：只要口令不等于 DEFAULTS 里的默认口令就算已改密。
    就地修改并返回传入字典（便于链式调用）。
    """
    try:
        _changed = str(cfg.get("admin_password")) != str(DEFAULTS["admin_password"])
    except Exception:
        _changed = False
    cfg["password_changed"] = _changed
    return cfg


def load():
    """每次读盘加载配置（含 normalize 防呆；secret 缺失会生成并回写）。

    高频路径请用 `load_cached()`（见文件末尾）：它按文件 stat 指纹缓存，语义等价。
    """
    return _load_state()[0]


def _load_state():
    """`load()` 的实际实现，额外返回「磁盘读取是否成功」。

    `disk_ok=False` 表示文件缺失 / JSON 损坏 / 不可读（此时返回 DEFAULTS 兜底值，
    与 `load()` 的历史行为一致）。`load_cached()` 据此拒绝缓存失败态：把回退值
    缓存下来会让用户「修好配置后仍然不生效」。
    """
    _ensure_dir()
    cfg = dict(DEFAULTS)
    disk_ok = False
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
            disk_ok = True
        except Exception:
            pass
    migrate_legacy_attack(cfg)   # 一次性：旧版 0/0/0 哨兵组合恢复默认开启
    migrate_github_repo(cfg)     # 一次性：空 github_repo 填入默认公开仓库
    normalize_auto_ban(cfg)   # 生效值统一：开关开启时未设置参数回退默认，避免「开着不生效」
    normalize_burst_cool(cfg)   # 突发观测/冷却防呆：窗口无效回退；冷却开启时参数防呆
    normalize_block_page(cfg)   # 拦截页防呆：端口非法/冲突回退；重定向端口白名单化
    normalize_listen(cfg)       # 监听地址/端口/并发上限防呆（先 block_page 再本项）
    normalize_addr_policy(cfg)  # strict_addr / ai_allow_private 必须是可识别的布尔
    normalize_password_flag(cfg)   # 默认口令未改 → password_changed=False
    if not cfg.get("secret"):
        cfg["secret"] = secrets.token_hex(32)
        try:
            save(cfg)
        except ValueError:
            # 磁盘配置损坏：拒绝覆盖（避免抹掉 secret / 密码等），本次仅用内存值
            pass
    return cfg, disk_ok


def _read_disk():
    """读取磁盘上的原始配置；文件缺失返回 {}，损坏/不可读抛 ValueError。

    严格解析是刻意的：save() 要在「磁盘现状」上合并本次修改，若把损坏的
    配置当成空字典继续写，会连 secret / admin_password / ai_api_key 一起抹掉。
    """
    if not os.path.exists(CONF_PATH):
        return {}
    try:
        with open(CONF_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError("配置文件损坏或不可读（%s）：%s" % (CONF_PATH, e))
    if not isinstance(data, dict):
        raise ValueError("配置文件根节点不是对象（%s）" % CONF_PATH)
    return data


# ---- 并发写保护：进程内线程锁 + 跨进程文件锁 ----
# 配置有两个常见写入方：WAF 守护进程（面板 /api/config、AI 审查）与宝塔插件
# 进程（设置页保存）。若各自「读 -> 改 -> 写」全量覆盖，后写者会把对方刚改的
# 其他字段冲回旧值。save() 因此改为 patch 语义：在锁内读磁盘现状、合并本次
# 修改后再原子替换，两个写入方改不同字段时互不覆盖（同字段并发以最后写入为准）。
_save_lock = threading.Lock()
_LOCK_PATH = CONF_PATH + ".lock"

try:
    import fcntl          # Linux（生产环境）
except ImportError:
    fcntl = None
try:
    import msvcrt         # Windows（本地开发 / 验证）
except ImportError:
    msvcrt = None

# 平台文件锁原语：经 getattr 解析。fcntl 仅 Linux、msvcrt 仅 Windows，静态检查器
# 在非对应平台下会报「模块缺属性」/「None 无属性」的误报，这里统一解析一次。
_FLOCK = getattr(fcntl, "flock", None)
_LOCK_EX = getattr(fcntl, "LOCK_EX", 0)
_LOCK_NB = getattr(fcntl, "LOCK_NB", 0)
_LOCK_UN = getattr(fcntl, "LOCK_UN", 0)
_MSVCRT_LOCKING = getattr(msvcrt, "locking", None)
_LK_NBLCK = getattr(msvcrt, "LK_NBLCK", 0)
_LK_UNLCK = getattr(msvcrt, "LK_UNLCK", 0)


def _try_lock(fd):
    """尝试对 fd 加独占非阻塞锁；成功返回 True，失败或平台不支持返回 False。"""
    if _FLOCK is not None:
        try:
            _FLOCK(fd, _LOCK_EX | _LOCK_NB)
            return True
        except OSError:
            return False
    if _MSVCRT_LOCKING is not None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            _MSVCRT_LOCKING(fd, _LK_NBLCK, 1)
            return True
        except OSError:
            return False
    return False


def _unlock(fd):
    """释放 fd 上的文件锁（失败忽略）。"""
    if _FLOCK is not None:
        try:
            _FLOCK(fd, _LOCK_UN)
        except OSError:
            pass
    elif _MSVCRT_LOCKING is not None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            _MSVCRT_LOCKING(fd, _LK_UNLCK, 1)
        except OSError:
            pass


class _conf_file_lock(object):
    """跨进程写锁（fcntl.flock / msvcrt.locking，取不到锁时降级为无锁）。

    锁文件独立于配置本体（配置用 os.replace 原子替换，不参与锁定）。
    降级而非报错：锁定能力受文件系统限制（如部分 NFS）时，保持原有
    「最后写入者生效」的行为，不因锁不可用而让配置完全无法保存。
    """

    def __init__(self, timeout=10.0):
        self.fd = None
        self.timeout = timeout

    def __enter__(self):
        if fcntl is None and msvcrt is None:
            return self
        try:
            fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            return self
        deadline = time.time() + self.timeout
        while True:
            if _try_lock(fd):
                self.fd = fd
                return self
            if time.time() >= deadline:
                os.close(fd)      # 拿不到锁：降级为无锁（不阻塞保存）
                return self
            time.sleep(0.05)

    def __exit__(self, exc_type, exc_value, tb):
        if self.fd is None:
            return False
        _unlock(self.fd)
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None
        return False


def strip_masked(patch):
    """返回「丢弃回显掩码后」的 patch 副本（不修改入参）。

    GET 回显把 MASKED_KEYS 里的字段替换成 MASKED_VALUE；「读配置 → 改一项 →
    整体回写」的客户端会把掩码原样提交，若照写就把真实值覆盖成 ******。
    丢弃该字段 = 保留磁盘原值（**不是清空**：清空需显式传空串）。

    这是纵深防御：daemon 与插件端各自也过滤了一层，本函数保证「所有写入路径
    都经 config.save」时同样安全，并给它们一处可共用的实现。
    """
    if not isinstance(patch, dict):
        return patch
    return {k: v for k, v in patch.items()
            if not (k in MASKED_KEYS and str(v) == MASKED_VALUE)}


def save(patch):
    """合并写入配置（patch 语义 + 并发保护）。

    调用方只传「本次要修改的字段」即可（如 {"admin_password": new}）；
    传完整配置字典同样兼容（等价于对磁盘全量覆盖）。流程：
      1. 丢弃 patch 里等于回显掩码的机密字段（见 strip_masked）；
      2. 进程内线程锁 + 跨进程文件锁串行化；
      3. 读磁盘现状（损坏则拒绝保存并抛 ValueError，绝不覆盖）；
      4. 在现状上先跑一次性旧版迁移，再合并 patch（用户本次意图优先）；
      5. normalize 防呆后原子替换写入，并失效读缓存。

    返回合并后的完整配置字典（便于调用方直接使用最新值）。
    """
    if not isinstance(patch, dict):
        raise TypeError("config.save() 需要 dict（本次修改的字段集合）")
    patch = strip_masked(patch)   # 掩码回写防护：丢弃 = 保留磁盘原值，不是清空
    _ensure_dir()
    with _save_lock, _conf_file_lock():
        disk = _read_disk()
        merged = dict(DEFAULTS)
        merged.update(disk)
        migrate_legacy_attack(merged)   # 先于 patch：旧版哨兵迁移不覆盖本次显式修改
        migrate_github_repo(merged)     # 先于 patch：空仓库地址填默认值，不覆盖本次显式修改
        merged.update(patch)
        normalize_auto_ban(merged)      # 防呆：开关开启时未设置参数回退默认
        normalize_burst_cool(merged)    # 防呆：观测窗口无效回退；冷却开启时参数防呆
        normalize_block_page(merged)    # 防呆：拦截页端口非法/冲突回退；重定向端口白名单化
        normalize_listen(merged)        # 防呆：监听端口/并发上限非法回退
        normalize_addr_policy(merged)   # 防呆：strict_addr / ai_allow_private 布尔归一化
        normalize_password_flag(merged)  # 防呆：password_changed 与口令实值对齐
        if not merged.get("secret"):
            merged["secret"] = secrets.token_hex(32)
        tmp = "%s.tmp.%d" % (CONF_PATH, os.getpid())   # 按进程隔离临时文件
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(merged, f, ensure_ascii=False, indent=2)
            os.replace(tmp, CONF_PATH)
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass
        try:
            os.chmod(CONF_PATH, 0o600)
        except Exception:
            pass
    invalidate()  # 写盘后立即失效缓存
    return merged


# 短 TTL 内存缓存：连接决策路径每次都要读配置，避免每连接都读盘。
# 管理端修改后调用 invalidate() 立即失效，保证改完即生效。
_cache = {"cfg": None, "at": 0.0}
_cache_lock = threading.Lock()
CACHE_TTL = 1.0  # 秒


def invalidate():
    """使配置缓存立即失效（写配置后调用）。

    同时清掉 TTL 缓存（`get()`）与 stat 指纹缓存（`load_cached()`），
    `tests/__init__.py` 的 `reset_caches()` 也走这里，故两个缓存必须一起清。
    """
    with _cache_lock:
        _cache["cfg"] = None
        _cache["at"] = 0.0
    _invalidate_load_cache()


def get():
    """带短 TTL 缓存的读取；未过期直接返回内存副本，过期则重新加载。"""
    now = time.time()
    with _cache_lock:
        if _cache["cfg"] is not None and now - _cache["at"] < CACHE_TTL:
            return dict(_cache["cfg"])
    cfg = load()
    with _cache_lock:
        _cache["cfg"] = dict(cfg)
        _cache["at"] = time.time()
    return cfg


# ---- stat 指纹缓存（认证路径专用）----
# 认证每次请求都要读整份配置（secret / admin_user / admin_password）。`load()`
# 是 makedirs + 读 JSON + 一串 normalize + 拷贝，面板一页十来个 /api/* 请求就
# 重复十几次。这里按「文件指纹」缓存整份配置，并且刻意不使用时间窗：
#   * 键包含 CONF_PATH：测试（tests.new_home）会改写模块常量，不同 home 不能串味；
#   * 失效条件 (st_mtime_ns, st_size)：插件端与守护进程是两个进程、共用一个
#     frpwaf.json，跨进程改密必然改动 mtime → 立即失效 → 「改完即生效」与不缓存等价；
#   * 文件缺失 / 解析失败不缓存（见 _load_state 的 disk_ok）；
#   * 进出都是独立副本（_copy_cfg）：调用方改返回值不污染缓存。
_load_cache = {"key": None, "cfg": None}
_load_cache_lock = threading.Lock()


def _copy_cfg(cfg):
    """配置字典的独立副本：标量不可变直接复用，只深拷容器。

    认证每个请求都要一份，`copy.deepcopy` 整份要几十微秒；名单/映射类配置项
    才可能是 list/dict，对它们深拷即可保证互不影响（标量本来就改不动）。
    """
    return {k: (copy.deepcopy(v) if isinstance(v, (dict, list, set)) else v)
            for k, v in cfg.items()}


def _conf_sig():
    """配置文件指纹 (mtime_ns, size)；文件不存在或 stat 失败返回 None。"""
    try:
        st = os.stat(CONF_PATH)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _invalidate_load_cache():
    """只清 stat 指纹缓存（`invalidate()` 会连带调用）。"""
    with _load_cache_lock:
        _load_cache["key"] = None
        _load_cache["cfg"] = None


def load_cached():
    """带 stat 指纹失效的 `load()`：文件未改动时零读盘。

    与 `get()` 的 1 秒 TTL 缓存刻意分开：决策路径接受「最多 1 秒旧值」，
    认证要求跨进程改密立即生效，只能靠指纹判断而不能靠时间窗口。
    返回**独立副本**（`_copy_cfg`），调用方可自由修改。
    """
    sig = _conf_sig()
    if sig is not None:
        key = (CONF_PATH, sig)
        with _load_cache_lock:
            if _load_cache["key"] == key and _load_cache["cfg"] is not None:
                return _copy_cfg(_load_cache["cfg"])
    cfg, disk_ok = _load_state()
    # 读取前后各取一次指纹，只有文件在读取期间没被改动才缓存：宁可少命中一次，
    # 也不能把「旧内容 + 新指纹」写进缓存（那样会一直陈旧到文件下次改变）。
    if disk_ok and sig is not None and sig == _conf_sig():
        with _load_cache_lock:
            _load_cache["key"] = (CONF_PATH, sig)
            _load_cache["cfg"] = _copy_cfg(cfg)
    return cfg
