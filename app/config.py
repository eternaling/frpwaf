#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 配置管理

配置保存在 data/frpwaf.json，首次运行自动生成（含默认管理员 admin/123456）。
"""
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

DEFAULTS = {
    # 管理/WAF 监听地址（frps httpPlugins 会回调到这里）
    "http_addr": "0.0.0.0",
    "http_port": 7080,
    # 是否启用「网页端」（WAF 管理面板）。关闭后仅停用网页访问（/ 与 /api/*），
    # frps 回调（/frp/handler）与 WAF 防护照常运行，可从宝塔插件端随时重新开启。
    "web_enabled": True,
    # 管理员账号（默认 admin / 123456，安装后请在面板内及时修改）
    "admin_user": "admin",
    "admin_password": "123456",
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
}


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


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


def load():
    _ensure_dir()
    cfg = dict(DEFAULTS)
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    migrate_legacy_attack(cfg)   # 一次性：旧版 0/0/0 哨兵组合恢复默认开启
    normalize_auto_ban(cfg)   # 生效值统一：开关开启时未设置参数回退默认，避免「开着不生效」
    normalize_burst_cool(cfg)   # 突发观测/冷却防呆：窗口无效回退；冷却开启时参数防呆
    if not cfg.get("secret"):
        cfg["secret"] = secrets.token_hex(32)
        try:
            save(cfg)
        except ValueError:
            # 磁盘配置损坏：拒绝覆盖（避免抹掉 secret / 密码等），本次仅用内存值
            pass
    return cfg


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
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                self.fd = fd
                return self
            except OSError:
                if time.time() >= deadline:
                    os.close(fd)      # 拿不到锁：降级为无锁（不阻塞保存）
                    return self
                time.sleep(0.05)

    def __exit__(self, *exc):
        if self.fd is None:
            return False
        try:
            if fcntl is not None:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            else:
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None
        return False


def save(patch):
    """合并写入配置（patch 语义 + 并发保护）。

    调用方只传「本次要修改的字段」即可（如 {"admin_password": new}）；
    传完整配置字典同样兼容（等价于对磁盘全量覆盖）。流程：
      1. 进程内线程锁 + 跨进程文件锁串行化；
      2. 读磁盘现状（损坏则拒绝保存并抛 ValueError，绝不覆盖）；
      3. 在现状上先跑一次性旧版迁移，再合并 patch（用户本次意图优先）；
      4. normalize 防呆后原子替换写入，并失效读缓存。

    返回合并后的完整配置字典（便于调用方直接使用最新值）。
    """
    if not isinstance(patch, dict):
        raise TypeError("config.save() 需要 dict（本次修改的字段集合）")
    _ensure_dir()
    with _save_lock:
        with _conf_file_lock():
            disk = _read_disk()
            merged = dict(DEFAULTS)
            merged.update(disk)
            migrate_legacy_attack(merged)   # 先于 patch：旧版哨兵迁移不覆盖本次显式修改
            merged.update(patch)
            normalize_auto_ban(merged)      # 防呆：开关开启时未设置参数回退默认
            normalize_burst_cool(merged)    # 防呆：观测窗口无效回退；冷却开启时参数防呆
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
    """使配置缓存立即失效（写配置后调用）。"""
    with _cache_lock:
        _cache["cfg"] = None
        _cache["at"] = 0.0


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
