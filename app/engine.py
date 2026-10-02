#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 决策引擎

决策顺序：
  1. 白名单命中 -> allow（白名单优先，直接放行）
  2. 黑名单命中 -> reject
  3. 自动封禁（ban_log 未过期）-> reject
  4. 限速超阈值 -> reject
  5. 自动封禁触发判断（窗口内次数达阈值则写入 ban_log 并 reject）
  6. 攻击类型自动封禁（CC / 端口扫描 / 敏感服务爆破，各自独立开关）
  7. 代理级冷却（分布式突发，默认关闭；冷却期内拒绝新出现 IP）
  8. 其余 -> allow
"""
import ipaddress
import re
import threading
import time

from . import config, store

# 内存规则缓存
_cache = {"black": [], "white": [], "loaded_at": 0}
_cache_lock = threading.Lock()
CACHE_TTL = 3  # 秒

# 限速计数： ip -> (window_start, count)
_rl = {}
_rl_lock = threading.Lock()

# 攻击特征计数（纯内存，不查库；命中阈值后才写封禁记录）：
#   cc   : ip -> (window_start, count)             对 HTTP/HTTPS 代理的连接数
#   scan : ip -> (window_start, {proxy_name, ...}, claimed)
#          访问过的不同代理集合与当前窗口是否已认领
#   ssh  : ip -> (window_start, count)              命中敏感服务代理的连接数
#   base : ip -> (window_start, count)              基础自动封禁（窗口内连接数）
# 窗口过期即重置，避免手动解封后旧计数立即再次触发。
_attack = {"cc": {}, "scan": {}, "ssh": {}, "base": {}}
_attack_lock = threading.Lock()
_ATTACK_MAX_IPS = 5000   # 每类计数硬上限（防持续新 IP 涌入时内存膨胀）
_ATTACK_EVICT = 1000     # 超限时一次淘汰的最旧条目数（摊还清理成本）

# 敏感服务代理关键字：正常用户不会在短时间内对这类端口高频新建连接，
# 出现即高度疑似爆破（ssh 为基本盘，其余为同类暴露服务的扩展覆盖）。
# 按「起始/非字母数字边界」匹配而非任意子串：ssh_22 / mysql-db / mongodb /
# postgresql / elasticsearch 命中，而 wordpress（内含 rdp 子串）不会被误判。
_SENSITIVE_KEYWORDS = ("ssh", "mysql", "redis", "rdp", "mongo", "postgres",
                       "elastic", "telnet", "smb", "vnc", "ftp")
_SENSITIVE_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:%s)" % "|".join(_SENSITIVE_KEYWORDS))

# ---- 分布式突发观测（A，纯内存、始终开启、无副作用）----
# 场景：海量不同 IP × 每 IP 仅 1 次的爬虫/扫描，单 IP 维度检测按设计不触发，
# 需按代理名聚合才能看清。观测结果供面板展示与冷却判定（cool_check）使用。
# 内存边界：最多 _BURST_MAX_PROXIES 个代理，每代理最多 _BURST_MAX_IPS 个 IP；
# 超出后不再收录新 IP（trunc 标记），占比/独立 IP 统计在洪峰下仍近似准确。
# `ips` 收录全部首现 IP（观测口径）；`eligible` 只收录「首现时代理不在冷却中」
# 的 IP（冻结资格口径）——冷却期内被拒的新 IP 不进 eligible，否则攻击者可用
# 「爆发—停歇—再爆发」循环，让上一轮被拒 IP 在重入冷却时被 known 冻结放行（洗白）。
_burst = {}          # proxy_name -> {start, conns, ips:set, multi:set, eligible:set, ptype, trunc}
_burst_lock = threading.Lock()
_BURST_MAX_PROXIES = 50
_BURST_MAX_IPS = 2000

# 代理级冷却状态（C）：proxy_name -> {"until": 到期时间戳, "known": frozenset(IP),
# "since": 进入冷却时间戳, "conns": 冷却期内累计连接数（续期证据）}。
# known 在进入冷却时冻结：冷却期内被拒的新 IP 因重试不会进入 known（否则第二次
# 即被放行，攻击者可洗白）；冷却结束后观测数据自然滚动，新周期重新判定。
# 硬上限：防大量代理名轮流触发冷却时条目线性增长（超出按 since 淘汰最旧）。
_cool = {}
_cool_lock = threading.Lock()
_COOL_MAX = 100


def _burst_reset(proxy_name, now, ptype=""):
    """开始/重置某代理的观测窗口（须在 _burst_lock 内调用）。"""
    _burst[proxy_name] = {
        "start": now, "conns": 0, "ips": set(), "multi": set(),
        "eligible": set(), "ptype": ptype or "", "trunc": False,
    }


def _burst_evict_locked(count=1):
    """淘汰最旧的 count 个观测窗口（须在 _burst_lock 内调用）。

    代理上限仅 50，精确淘汰即可（O(50 log 50) 可忽略）；调用方传入
    「需腾出的空位数」，避免批量淘汰后远低于上限。
    """
    n = max(1, int(count))
    for k in sorted(_burst, key=lambda k: _burst[k]["start"])[:n]:
        _burst.pop(k, None)


def _burst_track(proxy_name, proxy_type, ip, now):
    """记录一次通过前置准入的连接（第 3 步封禁判定之后调用）。

    已被黑名单/封禁拦截的 IP 不进入观测（已知恶意重试不污染突发定性）。
    冷却判定（第 7 步）晚于本调用，因此被 proxy_cool 拒绝的连接也会计入
    观测口径（ips/multi）；但「冻结资格」口径 eligible 额外要求该 IP 首现时
    代理不在冷却中——防止上一轮被拒 IP 在重入冷却时被 known 冻结放行。
    """
    if not proxy_name:
        return
    cfg = config.get()
    window = max(2, int(cfg.get("burst_window") or 60))
    with _cool_lock:
        c0 = _cool.get(proxy_name)
        cooling = bool(c0 and c0["until"] > now)
    try:
        with _burst_lock:
            d = _burst.get(proxy_name)
            if d is None:
                if len(_burst) >= _BURST_MAX_PROXIES:
                    _burst_evict_locked(len(_burst) - _BURST_MAX_PROXIES + 1)
                _burst_reset(proxy_name, now, proxy_type)
                d = _burst[proxy_name]
            elif now - d["start"] >= window:
                _burst_reset(proxy_name, now, proxy_type)
                d = _burst[proxy_name]
            d["conns"] += 1
            if ip not in d["ips"]:
                if len(d["ips"]) >= _BURST_MAX_IPS:
                    d["trunc"] = True   # 洪峰截断：不再收录新 IP（内存有界）
                else:
                    d["ips"].add(ip)
                    if not cooling:
                        # setdefault：兼容测试/异常路径下缺该键的窗口条目
                        d.setdefault("eligible", set()).add(ip)
            elif ip not in d["multi"]:
                d["multi"].add(ip)      # 第 2 次连接：移出「仅 1 次」口径
    except Exception:
        pass   # 观测失败不影响准入（fail-open）
    # 冷却续期证据：冷却期内累计连接数。观测窗口滚动（60s）会把 conns 清零，
    # 若只看窗口条件，持续攻击在窗口重置后可能让冷却中断；该计数跨窗口累积，
    # 只要冷却期内又送满 min_conns 条连接，就判定攻击仍在持续并续期。
    try:
        with _cool_lock:
            c = _cool.get(proxy_name)
            if c is not None and c["until"] > now:
                c["conns"] += 1
    except Exception:
        pass


def _burst_level(conns, uniq, single_pct):
    """观测定性标签（辅助展示，不是决策依据，阈值硬编码）。"""
    if uniq >= 50 and single_pct >= 80:
        return "distributed_probe"
    if conns >= 100 and uniq <= 3:
        return "single_source"
    return "normal"


def _burst_snapshot_locked(now):
    """生成观测快照（须在 _burst_lock 内调用；冷却状态单独取锁，见 burst_snapshot）。"""
    window = max(2, int(config.get().get("burst_window") or 60))
    out = []
    for name, d in _burst.items():
        age = now - d["start"]
        if age >= window:
            continue   # 过期窗口不展示，等待下次连接重置
        uniq = len(d["ips"])
        single = uniq - len(d["multi"])
        pct = (single * 100.0 / uniq) if uniq else 0.0
        conns = d["conns"]
        out.append({
            "proxy_name": name, "proxy_type": d["ptype"],
            "window": window, "age": int(age),
            "conns": conns, "uniq_ips": uniq, "single_ips": single,
            "single_pct": round(pct, 1),
            "rate": round(conns / window, 2),   # 平均新建连接速率（条/秒）
            "truncated": d["trunc"],
            "level": _burst_level(conns, uniq, pct),
        })
    out.sort(key=lambda x: x["conns"], reverse=True)
    return out


def burst_snapshot():
    """面板用观测快照：代理级指标 + 定性 + 当前冷却剩余（最多 50 行）。"""
    now = time.time()
    with _burst_lock:
        rows = _burst_snapshot_locked(now)
    with _cool_lock:
        for r in rows:
            c = _cool.get(r["proxy_name"])
            r["cool_remain"] = max(0, int(c["until"] - now)) if c else 0
    return rows


def cool_check():
    """后台判定（由 daemon 每 10s 调用）：进入/续期/清理代理级冷却。

    进入条件（同时满足）：开关开启、窗口内 conns ≥ min_conns、
    uniq ≥ uniq_threshold、single_pct ≥ single_pct 阈值。
    续期条件（二选一，均需开关开启）：
      a) 窗口条件持续满足（同上）；
      b) 冷却期内累计连接数 ≥ min_conns（_burst_track 维护的续期证据，
         跨观测窗口累积）——避免 60s 窗口滚动后条件短暂归零、
         攻击仍在持续却出现「冷却中断」的放行缺口。
    进入冷却时冻结 known 集合（eligible 口径：仅非冷却期首现的 IP，
    冷却期内被拒的新 IP 不会因重试被洗白），冷却期内放行；
    不再满足且无续期证据则到期自然失效。
    """
    cfg = config.get()
    if not cfg.get("proxy_cool_enabled"):
        with _cool_lock:
            _cool.clear()   # 开关关闭：清理状态，重新开启从干净状态判定
        return []
    min_conns = int(cfg.get("proxy_cool_min_conns") or 300)
    uniq_th = int(cfg.get("proxy_cool_uniq_threshold") or 200)
    pct_th = int(cfg.get("proxy_cool_single_pct") or 80)
    secs = max(10, int(cfg.get("proxy_cool_seconds") or 60))
    now = time.time()
    entered = []
    with _burst_lock:
        rows = _burst_snapshot_locked(now)
    for r in rows:
        if not (r["conns"] >= min_conns and r["uniq_ips"] >= uniq_th
                and r["single_pct"] >= pct_th):
            continue
        name = r["proxy_name"]
        with _cool_lock:
            c = _cool.get(name)
            if c is not None:
                # 条件持续满足：续期。证据计数一并归零，避免归零前
                # 又被下一轮「证据续期」重复触发（两路径互斥，各生效一次）。
                c["until"] = now + secs
                c["conns"] = 0
                continue
        # 冻结 known：必须在 _burst_lock 内快照（观测线程可能正在写该集合，
        # 无锁迭代会因集合大小变化抛 RuntimeError）。
        with _burst_lock:
            d = _burst.get(name)
            known = frozenset(d.get("eligible") or ()) if d else None
        if known is None:
            continue   # 窗口刚被淘汰/重置：跳过本轮，避免以空 known 冷启动（全员误拒）
        with _cool_lock:
            c = _cool.get(name)
            if c is None:
                _cool[name] = {"until": now + secs, "known": known,
                               "since": now, "conns": 0}
                entered.append(name)
            else:
                c["until"] = now + secs
                c["conns"] = 0
    # 续期证据：冷却期内累计连接数达到下限 -> 续期（覆盖观测窗口滚动场景）
    with _cool_lock:
        for k, c in _cool.items():
            if c["until"] > now and c.get("conns", 0) >= min_conns:
                c["until"] = now + secs
                c["conns"] = 0
        for k in [k for k, v in _cool.items() if v["until"] <= now]:
            _cool.pop(k, None)   # 到期清理
        # 硬上限（与 _burst 的 50 代理边界对称）：防御大量代理名轮流触发冷却时
        # 条目在冷却时长内线性增长；超限淘汰最旧（按 since）。
        if len(_cool) > _COOL_MAX:
            for k in sorted(_cool, key=lambda k: _cool[k]["since"])[:len(_cool) - _COOL_MAX]:
                _cool.pop(k, None)
    return entered


def _cool_active(proxy_name):
    """决策路径查询：该代理是否处于冷却中（O(1)，纯内存）。"""
    try:
        if not config.get().get("proxy_cool_enabled"):
            return False
        with _cool_lock:
            c = _cool.get(proxy_name)
            if c is None:
                return False
            if c["until"] <= time.time():
                return False
            return True
    except Exception:
        return False   # 判定异常放行（fail-open，与引擎整体一致）


def _cool_blocks(proxy_name, ip):
    """冷却期内：新出现 IP 拒绝，known（冻结集合）放行。"""
    with _cool_lock:
        c = _cool.get(proxy_name)
        if c is None or c["until"] <= time.time():
            return False
        return ip not in c["known"]


def _rules():
    now = time.time()
    with _cache_lock:
        if now - _cache["loaded_at"] > CACHE_TTL:
            blacks, whites = store.load_rules()
            _cache["black"] = blacks
            _cache["white"] = whites
            _cache["loaded_at"] = now
        return _cache["black"], _cache["white"]


def invalidate_cache():
    with _cache_lock:
        _cache["loaded_at"] = 0


def _ip_in(ip_obj, nets):
    for n in nets:
        try:
            if ip_obj in n:
                return True
        except TypeError:
            continue
    return False


def _rate_limited(ip, per_sec):
    if per_sec <= 0:
        return False
    now = time.time()
    with _rl_lock:
        start, cnt = _rl.get(ip, (now, 0))
        if now - start >= 1.0:
            start, cnt = now, 0
        cnt += 1
        _rl[ip] = (start, cnt)
        # 清理过期项：有界增长，避免字典无限膨胀
        if len(_rl) > 5000:
            for k in [k for k, v in _rl.items() if now - v[0] > 2]:
                _rl.pop(k, None)
            if len(_rl) > 5000:
                for k, _ in sorted(_rl.items(), key=lambda kv: kv[1][0])[:max(250, len(_rl) - 5000)]:
                    _rl.pop(k, None)
    return cnt > per_sec


def _is_banned(ip):
    # 复用 store 的封禁缓存集合判断（单 IP / CIDR），避免每次连接全表扫描
    try:
        return store.is_banned(ip)
    except Exception:
        return False


def _hit_sensitive(proxy_name, proxy_type):
    """代理名是否命中敏感服务关键字（SSH/数据库/远程桌面等爆破特征）。

    - 按非字母数字边界匹配（见 _SENSITIVE_RE），wordpress 这类含 rdp 子串的
      普通代理名不会被误判；
    - 仅适用于非 HTTP 类代理：http/https/tcpmux 是 Web 服务（其高频访问由
      CC 检测覆盖），避免域名片段被误判为敏感服务爆破而永久封禁。
    """
    ptype = (proxy_type or "").lower()
    if ptype in ("http", "https", "tcpmux"):
        return False
    text = ("%s %s" % (proxy_name or "", ptype)).lower()
    return _SENSITIVE_RE.search(text) is not None


def _attack_trim(store_d, now, window):
    """有界清理（须在 _attack_lock 内调用）：过期项优先，仍超上限则淘汰最旧条目。

    硬上限保证「持续新 IP 涌入」时字典不会无限增长，且清理后条目数回落，
    需再积累约 _ATTACK_EVICT 条才会再次全量清理（摊还成本，避免每连接 O(n)）。
    """
    if len(store_d) <= _ATTACK_MAX_IPS:
        return
    for k in [k for k, v in store_d.items() if now - v[0] >= window]:
        store_d.pop(k, None)
    if len(store_d) > _ATTACK_MAX_IPS:
        for k, _ in sorted(store_d.items(), key=lambda kv: kv[1][0])[:_ATTACK_EVICT]:
            store_d.pop(k, None)


def _attack_count(kind, ip, window, threshold):
    """计数型检测（cc / ssh / base）：返回 (cnt, claimed)。

    claimed=True 表示本次连接越过阈值并完成认领：计数在阈值处封顶，
    同一窗口内只有第一个越过阈值的线程能拿到 True（并发连接不会重复写库）。
    认领后计数保留封顶值而非清零，避免「封禁写入可见前的窄窗口内并发连接
    再次累积、二次触发」的竞态；手动解封后窗口内也不会凭旧计数立即再触发，
    窗口过期自动重置。写库失败时由调用方 _attack_reseed 回退一格重试。
    """
    now = time.time()
    with _attack_lock:
        store_d = _attack[kind]
        start, cnt = store_d.get(ip, (now, 0))
        if now - start >= window:
            start, cnt = now, 0
        if cnt >= threshold:
            cnt = threshold          # 已在阈值封顶：本窗口已认领过，不再触发
            claimed = False
        else:
            cnt += 1
            claimed = (cnt == threshold)
        store_d[ip] = (start, cnt)
        _attack_trim(store_d, now, window)
        return cnt, claimed


def _attack_scan(ip, proxy_name, window, threshold):
    """端口扫描检测：返回 (n, claimed, names)；语义同 _attack_count。

    names 为当前窗口内访问过的代理集合；同一窗口只认领一次。
    """
    now = time.time()
    with _attack_lock:
        store_d = _attack["scan"]
        start, names, was_claimed = store_d.get(ip, (now, set(), False))
        if now - start >= window:
            start, names, was_claimed = now, set(), False
        if proxy_name:
            names.add(proxy_name)
        n = len(names)
        claimed = n >= threshold and not was_claimed
        store_d[ip] = (start, names, was_claimed or claimed)
        _attack_trim(store_d, now, window)
        return n, claimed, names


def _attack_reseed(kind, ip, threshold, names=None):
    """写库失败时允许下一次连接重试封禁写入。"""
    with _attack_lock:
        if kind == "scan":
            _attack["scan"][ip] = (time.time(), set(names or ()), False)
        else:
            _attack[kind][ip] = (time.time(), max(0, threshold - 1))


# 内核同步请求：合并为单工作线程串行执行。
# 原实现每次 ssh 永久封禁都新起线程做全量 sync（查库 + spawn ipset 子进程），
# 批量封禁时线程/子进程风暴；现改为事件合并——同步进行中到达的多个请求，
# 只会在当前同步完成后合并为一次补跑（sync 自身全量，天然覆盖）。
_fw_sync_event = threading.Event()
_fw_sync_started = False
_fw_sync_lock = threading.Lock()


def _request_fw_sync():
    global _fw_sync_started
    with _fw_sync_lock:
        if not _fw_sync_started:
            _fw_sync_started = True
            threading.Thread(target=_fw_sync_worker, daemon=True).start()
    _fw_sync_event.set()


def _fw_sync_worker():
    while True:
        _fw_sync_event.wait()
        _fw_sync_event.clear()
        try:
            from . import firewall
            firewall.sync_from_store()
        except Exception:
            pass


def _attack_ban(ip, reason, kind):
    """执行自动封禁（计数清空已由 _attack_count/_attack_scan 原子完成）。

    分档处置：
      - kind == "ssh"（敏感服务爆破，确凿恶意）-> 永久黑名单（ip_list black）；
        若黑名单开关关闭（永久名单不参与判定），降级为临时封禁兜底，
        避免「功能开着却完全不生效」。
      - kind == "base"（基础自动封禁）          -> 临时封禁（auto_ban_seconds）
      - 其余（CC / 端口扫描，存在误伤可能）    -> 临时封禁（ban_log，到期自动释放）
    返回 True 表示已写入（或已存在于黑名单），False 表示写库失败。
    """
    cfg = config.get()
    try:
        if kind == "ssh":
            if cfg.get("blacklist_enabled", True):
                try:
                    store.add_ip(ip, "black", reason)
                    invalidate_cache()  # 黑名单规则缓存 3s TTL：写后立即失效，改完即生效
                except ValueError:
                    pass  # 已存在于黑名单（UNIQUE 约束）视为已处置
                try:
                    store.unban_ip(ip)  # 升级为永久后释放同名临时封禁
                except Exception:
                    pass
                try:
                    if cfg.get("fw_sync_enabled", True):
                        # 异步合并下发内核（sync 会查库并 spawn ipset 命令，不能
                        # 阻塞决策路径；失败也无妨，后台 10s 轮询兜底补齐）
                        _request_fw_sync()
                except Exception:
                    pass
            else:
                # 黑名单开关关闭：永久名单不参与判定，降级临时封禁保证仍被拦截
                secs = int(cfg.get("auto_ban_seconds") or 0)
                store.add_ban(ip, reason, secs if secs > 0 else 600)
        else:
            if kind == "base":
                secs = int(cfg.get("auto_ban_seconds") or 0)   # 基础档沿用 auto_ban_seconds
            else:
                secs = int(cfg.get("auto_ban_%s_seconds" % kind) or 0)
            store.add_ban(ip, reason, secs if secs > 0 else 600)  # 0 视为未设置，回退 600
        return True
    except Exception:
        return False


def decide(remote_ip, remote_port, proxy_name, proxy_type, user):
    """返回 (allow: bool, reason: str)。"""
    cfg = config.get()
    try:
        ip_obj = ipaddress.ip_address(remote_ip)
    except ValueError:
        return True, "invalid-ip-pass"

    blacks, whites = _rules()

    # 1. 白名单优先
    if cfg.get("whitelist_enabled") and _ip_in(ip_obj, whites):
        return True, "whitelist"

    # 2. 黑名单
    if cfg.get("blacklist_enabled") and _ip_in(ip_obj, blacks):
        return False, "blacklist"

    # 3. 自动封禁中
    if _is_banned(remote_ip):
        return False, "banned"

    # 突发观测：记录通过前置准入（白/黑/封禁）的连接。放在第 3 步之后，
    # 已知恶意 IP 的重试不进入观测；纯内存、失败静默，不影响准入。
    _burst_track(proxy_name, proxy_type, remote_ip, time.time())

    # 4. 限速
    if cfg.get("rate_limit_enabled") and _rate_limited(remote_ip, int(cfg.get("rate_limit_per_sec") or 0)):
        return False, "rate_limit"

    # 5. 自动封禁触发判断（纯内存计数，与第 6 步共用原子认领机制）
    #    注：白名单命中的 IP 已在第 1 步直接放行，天然不会走到这里（无需重复检查）。
    #    原实现每连接查一次 conn_log（磁盘 IO，违反决策路径红线），且并发时
    #    多个线程可同时达阈值重复写 ban_log；改为内存计数 + 锁内认领清零。
    if cfg.get("auto_ban_enabled"):
        window = int(cfg.get("auto_ban_window") or 60)
        threshold = int(cfg.get("auto_ban_threshold") or 0)
        if threshold > 0:
            cnt, claimed = _attack_count("base", remote_ip, window, threshold)
            if claimed:
                reason = "auto: %d conns/%ds" % (threshold, window)
                if not _attack_ban(remote_ip, reason, "base"):
                    _attack_reseed("base", remote_ip, threshold)
                return False, "auto_ban"

    # 6. 攻击类型自动封禁（CC / 端口扫描 / 敏感服务爆破，独立开关，纯内存检测）
    #    白名单保护：whitelist_enabled 开启时白名单 IP 在第 1 步已直接放行。
    blocked = _attack_detect(cfg, remote_ip, proxy_name, proxy_type)
    if blocked:
        return False, blocked

    # 7. 代理级冷却（默认关闭）：分布式突发下拒绝该代理「新出现 IP」的首连；
    #    冷却期间已见 IP（known 冻结集合）放行，控制对真实用户的误伤面。
    if proxy_name and _cool_active(proxy_name) and _cool_blocks(proxy_name, remote_ip):
        return False, "proxy_cool"

    return True, ""


def _attack_detect(cfg, ip, proxy_name, proxy_type):
    """攻击特征检测（第 6 步）：命中阈值则封禁并返回 reason，否则返回 ""。

    检测顺序：敏感服务（确凿，永久）-> CC -> 端口扫描。
    全部为内存计数，窗口过期自动重置，不查库、不做磁盘 IO。
    """
    # 6.1 敏感服务爆破（ssh/mysql/redis 等）：高频新建 -> 永久黑名单
    if cfg.get("auto_ban_ssh_enabled") and _hit_sensitive(proxy_name, proxy_type):
        window = max(1, int(cfg.get("auto_ban_ssh_window") or 60))
        threshold = int(cfg.get("auto_ban_ssh_threshold") or 0)
        if threshold > 0:
            cnt, claimed = _attack_count("ssh", ip, window, threshold)
            if claimed:
                reason = "auto_ssh: %s %d conns/%ds" % (proxy_name or "-", cnt, window)
                if not _attack_ban(ip, reason, "ssh"):
                    _attack_reseed("ssh", ip, threshold)
                return "auto_ban_ssh"

    # 6.2 CC 攻击：对 HTTP/HTTPS 代理的高频新建连接 -> 临时封禁
    if cfg.get("auto_ban_cc_enabled"):
        ptype = (proxy_type or "").lower()
        if ptype in ("http", "https", "tcpmux"):
            window = max(1, int(cfg.get("auto_ban_cc_window") or 60))
            threshold = int(cfg.get("auto_ban_cc_threshold") or 0)
            if threshold > 0:
                cnt, claimed = _attack_count("cc", ip, window, threshold)
                if claimed:
                    reason = "auto_cc: %d conns/%ds" % (cnt, window)
                    if not _attack_ban(ip, reason, "cc"):
                        _attack_reseed("cc", ip, threshold)
                    return "auto_ban_cc"

    # 6.3 端口扫描：窗口内访问大量不同代理 -> 临时封禁
    if cfg.get("auto_ban_scan_enabled") and proxy_name:
        window = max(1, int(cfg.get("auto_ban_scan_window") or 60))
        threshold = int(cfg.get("auto_ban_scan_threshold") or 0)
        if threshold > 0:
            n, claimed, names = _attack_scan(ip, proxy_name, window, threshold)
            if claimed:
                reason = "auto_scan: %d proxies/%ds" % (n, window)
                if not _attack_ban(ip, reason, "scan"):
                    _attack_reseed("scan", ip, threshold, names)
                return "auto_ban_scan"

    return ""


def auto_release():
    """释放已到期的封禁（由后台线程周期调用）。返回被释放的记录列表。"""
    released = store.expired_bans()
    for b in released:
        store.release_ban(b["id"])
    return released
