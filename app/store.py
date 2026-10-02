#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - SQLite 存储层

表结构：
  ip_list      : IP/CIDR 名单（黑/白）
  conn_log     : 连接审计日志
  ban_log      : 自动封禁记录（用于自动解封）
  proxy_stat   : 每个代理的累计连接统计
  settings     : 简单键值（预留）
"""
import ipaddress
import os
import sqlite3
import threading
import time

from . import config

_lock = threading.Lock()
_conn = None

# 生效封禁 IP 的内存缓存：连接决策路径每次都查会全表扫描，故做短 TTL 缓存。
_bans = {"ips": frozenset(), "at": 0.0}
_bans_lock = threading.Lock()
BANS_TTL = 2.0  # 秒

SCHEMA = """
CREATE TABLE IF NOT EXISTS ip_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    list_type TEXT NOT NULL DEFAULT 'black',   -- black / white
    remark TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    -- 同一 CIDR 允许同时存在于黑、白名单（白名单优先），故用组合唯一，
    -- 而非对 cidr 全局唯一（否则无法把黑名单项直接改判为白名单）。
    UNIQUE(cidr, list_type)
);
CREATE INDEX IF NOT EXISTS idx_ip_list_type ON ip_list(list_type);

CREATE TABLE IF NOT EXISTS conn_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER DEFAULT 0,
    proxy_name TEXT DEFAULT '',
    proxy_type TEXT DEFAULT '',
    user TEXT DEFAULT '',
    action TEXT NOT NULL,          -- allow / reject / rate_limit / error
    reason TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_conn_log_ts ON conn_log(ts);
CREATE INDEX IF NOT EXISTS idx_conn_log_ip ON conn_log(ip);
-- 复合索引：recent_count_by_ip(ip, 窗口) 与按 IP 过滤日志走该索引，
-- 单列 idx_conn_log_ip 在高频 IP 场景下仍需回表过滤 ts。
CREATE INDEX IF NOT EXISTS idx_conn_log_ip_ts ON conn_log(ip, ts);
-- 复合索引：summary_by_proxy 聚合视图按 (proxy_name<>'', ts>=窗口) 过滤 + 分组，
-- 走该索引避免全表扫描后回表过滤 ts（与 idx_conn_log_ip_ts 同思路）。
CREATE INDEX IF NOT EXISTS idx_conn_log_proxy_ts ON conn_log(proxy_name, ts);

CREATE TABLE IF NOT EXISTS ban_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT DEFAULT '',
    banned_at INTEGER NOT NULL,
    expire_at INTEGER NOT NULL,
    released INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ban_log_ip ON ban_log(ip);
-- 生效封禁查询（active_bans / expired_bans / is_banned 缓存重建）走该复合索引，
-- 避免 ban_log 增长后每次缓存重建全表扫描。
CREATE INDEX IF NOT EXISTS idx_ban_log_active ON ban_log(released, expire_at);

CREATE TABLE IF NOT EXISTS proxy_stat (
    proxy_name TEXT PRIMARY KEY,
    proxy_type TEXT DEFAULT '',
    total INTEGER NOT NULL DEFAULT 0,
    rejected INTEGER NOT NULL DEFAULT 0,
    last_ts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ai_review (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    batch_id INTEGER DEFAULT 0,
    ip TEXT DEFAULT '',
    verdict TEXT DEFAULT '',        -- malicious / suspicious / benign / error / none
    reason TEXT DEFAULT '',
    action TEXT DEFAULT '',         -- banned / none / error / skip
    model TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ai_review_ts ON ai_review(ts);
"""


_IP_LIST_DDL = """
CREATE TABLE IF NOT EXISTS ip_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    list_type TEXT NOT NULL DEFAULT 'black',
    remark TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE(cidr, list_type)
)
"""


def _migrate_ip_list(c):
    """迁移旧的 ip_list 表（cidr 全局唯一）到新结构（UNIQUE(cidr,list_type)）。

    旧结构下无法把已在黑名单的 CIDR 直接加入白名单；新结构允许同一 CIDR
    同时存在于黑白名单（白名单优先）。仅当检测到旧结构时重建，保留数据。
    """
    try:
        row = c.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='ip_list'"
        ).fetchone()
    except sqlite3.Error:
        return
    ddl = ((row[0] if row else "") or "").upper().replace(" ", "")
    if "UNIQUE(CIDR,LIST_TYPE)" in ddl:
        return  # 已是新结构
    if "CIDRTEXTNOTNULLUNIQUE" not in ddl:
        return  # 结构未知，保守跳过
    try:
        c.execute("ALTER TABLE ip_list RENAME TO ip_list_old")
        c.execute(_IP_LIST_DDL)
        c.execute(
            "INSERT OR IGNORE INTO ip_list(id,cidr,list_type,remark,created_at)"
            " SELECT id,cidr,list_type,remark,created_at FROM ip_list_old"
        )
        c.execute("DROP TABLE ip_list_old")
        # 旧表被删时其上的 idx_ip_list_type 索引一并消失，这里在新表上重建
        c.execute("CREATE INDEX IF NOT EXISTS idx_ip_list_type ON ip_list(list_type)")
        c.commit()
    except sqlite3.Error:
        # 迁移失败则还原，避免丢表
        try:
            c.execute("DROP TABLE IF EXISTS ip_list")
            c.execute("ALTER TABLE ip_list_old RENAME TO ip_list")
            c.commit()
        except sqlite3.Error:
            pass


def _connect():
    global _conn
    if _conn is not None:
        # 自愈：数据库文件被替换 / 连接已失效（进程重启、fd 陈旧）时重建
        try:
            _conn.execute("SELECT 1")
            return _conn
        except sqlite3.Error:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
    os.makedirs(config.DATA_DIR, exist_ok=True)
    _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False, timeout=15)
    _conn.row_factory = sqlite3.Row
    try:
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA busy_timeout=5000")
        # WAL 调优：更频繁自动 checkpoint + 限制 WAL 文件上限，
        # 避免高写入下 -wal 文件长期偏大（读连接也不会被过度阻塞）。
        _conn.execute("PRAGMA wal_autocheckpoint=512")          # 约 2MB 触发一次合并
        _conn.execute("PRAGMA journal_size_limit=16777216")     # checkpoint 后截断至 ≤16MB
        _conn.executescript(SCHEMA)
        _migrate_ip_list(_conn)   # 旧库：cidr 全局唯一 -> UNIQUE(cidr,list_type)
        _conn.commit()
    except sqlite3.Error:
        pass
    # 数据库含连接日志/封禁记录，收紧权限（与 frpwaf.json 一致）
    for p in (config.DB_PATH, config.DB_PATH + "-wal", config.DB_PATH + "-shm"):
        try:
            if os.path.exists(p):
                os.chmod(p, 0o600)
        except OSError:
            pass
    return _conn


def init():
    with _lock:
        _connect()


def _exec(sql, args=()):
    with _lock:
        c = _connect()
        cur = c.execute(sql, args)
        c.commit()
        return cur


def _query(sql, args=()):
    with _lock:
        c = _connect()
        cur = c.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]


def _query_ro(sql, args=()):
    """只读查询（独立临时连接，**不占全局 _lock**）。

    用于面板触发的重聚合查询（summary_by_proxy）：WAL 模式下读与写互不阻塞，
    长查询不再持有全局 _lock，避免拖住决策路径的缓存重建（banned_ips / _rules）。
    数据库文件不存在（未初始化）时返回 []。
    """
    if not os.path.exists(config.DB_PATH):
        return []
    c = sqlite3.connect(config.DB_PATH, timeout=5)
    try:
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=5000")
        return [dict(r) for r in c.execute(sql, args).fetchall()]
    finally:
        try:
            c.close()
        except Exception:
            pass


def checkpoint(truncate=False):
    """执行 WAL checkpoint。truncate=True 时回收 -wal 文件大小（有界）。"""
    try:
        with _lock:
            c = _connect()
            c.execute("PRAGMA wal_checkpoint(%s)" % ("TRUNCATE" if truncate else "PASSIVE"))
    except sqlite3.Error:
        pass


# ---------------- ip_list ----------------
# 面板名单接口的返回上限：防大名单场景全量返回 + 逐条归属地查询拖垮面板。
# 仅约束「展示接口」（daemon /api/iplist、插件端 list_ips/list_bans）；
# 内部逻辑（AI 白名单判断、内核同步）直接查库，不受此上限影响。
PANEL_LIST_CAP = 5000


def list_ips(list_type=None, limit=0):
    """名单列表。limit>0 时限制返回条数（面板大名单场景防全表拉取）。"""
    lim = int(limit or 0)
    if list_type:
        if lim > 0:
            return _query("SELECT * FROM ip_list WHERE list_type=? ORDER BY id DESC LIMIT ?",
                          (list_type, lim))
        return _query("SELECT * FROM ip_list WHERE list_type=? ORDER BY id DESC", (list_type,))
    if lim > 0:
        return _query("SELECT * FROM ip_list ORDER BY id DESC LIMIT ?", (lim,))
    return _query("SELECT * FROM ip_list ORDER BY id DESC")


def add_ip(cidr, list_type="black", remark=""):
    cidr = (cidr or "").strip()
    # 校验并规范化
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        cidr = str(net)
    except ValueError:
        raise ValueError("无效的 IP 或 CIDR: %s" % cidr)
    if list_type not in ("black", "white"):
        raise ValueError("list_type 只能是 black 或 white")
    try:
        _exec(
            "INSERT INTO ip_list(cidr,list_type,remark,created_at) VALUES(?,?,?,?)",
            (cidr, list_type, remark, int(time.time())),
        )
    except sqlite3.IntegrityError:
        raise ValueError("该条目已存在: %s" % cidr)
    return True


def del_ip(entry_id):
    _exec("DELETE FROM ip_list WHERE id=?", (entry_id,))
    return True


def load_rules():
    """加载为 (black_networks, white_networks) 两个列表。"""
    blacks, whites = [], []
    for row in _query("SELECT cidr,list_type FROM ip_list"):
        try:
            net = ipaddress.ip_network(row["cidr"], strict=False)
        except ValueError:
            continue
        (blacks if row["list_type"] == "black" else whites).append(net)
    return blacks, whites


# ---------------- conn_log ----------------
def add_log(ip, port, proxy_name, proxy_type, user, action, reason=""):
    _exec(
        "INSERT INTO conn_log(ts,ip,port,proxy_name,proxy_type,user,action,reason)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (int(time.time()), ip, int(port or 0), proxy_name or "", proxy_type or "",
         user or "", action, reason or ""),
    )


def add_log_and_bump(ip, port, proxy_name, proxy_type, user, action, reason="",
                     rejected=False):
    """连接日志 + 代理统计合并为一次事务提交。

    回调路径每连接原为两次独立写库（两次 fsync），高并发下是主要写放大来源；
    合并后单事务完成，语义与 add_log() + bump_proxy() 完全一致。
    """
    with _lock:
        c = _connect()
        try:
            c.execute(
                "INSERT INTO conn_log(ts,ip,port,proxy_name,proxy_type,user,action,reason)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (int(time.time()), ip, int(port or 0), proxy_name or "",
                 proxy_type or "", user or "", action, reason or ""),
            )
            if proxy_name:
                c.execute(
                    "INSERT INTO proxy_stat(proxy_name,proxy_type,total,rejected,last_ts)"
                    " VALUES(?,?,1,?,?)"
                    " ON CONFLICT(proxy_name) DO UPDATE SET"
                    "   total=total+1,"
                    "   rejected=rejected+excluded.rejected,"
                    "   proxy_type=excluded.proxy_type,"
                    "   last_ts=excluded.last_ts",
                    (proxy_name, proxy_type or "", 1 if rejected else 0,
                     int(time.time())),
                )
            c.commit()
        except sqlite3.Error:
            try:
                c.rollback()
            except sqlite3.Error:
                pass
            raise


def list_logs(limit=200, offset=0, ip=None, action=None, proxy=None):
    sql = "SELECT * FROM conn_log WHERE 1=1"
    args = []
    if ip:
        sql += " AND ip=?"
        args.append(ip)
    if action:
        sql += " AND action=?"
        args.append(action)
    if proxy:
        sql += " AND proxy_name=?"
        args.append(proxy)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args += [int(limit), int(offset)]
    return _query(sql, args)


def count_logs(ip=None, action=None, proxy=None):
    sql = "SELECT COUNT(*) AS n FROM conn_log WHERE 1=1"
    args = []
    if ip:
        sql += " AND ip=?"
        args.append(ip)
    if action:
        sql += " AND action=?"
        args.append(action)
    if proxy:
        sql += " AND proxy_name=?"
        args.append(proxy)
    return _query(sql, args)[0]["n"]


def log_proxy_names():
    """连接日志中出现过的代理名（用于筛选下拉框）。"""
    return [r["proxy_name"] for r in _query(
        "SELECT DISTINCT proxy_name FROM conn_log WHERE proxy_name<>'' ORDER BY proxy_name")]


def summary_by_proxy(window_sec, limit=50):
    """按代理聚合最近 window_sec 的连接日志（面板「聚合」视图数据源）。

    两阶段查询（走 idx_conn_log_proxy_ts 索引，读连接不占全局写锁）：
      1. 按 proxy_name 分组取窗口内连接数 Top-N（SQL 层 LIMIT，聚合下推到
         数据库，避免把窗口内全部 (proxy, ip) 行取回 Python）；
      2. 仅对 Top-N 代理做 GROUP BY proxy_name, ip 聚合（Python 计算
         「仅 1 次 IP 数」与占比），并用 IN 限定代理名。
    输出每代理：conns / uniq_ips / single_ips / single_pct / rejected /
    last_ts / proxy_type；按 conns 降序取前 limit 个（上限 200）。
    返回 {"rows": [...], "total_proxies": N, "limit": lim}：total_proxies 为
    窗口内代理总数（SQL COUNT(DISTINCT)，与截断无关），供面板文案展示。
    """
    since = int(time.time()) - max(1, int(window_sec))
    lim = max(1, min(200, int(limit)))
    top = _query_ro(
        "SELECT proxy_name, COUNT(*) AS n, MAX(ts) AS last_ts"
        " FROM conn_log WHERE ts>=? AND proxy_name<>''"
        " GROUP BY proxy_name ORDER BY n DESC LIMIT ?",
        (since, lim),
    )
    total_proxies = 0
    for r in _query_ro(
            "SELECT COUNT(DISTINCT proxy_name) AS n FROM conn_log"
            " WHERE ts>=? AND proxy_name<>''", (since,)):
        total_proxies = r["n"] or 0
    if not top:
        return {"rows": [], "total_proxies": total_proxies, "limit": lim}
    names = [r["proxy_name"] for r in top]
    agg = {}
    for r in top:
        agg[r["proxy_name"]] = {"proxy_name": r["proxy_name"], "proxy_type": "",
                                "conns": 0, "uniq_ips": 0, "single_ips": 0,
                                "rejected": 0, "last_ts": r["last_ts"] or 0}
    ph = ",".join("?" * len(names))
    rows = _query_ro(
        "SELECT proxy_name, ip, COUNT(*) AS n,"
        " SUM(CASE WHEN action<>'allow' THEN 1 ELSE 0 END) AS rejected"
        " FROM conn_log WHERE ts>=? AND proxy_name IN (%s)"
        " GROUP BY proxy_name, ip" % ph,
        (since,) + tuple(names),
    )
    for r in rows:
        d = agg.get(r["proxy_name"])
        if d is None:
            continue
        d["conns"] += r["n"]
        d["uniq_ips"] += 1
        if r["n"] == 1:
            d["single_ips"] += 1
        d["rejected"] += r["rejected"] or 0
    out = sorted(agg.values(), key=lambda x: x["conns"], reverse=True)[:lim]
    for d in out:
        d["single_pct"] = (round(d["single_ips"] * 100.0 / d["uniq_ips"], 1)
                           if d["uniq_ips"] else 0.0)
    if out:
        # 代理类型：proxy_stat 主键查询（比在主查询里带出更直观）
        names = [d["proxy_name"] for d in out]
        ph = ",".join("?" * len(names))
        for r in _query_ro(
                "SELECT proxy_name, proxy_type FROM proxy_stat"
                " WHERE proxy_name IN (%s)" % ph, tuple(names)):
            for d in out:
                if d["proxy_name"] == r["proxy_name"]:
                    d["proxy_type"] = r["proxy_type"] or ""
                    break
    for d in out:
        d["total_proxies"] = total_proxies
    return {"rows": out, "total_proxies": total_proxies, "limit": lim}


def recent_count_by_ip(ip, window_sec):
    since = int(time.time()) - int(window_sec)
    rows = _query(
        "SELECT COUNT(*) AS n FROM conn_log WHERE ip=? AND ts>=?", (ip, since)
    )
    return rows[0]["n"]


def trim_logs(max_rows):
    n = _query("SELECT COUNT(*) AS n FROM conn_log")[0]["n"]
    if n > max_rows:
        _exec(
            "DELETE FROM conn_log WHERE id IN "
            "(SELECT id FROM conn_log ORDER BY id ASC LIMIT ?)",
            (n - max_rows,),
        )


def purge_logs():
    _exec("DELETE FROM conn_log")
    return True


# ---------------- ban_log ----------------
def invalidate_bans():
    """使生效封禁缓存立即失效（增删封禁后调用）。"""
    with _bans_lock:
        _bans["at"] = 0.0


def banned_ips():
    """生效中的封禁集合（带短 TTL 缓存，供连接决策快速判断）。

    返回 ip_network 列表：单 IP 视作 /32、/128，也支持临时封禁整段 CIDR。
    缓存重建与失效共用一把锁：解封/新增封禁返回后，不会再发布旧快照。
    """
    now = time.time()
    with _bans_lock:
        if now - _bans["at"] < BANS_TTL:
            return _bans["ips"]
        nets = []
        for b in active_bans():
            try:
                nets.append(ipaddress.ip_network((b["ip"] or "").strip(), strict=False))
            except ValueError:
                continue
        _bans["ips"] = tuple(nets)
        _bans["at"] = time.time()
        return _bans["ips"]


def is_banned(ip):
    """判断某 IP 当前是否已被封禁（含落在已封 CIDR 段内的情况）。"""
    try:
        obj = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    for net in banned_ips():
        try:
            if obj in net:
                return True
        except TypeError:
            continue
    return False


def add_ban(ip, reason, seconds):
    ip = (ip or "").strip()
    try:
        net = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        raise ValueError("无效的 IP 或 CIDR: %s" % ip)
    ip = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    now = int(time.time())
    _exec(
        "INSERT INTO ban_log(ip,reason,banned_at,expire_at,released) VALUES(?,?,?,?,0)",
        (ip, reason or "", now, now + int(seconds)),
    )
    invalidate_bans()


def active_bans():
    now = int(time.time())
    return _query(
        "SELECT * FROM ban_log WHERE released=0 AND expire_at>? ORDER BY id DESC",
        (now,),
    )


def active_bans_count():
    """生效封禁数量（概览统计用，避免拉全量行）。"""
    now = int(time.time())
    return _query(
        "SELECT COUNT(*) AS n FROM ban_log WHERE released=0 AND expire_at>?",
        (now,),
    )[0]["n"]


def expired_bans():
    now = int(time.time())
    return _query(
        "SELECT * FROM ban_log WHERE released=0 AND expire_at<=?", (now,)
    )


def release_ban(ban_id):
    _exec("UPDATE ban_log SET released=1 WHERE id=?", (ban_id,))
    invalidate_bans()


def unban_ip(ip):
    _exec("UPDATE ban_log SET released=1 WHERE ip=? AND released=0", (ip,))
    invalidate_bans()


def ban_history(limit=200):
    return _query("SELECT * FROM ban_log ORDER BY id DESC LIMIT ?", (int(limit),))


def trim_bans(max_rows=20000):
    """裁剪已结束的封禁历史，绝不删除仍生效的封禁。

    ban_log 原先无任何裁剪：永久封禁只写 ip_list 不写 ban_log，但自动/手动/AI
    的临时封禁长期累积会导致表与索引持续膨胀。
    生效记录超过上限时允许总行数暂时超过上限。
    """
    n = _query("SELECT COUNT(*) AS n FROM ban_log")[0]["n"]
    if n > max_rows:
        _exec(
            "DELETE FROM ban_log WHERE id IN "
            "(SELECT id FROM ban_log WHERE released=1 OR expire_at<=? "
            "ORDER BY id ASC LIMIT ?)",
            (int(time.time()), n - max_rows),
        )


# ---------------- proxy_stat ----------------
def bump_proxy(proxy_name, proxy_type, rejected=False):
    if not proxy_name:
        return
    _exec(
        "INSERT INTO proxy_stat(proxy_name,proxy_type,total,rejected,last_ts)"
        " VALUES(?,?,1,?,?)"
        " ON CONFLICT(proxy_name) DO UPDATE SET"
        "   total=total+1,"
        "   rejected=rejected+excluded.rejected,"
        "   proxy_type=excluded.proxy_type,"
        "   last_ts=excluded.last_ts",
        (proxy_name, proxy_type or "", 1 if rejected else 0, int(time.time())),
    )


def list_proxy_stat():
    return _query("SELECT * FROM proxy_stat ORDER BY total DESC")


# ---------------- ai_review ----------------
def add_ai_review(batch_id, ip, verdict, reason, action, model):
    _exec(
        "INSERT INTO ai_review(ts,batch_id,ip,verdict,reason,action,model)"
        " VALUES(?,?,?,?,?,?,?)",
        (int(time.time()), int(batch_id or 0), ip or "", verdict or "", reason or "",
         action or "", model or ""),
    )


def list_ai_review(limit=200):
    return _query("SELECT * FROM ai_review ORDER BY id DESC LIMIT ?", (int(limit),))


def trim_ai_review(max_rows=5000):
    n = _query("SELECT COUNT(*) AS n FROM ai_review")[0]["n"]
    if n > max_rows:
        _exec(
            "DELETE FROM ai_review WHERE id IN "
            "(SELECT id FROM ai_review ORDER BY id ASC LIMIT ?)",
            (n - max_rows,),
        )


# ---------------- 汇总 ----------------
def stats():
    total = _query("SELECT COUNT(*) AS n FROM conn_log")[0]["n"]
    # 「今日」按服务器本地时区零点计算（面板展示的是本地时间）。
    # 注意：不可用 (ts // 86400 * 86400)，那是 UTC 零点，在东八区 00:00-08:00
    # 会把昨天的数据算进「今日」，导致统计口径与显示不一致。
    _lt = time.localtime()
    today0 = int(time.mktime((_lt.tm_year, _lt.tm_mon, _lt.tm_mday,
                              0, 0, 0, 0, 0, -1)))
    today = _query("SELECT COUNT(*) AS n FROM conn_log WHERE ts>=?", (today0,))[0]["n"]
    rejected = _query(
        "SELECT COUNT(*) AS n FROM conn_log WHERE ts>=? AND action!='allow'", (today0,)
    )[0]["n"]
    black = _query("SELECT COUNT(*) AS n FROM ip_list WHERE list_type='black'")[0]["n"]
    white = _query("SELECT COUNT(*) AS n FROM ip_list WHERE list_type='white'")[0]["n"]
    bans = active_bans_count()
    uniq = _query(
        "SELECT COUNT(DISTINCT ip) AS n FROM conn_log WHERE ts>=?", (today0,)
    )[0]["n"]
    return {
        "total_conns": total,
        "today_conns": today,
        "today_rejected": rejected,
        "today_uniq_ip": uniq,
        "black_count": black,
        "white_count": white,
        "active_bans": bans,
    }
