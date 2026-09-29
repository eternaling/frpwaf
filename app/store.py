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
    cidr TEXT NOT NULL UNIQUE,
    list_type TEXT NOT NULL DEFAULT 'black',   -- black / white
    remark TEXT DEFAULT '',
    created_at INTEGER NOT NULL
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

CREATE TABLE IF NOT EXISTS ban_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    reason TEXT DEFAULT '',
    banned_at INTEGER NOT NULL,
    expire_at INTEGER NOT NULL,
    released INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ban_log_ip ON ban_log(ip);

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


def checkpoint(truncate=False):
    """执行 WAL checkpoint。truncate=True 时回收 -wal 文件大小（有界）。"""
    try:
        with _lock:
            c = _connect()
            c.execute("PRAGMA wal_checkpoint(%s)" % ("TRUNCATE" if truncate else "PASSIVE"))
    except sqlite3.Error:
        pass


# ---------------- ip_list ----------------
def list_ips(list_type=None):
    if list_type:
        return _query("SELECT * FROM ip_list WHERE list_type=? ORDER BY id DESC", (list_type,))
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
    nets = tuple(nets)
    with _bans_lock:
        _bans["ips"] = nets
        _bans["at"] = time.time()
    return nets


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
    today0 = int(time.time()) // 86400 * 86400
    today = _query("SELECT COUNT(*) AS n FROM conn_log WHERE ts>=?", (today0,))[0]["n"]
    rejected = _query(
        "SELECT COUNT(*) AS n FROM conn_log WHERE ts>=? AND action!='allow'", (today0,)
    )[0]["n"]
    black = _query("SELECT COUNT(*) AS n FROM ip_list WHERE list_type='black'")[0]["n"]
    white = _query("SELECT COUNT(*) AS n FROM ip_list WHERE list_type='white'")[0]["n"]
    bans = len(active_bans())
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
