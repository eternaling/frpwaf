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
import contextlib
import ipaddress
import os
import re
import shutil
import sqlite3
import threading
import time

from . import config

_lock = threading.Lock()
_conn = None

# 生效封禁 IP 的内存缓存：连接决策路径每次都查会全表扫描，故做短 TTL 缓存。
# gen 为失效版本号：重建期间发生过 invalidate 时用来自查，避免把失效前的旧
# 数据重新发布成新快照（解封接口返回后不能再被旧快照覆盖）。
_bans = {"ips": (), "at": 0.0, "gen": 0}
_bans_lock = threading.Lock()        # 只保护快照本身（纯内存，微秒级）
_bans_build_lock = threading.Lock()  # 保证同一时刻只有一个线程重建缓存
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
-- 复合索引：日志面板按 action 过滤（"只看拦截"）与 count_logs(action=) 走该索引。
-- 取 (action, id) 而非 (action, ts)：store 里没有任何「action + ts 区间」的组合
-- 条件，而 list_logs 是 `WHERE action=? ORDER BY id DESC LIMIT ?`，按 (action, id)
-- 可直接有序扫描，省掉过滤后的排序。已有库在 _connect() 里由 IF NOT EXISTS 补齐。
CREATE INDEX IF NOT EXISTS idx_conn_log_action_id ON conn_log(action, id);

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
-- 自动学习到的「可信回源网段」：AI 判定某 IP 为 CDN 回源（或同段熔断触发）时
-- 记下它，以后同类 IP 直接跳过自动封禁。
-- 为什么需要：站点前置 CDN/WAF 时，回源 IP 属于共享边缘节点，封一个等于封
-- 一片真实用户（2026-11 封掉阿里云 ESA 回源段 → 整站 522）。回源 IP 段不是
-- 固定公开列表，无法预先写死，只能“遇到过就记住”。
CREATE TABLE IF NOT EXISTS trusted_cidr (
    cidr TEXT PRIMARY KEY,          -- 单 IP 存 /32，段存 /24 等
    reason TEXT DEFAULT '',
    hits INTEGER NOT NULL DEFAULT 1, -- 命中次数（重复学到同一段时累加）
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trusted_cidr_seen ON trusted_cidr(last_seen);
-- source / expires_at / first_reason / ai_review_id 四列由 _migrate_trusted_cidr 幂等补齐
-- （新库旧库同一路径），expires_at 索引也在迁移里建：旧库执行本脚本时该列尚不存在。
-- 登录即信任：面板登录成功后把来源 IP 记进来（带过期时间）。
-- 解决「在外面开发、IP 不固定、连数据库被自己的自动封禁误封」：
-- 换网络后只要登录一次面板，当前 IP 就自动获得豁免，不用手加白名单。
CREATE TABLE IF NOT EXISTS trust_login_ip (
    ip TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
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


# trusted_cidr 后补的列：列名 -> 完整 ALTER 语句（白名单字面量，不做任何字符串拼接）。
_TRUSTED_CIDR_NEW_COLS = (
    # model/keyword/behavior/subnet/manual/legacy
    ("source", "ALTER TABLE trusted_cidr ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy'"),
    # 0 = 永不过期
    ("expires_at", "ALTER TABLE trusted_cidr ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0"),
    # 首次学习理由，冲突更新不覆盖
    ("first_reason", "ALTER TABLE trusted_cidr ADD COLUMN first_reason TEXT DEFAULT ''"),
    # 首次学到该段的 ai_review.id（0 = 无关联：老库存量、人工配置、升级产生的整段行）。
    # 只存首次来源，命中续期与冲突更新都不改写，排障时据此回查当时那次审查。
    # 不加外键约束：ai_review 由 trim_ai_review 定期裁剪，硬约束会让删除失败或级联丢学习条目；
    # 记录被裁掉后本列留下悬空 id，面板按 0/空 处理即可。
    ("ai_review_id", "ALTER TABLE trusted_cidr ADD COLUMN ai_review_id INTEGER NOT NULL DEFAULT 0"),
)


def _migrate_trusted_cidr(c):
    """给 trusted_cidr 补 source / expires_at / first_reason / ai_review_id 四列（幂等，可重复执行）。

    先查 PRAGMA table_info，缺列才 ALTER（裸 ALTER 重复执行会报 duplicate column）。
    本次补上 expires_at 时，存量行统一标 legacy；而 legacy 条目在结束时**直接清掉**，
    原因见 purge_legacy_trusted_cidrs()。
    expires_at 索引放在这里而不是 SCHEMA：旧库执行 SCHEMA 时该列还不存在，会中断建表脚本。
    后补的 ai_review_id 对存量行一律取默认 0（无关联），不改写、不删除任何存量条目。
    """
    try:
        cols = {r[1] for r in c.execute("PRAGMA table_info(trusted_cidr)").fetchall()}
    except sqlite3.Error:
        return
    if not cols:
        return  # 表不存在（SCHEMA 执行失败），保守跳过
    try:
        added = set()
        for name, alter_sql in _TRUSTED_CIDR_NEW_COLS:
            if name not in cols:
                # pi-lens-ignore: python-sql-injection -- alter_sql 只取自 _TRUSTED_CIDR_NEW_COLS 白名单字面量，无外部输入
                c.execute(alter_sql)
                added.add(name)
        if "expires_at" in added:
            c.execute(
                "UPDATE trusted_cidr SET expires_at=? WHERE source='legacy' AND expires_at=0",
                (int(time.time()) + TRUST_TTL["legacy"],))
        if "first_reason" in added:
            c.execute("UPDATE trusted_cidr SET first_reason=COALESCE(reason,'') "
                      "WHERE COALESCE(first_reason,'')=''")
        c.execute("CREATE INDEX IF NOT EXISTS idx_trusted_cidr_exp ON trusted_cidr(expires_at)")
        # 旧版本误学的 legacy 条目在启动时直接清掉（幂等，老的已迁移库也会被清）
        c.execute("DELETE FROM trusted_cidr WHERE source='legacy'")
        c.commit()
    except sqlite3.Error:
        try:
            c.rollback()
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
        _migrate_trusted_cidr(_conn)   # trusted_cidr 补 source / expires_at / first_reason / ai_review_id
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
        # pi-lens-ignore: python-sql-injection -- SQL 只由本模块的字面量传入，参数全部走占位符绑定
        cur = c.execute(sql, args)
        return [dict(r) for r in cur.fetchall()]


# 只读连接的 PRAGMA：该连接不受 _lock 保护，与写事务/checkpoint 竞争时靠
# busy_timeout 让 SQLite 退避重试，而不是立刻抛 database is locked；query_only
# 兜底：只读连接上永远不该发生写。PRAGMA 不支持占位符绑定，只能写字面量。
@contextlib.contextmanager
def _ro_conn():
    """打开一条独立的只读连接（**不占全局 _lock**），退出时关闭。

    WAL 模式下读与写互不阻塞：长查询不再持有全局 _lock，也就不会把每连接的
    决策写入（add_log_and_bump）和缓存重建（banned_ips / _rules）堵在后面。
    - 库文件不存在时先 init() 建库建表（首次安装 / 面板先于后台任务查询）；
    - busy_timeout 必设：本连接不在 _lock 保护下，只能靠 SQLite 退避重试；
    - query_only=1 兜底：只读连接上永远不该发生写。
    """
    if not os.path.exists(config.DB_PATH):
        init()
    c = sqlite3.connect(config.DB_PATH, timeout=5)
    try:
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=5000")
        c.execute("PRAGMA query_only=1")
        yield c
    finally:
        try:
            c.close()
        except Exception:
            pass


def _query_ro(sql, args=()):
    """只读查询（独立连接，**不占全局 _lock**）。

    除本模块的展示/聚合查询外，也必须供**决策路径的缓存重建**使用：读走只读
    连接后，一次慢查询既不会阻塞写入，也不会被写入阻塞。
    """
    with _ro_conn() as c:
        # pi-lens-ignore: python-sql-injection -- SQL 只由本模块的字面量传入，参数全部走占位符绑定
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


# ---------------- 数据快照备份 ----------------
# 在线升级刻意只备份程序本体、不碰 data/（见 app/upgrade.py），因此数据侧必须
# 有自己的快照机制：purge_logs / clear_blacklist / 卸载后手删目录都是不可逆
# 操作，没有快照就只能认栽。目录名、命名规则、保留份数与空间阈值集中在这里，
# daemon 只负责按周期触发。
BACKUP_DIRNAME = "backup"
BACKUP_KEEP = 7                              # 保留份数（每天一份 ≈ 一周）
BACKUP_MIN_FREE = 200 * 1024 * 1024          # 备份前要求的最小剩余空间（200MB）
# 备份文件名：frpwaf-YYYYMMDD-HHMMSS-ffffff.db。微秒段必须是名字的一部分，
# 否则同一秒内的多次备份会撞同一个文件名、互相 overwrite——保留策略就永远
# 攒不到 keep 份（这曾经是真的 bug：连做 10 次只剩 2 个文件）。
# 末尾的 -\d{6} 可选：兼容早期只有秒精度的备份文件（不能变成删不掉的垃圾）。
_BACKUP_NAME_RE = re.compile(r"^frpwaf-\d{8}-\d{6}(?:-\d{6})?\.db$")
# 临时文件同样按完整模式匹配：清理残留时绝不误删运维自己放的其它文件。
_BACKUP_TMP_RE = re.compile(r"^frpwaf-\d{8}-\d{6}(?:-\d{6})?\.db\.tmp$")
_BACKUP_TMP_SUFFIX = ".db.tmp"               # 不以 .db 结尾：不会被当成一份备份
_STALE_TMP_SEC = 3600                        # 中断残留的临时文件超过 1 小时即清理
_MAX_NAME_TRIES = 1000                       # 同一微秒内最多顺延多少个名字


def backup_dir():
    """备份目录（默认 data/backup/）。"""
    return os.path.join(config.DATA_DIR, BACKUP_DIRNAME)


def _backup_name(us=None):
    """备份文件名 frpwaf-YYYYMMDD-HHMMSS-ffffff.db（本地时区，微秒定宽）。

    取整数微秒而不是「秒 + 浮点小数」：epoch 秒已经是 1.7e9，float64 在这个
    量级上的最小增量约 0.24µs，用浮点算亚秒段会抖。所有字段定宽且分隔符
    一致，所以**字典序 = 时间序**（保留策略靠排序挑最旧的删）。
    """
    if us is None:
        us = int(time.time() * 1000000)
    return "frpwaf-%s-%06d.db" % (
        time.strftime("%Y%m%d-%H%M%S", time.localtime(us // 1000000)),
        us % 1000000)


def _free_bytes(path):
    """path 所在分区的剩余字节数；目录尚不存在时上溯到存在的祖先。

    取不到（权限/异常/盘符异常）返回 -1：宁可放弃空间判断，也不要因为拿不到
    数字就永久不备份——备份缺失的代价远大于一次可能失败的写入。
    """
    p = os.path.abspath(path)
    while True:
        try:
            return shutil.disk_usage(p).free
        except OSError:
            parent = os.path.dirname(p)
            if parent == p:
                return -1
            p = parent


def list_backups(dest_dir=None):
    """已有备份的文件名（按名字升序 = 时间升序）。

    只认本程序生成的命名（frpwaf-<时间戳>.db）：运维自己放进备份目录的其它
    .db（手拷、别的工具产出）不会被当成一份备份，也就永远不会被裁剪删掉。
    """
    d = dest_dir or backup_dir()
    try:
        names = os.listdir(d)
    except OSError:
        return []
    return sorted(n for n in names if _BACKUP_NAME_RE.match(n))


def last_backup_time(dest_dir=None):
    """最新一份备份的产生时刻（epoch 秒）；一份都没有时返回 0。

    取文件 mtime 而非文件名解析：用户手工拷贝备份文件时名字可能被改，
    mtime 始终反映「这份快照是什么时候写出来的」。
    """
    d = dest_dir or backup_dir()
    names = list_backups(d)
    if not names:
        return 0
    try:
        return int(os.path.getmtime(os.path.join(d, names[-1])))
    except OSError:
        return 0


def _clean_stale_tmp(dest):
    """清理被中断的备份残留（*.db.tmp），只删 1 小时以前的。

    正常备份写完就 os.replace 掉了；长时间残留说明进程在写入过程中被杀
    （磁盘满 / OOM / 重启），留着只会白占空间。两个边界：
      - 只删符合 frpwaf-<时间戳>.db.tmp 完整模式的文件，备份目录里运维自己
        放的任何其它文件（包括自己命名的 .db）一律不碰；
      - 加时间窗是为了不误删另一个进程正在写的临时文件。
    """
    now = time.time()
    try:
        names = os.listdir(dest)
    except OSError:
        return 0
    n = 0
    for name in names:
        if not _BACKUP_TMP_RE.match(name):
            continue
        p = os.path.join(dest, name)
        try:
            if now - os.path.getmtime(p) >= _STALE_TMP_SEC:
                os.remove(p)
                n += 1
        except OSError:
            pass
    return n


def _prune_backups(dest, keep):
    """只保留最近 keep 份（文件名排序即时间序），返回删除份数。

    keep <= 0 视为「不裁剪」：宁可多占磁盘，也不因为传入 0 就把全部备份删光。
    """
    if keep <= 0:
        return 0
    names = list_backups(dest)
    stale = names[:-keep] if len(names) > keep else []
    n = 0
    for name in stale:
        try:
            os.remove(os.path.join(dest, name))
            n += 1
        except OSError:
            pass
    return n


def _claim_backup_path(dest):
    """为本轮备份原子地占一个不重名的 (final, tmp) 路径；占不到返回 None。

    先按当前微秒生成名字，再以 O_CREAT|O_EXCL 创建 `<name>.db.tmp`：OS 保证
    同一时刻只有一个进程能创建成功，因此并发（daemon 与插件端同时备份）也
    不会抢到同一个名字。名字已被占（同微秒已有备份，或另一个进程先到）就把
    时间戳顺延 1µs 重试：新名字仍比旧名字大，字典序 = 时间序不变。
    返回的 tmp 文件此时已存在（0 字节），SQLite 会把 0 字节文件当成空库打开。
    """
    base_us = int(time.time() * 1000000)
    for bump in range(_MAX_NAME_TRIES):
        name = _backup_name(base_us + bump)
        final = os.path.join(dest, name)
        if os.path.exists(final):       # 同微秒已有成品快照：不能用它（会覆盖旧快照）
            continue
        tmp = final + ".tmp"            # frpwaf-*.db.tmp：不以 .db 结尾，不会被当成备份
        try:
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue                    # 另一个进程正在用这个名字
        except OSError:
            return None
        os.close(fd)
        return final, tmp
    return None


def backup_db(keep=BACKUP_KEEP, dest_dir=None):
    """把当前库快照成一个独立文件，只保留最近 keep 份。

    返回 (ok, path_or_error)。

    为什么用 sqlite3.Connection.backup() 而不是 VACUUM INTO：
      - backup() 是官方给**热备份**用的 API，走 SQLite 自己的页级备份协议，
        WAL 模式下与并发写天然安全（源连接只开读事务，不需要独占锁），备份
        期间的写入继续落库，快照仍是一致的；
      - VACUUM INTO 要求 SQLite ≥ 3.27（多数发行版满足，但没必要赌），语义上
        它是一次「整理后导出」——重写整库、重建所有页，额外 CPU/IO 都落在
        生产机上，而不是单纯复制；
      - VACUUM INTO 还要求目标文件不存在、只能写在 SQL 字面量里，失败面更大。

    实现要点：
      - **不持全局 _lock**：决策路径（add_log_and_bump）靠它串行化写入，一次
        几十 MB 的备份持锁会直接把回调请求堵死。备份用独立连接，与全局 _conn
        不共享事务状态；
      - **先写临时文件再 os.replace 原子落地**：避免备份到一半被中断时留下半个
        .db 被当成一份可用备份（还原时才发现是废的，代价最大）；
      - **磁盘守卫**：这台机器曾被日志撑到 90%，把盘塞满会让服务直接失能
        （SQLite 写不进去 = 日志/封禁全丢），所以剩余空间低于 BACKUP_MIN_FREE
        干脆不做，并由调用方计数上报；
      - **文件名绝不撞名**：名字带微秒时间戳（frpwaf-YYYYMMDD-HHMMSS-ffffff.db），
        另在写入前用 O_CREAT|O_EXCL 原子地占位，撞名就把时间戳顺延 1µs 重试。
        这一步不能省：只靠「秒级时间戳 + 直接 overwrite」时，连续备份会互相
        覆盖，保留策略永远攒不到 keep 份（真实缺陷：连做 10 次只剩 2 个文件）；
      - 库文件不存在（未初始化 / 已被删）返回失败原因，不抛异常：备份由后台
        循环调用，抛异常只会变成一条没人看的 traceback。
    """
    dest = dest_dir or backup_dir()
    src_path = config.DB_PATH
    if not os.path.exists(src_path):
        return False, "数据库文件不存在：%s" % src_path
    try:
        os.makedirs(dest, exist_ok=True)
    except OSError as exc:
        return False, "无法创建备份目录 %s：%s" % (dest, exc)
    free = _free_bytes(dest)
    if 0 <= free < BACKUP_MIN_FREE:
        return False, ("磁盘剩余空间不足（剩余 %dMB，低于阈值 %dMB），已跳过备份"
                       % (free // (1024 * 1024), BACKUP_MIN_FREE // (1024 * 1024)))
    _clean_stale_tmp(dest)
    claimed = _claim_backup_path(dest)
    if claimed is None:
        return False, ("无法占用备份文件名（同名快照过多或临时文件创建失败），"
                       "已跳过本次不覆盖旧快照")
    final, tmp = claimed
    src = None
    dst = None
    try:
        src = sqlite3.connect(src_path, timeout=15)
        src.execute("PRAGMA busy_timeout=5000")
        dst = sqlite3.connect(tmp, timeout=15)
        # pages=-1 = 一次拷完；sleep 只在需要等锁时用得上，WAL 下基本不触发
        src.backup(dst)
        dst.close()
        dst = None
        src.close()
        src = None
        try:
            # 备份里是全量审计日志/名单/封禁，权限与 db 一致
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, final)
    except (sqlite3.Error, OSError) as exc:
        return False, "备份失败：%s" % exc
    except Exception as exc:            # 兜底：后台循环的调用方不能因此崩
        return False, "备份失败：%s" % exc
    finally:
        for c in (dst, src):
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass
        # 执行到这里 tmp 还在，说明 os.replace 没成功：必须清掉，否则半个 .db
        # 会被当成一份「可用」备份（成功时 tmp 已被 replace 掉，这里是空操作）
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    _prune_backups(dest, int(keep or 0))
    return True, final


def export_rows(ban_limit=20000):
    """导出口径的只读快照：全部名单 + 封禁历史（供 /api/export）。

    只读连接（_query_ro）：导出可能与连接回调并发，绝不能占全局 _lock，
    也不该把大结果集读进写连接的事务里。
    """
    return {
        "ip_list": _query_ro(
            "SELECT cidr,list_type,remark,created_at FROM ip_list ORDER BY id"),
        "bans": _query_ro(
            "SELECT ip,reason,banned_at,expire_at,released FROM ban_log"
            " ORDER BY id DESC LIMIT ?", (int(ban_limit),)),
    }


# ---------------- ip_list ----------------
# 面板名单接口的返回上限：防大名单场景全量返回 + 逐条归属地查询拖垮面板。
# 仅约束「展示接口」（daemon /api/iplist、插件端 list_ips/list_bans）；
# 内部逻辑（AI 白名单判断、内核同步）直接查库，不受此上限影响。
PANEL_LIST_CAP = 5000


def list_ips(list_type=None, limit=0):
    """名单列表。limit>0 时限制返回条数（面板大名单场景防全表拉取）。

    只读：面板展示 + AI 白名单判定（ai._is_whitelisted）使用，走只读连接。
    """
    lim = int(limit or 0)
    if list_type:
        if lim > 0:
            return _query_ro("SELECT * FROM ip_list WHERE list_type=? ORDER BY id DESC LIMIT ?",
                             (list_type, lim))
        return _query_ro("SELECT * FROM ip_list WHERE list_type=? ORDER BY id DESC", (list_type,))
    if lim > 0:
        return _query_ro("SELECT * FROM ip_list ORDER BY id DESC LIMIT ?", (lim,))
    return _query_ro("SELECT * FROM ip_list ORDER BY id DESC")


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


# ---------------- 自动学习的可信回源网段 ----------------

# 学习来源 -> 有效期（秒）；0 = 永不过期。
# 来源越弱有效期越短：误学的条目不再活跃就自然过期，不依赖人工清理。
TRUST_TTL = {
    "manual": 0,
    "keyword": 30 * 86400,
    "model": 14 * 86400,
    "behavior": 86400,
    "subnet": 86400,
    "legacy": 7 * 86400,
}
# 强证据来源：只有这些 /32 计入「同段升级为 /24」的计数
TRUST_STRONG_SOURCES = ("keyword", "model", "manual")
# 来源强弱：冲突更新时保留较强者
_TRUST_RANK = {"legacy": 0, "behavior": 1, "subnet": 1, "model": 2, "keyword": 3, "manual": 4}
TRUST_MAX_AGE = 90 * 86400     # 续期上限：expires_at 不超过 created_at + 90 天
TRUSTED_CIDR_CAP = 2000        # 条数上限，超出时淘汰 hits 最低且最久未见的非 manual 条目


def _trust_source(source):
    """规范化学习来源：未知值按最弱的 behavior 处理；legacy 只由迁移产生，不接受写入。"""
    src = (source or "").strip().lower()
    if src not in TRUST_TTL or src == "legacy":
        return "behavior"
    return src


def _trust_expiry(source, now):
    ttl = TRUST_TTL.get(source, TRUST_TTL["behavior"])
    return 0 if ttl == 0 else now + ttl


def add_trusted_cidr(cidr, reason="", hits=1, source="behavior", ai_review_id=0):
    """记下一条「可信回源网段」（已存在则累加命中次数）。

    cidr 会被规范化（单 IP 归一为 /32）。非法值抛 ValueError，由调用方决定怎么处理。
    source 决定有效期（见 TRUST_TTL）；未声明来源按最弱的 behavior（24 小时）处理，
    更强的来源必须由调用方显式声明。
    ai_review_id 是首次学到该段的审查记录 id（0 = 无关联），用于面板/排障回查来源。

    冲突更新规则：
      - first_reason 只在首次写入时填，之后不覆盖（审计需要保留最初的学习理由）；
      - ai_review_id 同理只在首次写入时填，已有值不改写（空值才补，避免后次学习顶替来源）；
      - 来源取新旧中较强者；manual 条目保持永久；
      - 未过期：expires_at 只延长不缩短，且不超过 created_at + 90 天；
      - 已过期（尚未被清理）或已超出 90 天窗口：按重新学习处理，重置 created_at 与 expires_at。
    """
    net = ipaddress.ip_network((cidr or "").strip(), strict=False)
    cidr = str(net)
    src = _trust_source(source)
    reason = (reason or "")[:200]
    now = int(time.time())
    exp = _trust_expiry(src, now)
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT source, expires_at, created_at FROM trusted_cidr WHERE cidr=?",
            (cidr,)).fetchone()
        rev_id = int(ai_review_id or 0)
        if row is None:
            c.execute(
                "INSERT INTO trusted_cidr(cidr, reason, hits, created_at, last_seen, "
                "source, expires_at, first_reason, ai_review_id) VALUES(?,?,?,?,?,?,?,?,?)",
                (cidr, reason, int(hits), now, now, src, exp, reason, rev_id))
        else:
            old_src = row[0] or "legacy"
            old_exp = int(row[1] or 0)
            created = int(row[2] or now)
            if old_src == "manual" or src == "manual":
                new_src, new_exp = "manual", 0
            elif (old_exp and old_exp <= now) or now - created >= TRUST_MAX_AGE:
                new_src, new_exp, created = src, exp, now
            else:
                new_src = src if _TRUST_RANK.get(src, 1) >= _TRUST_RANK.get(old_src, 0) else old_src
                new_exp = max(old_exp, min(exp, created + TRUST_MAX_AGE))
            c.execute(
                "UPDATE trusted_cidr SET hits=hits+?, reason=?, last_seen=?, source=?, "
                "expires_at=?, created_at=?, "
                "first_reason=CASE WHEN COALESCE(first_reason,'')='' THEN ? ELSE first_reason END, "
                "ai_review_id=CASE WHEN COALESCE(ai_review_id,0)=0 THEN ? ELSE ai_review_id END "
                "WHERE cidr=?",
                (int(hits), reason, now, new_src, new_exp, created, reason, rev_id, cidr))
        c.commit()
    return cidr


def list_trusted_cidrs(limit=0):
    """已学习的可信网段列表（仅未过期，按命中次数降序）。只读。"""
    lim = int(limit or 0)
    sql = ("SELECT * FROM trusted_cidr WHERE expires_at = 0 OR expires_at > ? "
           "ORDER BY hits DESC, last_seen DESC")
    now = int(time.time())
    if lim > 0:
        return _query_ro(sql + " LIMIT ?", (now, lim))
    return _query_ro(sql, (now,))


def list_trusted_cidr_strings():
    """只取未过期条目的 cidr 字段（匹配用）。只读。

    过期条目不再参与匹配：误学的段不活跃即自动失效，由周期清理物理删除。
    """
    return [r["cidr"] for r in _query_ro(
        "SELECT cidr FROM trusted_cidr WHERE expires_at = 0 OR expires_at > ?",
        (int(time.time()),))]


def count_trusted_cidrs():
    """未过期学习条目数（面板计数用）。只读。

    用 SELECT COUNT(*) 而不是 len(list_trusted_cidr_strings())：后者为了一个数字
    把整表拉进内存，学习表接近上限时面板每次刷新都白白多搬一遍数据。
    过期口径与 list_trusted_cidrs / list_trusted_cidr_strings 一致。
    """
    rows = _query_ro(
        "SELECT COUNT(*) AS n FROM trusted_cidr WHERE expires_at = 0 OR expires_at > ?",
        (int(time.time()),))
    try:
        return int((rows[0] or {}).get("n") or 0)
    except (IndexError, TypeError, ValueError):
        return 0


def touch_trusted_cidr(cidr):
    """学习表命中：hits+1、刷新 last_seen，并按来源 TTL 续期。

    续期只延长不缩短，且不超过 created_at + 90 天；manual（永久）不变；
    legacy 不续期——旧逻辑学到的条目必须由强证据重新学到才能留下。
    只动 hits / last_seen / expires_at：ai_review_id 记的是**首次**来源，命中续期不得改写它，
    否则一条被反复命中的老条目会被最近一次无关审查顶掉来源。
    返回是否找到该条目。
    """
    try:
        cidr = str(ipaddress.ip_network((cidr or "").strip(), strict=False))
    except ValueError:
        return False
    now = int(time.time())
    with _lock:
        c = _connect()
        row = c.execute(
            "SELECT source, expires_at, created_at FROM trusted_cidr WHERE cidr=?",
            (cidr,)).fetchone()
        if row is None:
            return False
        src = row[0] or "legacy"
        old_exp = int(row[1] or 0)
        created = int(row[2] or now)
        if old_exp == 0 or src == "legacy":
            new_exp = old_exp
        else:
            ttl = TRUST_TTL.get(src) or TRUST_TTL["behavior"]
            new_exp = max(old_exp, min(now + ttl, created + TRUST_MAX_AGE))
        c.execute("UPDATE trusted_cidr SET hits=hits+1, last_seen=?, expires_at=? WHERE cidr=?",
                  (now, new_exp, cidr))
        c.commit()
    return True


def purge_expired_trusted_cidrs(cap=TRUSTED_CIDR_CAP):
    """删除已过期条目；条数超过 cap 时淘汰 hits 最低且最久未见的非 manual 条目。

    返回 (过期删除数, 超限淘汰数)。由守护进程后台循环周期调用。
    """
    now = int(time.time())
    try:
        cap = int(cap or 0)
    except (TypeError, ValueError):
        cap = 0
    with _lock:
        c = _connect()
        expired = c.execute(
            "DELETE FROM trusted_cidr WHERE expires_at > 0 AND expires_at <= ?", (now,)).rowcount
        evicted = 0
        if cap > 0:
            total = int(c.execute("SELECT COUNT(*) FROM trusted_cidr").fetchone()[0] or 0)
            if total > cap:
                evicted = c.execute(
                    "DELETE FROM trusted_cidr WHERE cidr IN (SELECT cidr FROM trusted_cidr "
                    "WHERE source != 'manual' ORDER BY hits ASC, last_seen ASC, created_at ASC "
                    "LIMIT ?)", (total - cap,)).rowcount
        c.commit()
    return max(expired or 0, 0), max(evicted or 0, 0)


def count_trusted_in_subnet(prefix):
    """已学习表里落在给定 /24 内的强证据 /32 个数（供调用方判定是否升级）。只读。

    本函数只负责「数」，不含门槛：升级阈值由调用方（ai._learn_trusted 的
    `_TRUST_SUBNET_MIN_IPS`）决定，放这里会变成第二处硬编码。

    只计未过期的强证据 /32（`TRUST_STRONG_SOURCES`：keyword / model / manual），
    弱证据（behavior）与已学到的 /24 行本身都不计入，所以重复数不会因为已经升级过而膨胀。
    prefix 传 `a.b.c.0/24`；用 LIKE 前缀近似（trusted_cidr 里存的是单 IP 或少数 CIDR），
    不会把 /16 之类的宽条目算进来 —— 这里只想知道「同段有几个具体回源 IP 被学到」。
    """
    try:
        base = str(prefix).split("/")[0].rsplit(".", 1)[0] + "."
    except (AttributeError, IndexError):
        return 0
    ph = ",".join("?" * len(TRUST_STRONG_SOURCES))
    # 拼接的只有 ? 占位符（由 TRUST_STRONG_SOURCES 长度生成），值全部走参数绑定；
    # 不用 % 格式化是为了避开 SQL 里的 `%/32` 字面量。S608 对这种占位符拼接是误报。
    sql = ("SELECT COUNT(*) AS n FROM trusted_cidr"  # noqa: S608
           " WHERE cidr LIKE ? AND cidr LIKE '%/32'"
           " AND source IN (" + ph + ")"
           " AND (expires_at = 0 OR expires_at > ?)")
    rows = _query_ro(sql, (base + "%",) + tuple(TRUST_STRONG_SOURCES) + (int(time.time()),))
    try:
        return int((rows[0] or {}).get("n") or 0)
    except (IndexError, TypeError, ValueError):
        return 0


def del_trusted_cidr(cidr):
    """移除一条学习的可信网段（运维误学时用）。"""
    try:
        cidr = str(ipaddress.ip_network((cidr or "").strip(), strict=False))
    except ValueError:
        return 0
    cur = _exec("DELETE FROM trusted_cidr WHERE cidr=?", (cidr,))
    return cur.rowcount


def clear_trusted_cidrs():
    """清空所有学习的可信网段，返回删除条数。"""
    cur = _exec("DELETE FROM trusted_cidr")
    return cur.rowcount


def purge_legacy_trusted_cidrs():
    """删除 `source='legacy'` 的学习条目，返回删除条数。幂等，可重复调用。

    legacy 是 2026-11 P0 修复**之前**的产物：那时 `_is_cdn_origin()` 第 3 层只要
    「碰过 ≥2 个代理」就判回源，没有 `proxy_type` 类型检查，于是纯 tcp 来源也会被
    写成可信回源段（生产实证：177 次全 tcp、零拒绝的 IP 被记为 /32）。

    为什么要清掉而不是留着等过期：这类条目会被**两处**豁免同时认账——AI 处置
    （`ai._in_learned_cidrs`）与引擎的自动封禁（`engine._in_trusted_cidr`），留着
    等于给一个按现行口径根本不算回源的 IP 长期免封。而 `touch_trusted_cidr` 按设计
    不给 legacy 续期，说明它本身就在等被清掉。

    类型硬否决上线后不可能再产生 legacy（`_trust_source` 也拒绝写入 legacy），
    所以这里全量删除是安全的。由启动迁移 `_migrate_trusted_cidr` 调用一次。
    """
    cur = _exec("DELETE FROM trusted_cidr WHERE source='legacy'")
    n = cur.rowcount
    return n if isinstance(n, int) and n > 0 else 0


# ---------------- 登录即信任（豁免自动封禁） ----------------

def trust_login_ip(ip, ttl):
    """把面板登录成功的来源 IP 记为「可信」（带过期时间，续期覆盖）。

    用途：在外面开发时 IP 经常变，连数据库/SSH 代理容易触发自动封禁把自己封了。
    换网络后只要登录一次面板，当前 IP 就自动豁免自动封禁（不需要手加白名单）。

    ttl <= 0 时视为不启用（不写）。非法 IP 不写（防脏数据）。
    """
    try:
        obj = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return None
    ttl = int(ttl or 0)
    if ttl <= 0:
        return None
    now = int(time.time())
    _exec(
        "INSERT INTO trust_login_ip(ip, expires_at, created_at) VALUES(?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET expires_at=excluded.expires_at",
        (str(obj), now + ttl, now))
    return str(obj)


def list_trusted_login_ips():
    """当前仍有效的登录信任 IP（已过期的自动忽略，不依赖定时清理）。只读。"""
    return [r["ip"] for r in _query_ro(
        "SELECT ip FROM trust_login_ip WHERE expires_at>?", (int(time.time()),))]


def trusted_login_ips_with_expiry():
    """带过期时间的登录信任列表（面板展示用）。只读。"""
    return _query_ro(
        "SELECT ip, expires_at, created_at FROM trust_login_ip WHERE expires_at>? "
        "ORDER BY expires_at DESC", (int(time.time()),))


def trusted_login_expiry(ip):
    """某 IP 登录信任的到期时间戳；不存在、已过期或 IP 非法时返回 0。只读。

    供面板「访问即信任」做按 IP 去重：剩余有效期还长就不重写、不记审计。
    """
    try:
        obj = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return 0
    rows = _query_ro(
        "SELECT expires_at FROM trust_login_ip WHERE ip=? AND expires_at>?",
        (obj, int(time.time())))
    try:
        return int((rows[0] or {}).get("expires_at") or 0)
    except (IndexError, TypeError, ValueError):
        return 0


def untrust_login_ip(ip):
    """取消某 IP 的登录信任，返回删除条数。"""
    try:
        obj = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return 0
    cur = _exec("DELETE FROM trust_login_ip WHERE ip=?", (obj,))
    return cur.rowcount


def clear_trusted_login_ips():
    """清空登录信任，返回删除条数。"""
    cur = _exec("DELETE FROM trust_login_ip")
    return cur.rowcount


def clear_blacklist():
    """清空黑名单全部条目（一键解封永久封禁），返回删除条数。

    供面板「解封全部黑名单」按钮使用；调用方负责刷新规则缓存
    （engine.invalidate_cache）并触发内核同步（firewall.sync_from_store）。
    写前紧邻的计数刻意留在 _query（与写同一连接），避免并发插入让返回值走样。
    """
    n = _query("SELECT COUNT(*) AS n FROM ip_list WHERE list_type='black'")[0]["n"]
    _exec("DELETE FROM ip_list WHERE list_type='black'")
    return n


def load_rules():
    """加载为 (black_networks, white_networks) 两个列表。

    决策路径的规则缓存（engine._rules，TTL 3s）靠它重建：必须走只读连接，
    否则名单很大时重建会让每连接的写入排队。
    """
    blacks, whites = [], []
    for row in _query_ro("SELECT cidr,list_type FROM ip_list"):
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
    """日志列表（面板翻页，纯展示）。走只读连接：带 action 过滤 + 深页 OFFSET
    时可能是全表扫描，占着全局 _lock 会把每连接的决策写堵在后面。
    """
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
    return _query_ro(sql, args)


def count_logs(ip=None, action=None, proxy=None):
    """日志总数（面板分页文案 + /api/geo 展示），纯展示、走只读连接。"""
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
    return _query_ro(sql, args)[0]["n"]


def log_proxy_names():
    """连接日志中出现过的代理名（用于筛选下拉框，纯展示）。"""
    return [r["proxy_name"] for r in _query_ro(
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
        "SELECT proxy_name, ip, COUNT(*) AS n,"  # noqa: S608 - 只拼接 ? 占位符，值走参数绑定
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
                "SELECT proxy_name, proxy_type FROM proxy_stat"  # noqa: S608 - 同上，仅占位符
                " WHERE proxy_name IN (%s)" % ph, tuple(names)):
            for d in out:
                if d["proxy_name"] == r["proxy_name"]:
                    d["proxy_type"] = r["proxy_type"] or ""
                    break
    for d in out:
        d["total_proxies"] = total_proxies
    return {"rows": out, "total_proxies": total_proxies, "limit": lim}


def recent_count_by_ip(ip, window_sec):
    """某 IP 在窗口内的连接数（/api/geo 展示用，只读）。

    注意：连接决策路径的窗口计数用的是 engine 的内存滑窗，不走这里，
    所以可以安全地改成独立只读连接。
    """
    since = int(time.time()) - int(window_sec)
    rows = _query_ro(
        "SELECT COUNT(*) AS n FROM conn_log WHERE ip=? AND ts>=?", (ip, since)
    )
    return rows[0]["n"]


def trim_logs(max_rows):
    """裁剪最旧的连接日志，保留最近 max_rows 条（后台 tick 每 10s 一次）。

    不再每轮 `COUNT(*)` 全表计数（20 万行表上属稳态空转）：先用 MIN/MAX(id)
    预判，`INTEGER PRIMARY KEY` 上取端点只走 b-tree 两端、不扫表；
    `MAX-MIN+1` 是真实行数的**上界**，它不超上限时必然无需裁剪，直接返回。

    只有在确实超限时才发一条 DELETE。span 可以直接当行数用：本表唯一的删除
    路径就是这里，且每次删的都是「最旧的一段」，存活行始终是 id 的一个连续
    后缀，故 span == COUNT(*)。即使 id 出现空洞（人手改库导致），偏大的 span
    最多多删几条最旧的日志，绝不会留下超过上限的行、也不会抛异常。

    注意写法：必须用「两个标量子查询」而不是 `SELECT MIN(id), MAX(id) FROM t`——
    后者有 min 和 max 两个聚合，SQLite **用不上 rowid 端点优化**，会退化成全表
    索引扫描（实测 20 万行 26ms）；拆成两个标量子查询后两者都走 `SEARCH`
    （EXPLAIN QUERY PLAN 可见），合计约 0.01ms。改回去等于什么都没优化。
    """
    try:
        max_rows = int(max_rows)
    except (TypeError, ValueError):
        return
    if max_rows < 0:
        max_rows = 0
    rows = _query_ro(
        "SELECT (SELECT MIN(id) FROM conn_log) AS lo,"
        " (SELECT MAX(id) FROM conn_log) AS hi"
    )
    if not rows:
        return
    lo, hi = rows[0]["lo"], rows[0]["hi"]
    if lo is None or hi is None:      # 空表：无需裁剪
        return
    excess = hi - lo + 1 - max_rows
    if excess <= 0:
        return
    _exec(
        "DELETE FROM conn_log WHERE id IN "
        "(SELECT id FROM conn_log ORDER BY id ASC LIMIT ?)",
        (excess,),
    )


def purge_logs():
    _exec("DELETE FROM conn_log")
    return True


# ---------------- ban_log ----------------
def invalidate_bans():
    """使生效封禁缓存立即失效（增删封禁后调用）。"""
    with _bans_lock:
        _bans["at"] = 0.0
        _bans["gen"] += 1


def banned_ips():
    """生效中的封禁集合（带短 TTL 缓存，供连接决策快速判断）。

    返回 ip_network 列表：单 IP 视作 /32、/128，也支持临时封禁整段 CIDR。

    缓存重建与读路径分离，避免“一次慢查询卡住所有回调”：
      - 命中/未命中都只短暂持有 _bans_lock（纯内存），绝不持锁做 DB 查询；
      - 重建由 _bans_build_lock 保证单线程执行，抢不到锁的线程**直接返回旧
        快照**而不是排队等库（旧快照最多旧 BANS_TTL + 一次查询耗时，对封禁
        判定的影响是“晚几秒生效”，远优于把 frps 回调拖到 fail-closed）；
      - 重建期间的 invalidate_bans() 用 gen 版本号识别，失效前读到的旧数据
        不会被发布成新快照（解封接口返回后不会被旧快照覆盖）。
    """
    with _bans_lock:
        if time.time() - _bans["at"] < BANS_TTL:
            return _bans["ips"]
        snap = _bans["ips"]
    if not _bans_build_lock.acquire(False):
        return snap            # 已有线程在重建：先用旧快照，不阻塞决策路径
    try:
        at = time.time()
        with _bans_lock:
            if at - _bans["at"] < BANS_TTL:   # 等锁期间别人已重建完成
                return _bans["ips"]
            gen = _bans["gen"]
        nets = []
        try:
            for b in active_bans():
                try:
                    nets.append(ipaddress.ip_network((b["ip"] or "").strip(), strict=False))
                except ValueError:
                    continue
        except sqlite3.Error:
            # 库异常：沿用旧快照，并给一个 1s 的重试间隔（at 往后推），
            # 否则缓存永远处于“失效”状态，每个连接都会来试一次重建。
            with _bans_lock:
                if _bans["gen"] == gen:
                    _bans["at"] = at - BANS_TTL + 1.0
            return snap
        nets = tuple(nets)
        with _bans_lock:
            if _bans["gen"] == gen:        # 重建期间未被失效 → 发布
                _bans["ips"] = nets
                _bans["at"] = at
            return nets
    finally:
        _bans_build_lock.release()


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
    """生效中的封禁（面板展示 / 内核同步 / 决策缓存重建，全是只读）。

    走只读连接：调用方包括 banned_ips() 的缓存重建（决策路径）、firewall 的
    10s 内核对账、面板 /api/bans，都不应该为了一次查询去抢全局 _lock。
    """
    now = int(time.time())
    return _query_ro(
        "SELECT * FROM ban_log WHERE released=0 AND expire_at>? ORDER BY id DESC",
        (now,),
    )


def active_bans_count():
    """生效封禁数量（概览统计用，避免拉全量行；只读）。"""
    now = int(time.time())
    return _query_ro(
        "SELECT COUNT(*) AS n FROM ban_log WHERE released=0 AND expire_at>?",
        (now,),
    )[0]["n"]


def expired_bans():
    """到期未释放的封禁（engine.auto_release 的输入，只读）。"""
    now = int(time.time())
    return _query_ro(
        "SELECT * FROM ban_log WHERE released=0 AND expire_at<=?", (now,)
    )


def release_ban(ban_id):
    _exec("UPDATE ban_log SET released=1 WHERE id=?", (ban_id,))
    invalidate_bans()


def count_recent_bans_in_subnet(subnet, window_sec):
    """窗口内同一网段下被 **AI 临时封禁** 的不同 IP 数量（同段熔断用，只读）。

    subnet 传 CIDR（如 `61.241.14.0/24`），用 SQL 前缀匹配近似：
    把 CIDR 拆成前 3 段做 `ip LIKE 'a.b.c.%'`。比在应用层遍历所有 ban_log 便宜得多，
    且 /24 场景下与真正的网段判断等价（ban_log 里存的是单 IP，不是 CIDR）。

    口径（以代码为准）：只统计 `ban_log` 里 reason 以 `ai:` 开头的记录，即 AI 判
    suspicious 后写下的**临时封禁**。以下不计入：
      - AI 永久处置（malicious，或 SSH 从严的 suspicious）：走 `add_ip` 写 `ip_list`
        黑名单，而 `add_ip` 只写 `ip_list`、不写 `ban_log`；
      - 引擎自动封禁（reason 为 `auto:` / `auto_ssh:` / `auto_cc:` / `auto_scan:`）；
      - 手工封禁（人工判断，不应被自动熔断屏蔽）。
    已定口径：永久黑名单**不计入**同段熔断。同一 /24 的 IP 若都被判 malicious 直接永久
    拉黑，不会推高这个计数，熔断也不会因此触发。原因：熔断的用途是防止 CDN/共享出口
    被临时封禁成片误伤；malicious 属高置信判定，若计入，会让同段恶意 IP 越多、
    熔断越早触发，反而替该段后续的攻击者挡掉处置。
    """
    now = int(time.time())
    since = now - int(window_sec)
    prefix = str(subnet).split("/")[0].rsplit(".", 1)[0] + "."
    rows = _query_ro(
        "SELECT COUNT(DISTINCT ip) AS n FROM ban_log "
        "WHERE banned_at>=? AND substr(reason,1,3)='ai:' AND ip LIKE ?",
        (since, prefix + "%"))
    try:
        return int((rows[0] or {}).get("n") or 0)
    except (IndexError, TypeError, ValueError):
        return 0


def release_bans(ids):
    """批量把 ban_log 里给定 id 标记为已释放（一条语句一次 commit）。

    返回实际影响行数。ids 为空时返回 0 且不执行 SQL。
    一批临时封禁同时到期时，逐条 `release_ban` 会做 N 次 commit（持锁时间叠加）；
    这里合并成一条 UPDATE，只提交一次。`released=0` 让返回值表示「本次真正
    解封的条数」，重复调用幂等。
    """
    if not ids:
        return 0
    want = []
    seen = set()
    for x in ids:
        try:
            v = int(x)
        except (TypeError, ValueError):
            continue      # 非法 id 直接跳过，不让一条脏数据毁掉整批解封
        if v in seen:
            continue
        seen.add(v)
        want.append(v)
    if not want:
        return 0
    # 占位符个数是代码生成的（只由 ',' 与 '?' 组成），值仍全部走参数绑定；
    # 字符串拼接的只有占位符，S608（hardcoded SQL expression）对此是误报。
    sql = ("UPDATE ban_log SET released=1 WHERE released=0 AND id IN (%s)"  # noqa: S608
           % ",".join("?" * len(want)))
    cur = _exec(sql, tuple(want))
    invalidate_bans()
    try:
        return int(cur.rowcount or 0)
    except (TypeError, ValueError):   # pragma: no cover - 防御性
        return 0


def unban_ip(ip):
    _exec("UPDATE ban_log SET released=1 WHERE ip=? AND released=0", (ip,))
    invalidate_bans()


def release_all_bans():
    """释放全部生效中的临时封禁（一键解封），返回释放条数。

    供面板「解封全部临时封禁」按钮使用；调用方负责触发内核同步
    （firewall.sync_from_store），把已释放条目从 ipset 移除。
    写前紧邻的计数刻意留在 _query（与写同一连接），返回值才是“本次释放条数”。
    """
    n = _query(
        "SELECT COUNT(*) AS n FROM ban_log WHERE released=0 AND expire_at>?",
        (int(time.time()),),
    )[0]["n"]
    _exec("UPDATE ban_log SET released=1 WHERE released=0 AND expire_at>?",
          (int(time.time()),))
    invalidate_bans()
    return n


def ban_history(limit=200):
    """封禁历史（面板展示，只读）。"""
    return _query_ro("SELECT * FROM ban_log ORDER BY id DESC LIMIT ?", (int(limit),))


def trim_bans(max_rows=20000):
    """裁剪已结束的封禁历史，绝不删除仍生效的封禁。

    ban_log 原先无任何裁剪：永久封禁只写 ip_list 不写 ban_log，但自动/手动/AI
    的临时封禁长期累积会导致表与索引持续膨胀。
    生效记录超过上限时允许总行数暂时超过上限。
    先用 MIN/MAX(id) 做 O(1) 预判（20 万行上不再每 10s 全表计数），确认可能
    超限后才精确计数：ban_log 要跳过仍生效的封禁，生效行会夹在已结束行之间
    存活，id 空洞是常态（span 远大于行数），必须拿到真实行数才知道该删几条。
    这张表被本函数自身限制在 max_rows + 少量生效行，分支内的 COUNT(*) 有界。
    （MIN/MAX 必须写成两个标量子查询，原因见 trim_logs 的注释。）
    """
    try:
        max_rows = int(max_rows)
    except (TypeError, ValueError):
        return
    if max_rows < 0:
        max_rows = 0
    rows = _query_ro(
        "SELECT (SELECT MIN(id) FROM ban_log) AS lo,"
        " (SELECT MAX(id) FROM ban_log) AS hi"
    )
    if not rows:
        return
    lo, hi = rows[0]["lo"], rows[0]["hi"]
    if lo is None or hi is None:      # 空表：无需裁剪
        return
    if hi - lo + 1 <= max_rows:       # 行数上界未超上限 -> 必然无需裁剪
        return
    n = _query_ro("SELECT COUNT(*) AS n FROM ban_log")[0]["n"]
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
    """代理累计统计（面板 /api/proxies，只读）。"""
    return _query_ro("SELECT * FROM proxy_stat ORDER BY total DESC")


def trim_proxy_stat(days=90):
    """删除「最近 days 天无更新」的代理统计行，返回删除行数。

    代理名来自 frpc 客户端，每个新名字都会新增一行且永不清理；proxy_stat 没有
    id 列（主键 proxy_name），只能按 last_ts（epoch 秒）判断陈旧。
    行数等于历史上出现过的代理名个数，量级很小，单条 DELETE 即可，无需分段。
    days <= 0 或非整数一律不删（防止把整表清空）。
    调用位置见 daemon.py 后台循环，本函数不自动触发。
    """
    try:
        days = int(days)
    except (TypeError, ValueError):
        return 0
    if days <= 0:
        return 0
    cutoff = int(time.time()) - days * 86400
    cur = _exec("DELETE FROM proxy_stat WHERE last_ts < ?", (cutoff,))
    try:
        return int(cur.rowcount or 0)
    except (TypeError, ValueError):   # pragma: no cover - 防御性
        return 0


# ---------------- ai_review ----------------
def add_ai_review(batch_id, ip, verdict, reason, action, model):
    """写一条 AI 审查记录，返回其 id。

    返回 id 是为了让调用方把「哪次审查学到的回源网段」记进 trusted_cidr.ai_review_id：
    学习条目与审查记录在同一处置分支里产生，先写审查记录拿到 id、再写学习条目即可关联。
    写入失败仍由 sqlite3 异常向外抛（与改前一致，不在这里静默）。
    """
    cur = _exec(
        "INSERT INTO ai_review(ts,batch_id,ip,verdict,reason,action,model)"
        " VALUES(?,?,?,?,?,?,?)",
        (int(time.time()), int(batch_id or 0), ip or "", verdict or "", reason or "",
         action or "", model or ""),
    )
    return int(cur.lastrowid or 0)


def list_ai_review(limit=200):
    """AI 审查记录（面板展示，只读）。"""
    return _query_ro("SELECT * FROM ai_review ORDER BY id DESC LIMIT ?", (int(limit),))


def trim_ai_review(max_rows=5000):
    """裁剪最旧的 AI 审查记录，保留最近 max_rows 条。

    与 trim_logs 同一套改造：MIN/MAX(id) 做 O(1) 预判，确认超限后才发一条
    DELETE；span 与真实行数的关系同理（唯一删除路径、每次删最旧的一段）。
    """
    try:
        max_rows = int(max_rows)
    except (TypeError, ValueError):
        return
    if max_rows < 0:
        max_rows = 0
    rows = _query_ro(
        "SELECT (SELECT MIN(id) FROM ai_review) AS lo,"
        " (SELECT MAX(id) FROM ai_review) AS hi"
    )
    if not rows:
        return
    lo, hi = rows[0]["lo"], rows[0]["hi"]
    if lo is None or hi is None:      # 空表：无需裁剪
        return
    excess = hi - lo + 1 - max_rows
    if excess <= 0:
        return
    _exec(
        "DELETE FROM ai_review WHERE id IN "
        "(SELECT id FROM ai_review ORDER BY id ASC LIMIT ?)",
        (excess,),
    )


# ---------------- 汇总 ----------------
def stats():
    """概览统计（面板 /api/overview 与插件端 waf_overview，纯展示）。

    7 次聚合在大表上可达几十毫秒（`COUNT(DISTINCT ip)` 与多次全表 COUNT），
    迁移前全程占着全局 _lock，把这期间的每连接决策写入都堵在后面。现在：
      - 全部走只读连接，共用一条（避免每次新建连接）；
      - 不占全局 _lock，与决策路径的写入/缓存重建完全解耦。
    """
    # 「今日」按服务器本地时区零点计算（面板展示的是本地时间）。
    # 注意：不可用 (ts // 86400 * 86400)，那是 UTC 零点，在东八区 00:00-08:00
    # 会把昨天的数据算进「今日」，导致统计口径与显示不一致。
    _lt = time.localtime()
    today0 = int(time.mktime((_lt.tm_year, _lt.tm_mon, _lt.tm_mday,
                              0, 0, 0, 0, 0, -1)))
    now = int(time.time())
    with _ro_conn() as c:
        def val(row):
            return (row[0] if row else 0) or 0

        # 每条 SQL 都写成字面量：既符合“参数必定绑定”的可审计要求，
        # 也让习惯读 SQL 就能定位索引的人一眼看出走的哪条索引。
        total = val(c.execute("SELECT COUNT(*) FROM conn_log").fetchone())
        today = val(c.execute(
            "SELECT COUNT(*) FROM conn_log WHERE ts>=?", (today0,)).fetchone())
        rejected = val(c.execute(
            "SELECT COUNT(*) FROM conn_log WHERE ts>=? AND action!='allow'",
            (today0,)).fetchone())
        black = val(c.execute(
            "SELECT COUNT(*) FROM ip_list WHERE list_type='black'").fetchone())
        white = val(c.execute(
            "SELECT COUNT(*) FROM ip_list WHERE list_type='white'").fetchone())
        bans = val(c.execute(
            "SELECT COUNT(*) FROM ban_log WHERE released=0 AND expire_at>?",
            (now,)).fetchone())
        uniq = val(c.execute(
            "SELECT COUNT(DISTINCT ip) FROM conn_log WHERE ts>=?",
            (today0,)).fetchone())
    return {
        "total_conns": total,
        "today_conns": today,
        "today_rejected": rejected,
        "today_uniq_ip": uniq,
        "black_count": black,
        "white_count": white,
        "active_bans": bans,
    }
