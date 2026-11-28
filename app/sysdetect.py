#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 系统端口（非 frp 端口）来源检测

两件事，共用同一个「增量读 auth.log」的过程：

1. **SSH 登录信任**（安全前提，默认开启）
   `store.trust_login_ip()` 原来只被面板登录调用，SSH 登录完全不会写这张表。
   而 ipset 的 DROP 是**全端口**的——一旦某个来源被误封，22 端口一样进不去，
   owner 只能上云厂商控制台/VNC 救机器。所以这里把「成功 SSH 登录」的来源 IP
   也写进同一张信任表（TTL 复用 `trust_login_ttl`，与面板登录同口径）。
   为什么走 auth.log：守护进程拿不到 sshd 的登录回调，而 auth.log 的
   `Accepted <method> for <user> from <ip>` 就是登录成功的权威记录，
   复用第二部分同一套 tail 机制，零新增依赖、不改 sshd_config。

2. **P0 系统端口封禁检测**（默认关闭 + 默认只观察）
   非 frp 端口（22/6379/8888/…）的失败事件不经过 frps 回调，`engine.decide()`
   永远看不到它们。这里增量 tail auth.log，按失败类事件做「单 IP 滑窗计数」，
   达阈值走现有链路写**临时封禁**（`store.add_ban` → `ban_log` → 现有
   `firewall.sync_from_store()` 下发 ipset），到期由 `engine.auto_release()` 自愈。

红线（改动前请先读）：
- 一切都在**独立后台线程**里（`loop_forever`），绝不进入 `engine.decide()`
  的每连接热路径；本模块也不被 decide 调用。
- 默认关闭（`sys_detect_enabled=False`），打开后默认只观察
  （`sys_detect_dry_run=True`）：只记 `sys_event`、不封禁。
- 读日志失败（权限/不存在/轮转竞争）只记限频告警，**绝不影响服务主流程**。
- 只封 `/32`（单 IP），绝不整段连坐；不升永久黑名单（距误封代价的取舍见下）。

误封代价为什么这么大：ipset 全端口 DROP，被封后 7080/8888 面板同样进不来，
**无法通过面板自助解封**。因此本模块的处置一律是「短 TTL 临时封禁」，
并且处置前过六道豁免（见 `_protected_reason`）。
"""
import calendar
import ipaddress
import os
import re
import threading
import time
import traceback

from . import config, engine, store

# ---------------- 常量 ----------------

# auth.log 自动探测顺序：Debian/Ubuntu 是 auth.log，RHEL 系是 secure。
# 只在读取时探测，探测失败不改任何其它行为（检测静默不生效，告警限频一次）。
_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")

# 单轮最多从文件里读多少字节。日志被刷爆时宁可少读、下轮继续，
# 也不能一轮读完几十 MB 把线程挂住（性能红线：单轮有上限）。
_MAX_READ_BYTES = 256 * 1024

# 单轮最多处理多少行（配置项之外的第二道闸：即使行长很小也不无限循环）。
_MAX_LINES_DEFAULT = 2000

# 活跃 SSH 会话跟踪的内存上限与「无 close 事件时的兜底过期」。
# sshd 的 `session closed for user` 行**不带 IP**，无法反查是哪条连接结束，
# 所以除了 `Disconnected from user <user> <ip>` 精确减一，还必须有时间兜底，
# 否则字典会因「有 Accepted 无 Disconnected」一直累积（长期保活会话/SIGHUP 丢失）。
_SESSION_MAX_AGE = 12 * 3600
_MAX_TRACK_IPS = 4096

# 事件/计数内存字典的硬上限（防「全网段扫过来」时无界增长）。
_MAX_COUNT_IPS = 8192

# 告警限频：同一类告警 600 秒最多一条（与 firewall 侧口径一致）。
_ALERT_INTERVAL = 600


# ---------------- 日志输出 ----------------
# 本模块不 import daemon（daemon import 本模块，会成环）。改为可注入的 logger：
# daemon 启动时调用 `set_logger(_log)` 并入同一份运行日志；未注入时静默
# （测试里也方便断言）。日志失败永远不能影响检测主流程。
_logger = {"fn": None}
_alert_at = {}
_alert_lock = threading.Lock()


def set_logger(fn):
    """接入运行日志（daemon 启动时调用；接口未就绪时保持静默）。"""
    if callable(fn):
        _logger["fn"] = fn


def _log(msg):
    fn = _logger["fn"]
    if fn is None:
        return
    try:
        fn(msg)
    except Exception:
        pass


def _alert(key, msg):
    """限频告警：同类事件 _ALERT_INTERVAL 内只记一条，避免日志被刷满。"""
    now = time.time()
    with _alert_lock:
        if now - _alert_at.get(key, 0.0) < _ALERT_INTERVAL:
            return False
        _alert_at[key] = now
    _log(msg)
    return True


# ---------------- 解析 ----------------

# 时间戳：
#   Debian/Ubuntu 新版：2026-11-28T14:00:09.425722+08:00 host sshd[160087]: ...
#   传统 syslog：      Nov 28 14:00:09 host sshd[160087]: ...
# 没解析出来时按「当前时间」计（宁可少算、也绝不因为时间解析失败而封禁）。
_TS_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?")
_TS_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

# sshd 的日志正文部分（`sshd[pid]: ` 之后）。只认 sshd，其它程序行一律忽略：
# pam/cron/systemd 也写 auth.log，若不限定程序名，`Failed password` 之类
# 关键字在别的上下文里出现就会被误计。
_IDENT_RE = re.compile(r"\b(?:sshd|sshd-session)\[(\d+)\]:\s*(.*)$")
_ANY_IDENT_RE = re.compile(r"\b([\w./-]+)\[(\d+)\]:\s*")

# 失败类事件：全部用 `(?P<ip>\S+)` 抓「from 后面那个字段」，再交给
# `_norm_ip()` 做真正的合法性校验。不在这里写 IP 正则的原因：
# IPv6 的写法太多（压缩/带 zone/带方括号），手写必然漏；
# 而「取 from 后的下一个空白分隔字段」在 sshd 的所有失败行里都成立，
# 且不会把 `port 5512` 里的 5512 当成 IP。
_FAIL_PATTERNS = (
    # Failed password for root from 183.222.230.188 port 5512 ssh2
    # Failed password for invalid user admin from 1.2.3.4 port 5512 ssh2
    # Failed publickey for root from 1.2.3.4 port 5596 ssh2: RSA SHA256:...
    # Failed none for root from 1.2.3.4 port 22 ssh2
    ("failed-auth",
     re.compile(r"Failed (?:password|publickey|none|gssapi-keyex|keyboard-interactive)"
                r" for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+)")),
    # Invalid user admin from 111.29.52.71 port 3312
    ("invalid-user",
     re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")),
    # Connection closed by authenticating user root 43.143.9.47 port 22 [preauth]
    ("closed-auth",
     re.compile(r"Connection closed by authenticating user (?P<user>\S*) (?P<ip>\S+)")),
    # error: maximum authentication attempts exceeded for root from 1.2.3.4 port 22 ssh2
    ("max-attempts",
     re.compile(r"maximum authentication attempts exceeded for (?:invalid user )?"
                r"(?P<user>\S*) from (?P<ip>\S+)")),
)

# 成功登录：Accepted publickey / password / keyboard-interactive/pam ... from <ip> port <n>
_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>[\w/-]+) for (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?")

# 会话结束（正常登出）：Disconnected from user root 1.2.3.4 port 5596
# 注意与 `Connection closed by authenticating user ...` 区分：后者是
# 「认证阶段就断了」，不是已建立的会话，不能用来减计数。
_DISCONNECT_RE = re.compile(
    r"Disconnected from (?:authenticating )?user (?P<user>\S*) (?P<ip>\S+?)(?: port \d+)?$")


def _parse_ts(line, now=None):
    """从行首解出时间戳（epoch 秒）；解析不出来返回当前时间。"""
    now = int(time.time()) if now is None else int(now)
    m = _TS_ISO.match(line)
    if m:
        y, mo, d, hh, mm, ss, frac, tz = m.groups()
        try:
            tup = (int(y), int(mo), int(d), int(hh), int(mm), int(ss), 0, 0, -1)
            # base = 当本地时间解；utc_equiv = 当 UTC 解（配上行内偏移即真实 epoch）。
            # 不手算本地偏移：time.timezone/altzone 在「已定义夏令时但当前未生效」
            # 的时区上会算错，而 mktime 已经把夏令时算进去了。
            base = int(time.mktime(tup))
            utc_equiv = int(calendar.timegm(tup))
            # mktime 按本地时区解释；行内带偏移时要减掉偏移量差，否则跨时区
            # 部署下窗口计数会整体偏移（影响很小，但会让 600s 窗口错位）。
            if not tz:
                return base
            if tz == "Z":
                off = 0
            else:
                sign = -1 if tz[0] == "-" else 1
                body = tz[1:].replace(":", "")
                off = sign * (int(body[:2]) * 3600 + int(body[2:4]) * 60)
            return utc_equiv - off
        except (ValueError, OverflowError):
            return now
    m = _TS_SYSLOG.match(line)
    if m:
        mon, day, hh, mm, ss = m.groups()
        month = _MONTHS.get(mon)
        if month:
            year = int(time.localtime(now).tm_year)
            try:
                ts = int(time.mktime((year, month, int(day), int(hh), int(mm),
                                      int(ss), 0, 0, -1)))
            except (ValueError, OverflowError):
                return now
            # 传统 syslog 不带年份：若算出来「比现在还晚一天以上」，说明是去年
            # 12 月的行，回退一年（日志跨年时窗口计数不会整段错位）。
            if ts > now + 86400:
                try:
                    ts = int(time.mktime((year - 1, month, int(day), int(hh),
                                          int(mm), int(ss), 0, 0, -1)))
                except (ValueError, OverflowError):
                    return now
            return ts
    return now


def _norm_ip(raw):
    """把日志里的来源字段规整成 ip_address；非法返回 None。

    只做「是不是一个地址」的判断，不管公网/私网——是否公网由
    `_is_public()` 决定（两件事的判定口径不同，混在一起会互相拖累）。
    """
    s = (raw or "").strip().strip("[]")
    if not s:
        return None
    if s.lower().startswith("::ffff:") and "." in s:   # IPv4-mapped
        s = s[7:]
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _is_public(obj):
    """是否公网地址。口径对齐宝塔插件端 `trust_my_ip()`：
    回环 / 链路本地 / 内网 / 未指定 / 组播 / 保留 一律不处理。

    为什么必须跳过：这些地址不可能是「外部攻击来源」，把 127.0.0.1 或内网
    地址写进信任表/封禁表只会污染数据；内核 DROP 对内网来源也毫无意义。
    """
    if obj is None:
        return False
    if obj.is_loopback or obj.is_link_local or obj.is_private:
        return False
    return not (obj.is_unspecified or obj.is_multicast or obj.is_reserved)


def parse_line(line, now=None):
    """解析一行 auth.log，返回事件 dict；无关行返回 None。

    返回字段：
        ts      事件时间（epoch 秒，解析失败按当前时间）
        kind    "fail" / "accept" / "disconnect"
        ip      来源 IP 字符串（已规整；非法时为 ""）
        user    用户名（尽力而为，可能为 ""）
        port    建立端口（仅 accept 有；其它为 0）
        method  认证方式（仅 accept：publickey / password / ...）
        note    细分事件名（failed-auth / invalid-user / closed-auth /
                max-attempts / accepted / disconnected）

    只解析 sshd 的行：auth.log 里还有 cron/systemd/pam 的条目，
    不限定程序名会把别处的同名字段当成登录事件。
    """
    if not line:
        return None
    m_ident = _IDENT_RE.search(line)
    if not m_ident:
        return None
    body = m_ident.group(2)

    for note, pat in _FAIL_PATTERNS:
        m = pat.search(body)
        if m:
            obj = _norm_ip(m.group("ip"))
            return {"ts": _parse_ts(line, now), "kind": "fail",
                    "ip": str(obj) if obj else "",
                    "user": (m.groupdict().get("user") or ""),
                    "port": 0, "method": "", "note": note}

    m = _ACCEPT_RE.search(body)
    if m:
        obj = _norm_ip(m.group("ip"))
        try:
            port = int(m.group("port") or 0)
        except (TypeError, ValueError):
            port = 0
        return {"ts": _parse_ts(line, now), "kind": "accept",
                "ip": str(obj) if obj else "",
                "user": (m.group("user") or ""),
                "port": port, "method": (m.group("method") or ""),
                "note": "accepted"}

    m = _DISCONNECT_RE.search(body)
    if m:
        obj = _norm_ip(m.group("ip"))
        return {"ts": _parse_ts(line, now), "kind": "disconnect",
                "ip": str(obj) if obj else "",
                "user": (m.group("user") or ""),
                "port": 0, "method": "", "note": "disconnected"}
    return None


# ---------------- 增量 tail ----------------

def _safe_log_path(p):
    """规整配置里的 auth.log 路径。

    只接受绝对路径且不含 `..` 段：配置文件能被宝塔插件端直接改写，
    若把路径当前任意文件读取通道，就多了一个不该有的读文件面。
    """
    s = str(p or "").strip()
    if not s or not os.path.isabs(s):
        return ""
    if ".." in s.replace("\\", "/").split("/"):
        return ""
    return s


class AuthLogTailer(object):
    """auth.log 增量读取器（只在内存里记 inode + offset）。

    轮转处理（两条判定，任一命中即从头重读当前文件）：
      - inode 变了（logrotate rename+create 的标准形态）；
      - 文件比上次读到的位置更小（copytruncate 形态，或人工清空）。
    首次读取**从文件末尾开始**：一上来就把若干天历史全算一遍，等于开服瞬间
    产生一次批量封禁，这是最危险的误封形态。

    只在「读到完整行」时推进 offset：行被切断（正在写/被字节上限截断）时
    不前进，下轮从同一位置重读该行，避免把半行当两行解析。
    """

    def __init__(self, path=""):
        self.path = path or ""
        self._ino = None
        self._offset = 0
        self._started = False
        self._skip_pending = False   # 置位后下一次读取只做「跳到末尾」，不产出事件

    def resolve_path(self):
        """实际读取的文件路径：配置项优先，未配置时按候选顺序探测。"""
        if self.path:
            return _safe_log_path(self.path)
        for cand in _LOG_CANDIDATES:
            try:
                if os.path.isfile(cand):
                    return cand
            except OSError:
                continue
        return ""

    def seek_end(self):
        """下一轮直接跳到文件末尾（检测关闭期间不处理历史，避免开关一开就批量封禁）。"""
        self._skip_pending = True

    def reset(self):
        """丢掉全部状态（配置换日志路径时用）。"""
        self._ino = None
        self._offset = 0
        self._started = False
        self._skip_pending = False

    def state(self):
        """当前读取位置（面板/测试观察用，只读）。"""
        return {"path": self.resolve_path(), "inode": self._ino,
                "offset": self._offset, "started": self._started}

    def _relocate(self, st, path):
        """定位本轮起点，返回 (event, 需提前返回的 info 或 None)。

        三种情况：
          - 首次 / 显式 seek_end：跳到文件末尾，不产出事件（防一次性补算历史）；
          - 轮转（inode 变化）/ 截断（文件变小）：记录事件并从 0 重读；
          - 其余：保持当前位置，event="read"。
        """
        if not self._started or self._skip_pending:
            event = "first-run" if not self._started else "seek-end"
            self._ino = st.st_ino
            self._offset = st.st_size
            self._started = True
            self._skip_pending = False
            return event, {"event": event, "path": path, "lines": 0}
        event = "read"
        if st.st_ino != self._ino:
            event = "rotated"
        elif st.st_size < self._offset:
            event = "truncated"
        if event != "read":
            self._ino = st.st_ino
            self._offset = 0
        if st.st_size <= self._offset:
            # 轮转/截断后新文件可能是空的（logrotate 的常见形态）：
            # 这里必须保留 rotated/truncated 事件，否则「记录一条轮转日志」会丢。
            return event, {"event": ("none" if event == "read" else event),
                           "path": path, "lines": 0}
        return event, None

    def _read_chunk(self, path, size):
        """从当前 offset 起读最多 size 字节；失败返回 None。"""
        want = min(size, _MAX_READ_BYTES)
        try:
            # pi-lens-ignore: python-path-traversal -- 路径只来自 _safe_log_path（绝对路径、无 `..`）或内置候选常量，不来自请求
            with open(path, "rb") as f:
                f.seek(self._offset)
                return f.read(want)
        except OSError:
            return None

    def read_new(self, max_lines=_MAX_LINES_DEFAULT):
        """返回 (lines, info)。

        lines 为新增的完整行（已 decode，去掉行尾换行）；
        info 说明本轮做了什么，供调用方记日志与断言轮转行为：
            {"event": "first-run" | "seek-end" | "rotated" | "truncated" |
                      "read" | "none" | "no-file", "path": ..., "lines": n}
        """
        path = self.resolve_path()
        if not path:
            return [], {"event": "no-file", "path": "", "lines": 0}
        try:
            st = os.stat(path)
        except OSError:
            return [], {"event": "no-file", "path": path, "lines": 0}

        try:
            limit = max(1, int(max_lines))
        except (TypeError, ValueError):
            limit = _MAX_LINES_DEFAULT

        event, early = self._relocate(st, path)
        if early is not None:
            return [], early

        chunk = self._read_chunk(path, st.st_size - self._offset)
        if chunk is None:
            return [], {"event": "no-file", "path": path, "lines": 0}

        cut = chunk.rfind(b"\n")
        if cut < 0:
            # 没有完整的行：要么这行还没写完（下轮从同一位置重读），
            # 要么单行超过读取上限（必须丢弃，否则每轮都卡在同一位置）。
            if len(chunk) >= _MAX_READ_BYTES:
                self._offset += len(chunk)
                _alert("oversize-line",
                       "auth.log 出现超过 %d 字节的单行，已跳过（读取位置 %d）"
                       % (_MAX_READ_BYTES, self._offset))
            return [], {"event": event, "path": path, "lines": 0}

        usable = chunk[:cut + 1]
        raw_lines = usable.split(b"\n")[:-1]     # 末尾必然是空串，去掉
        if len(raw_lines) > limit:
            # 只消费前 limit 行，offset 停在这之后；剩余下轮继续（不丢行）。
            consumed = b"\n".join(raw_lines[:limit]) + b"\n"
            raw_lines = raw_lines[:limit]
            self._offset += len(consumed)
        else:
            self._offset += len(usable)

        lines = [b.decode("utf-8", "replace").rstrip("\r") for b in raw_lines]
        return lines, {"event": event, "path": path, "lines": len(lines)}


# ---------------- 运行期状态 ----------------

_state = {
    "tailer": None,
    "counts": {},        # ip -> {"start": ts, "n": int, "claimed": bool}
    "sessions": {},      # ip -> {"n": 已建立会话数, "at": 最近一次 accept 时间}
    "ban_times": [],     # 近一小时内新增封禁的时间戳（全局熔断）
    "last_round": 0,
    "last_events": 0,
    "seen_events": 0,
}
_lock = threading.Lock()


def reset_state():
    """清空运行期状态（测试隔离用；daemon 不会调用）。"""
    with _lock:
        _state["tailer"] = None
        _state["counts"] = {}
        _state["sessions"] = {}
        _state["ban_times"] = []
        _state["last_round"] = 0
        _state["last_events"] = 0
        _state["seen_events"] = 0


def _tailer(cfg):
    """取（必要时新建）tailer；配置里换了日志路径就重建并清空位置。"""
    want = str(cfg.get("sys_ssh_log") or "").strip()
    t = _state["tailer"]
    if t is None:
        t = AuthLogTailer(want)
        _state["tailer"] = t
    elif (t.path or "") != want:
        t = AuthLogTailer(want)
        _state["tailer"] = t
        _log("系统端口检测：日志路径改为 %r，重新定位读取位置"
             % (want or "(自动探测)"))
    return t


# ---------------- 计数（滑窗） ----------------

def _count_fail(ip, ts, window, threshold):
    """失败事件滑窗计数，返回 (窗口内次数, 本轮是否越阈值认领)。

    语义对齐 `engine._attack_count()`：同一窗口内只有第一个越过阈值的
    调用拿到 claimed=True（并发/批量行不会重复写封禁）；越过阈值后计数
    封顶，避免「封禁尚未可见」的窄窗口内二次触发。
    """
    now = float(ts)
    window = max(1, int(window))
    threshold = max(0, int(threshold))
    with _lock:
        counts = _state["counts"]
        ent = counts.get(ip)
        if not ent or now - ent["start"] >= window:
            ent = {"start": now, "n": 0, "claimed": False}
            counts[ip] = ent
        if ent["n"] < threshold:
            ent["n"] += 1
        claimed = bool(threshold > 0 and ent["n"] >= threshold and not ent["claimed"])
        if claimed:
            ent["claimed"] = True
        # 有界清理：过期条目优先，仍超上限则淘汰最旧的（防无界增长）。
        if len(counts) > _MAX_COUNT_IPS:
            for k in [k for k, v in counts.items() if now - v["start"] >= window]:
                counts.pop(k, None)
            if len(counts) > _MAX_COUNT_IPS:
                for k, _ in sorted(counts.items(), key=lambda kv: kv[1]["start"])[:512]:
                    counts.pop(k, None)
        return ent["n"], claimed


def session_add(ip, ts):
    """记录一条已建立的 SSH 会话（Accepted 之后）。"""
    now = float(ts)
    with _lock:
        ent = _state["sessions"].get(ip)
        if not ent:
            ent = {"n": 0, "at": now}
            _state["sessions"][ip] = ent
        ent["n"] = int(ent.get("n") or 0) + 1
        ent["at"] = now
        _prune_sessions(now)


def session_remove(ip, ts=None):
    """会话结束（Disconnected）时减一；减到 0 即从活跃集合移除。"""
    now = float(ts or time.time())
    with _lock:
        ent = _state["sessions"].get(ip)
        if not ent:
            return
        ent["n"] = int(ent.get("n") or 0) - 1
        ent["at"] = now
        if ent["n"] <= 0:
            _state["sessions"].pop(ip, None)
        _prune_sessions(now)


def _prune_sessions(now):
    """须在 _lock 内调用：丢掉超过 _SESSION_MAX_AGE 没有活动的会话记录。"""
    sessions = _state["sessions"]
    if not sessions:
        return
    if len(sessions) > _MAX_TRACK_IPS:
        oldest = [k for k, _ in sorted(sessions.items(), key=lambda kv: kv[1]["at"])]
        for k in oldest[:max(1, _MAX_TRACK_IPS // 4)]:
            sessions.pop(k, None)
        return
    for k in [k for k, v in sessions.items() if now - v["at"] >= _SESSION_MAX_AGE]:
        sessions.pop(k, None)


def active_session_ips():
    """当前被跟踪为「已建立 SSH 会话」的来源 IP（保护判定用，只读快照）。"""
    with _lock:
        _prune_sessions(time.time())
        return set(_state["sessions"])


def current_counts():
    """当前滑窗计数快照（面板/测试观察用，只读）。"""
    with _lock:
        return {k: {"start": v["start"], "n": v["n"], "claimed": v["claimed"]}
                for k, v in _state["counts"].items()}


# ---------------- 豁免判定（误封防护） ----------------

def _cidr_match(obj, raw):
    """CIDR 列表（逗号/分号/空白分隔）里是否命中；命中返回该条目，否则 ""。"""
    raw = str(raw or "").strip()
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


def _whitelisted(obj):
    """是否落在 `ip_list(white)` 内。

    **故意不看 `whitelist_enabled` 开关**，与 `ai._is_whitelisted()` 同口径。
    原因：该开关默认 False，而它关闭时内核同步与 `engine.decide()` 都不把
    白名单当作剔除条件——若这里也跟随开关，就会出现「owner 把自己加进白名单，
    22 端口照样被封」的锁门事故。检测侧的处置必须永远尊重白名单。
    """
    try:
        for r in store.list_ips("white"):
            try:
                if obj in ipaddress.ip_network(str(r.get("cidr") or ""), strict=False):
                    return True
            except ValueError:
                continue
    except Exception:
        # 读名单失败按「不在白名单」处理（宁可照常判定，也不因读库失败放行）。
        return False
    return False


def _protected_reason(obj, cfg, sessions=None):
    """处置前二次校验：返回不封的原因；返回 "" 表示可以封。

    顺序即短路优先级（任一条命中即不封）：
      1. 非法/非公网地址
      2. 白名单（无条件，不看 whitelist_enabled）
      3. 登录信任 trust_login_ip
      4. 可信回源网段（ai_trusted_cidrs + 学习表 trusted_cidr）
      5. sys_protect_ips 人工永不封禁段
      6. 当前活跃 SSH 会话来源
    """
    if obj is None or not _is_public(obj):
        return "non-public"
    ip = str(obj)
    if _whitelisted(obj):
        return "whitelist"
    try:
        if int(store.trusted_login_expiry(ip) or 0) > 0:
            return "trust-login"
    except Exception:
        pass
    try:
        hit = _cidr_match(obj, cfg.get("ai_trusted_cidrs")) \
            or engine._in_trusted_cidr(obj, cfg)
        if hit:
            return "trusted-cidr"
    except Exception:
        pass
    hit = _cidr_match(obj, cfg.get("sys_protect_ips"))
    if hit:
        return "protect-cidr"
    if sessions is None:
        sessions = active_session_ips()
    if ip in sessions:
        return "active-session"
    return ""


# ---------------- 处置 ----------------

def _circuit_open(cfg, now=None):
    """全局熔断：一小时内新增封禁数达上限则停止新增（返回 True）。

    对应「整段被扫」导致的批量误伤：宁可这小时内少封，也不要一夜之间把
    整片出口 IP 送进内核黑名单（面板同端口被封后无法自助解封）。
    """
    now = time.time() if now is None else float(now)
    try:
        limit = int(cfg.get("sys_ban_max_per_hour") or 0)
    except (TypeError, ValueError):
        limit = 0
    if limit <= 0:
        return False
    with _lock:
        times = [t for t in _state["ban_times"] if now - t < 3600]
        _state["ban_times"] = times
        return len(times) >= limit


def _note_ban(now=None):
    now = time.time() if now is None else float(now)
    with _lock:
        _state["ban_times"].append(now)
        if len(_state["ban_times"]) > 4096:
            del _state["ban_times"][:-4096]


def _record(ts, ip, source, hits, window, action, reason, port=0):
    """写一条 sys_event（观察模式的唯一可观测产物），失败不影响主流程。"""
    try:
        store.add_sys_event(ts=ts, ip=ip, source=source, port=port, hits=hits,
                            window_sec=window, action=action, reason=reason)
    except Exception:
        _alert("sys-event-write",
               "系统端口检测：sys_event 写入失败（不影响检测）：%s"
               % traceback.format_exc()[-200:])


def _ban_seconds(cfg):
    try:
        secs = int(cfg.get("sys_ssh_ban_seconds") or 0)
    except (TypeError, ValueError):
        secs = 0
    if secs <= 0:
        secs = int(config.DEFAULTS.get("sys_ssh_ban_seconds") or 600)
    # 单条上限钳制：配置写错（例如 99999999）也不能变成事实上的永久封禁。
    try:
        cap = int(cfg.get("sys_ban_max_seconds") or 0)
    except (TypeError, ValueError):
        cap = 0
    if cap <= 0:
        cap = int(config.DEFAULTS.get("sys_ban_max_seconds") or 3600)
    return max(60, min(secs, cap))


def handle_fail(ip_obj, ts, cfg):
    """处理一条失败事件：计数 → 达阈值 → 豁免判定 → 临时封禁 / 仅观察。

    返回处置结果字符串（供测试与日志使用）：
        "counted" / "already-banned" / "observed" / "skipped:<原因>" / "banned"
    """
    ip = str(ip_obj)
    try:
        window = int(cfg.get("sys_ssh_window") or 0) or \
            int(config.DEFAULTS["sys_ssh_window"])
    except (TypeError, ValueError):
        window = int(config.DEFAULTS["sys_ssh_window"])
    try:
        threshold = int(cfg.get("sys_ssh_threshold") or 0)
    except (TypeError, ValueError):
        threshold = 0
    if threshold <= 0:
        return "counted"           # 阈值 0 = 只计数不处置（显式关闭触发）

    n, claimed = _count_fail(ip, ts, window, threshold)
    if not claimed:
        return "counted"

    reason = "sys: authlog sshd %d 次失败/%ds" % (n, window)
    if bool(cfg.get("sys_detect_dry_run", True)):
        # 观察模式：只记录「本应封禁」，绝不动 ban_log/ipset。
        _record(ts, ip, "sshd", n, window, "observed", reason)
        _log("系统端口检测（观察模式）：%s 在 %ds 内失败 %d 次，本应临时封禁 %ds"
             % (ip, window, n, _ban_seconds(cfg)))
        return "observed"

    try:
        if store.is_banned(ip):
            _record(ts, ip, "sshd", n, window, "skipped:already-banned", reason)
            return "already-banned"
    except Exception:
        pass

    why = _protected_reason(ip_obj, cfg)
    if why:
        _record(ts, ip, "sshd", n, window, "skipped:" + why, reason)
        _log("系统端口检测：%s 达阈值但被豁免（%s），不封禁" % (ip, why))
        return "skipped:" + why

    if _circuit_open(cfg, ts):
        _record(ts, ip, "sshd", n, window, "skipped:circuit", reason)
        _alert("circuit-open",
               "系统端口检测：一小时内新增封禁数已达上限（sys_ban_max_per_hour），"
               "暂停新增封禁（最近一条：%s）" % reason)
        return "skipped:circuit"

    secs = _ban_seconds(cfg)
    try:
        store.add_ban(ip, reason, secs)     # 内部会 invalidate_bans()
    except Exception:
        _alert("ban-write",
               "系统端口检测：临时封禁写入失败（%s）：%s"
               % (ip, traceback.format_exc()[-200:]))
        return "skipped:db-error"
    _note_ban(ts)
    try:
        engine.invalidate_cache()           # 规则缓存无关，但保持一致（黑名单可能被同步读）
    except Exception:
        pass
    if cfg.get("fw_sync_enabled", True):
        try:
            engine._request_fw_sync()       # 事件合并下发内核（不新起线程做 sync）
        except Exception:
            pass
    _record(ts, ip, "sshd", n, window, "banned", reason)
    _log("系统端口检测：%s 在 %ds 内失败 %d 次，临时封禁 %d 秒（%s）"
         % (ip, window, n, secs, reason))
    return "banned"


def handle_accept(ip_obj, ts, cfg, method=""):
    """处理一条成功 SSH 登录：写登录信任 + 记活跃会话。

    为什么「能成功认证」就可以信任：走到 `Accepted` 说明认证已经通过，
    来源已持有该主机的 SSH 凭据（密钥或口令）。对这类来源做临时豁免不会
    扩大威胁面，而且只写 /32、带 TTL、面板可逐条解绑。
    **这是唯一会写 trust_login_ip 的 SSH 路径；失败登录永不写入。**
    """
    ip = str(ip_obj)
    session_add(ip, ts)
    if not _is_public(ip_obj):
        return False
    if not bool(cfg.get("sys_trust_ssh_login", True)):
        return False
    try:
        ttl = int(cfg.get("trust_login_ttl") or 0)
    except (TypeError, ValueError):
        ttl = 0
    if ttl <= 0:
        return False                      # 0 = 关闭登录信任（与面板登录同口径）
    try:
        expired = int(store.trusted_login_expiry(ip) or 0)
        if expired - int(time.time()) > ttl // 2:
            return False                  # 剩余有效期还长：不重写、不刷日志（天然限频）
        store.trust_login_ip(ip, ttl)
        engine.invalidate_cache()         # 信任缓存 3s TTL：写后立即生效
    except Exception:
        _alert("trust-write",
               "系统端口检测：SSH 登录信任写入失败（%s）：%s"
               % (ip, traceback.format_exc()[-200:]))
        return False
    _log("SSH 登录成功（%s）来自 %s，已加入登录信任 %d 秒"
         % (method or "unknown", ip, ttl))
    return True


# ---------------- 单轮执行 ----------------

def tick(now=None):
    """读一轮新增日志并处理；返回本轮处理的事件数。

    只在后台线程调用（测试可直接调用以驱动确定性断言）。
    任何异常都被吞掉：日志读不到、库写失败都不允许把服务拖下水。
    """
    cfg = config.get()
    want_trust = bool(cfg.get("sys_trust_ssh_login", True)) and \
        int(cfg.get("trust_login_ttl") or 0) > 0
    want_detect = bool(cfg.get("sys_detect_enabled"))
    tailer = _tailer(cfg)

    if not want_trust and not want_detect:
        # 两件事都不需要：只把读取位置推到末尾，避免以后开启时补算历史。
        tailer.seek_end()
        return 0

    try:
        max_lines = int(cfg.get("sys_ssh_max_lines") or 0) or _MAX_LINES_DEFAULT
    except (TypeError, ValueError):
        max_lines = _MAX_LINES_DEFAULT
    lines, info = tailer.read_new(max_lines)
    ev = info.get("event")
    if ev == "first-run":
        _log("系统端口检测：%s 首次读取从文件末尾开始（offset=%d），历史行不计数"
             % (info.get("path") or "(未找到日志)", tailer.state()["offset"]))
    elif ev in ("rotated", "truncated"):
        _log("系统端口检测：%s 发生%s（inode=%s），从头重读"
             % (info.get("path") or "", "轮转" if ev == "rotated" else "截断",
                tailer.state()["inode"]))
    elif ev == "no-file" and (want_detect or want_trust):
        _alert("no-authlog",
               "系统端口检测：未找到可读的 auth.log（候选 %s），本轮跳过"
               % ", ".join(_LOG_CANDIDATES))

    handled = 0
    for line in lines:
        try:
            evd = parse_line(line, now)
        except Exception:
            _alert("parse-error",
                   "系统端口检测：日志行解析异常（已跳过）：%s"
                   % traceback.format_exc()[-200:])
            continue
        if not evd:
            continue
        obj = _norm_ip(evd.get("ip"))
        if obj is None:
            continue
        ts = evd.get("ts") or int(time.time())
        kind = evd.get("kind")
        if kind == "accept":
            try:
                handle_accept(obj, ts, cfg, evd.get("method") or "")
            except Exception:
                pass
            handled += 1
        elif kind == "disconnect":
            try:
                session_remove(str(obj), ts)
            except Exception:
                pass
        elif kind == "fail":
            if not want_detect:
                continue              # 检测关闭时只做登录信任，不累计失败
            try:
                handle_fail(obj, ts, cfg)
            except Exception:
                pass
            handled += 1
    with _lock:
        _state["last_round"] = int(time.time())
        _state["last_events"] = handled
        _state["seen_events"] = int(_state.get("seen_events") or 0) + handled
    return handled


def loop_forever():
    """后台线程主循环（daemon.main 里与 ai.loop_forever 并列启动）。"""
    while True:
        try:
            tick()
        except Exception:
            _alert("tick-error",
                   "系统端口检测单轮异常（不影响服务）：%s"
                   % traceback.format_exc()[-300:])
        try:
            interval = int(config.get().get("sys_ssh_poll_interval") or 0)
        except (TypeError, ValueError):
            interval = 0
        time.sleep(max(1, interval or 5))


# ---------------- 面板/只读接口用 ----------------

def status():
    """当前检测状态（/api/sysdetect 的 GET 用）：配置摘要 + 跟随位置 + 计数。"""
    cfg = config.get()
    tailer = _state["tailer"]
    with _lock:
        counts = {k: dict(v) for k, v in _state["counts"].items()}
        sessions = set(_state["sessions"])
        last_round = _state["last_round"]
        seen = _state["seen_events"]
        bans_last_hour = len([t for t in _state["ban_times"]
                              if time.time() - t < 3600])
    keys = ("sys_detect_enabled", "sys_detect_dry_run", "sys_ssh_log",
            "sys_ssh_window", "sys_ssh_threshold", "sys_ssh_ban_seconds",
            "sys_ssh_poll_interval", "sys_ssh_max_lines", "sys_ban_max_per_hour",
            "sys_ban_max_seconds", "sys_protect_ips", "sys_trust_ssh_login",
            "trust_login_ttl")
    return {
        "config": {k: cfg.get(k, config.DEFAULTS.get(k)) for k in keys},
        "tail": tailer.state() if tailer is not None else
                AuthLogTailer(str(cfg.get("sys_ssh_log") or "")).state(),
        "counts": counts,
        "active_sessions": sorted(sessions),
        "last_round": last_round,
        "events_seen": seen,
        "bans_last_hour": bans_last_hour,
    }
