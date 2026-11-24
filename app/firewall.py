#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 内核防火墙封禁同步（ipset + iptables）

为什么需要它：
  frp 的 httpPlugins 是「应用层」准入。被拒绝的连接，其 TCP 连接仍会被内核
  接受、再由 frps 断开。因此被禁 IP 仍能不停发起新连接，导致：
    - conn_log / proxy_stat 计数持续上涨（每次重试都记一条）
    - 白白消耗 frps 与 WAF 的 CPU、连接资源

本模块把「黑名单 + 生效中的封禁」同步进一个 ipset 集合，并在 INPUT 链最前面
用一条规则对命中集合的来源直接 DROP。这样被禁 IP 的数据包在内核层即被丢弃，
连不到 frps，计数自然停止，也省资源。

  ipset : frpwaf_block   (IPv4, hash:net, 支持 per-entry timeout)
          frpwaf_block6  (IPv6)
  iptables : 链 FRPWAF_BLOCK，由 INPUT 第 1 条跳入，命中集合则 DROP

仅使用系统命令，无第三方依赖；非 root 或缺少 ipset/iptables 时自动降级为
「不启用」（此时仍由 frp 应用层拦截，只是计数会继续增长）。

同步策略（稳态零 fork）：
  后台每 10s 调一次 sync_from_store()。若每轮都无条件执行
  `_ensure_sets` / `_clear_redirect` / `_ensure_drop` / `ipset save`，稳态下
  每轮要 ~18 次 subprocess fork（其中 6 条 `iptables -D` 在 drop 模式下按设计
  必然失败），小规格 ECS 上长期占 1%-2% 单核，还会在内核日志里制造噪音。
  故这里做两层记忆化：
    1. 规则记忆（_RULES）：记下已下发的处置形态（drop/redirect/off）、
       REDIRECT 端口集合与拦截页端口，配置不变就不重复下发；
    2. 成员记忆（_MEMBERS）：记下每个集合已下发的成员及「绝对到期时间戳」，
       与目标快照比对，只下发差量（增/删/改超时），名单不变时一轮 0 fork。
  记忆化会失去「外部改动（firewalld reload、iptables -F）后自动补回」的能力，
  因此保留周期性审计：每 VERIFY_INTERVAL 秒用轻量探测（`iptables -C`、一次
  `ipset save`）核对内核真值，不一致才重新下发。首次同步（进程刚启动）也走
  一次真值读取，避免把上一进程留下的内核残留条目当成「已同步」。
"""
import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import threading
import time

SET4 = "frpwaf_block"
SET6 = "frpwaf_block6"
CHAIN = "FRPWAF_BLOCK"
NAT_CHAIN = "FRPWAF_REDIRECT"

_lock = threading.Lock()
# 全量同步串行锁：从「读库构建快照」到「下发内核」全程互斥。
# 否则并发同步（如引擎封禁线程 + 后台轮询 + 面板手动同步）中，持旧快照的
# 调用可能后于新快照执行，把已解封条目重新写回内核（写覆盖竞态）。
_sync_lock = threading.RLock()

# ---------------------------------------------------------------------------
# 运行状态记忆（稳态短路）
# ---------------------------------------------------------------------------
# _RULES   : 上一次成功下发的规则形态。mode=None 表示「未知，需重新下发」。
# _MEMBERS : {集合名: {成员: 绝对到期时间戳}}（0 表示永久）。缺键或值为 None
#            表示「未知」，下一次同步先读内核真值（ipset save）再比差异。
# _sets_ok : 集合已确认存在（避免每轮 2 次 ipset create）。
# _checked : 集合/规则的最近一次内核一致性核对时间。
VERIFY_INTERVAL = 600.0        # 内核状态审计周期（秒）
RULE_RETRY_INTERVAL = 60.0     # 规则下发失败后的重试间隔（秒）
# 临时封禁到期时刻变化超过 10%（且至少 5 秒）才重建条目，抑制抖动：
# `ipset add -exist` 不会刷新已存在条目的 timeout，故延长必须 del + add。
TIMEOUT_REFRESH_RATIO = 0.1
TIMEOUT_REFRESH_MIN = 5

_RULES = {"mode": None, "ports": (), "block_port": 0, "checked_at": 0.0}
_MEMBERS = {}
_sets_ok = False
_sets_checked_at = 0.0
_MISSING = object()
# _have() 的结果缓存：稳态下每轮会问十几次 PATH，缓存 5 分钟足够，
# 又能在补装 ip6tables 后自愈（不缓存负结果到进程结束）。
_WHICH_TTL = 300.0
_which_cache = {}

# ---------------------------------------------------------------------------
# 失败可见（限频日志）
# ---------------------------------------------------------------------------
# 历史上这些子进程的错误全被丢弃（等价于 `2>/dev/null`），真实故障无从定位。
# 现在保留 stderr 并按「命令族」限频记录：同一族每 FAIL_LOG_INTERVAL 秒最多
# 一条，且把期间被抑制的次数带在行尾——既能看见故障，又不会刷爆 syslog。
FAIL_LOG_INTERVAL = 600.0
_fail_log = {}
_fail_log_lock = threading.Lock()
_logger = None


def set_logger(fn):
    """注入日志函数（可选）。未注入时退化为 logging，再退化为 stderr。

    daemon 可在启动时传入自己的 _log，使防火墙告警与运行日志落到同一文件。
    """
    global _logger
    _logger = fn


def _emit(msg):
    fn = _logger
    if fn is not None:
        try:
            fn(msg)
            return
        except Exception:
            pass
    try:
        log = logging.getLogger("frpwaf.firewall")
        if log.handlers or logging.getLogger().handlers:
            log.warning(msg)
            return
    except Exception:
        pass
    try:
        sys.stderr.write("[firewall] %s\n" % msg)
        sys.stderr.flush()
    except Exception:
        pass


def _first_line(text, limit=160):
    line = (text or "").strip()
    if not line:
        return ""
    out = line.splitlines()[0].strip()
    return out[:limit]


def _report_failure(key, args, rc, err):
    """限频记录一次子进程失败（同一 key 每 FAIL_LOG_INTERVAL 秒最多一条）。"""
    now = time.time()
    with _fail_log_lock:
        rec = _fail_log.get(key) or {"at": 0.0, "n": 0}
        last = rec["at"]
        if last and now - last < FAIL_LOG_INTERVAL:
            rec["n"] += 1          # 期间同类失败，等下次窗口一起报数量
            _fail_log[key] = rec
            return
        suppressed = rec["n"]
        _fail_log[key] = {"at": now, "n": 0}
    detail = _first_line(err) or "无 stderr 输出"
    msg = "内核封禁同步：`%s` 退出码 %d：%s" % (
        " ".join(str(a) for a in args), rc, detail)
    if suppressed:
        msg += "（此前 %ds 内另有 %d 次同类失败已抑制）" % (
            int(FAIL_LOG_INTERVAL), suppressed)
    _emit(msg)


def _run(args, timeout=10, input_data=None):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           input=input_data, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", str(e)


# 这些 stderr 是「幂等命令的正常分支」，不是故障，不应进日志：
#   - 链/规则已存在（-N）、规则不存在（-D 清理时）
#   - 集合已被删除（destroy/flush 后的残留调用）
# 注意不要把真实故障（权限/内核不支持等）列进来，否则等于重新静默。
_EXPECTED_ERR = (
    "already exists",
    "does a matching rule exist",
    "does not exist",
    "No chain/target/match",
)


def _expected(err):
    low = (err or "").lower()
    return any(tok.lower() in low for tok in _EXPECTED_ERR)


def _apply(args, key, timeout=10, input_data=None):
    """执行写命令；失败（且非幂等分支）时限频记日志。返回是否「已到位」。

    注意：幂等分支的失败（如 -D 一条本就不存在的规则）说明目标状态已达成，
    返回 True；否则清理步骤会让调用方误以为失败而每轮重试（稳态 fork 反弹）。
    """
    rc, _out, err = _run(args, timeout=timeout, input_data=input_data)
    if rc == 0:
        return True
    if _expected(err):
        return True
    _report_failure(key, args, rc, err)
    return False


def _probe(args):
    """存在性探测（-C 等）；非 0 是正常分支，不记日志。"""
    rc, _out, _err = _run(args)
    return rc == 0


def _have(name):
    now = time.time()
    hit = _which_cache.get(name)
    if hit and now - hit[0] < _WHICH_TTL:
        return hit[1]
    ok = shutil.which(name) is not None
    _which_cache[name] = (now, ok)
    return ok


def available():
    """当前环境是否支持内核级封禁。"""
    geteuid = getattr(os, "geteuid", None)   # Windows 无该接口：直接视为不支持
    if geteuid is None or geteuid() != 0:
        return False
    return _have("ipset") and _have("iptables")


def _norm(cidr):
    """规范化为 ip_network；/32、/128 直接返回单地址字符串。"""
    try:
        net = ipaddress.ip_network(str(cidr).strip(), strict=False)
    except ValueError:
        return None
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address), net.version
    return str(net), net.version


def _ensure_sets(force=False):
    """创建 ipset 集合（幂等；不含 iptables 规则）。

    已确认存在时直接返回（稳态 0 fork）；force 用于审计发现集合丢失后重建。
    """
    global _sets_ok
    if _sets_ok and not force:
        return True
    ok = _apply(["ipset", "create", SET4, "hash:net", "timeout", "0", "-exist"],
                "ipset.create4")
    if _have("ip6tables"):
        ok = _apply(["ipset", "create", SET6, "hash:net", "family", "inet6",
                     "timeout", "0", "-exist"], "ipset.create6") and ok
    _sets_ok = ok
    return ok


def _ensure_drop():
    """确保 filter 表 FRPWAF_BLOCK 链与 DROP 规则就绪（幂等）。"""
    ok = True
    ok = _apply(["iptables", "-N", CHAIN], "iptables.N4") and ok
    if not _probe(["iptables", "-C", "INPUT", "-j", CHAIN]):
        ok = _apply(["iptables", "-I", "INPUT", "1", "-j", CHAIN], "iptables.hook4") and ok
    if not _probe(["iptables", "-C", CHAIN, "-m", "set", "--match-set", SET4,
                   "src", "-j", "DROP"]):
        ok = _apply(["iptables", "-A", CHAIN, "-m", "set", "--match-set", SET4,
                     "src", "-j", "DROP"], "iptables.drop4") and ok
    if _have("ip6tables"):
        ok = _apply(["ip6tables", "-N", CHAIN], "iptables.N6") and ok
        if not _probe(["ip6tables", "-C", "INPUT", "-j", CHAIN]):
            ok = _apply(["ip6tables", "-I", "INPUT", "1", "-j", CHAIN], "iptables.hook6") and ok
        if not _probe(["ip6tables", "-C", CHAIN, "-m", "set", "--match-set", SET6,
                       "src", "-j", "DROP"]):
            ok = _apply(["ip6tables", "-A", CHAIN, "-m", "set", "--match-set", SET6,
                         "src", "-j", "DROP"], "iptables.drop6") and ok
    return ok


def _clear_drop():
    """移除 DROP 规则（保留链与 INPUT 跳转，便于快速切回）。"""
    ok = True
    ok = _apply(["iptables", "-D", CHAIN, "-m", "set", "--match-set", SET4,
                 "src", "-j", "DROP"], "iptables.undrop4") and ok
    if _have("ip6tables"):
        ok = _apply(["ip6tables", "-D", CHAIN, "-m", "set", "--match-set", SET6,
                     "src", "-j", "DROP"], "iptables.undrop6") and ok
    return ok


def _redirect_rule(setname, port, block_port):
    return ["-m", "set", "--match-set", setname, "src", "-p", "tcp",
            "--dport", str(port), "-j", "REDIRECT", "--to-ports", str(block_port)]


def _rule_redirect(ipt, setname, port, block_port):
    """幂等下发一条 REDIRECT 规则（先 -C 再 -A）。"""
    rule = _redirect_rule(setname, port, block_port)
    if not _probe([ipt, "-t", "nat", "-C", NAT_CHAIN] + rule):
        return _apply([ipt, "-t", "nat", "-A", NAT_CHAIN] + rule, "iptables.redirect")
    return True


def _ensure_redirect(ports, block_port):
    """确保 nat 表 FRPWAF_REDIRECT 链与 REDIRECT 规则就绪（幂等）。

    被禁 IP 访问 frps HTTP 端口时，在 PREROUTING 阶段改道到拦截页服务；
    必须先摘除 DROP（nat 在 filter 之前，但改道后的包仍会在 INPUT 被 DROP 命中）。
    """
    ok = True
    ok = _apply(["iptables", "-t", "nat", "-N", NAT_CHAIN], "iptables.natN4") and ok
    if not _probe(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN]):
        ok = _apply(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", NAT_CHAIN],
                    "iptables.natHook4") and ok
    if _have("ip6tables"):
        ok = _apply(["ip6tables", "-t", "nat", "-N", NAT_CHAIN], "iptables.natN6") and ok
        if not _probe(["ip6tables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN]):
            ok = _apply(["ip6tables", "-t", "nat", "-I", "PREROUTING", "1", "-j", NAT_CHAIN],
                        "iptables.natHook6") and ok
    for p in ports:
        ok = _rule_redirect("iptables", SET4, p, block_port) and ok
        if _have("ip6tables"):
            ok = _rule_redirect("ip6tables", SET6, p, block_port) and ok
    return ok


def _clear_redirect():
    """移除 nat 表 REDIRECT 链与规则（幂等）。"""
    ok = True
    ok = _apply(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", NAT_CHAIN],
                "iptables.natDel4") and ok
    ok = _apply(["iptables", "-t", "nat", "-F", NAT_CHAIN], "iptables.natF4") and ok
    ok = _apply(["iptables", "-t", "nat", "-X", NAT_CHAIN], "iptables.natX4") and ok
    if _have("ip6tables"):
        ok = _apply(["ip6tables", "-t", "nat", "-D", "PREROUTING", "-j", NAT_CHAIN],
                    "iptables.natDel6") and ok
        ok = _apply(["ip6tables", "-t", "nat", "-F", NAT_CHAIN], "iptables.natF6") and ok
        ok = _apply(["ip6tables", "-t", "nat", "-X", NAT_CHAIN], "iptables.natX6") and ok
    return ok


def _mode(cfg):
    """内核层处置模式：drop（静默丢包）/ redirect（重定向到拦截页）/ off。"""
    if cfg.get("fw_sync_enabled", True):
        return "drop"
    if cfg.get("block_page_enabled", True):
        return "redirect"
    return "off"


def _redirect_ports(cfg):
    """REDIRECT 目标端口：显式配置优先，否则自动读取 frps vhostHTTPPort。

    显式配置为逗号分隔端口（normalize 已白名单化）；自动读取失败或为空时返回 []，
    调用方据此退化为 DROP（至少保证拦截）。
    """
    ports = []
    for tok in str(cfg.get("block_page_redirect_ports") or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            p = int(tok)
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535 and p not in ports:
            ports.append(p)
    if ports:
        return ports
    try:
        from . import frp
        ok, data = frp.load_config("frps")
        if ok and isinstance(data, dict):
            try:
                v = int(data.get("vhostHTTPPort") or 0)
            except (TypeError, ValueError):
                v = 0
            if 1 <= v <= 65535:
                ports.append(v)
    except Exception:
        pass
    return ports


# ---------------------------------------------------------------------------
# 规则记忆与审计
# ---------------------------------------------------------------------------
def _verify_rules(shape, ports, block_port):
    """轻量核对已下发规则是否仍在（只用 -C 探测，不写）。"""
    checks = []
    if shape == "drop":
        checks.append(["iptables", "-C", "INPUT", "-j", CHAIN])
        checks.append(["iptables", "-C", CHAIN, "-m", "set", "--match-set", SET4,
                       "src", "-j", "DROP"])
        if _have("ip6tables"):
            checks.append(["ip6tables", "-C", "INPUT", "-j", CHAIN])
            checks.append(["ip6tables", "-C", CHAIN, "-m", "set", "--match-set", SET6,
                           "src", "-j", "DROP"])
    elif shape == "redirect":
        checks.append(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN])
        for p in ports:
            checks.append(["iptables", "-t", "nat", "-C", NAT_CHAIN]
                          + _redirect_rule(SET4, p, block_port))
        if _have("ip6tables"):
            checks.append(["ip6tables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN])
            for p in ports:
                checks.append(["ip6tables", "-t", "nat", "-C", NAT_CHAIN]
                              + _redirect_rule(SET6, p, block_port))
    else:   # off：两条跳转都不该存在
        return not (_probe(["iptables", "-C", "INPUT", "-j", CHAIN])
                    or _probe(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN]))
    return all(_probe(c) for c in checks)


def _apply_rules(shape, ports, block_port):
    """按记忆化状态下发 filter/nat 规则；配置未变且审计通过时 0 fork。"""
    now = time.time()
    ports = tuple(ports)
    same = (_RULES["mode"] == shape and _RULES["ports"] == ports
            and _RULES["block_port"] == block_port)
    if same and _RULES["mode"] is not None:
        if now - _RULES["checked_at"] < VERIFY_INTERVAL:
            return True                      # 记忆命中：稳态 0 fork
        if _verify_rules(shape, ports, block_port):      # 到期审计：只做 -C 探测
            _RULES["checked_at"] = now
            return True
    if shape == "drop":
        ok = _clear_redirect()
        ok = _ensure_drop() and ok
    elif shape == "redirect":
        ok = _clear_drop()
        ok = _ensure_redirect(list(ports), block_port) and ok
    else:
        ok = _clear_drop()
        ok = _clear_redirect() and ok
    if ok:
        _RULES.update({"mode": shape, "ports": ports,
                       "block_port": block_port, "checked_at": now})
    else:
        # 下发未完全成功：仍记住形态，但把下一次重试拉长到 RULE_RETRY_INTERVAL。
        # 审计探测（-C）会发现缺口并重新下发，所以不能因为一次失败就每 10s
        # 重放一遍全部规则命令（那正是本次优化要消除的空转）。
        _RULES.update({"mode": shape, "ports": ports, "block_port": block_port,
                       "checked_at": now - VERIFY_INTERVAL + RULE_RETRY_INTERVAL})
    return ok


# ---------------------------------------------------------------------------
# 集合内容同步
# ---------------------------------------------------------------------------
def _members(setname):
    """返回 {member: timeout}，timeout<=0 表示永久。集合不存在时返回 None。"""
    rc, out, _ = _run(["ipset", "save", setname])
    if rc != 0:
        return None
    res = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "add" and parts[1] == setname:
            t = 0
            if "timeout" in parts:
                try:
                    t = int(parts[parts.index("timeout") + 1])
                except (ValueError, IndexError):
                    t = 0
            res[parts[2]] = t
    return res


def _abs_deadlines(cur, now):
    """内核真值（剩余 timeout）-> 绝对到期时间戳（0=永久）。"""
    res = {}
    for m, t in (cur or {}).items():
        t = int(t or 0)
        res[m] = 0 if t <= 0 else now + t
    return res


def _deadline_same(old, new, now):
    """两个绝对到期时刻是否可视为同一条目（性质一致且时长差在容差内）。"""
    old = int(old or 0)
    new = int(new or 0)
    if (old <= 0) != (new <= 0):
        return False                       # 永久 <-> 临时：必须重建
    if old <= 0:
        return True
    remaining = max(new - now, 0)
    tol = max(int(remaining * TIMEOUT_REFRESH_RATIO), TIMEOUT_REFRESH_MIN)
    return abs(new - old) <= tol


def _add_line(setname, member, deadline, now):
    if not deadline or deadline <= 0:
        return "add %s %s" % (setname, member)
    return "add %s %s timeout %d" % (setname, member, max(int(deadline - now), 1))


def _restore(setname, cmds):
    """一次事务下发差量；restore 不可用时退化为逐条。"""
    payload = ("\n".join(cmds) + "\n").encode("utf-8")
    rc, _out, err = _run(["ipset", "restore", "-exist"], input_data=payload)
    if rc == 0:
        return True
    if not _expected(err):
        _report_failure("ipset.restore." + setname, ["ipset", "restore", "-exist"],
                        rc, err)
    # 批量失败（如内核不支持 restore）：退化为逐条执行，保证同步仍然完成
    for line in cmds:
        arc, _o, aerr = _run(["ipset"] + line.split())
        if arc != 0:
            if not _expected(aerr):
                _report_failure("ipset." + line.split()[0], ["ipset"] + line.split(),
                                arc, aerr)
            return False
    return True


def _reconcile(setname, want, cur=None):
    """让集合内容与 want 一致，只下发差量；无需变更时 0 fork。

    setname : 集合名
    want    : {member: 绝对到期时间戳}，0 表示永久
    cur     : 可选，内核真值 {member: 剩余 timeout}（审计时传入）

    临时条目在「到期时刻变化超过 10%（且至少 5 秒）」时 del + add 重建：
    `ipset add -exist` 对已存在条目不会刷新 timeout，否则封禁被延长后内核会
    提前解封（应用层仍在拦，但失去内核层减少连接的价值）。
    """
    now = int(time.time())
    if cur is not None:
        base = _abs_deadlines(cur, now)
    else:
        memo = _MEMBERS.get(setname, _MISSING)
        if memo is _MISSING or memo is None:
            got = _members(setname)          # 首次同步或上次下发失败：读内核真值
            if got is None:
                _ensure_sets(force=True)
                got = _members(setname)
                if got is None:
                    return False
            base = _abs_deadlines(got, now)
        else:
            base = memo

    cmds = []
    for m, exp in base.items():
        if m in want:
            continue
        # 已到期也必须主动 del，不能指望集合自身的 per-entry timeout：
        # 那个 timeout 只保证「到点后不再命中」，但条目会留在集合里，
        # 而集合大小是有限的（且 ipset 不会自动清理已过期条目 —— 实际观测
        # 过内核里留下 9 条 expire_at 已过、timeout 仍在等的情况）。
        # 依赖内核 timeout 会导致 DB 与内核长期不一致。
        cmds.append("del %s %s" % (setname, m))
    for m, exp in want.items():
        old = base.get(m, _MISSING)
        if old is _MISSING:
            cmds.append(_add_line(setname, m, exp, now))
            continue
        if _deadline_same(old, exp, now):
            continue
        cmds.append("del %s %s" % (setname, m))
        cmds.append(_add_line(setname, m, exp, now))
    if not cmds:
        _MEMBERS[setname] = dict(want)
        return True
    if not _restore(setname, cmds):
        _MEMBERS[setname] = None             # 状态未知，下一轮重新读内核真值
        return False
    # 记忆更新：目标快照本身（含已到期但仍在内核里的条目由超时自行移除）
    _MEMBERS[setname] = dict(want)
    return True


def _sync_sets(want4, want6):
    """确保集合存在并下发差量；每 VERIFY_INTERVAL 秒做一次全量核对。"""
    global _sets_checked_at
    now = time.time()
    audit = (now - _sets_checked_at >= VERIFY_INTERVAL)
    ok = _ensure_sets()
    for setname, want in ((SET4, want4), (SET6, want6)):
        if setname == SET6 and not _have("ip6tables"):
            continue
        cur = None
        if audit:
            cur = _members(setname)          # 审计：与内核真值比对
            if cur is None:
                _ensure_sets(force=True)
                cur = _members(setname)
                if cur is None:
                    ok = False
                    continue
        ok = _reconcile(setname, want, cur=cur) and ok
    if audit and ok:
        _sets_checked_at = now
    return ok


def _member(net):
    """网络 -> ipset 成员字符串（/32、/128 用裸地址）。"""
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def _apply_whitelist(bucket, wnets):
    """从 bucket({member: 到期时间戳}) 中剔除白名单覆盖的地址段。

    仅「成员落在白名单内」直接删除是不够的：若成员是 CIDR（如 10.0.0.0/8）
    而白名单只放了其中某个 IP/子网（如 10.0.0.5），整段仍会下发到内核，
    导致白名单地址在内核层被 DROP（应用层放行、内核拦截）。故这里做 CIDR
    差集：把命中白名单的成员拆成「原段 - 白名单段」后重新放入。
    """
    for m in list(bucket):
        try:
            net = ipaddress.ip_network(m, strict=False)
        except ValueError:
            continue
        t = bucket[m]
        remaining = [net]
        for w in wnets:
            if w.version != net.version:
                continue
            newr = []
            for n in remaining:
                if not n.overlaps(w):
                    newr.append(n)
                elif n.subnet_of(w):
                    pass                      # 整段都在白名单内 -> 丢弃
                else:
                    newr.extend(n.address_exclude(w))   # w 在 n 内 -> 取差集
            remaining = newr
        if len(remaining) == 1 and _member(remaining[0]) == m:
            continue                          # 未变化
        bucket.pop(m, None)
        for n in remaining:
            bucket[_member(n)] = t


def _build_want(permanent, bans, whitelist=None):
    """构建目标快照 {member: 绝对到期时间戳}（0 = 永久），按 v4/v6 分桶。"""
    want4, want6 = {}, {}
    now = int(time.time())
    # 先放临时封禁（带到期时间；单 IP 或 CIDR 均可）
    for b in (bans or []):
        ip = (b.get("ip") or "").strip() if isinstance(b, dict) else ""
        if not ip:
            continue
        try:
            net = ipaddress.ip_network(ip, strict=False)
        except ValueError:
            continue
        try:
            exp = int(b.get("expire_at") or 0)
        except (TypeError, ValueError):
            continue
        if exp <= now:
            continue  # 已到期，交给集合自身超时移除
        (want6 if net.version == 6 else want4)[_member(net)] = exp
    # 永久黑名单最后写入，始终为永久（timeout 0），不被临时封禁覆盖
    for cidr in (permanent or []):
        n = _norm(cidr)
        if not n:
            continue
        member, ver = n
        (want6 if ver == 6 else want4)[member] = 0

    # 白名单优先：把落在白名单内的成员按 CIDR 差集剔除
    if whitelist:
        wnets = []
        for cidr in whitelist:
            try:
                wnets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        if wnets:
            _apply_whitelist(want4, wnets)
            _apply_whitelist(want6, wnets)
    return want4, want6


def sync(permanent, bans, whitelist=None):
    """同步封禁集合。

    permanent : 永久黑名单 CIDR 列表
    bans      : 生效中的临时封禁（含 ip / expire_at）
    whitelist : 白名单 CIDR，命中的成员不下发到内核（白名单优先）

    快照构建与内核下发全程持 _sync_lock：并发调用时后到者排队执行，
    以最新入参重建快照，避免旧快照覆盖新结果（解封后被回填的竞态）。
    """
    if not available():
        return False
    with _sync_lock:
        want4, want6 = _build_want(permanent, bans, whitelist)
        with _lock:
            return _sync_sets(want4, want6)


def sync_from_store():
    """从数据库读取黑名单与生效封禁，并按开关决定内核层处置。

    必须与引擎决策保持一致：内核层是「应用层拦截」的加速手段，其拦截集合
    应当等于应用层实际会拒绝的集合，否则会出现：
      - blacklist_enabled 关闭后，应用层放行、内核却仍下发黑名单 -> 仍被丢包；
      - whitelist_enabled 关闭后，内核仍按白名单剔除成员 -> 黑名单漏封。
    故这里按开关裁剪：黑名单开关关闭则不下发永久黑名单；白名单开关关闭则
    不把白名单作为剔除条件（临时封禁不受名单开关影响，始终下发）。

    处置模式（与需求 7 对应）：
      - fw_sync_enabled 开            -> DROP（静默丢包，无页面）
      - 关 + block_page_enabled 开    -> nat REDIRECT 到拦截页服务（展示页面）
      - 都关                          -> 清理内核规则（仅应用层 reject）
    失败不回滚数据库（数据库是事实源，内核是派生状态，由后台轮询兜底）。

    稳态（名单与配置都没变）下本函数不产生任何 subprocess：
    集合比差异走 _MEMBERS 记忆，规则比形态走 _RULES 记忆，只在配置变化、
    下发失败或每 VERIFY_INTERVAL 秒的审计时才真正调用 ipset/iptables。
    """
    if not available():
        return False
    from . import config, store
    with _sync_lock:
        cfg = config.get()
        mode = _mode(cfg)
        try:
            block_port = int(cfg.get("block_page_port") or 7081)
        except (TypeError, ValueError):
            block_port = 7081
        if mode == "off":
            with _lock:
                _apply_rules("off", (), 0)
            return False
        ports = ()
        shape = "drop"
        if mode == "redirect":
            ports = tuple(_redirect_ports(cfg))
            # 无可用目标端口：退化为 DROP，至少保证拦截
            shape = "redirect" if ports else "drop"
        perms = []
        if cfg.get("blacklist_enabled", True):
            perms = [r["cidr"] for r in store._query("SELECT cidr FROM ip_list WHERE list_type='black'")]
        whites = []
        if cfg.get("whitelist_enabled", False):
            whites = [r["cidr"] for r in store._query("SELECT cidr FROM ip_list WHERE list_type='white'")]
        bans = store.active_bans()
        want4, want6 = _build_want(perms, bans, whites)
        ok = True
        with _lock:
            ok = _sync_sets(want4, want6)
            ok = _apply_rules(shape, ports, block_port) and ok
        return ok


def remove(ip):
    """从内核集合中移除单个地址或 CIDR（解封时调用）。"""
    if not available():
        return False
    try:
        net = ipaddress.ip_network((ip or "").strip(), strict=False)
    except ValueError:
        return False
    setname = SET6 if net.version == 6 else SET4
    member = str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    with _sync_lock:
        rc, _out, err = _run(["ipset", "del", setname, member, "-exist"])
        if rc == 0:
            memo = _MEMBERS.get(setname)
            if isinstance(memo, dict):
                memo.pop(member, None)
            elif memo is None:
                pass                      # 已是「未知」状态，保持
        else:
            if not _expected(err):
                _report_failure("ipset.del." + setname,
                                ["ipset", "del", setname, member, "-exist"], rc, err)
            # 内核可能有残留：标记未知，下一次同步按真值重新对齐
            _MEMBERS[setname] = None
    return True


def invalidate():
    """作废本进程的同步记忆，强制下一次同步按内核真值重新对齐。

    多进程场景用：宝塔插件端（`frpwaf_main.py`）也会调 `sync_from_store()` /
    `teardown()`，两个进程各有独立记忆。一方改动内核后，另一方调用本函数
    才能立即重新读真值（不调也不会错，只是要等一个审计周期 VERIFY_INTERVAL，
    此时内核层可能短暂缺少/多出条目，应用层判定不受影响）。
    """
    global _sets_checked_at
    with _sync_lock:
        _MEMBERS.clear()
        _RULES.update({"mode": None, "ports": (), "block_port": 0, "checked_at": 0.0})
        _sets_checked_at = 0.0


def flush():
    """清空集合内所有条目（保留集合与规则）。"""
    if not available():
        return False
    with _sync_lock:
        _run(["ipset", "flush", SET4])
        if _have("ip6tables"):
            _run(["ipset", "flush", SET6])
        _MEMBERS.clear()       # 记忆作废：下一次同步重新读内核真值
    return True


def teardown():
    """移除 iptables 规则、链与集合（卸载时调用）。"""
    global _sets_ok, _sets_checked_at
    # 不在缺 iptables 时提前返回：只要 ipset 在，集合照样要删，
    # 否则残留集合会一直引用着内核资源（且卸载后无法再通过本程序清理）。
    has_ipt = _have("iptables")
    has_ipset = _have("ipset")
    with _sync_lock:
        if has_ipt:
            _clear_drop()
            _clear_redirect()
            _run(["iptables", "-D", "INPUT", "-j", CHAIN])
            _run(["iptables", "-F", CHAIN])
            _run(["iptables", "-X", CHAIN])
            if _have("ip6tables"):
                _run(["ip6tables", "-D", "INPUT", "-j", CHAIN])
                _run(["ip6tables", "-F", CHAIN])
                _run(["ip6tables", "-X", CHAIN])
        if has_ipset:
            _run(["ipset", "destroy", SET4])
            _run(["ipset", "destroy", SET6])
        # 内核对象已全部删除：记忆一并清空，避免后续调用误判「已下发」
        _MEMBERS.clear()
        _RULES.update({"mode": None, "ports": (), "block_port": 0, "checked_at": 0.0})
        _sets_ok = False
        _sets_checked_at = 0.0
    return has_ipt or has_ipset


def status():
    """返回给界面展示的状态。"""
    info = {"available": available(), "enabled": False, "mode": "off",
            "set4": 0, "set6": 0, "rule": False,
            "redirect": False, "redirect_ports": []}
    if not info["available"]:
        return info
    try:
        from . import config
        cfg = config.get()
        info["mode"] = _mode(cfg)
        info["enabled"] = info["mode"] != "off"
        info["redirect_ports"] = _redirect_ports(cfg)
    except Exception:
        pass
    for name, key in ((SET4, "set4"), (SET6, "set6")):
        rc, out, _ = _run(["ipset", "list", name])
        if rc == 0:
            for line in out.splitlines():
                if line.startswith("Number of entries:"):
                    try:
                        info[key] = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
    rc, _, _ = _run(["iptables", "-C", "INPUT", "-j", CHAIN])
    info["rule"] = (rc == 0)
    rc, _, _ = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN])
    info["redirect"] = (rc == 0)
    return info
