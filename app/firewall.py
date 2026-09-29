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
"""
import ipaddress
import os
import shutil
import subprocess
import threading
import time

SET4 = "frpwaf_block"
SET6 = "frpwaf_block6"
CHAIN = "FRPWAF_BLOCK"

_lock = threading.Lock()


def _run(args, timeout=10):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", str(e)


def _have(name):
    return shutil.which(name) is not None


def available():
    """当前环境是否支持内核级封禁。"""
    try:
        if os.geteuid() != 0:
            return False
    except AttributeError:
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


def _ensure():
    """确保集合、链、规则就绪（幂等）。"""
    _run(["ipset", "create", SET4, "hash:net", "timeout", "0", "-exist"])
    # 链
    _run(["iptables", "-N", CHAIN])
    rc, _, _ = _run(["iptables", "-C", "INPUT", "-j", CHAIN])
    if rc != 0:
        _run(["iptables", "-I", "INPUT", "1", "-j", CHAIN])
    rc, _, _ = _run(["iptables", "-C", CHAIN, "-m", "set", "--match-set", SET4, "src", "-j", "DROP"])
    if rc != 0:
        _run(["iptables", "-A", CHAIN, "-m", "set", "--match-set", SET4, "src", "-j", "DROP"])
    # IPv6（可选）
    if _have("ip6tables"):
        _run(["ipset", "create", SET6, "hash:net", "family", "inet6", "timeout", "0", "-exist"])
        _run(["ip6tables", "-N", CHAIN])
        rc, _, _ = _run(["ip6tables", "-C", "INPUT", "-j", CHAIN])
        if rc != 0:
            _run(["ip6tables", "-I", "INPUT", "1", "-j", CHAIN])
        rc, _, _ = _run(["ip6tables", "-C", CHAIN, "-m", "set", "--match-set", SET6, "src", "-j", "DROP"])
        if rc != 0:
            _run(["ip6tables", "-A", CHAIN, "-m", "set", "--match-set", SET6, "src", "-j", "DROP"])


def _members(setname):
    """返回 {member: timeout}，timeout<=0 表示永久。"""
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


def _reconcile(setname, want):
    """让集合内容与 want({member: timeout}) 一致。timeout<=0 表示永久。"""
    cur = _members(setname)
    if cur is None:
        _run(["ipset", "create", setname, "hash:net", "timeout", "0", "-exist"])
        cur = _members(setname) or {}
    for m, t in want.items():
        permanent = (not t) or t <= 0
        if m in cur:
            cur_perm = (cur[m] or 0) <= 0
            if cur_perm == permanent:
                continue  # 已存在且性质一致
            _run(["ipset", "del", setname, m, "-exist"])  # 永久/临时 变更，重建
        if permanent:
            _run(["ipset", "add", setname, m, "-exist"])
        else:
            _run(["ipset", "add", setname, m, "timeout", str(int(t)), "-exist"])
    for m in list(cur):
        if m not in want:
            _run(["ipset", "del", setname, m, "-exist"])


def _member_in(member, net):
    """member（单地址或 CIDR）是否落在 net 内。"""
    try:
        return ipaddress.ip_address(member) in net
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(member, strict=False).subnet_of(net)
    except (ValueError, AttributeError):
        return False


def sync(permanent, bans, whitelist=None):
    """同步封禁集合。

    permanent : 永久黑名单 CIDR 列表
    bans      : 生效中的临时封禁（含 ip / expire_at）
    whitelist : 白名单 CIDR，命中的成员不下发到内核（白名单优先）
    """
    if not available():
        return False
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
        t = int(b.get("expire_at") or 0) - now
        if t <= 0:
            continue  # 已到期，交给集合自身超时移除
        if net.prefixlen == net.max_prefixlen:
            member = str(net.network_address)
        else:
            member = str(net)
        (want6 if net.version == 6 else want4)[member] = t
    # 永久黑名单最后写入，始终为永久（timeout 0），不被临时封禁覆盖
    for cidr in (permanent or []):
        n = _norm(cidr)
        if not n:
            continue
        member, ver = n
        (want6 if ver == 6 else want4)[member] = 0

    # 白名单优先：剔除落在白名单内的成员
    if whitelist:
        for cidr in whitelist:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            for bucket in (want4, want6):
                for m in list(bucket):
                    if _member_in(m, net):
                        bucket.pop(m, None)

    with _lock:
        _ensure()
        _reconcile(SET4, want4)
        if _have("ip6tables"):
            _reconcile(SET6, want6)
    return True


def sync_from_store():
    """从数据库读取黑名单与生效封禁并同步。

    必须与引擎决策保持一致：内核层是「应用层拦截」的加速手段，其拦截集合
    应当等于应用层实际会拒绝的集合，否则会出现：
      - blacklist_enabled 关闭后，应用层放行、内核却仍下发黑名单 -> 仍被丢包；
      - whitelist_enabled 关闭后，内核仍按白名单剔除成员 -> 黑名单漏封。
    故这里按开关裁剪：黑名单开关关闭则不下发永久黑名单；白名单开关关闭则
    不把白名单作为剔除条件（临时封禁不受名单开关影响，始终下发）。
    """
    if not available():
        return False
    from . import config, store
    cfg = config.get()
    perms = []
    if cfg.get("blacklist_enabled", True):
        perms = [r["cidr"] for r in store._query("SELECT cidr FROM ip_list WHERE list_type='black'")]
    whites = []
    if cfg.get("whitelist_enabled", False):
        whites = [r["cidr"] for r in store._query("SELECT cidr FROM ip_list WHERE list_type='white'")]
    bans = store.active_bans()
    return sync(perms, bans, whites)


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
    _run(["ipset", "del", setname, member, "-exist"])
    return True


def flush():
    """清空集合内所有条目（保留集合与规则）。"""
    if not available():
        return False
    _run(["ipset", "flush", SET4])
    if _have("ip6tables"):
        _run(["ipset", "flush", SET6])
    return True


def teardown():
    """移除 iptables 规则、链与集合（卸载时调用）。"""
    if not _have("iptables"):
        return False
    _run(["iptables", "-D", "INPUT", "-j", CHAIN])
    _run(["iptables", "-F", CHAIN])
    _run(["iptables", "-X", CHAIN])
    if _have("ip6tables"):
        _run(["ip6tables", "-D", "INPUT", "-j", CHAIN])
        _run(["ip6tables", "-F", CHAIN])
        _run(["ip6tables", "-X", CHAIN])
    _run(["ipset", "destroy", SET4])
    _run(["ipset", "destroy", SET6])
    return True


def status():
    """返回给界面展示的状态。"""
    info = {"available": available(), "enabled": False,
            "set4": 0, "set6": 0, "rule": False}
    if not info["available"]:
        return info
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
    return info
