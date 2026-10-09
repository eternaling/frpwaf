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
NAT_CHAIN = "FRPWAF_REDIRECT"

_lock = threading.Lock()
# 全量同步串行锁：从「读库构建快照」到「下发内核」全程互斥。
# 否则并发同步（如引擎封禁线程 + 后台轮询 + 面板手动同步）中，持旧快照的
# 调用可能后于新快照执行，把已解封条目重新写回内核（写覆盖竞态）。
_sync_lock = threading.RLock()


def _run(args, timeout=10, input_data=None):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           input=input_data, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", str(e)


def _have(name):
    return shutil.which(name) is not None


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


def _ensure_sets():
    """创建 ipset 集合（幂等；不含 iptables 规则）。"""
    _run(["ipset", "create", SET4, "hash:net", "timeout", "0", "-exist"])
    if _have("ip6tables"):
        _run(["ipset", "create", SET6, "hash:net", "family", "inet6", "timeout", "0", "-exist"])


def _ensure_drop():
    """确保 filter 表 FRPWAF_BLOCK 链与 DROP 规则就绪（幂等）。"""
    _run(["iptables", "-N", CHAIN])
    rc, _, _ = _run(["iptables", "-C", "INPUT", "-j", CHAIN])
    if rc != 0:
        _run(["iptables", "-I", "INPUT", "1", "-j", CHAIN])
    rc, _, _ = _run(["iptables", "-C", CHAIN, "-m", "set", "--match-set", SET4, "src", "-j", "DROP"])
    if rc != 0:
        _run(["iptables", "-A", CHAIN, "-m", "set", "--match-set", SET4, "src", "-j", "DROP"])
    if _have("ip6tables"):
        _run(["ip6tables", "-N", CHAIN])
        rc, _, _ = _run(["ip6tables", "-C", "INPUT", "-j", CHAIN])
        if rc != 0:
            _run(["ip6tables", "-I", "INPUT", "1", "-j", CHAIN])
        rc, _, _ = _run(["ip6tables", "-C", CHAIN, "-m", "set", "--match-set", SET6, "src", "-j", "DROP"])
        if rc != 0:
            _run(["ip6tables", "-A", CHAIN, "-m", "set", "--match-set", SET6, "src", "-j", "DROP"])


def _clear_drop():
    """移除 DROP 规则（保留链与 INPUT 跳转，便于快速切回）。"""
    _run(["iptables", "-D", CHAIN, "-m", "set", "--match-set", SET4, "src", "-j", "DROP"])
    if _have("ip6tables"):
        _run(["ip6tables", "-D", CHAIN, "-m", "set", "--match-set", SET6, "src", "-j", "DROP"])


def _rule_redirect(ipt, setname, port, block_port):
    """幂等下发一条 REDIRECT 规则（先 -C 再 -A）。"""
    rule = ["-m", "set", "--match-set", setname, "src", "-p", "tcp",
            "--dport", str(port), "-j", "REDIRECT", "--to-ports", str(block_port)]
    rc, _, _ = _run([ipt, "-t", "nat", "-C", NAT_CHAIN] + rule)
    if rc != 0:
        _run([ipt, "-t", "nat", "-A", NAT_CHAIN] + rule)


def _ensure_redirect(ports, block_port):
    """确保 nat 表 FRPWAF_REDIRECT 链与 REDIRECT 规则就绪（幂等）。

    被禁 IP 访问 frps HTTP 端口时，在 PREROUTING 阶段改道到拦截页服务；
    必须先摘除 DROP（nat 在 filter 之前，但改道后的包仍会在 INPUT 被 DROP 命中）。
    """
    _run(["iptables", "-t", "nat", "-N", NAT_CHAIN])
    rc, _, _ = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN])
    if rc != 0:
        _run(["iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", NAT_CHAIN])
    if _have("ip6tables"):
        _run(["ip6tables", "-t", "nat", "-N", NAT_CHAIN])
        rc, _, _ = _run(["ip6tables", "-t", "nat", "-C", "PREROUTING", "-j", NAT_CHAIN])
        if rc != 0:
            _run(["ip6tables", "-t", "nat", "-I", "PREROUTING", "1", "-j", NAT_CHAIN])
    for p in ports:
        _rule_redirect("iptables", SET4, p, block_port)
        if _have("ip6tables"):
            _rule_redirect("ip6tables", SET6, p, block_port)


def _clear_redirect():
    """移除 nat 表 REDIRECT 链与规则（幂等）。"""
    _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", NAT_CHAIN])
    _run(["iptables", "-t", "nat", "-F", NAT_CHAIN])
    _run(["iptables", "-t", "nat", "-X", NAT_CHAIN])
    if _have("ip6tables"):
        _run(["ip6tables", "-t", "nat", "-D", "PREROUTING", "-j", NAT_CHAIN])
        _run(["ip6tables", "-t", "nat", "-F", NAT_CHAIN])
        _run(["ip6tables", "-t", "nat", "-X", NAT_CHAIN])


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
    """让集合内容与 want({member: timeout}) 一致。timeout<=0 表示永久。

    批量提交：`ipset restore` 一次事务完成增删（原实现逐条 spawn ipset 命令，
    集合较大时进程风暴）；restore 内容里的 `del` 对不存在成员不报错，
    增删顺序为「先删后加」，与逐条语义一致。
    """
    cur = _members(setname)
    if cur is None:
        _run(["ipset", "create", setname, "hash:net", "timeout", "0", "-exist"])
        cur = _members(setname) or {}
    cmds = []
    for m in list(cur):
        if m not in want:
            cmds.append("del %s %s" % (setname, m))
    for m, t in want.items():
        permanent = (not t) or t <= 0
        if m in cur:
            cur_perm = (cur[m] or 0) <= 0
            if cur_perm == permanent:
                continue  # 已存在且性质一致
            cmds.append("del %s %s" % (setname, m))  # 永久/临时 变更，重建
        if permanent:
            cmds.append("add %s %s" % (setname, m))
        else:
            cmds.append("add %s %s timeout %d" % (setname, m, int(t)))
    if not cmds:
        return
    payload = ("\n".join(cmds) + "\n").encode("utf-8")
    rc, _, err = _run(["ipset", "restore", "-exist"], input_data=payload)
    if rc != 0:
        # 批量失败（如内核不支持 restore）：退化为逐条执行，保证同步仍然完成
        for line in cmds:
            _run(["ipset"] + line.split())


def _member(net):
    """网络 -> ipset 成员字符串（/32、/128 用裸地址）。"""
    if net.prefixlen == net.max_prefixlen:
        return str(net.network_address)
    return str(net)


def _apply_whitelist(bucket, wnets):
    """从 bucket({member: timeout}) 中剔除白名单覆盖的地址段。

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
            (want6 if net.version == 6 else want4)[_member(net)] = t
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

        with _lock:
            _ensure_sets()
            _reconcile(SET4, want4)
            if _have("ip6tables"):
                _reconcile(SET6, want6)
    return True


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
    失败不回滚数据库（数据库是事实源，内核是派生状态，由后台 10s 轮询兜底）。
    """
    if not available():
        return False
    from . import config, store
    with _sync_lock:
        cfg = config.get()
        mode = _mode(cfg)
        if mode == "off":
            _clear_drop()
            _clear_redirect()
            return False
        perms = []
        if cfg.get("blacklist_enabled", True):
            perms = [r["cidr"] for r in store._query("SELECT cidr FROM ip_list WHERE list_type='black'")]
        whites = []
        if cfg.get("whitelist_enabled", False):
            whites = [r["cidr"] for r in store._query("SELECT cidr FROM ip_list WHERE list_type='white'")]
        bans = store.active_bans()
        ok = sync(perms, bans, whites)   # 填充 ipset（白名单差集在 sync 内完成）
        try:
            block_port = int(cfg.get("block_page_port") or 7081)
        except (TypeError, ValueError):
            block_port = 7081
        with _lock:
            _ensure_sets()
            if mode == "drop":
                _clear_redirect()
                _ensure_drop()
            else:  # redirect
                ports = _redirect_ports(cfg)
                if ports:
                    # 先摘 DROP：nat 在 filter 之前，但改道后的包仍会在 INPUT 被 DROP 命中
                    _clear_drop()
                    _ensure_redirect(ports, block_port)
                else:
                    # 无可用目标端口：退化为 DROP，至少保证拦截
                    _clear_redirect()
                    _ensure_drop()
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
    with _sync_lock:
        _clear_drop()
        _clear_redirect()
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
