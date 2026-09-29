#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 决策引擎

决策顺序：
  1. 白名单命中 -> allow（白名单优先，直接放行）
  2. 黑名单命中 -> reject
  3. 自动封禁（ban_log 未过期）-> reject
  4. 限速超阈值 -> reject
  5. 自动封禁触发判断（窗口内次数达阈值则写入 ban_log 并 reject）
  6. 其余 -> allow
"""
import ipaddress
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
    return cnt > per_sec


def _is_banned(ip):
    # 复用 store 的封禁缓存集合判断（单 IP / CIDR），避免每次连接全表扫描
    try:
        return store.is_banned(ip)
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

    # 4. 限速
    if cfg.get("rate_limit_enabled") and _rate_limited(remote_ip, int(cfg.get("rate_limit_per_sec") or 0)):
        return False, "rate_limit"

    # 5. 自动封禁触发判断（基于最近窗口的连接数，含本次之前的记录）
    if cfg.get("auto_ban_enabled"):
        window = int(cfg.get("auto_ban_window") or 60)
        threshold = int(cfg.get("auto_ban_threshold") or 0)
        if threshold > 0 and store.recent_count_by_ip(remote_ip, window) >= threshold:
            store.add_ban(remote_ip, "auto: %d conns/%ds" % (threshold, window),
                          int(cfg.get("auto_ban_seconds") or 600))
            return False, "auto_ban"

    return True, ""


def auto_release():
    """释放已到期的封禁（由后台线程周期调用）。返回被释放的记录列表。"""
    released = store.expired_bans()
    for b in released:
        store.release_ban(b["id"])
    return released
