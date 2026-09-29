#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - IP 归属地查询

优先使用本机已有的 GeoLite2 mmdb（宝塔自带，含 国家/省/市/ISP/经纬度）。
纯离线、无网络请求、带内存缓存。
"""
import ipaddress
import os
import threading

from . import config

# 候选数据库路径（按顺序探测）
CANDIDATES = [
    "/www/server/panel/config/GeoLite2-City.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    os.path.join(config.DATA_DIR, "GeoLite2-City.mmdb"),
]

_reader = None
_reader_tried = False
_cache = {}
_lock = threading.Lock()
MAX_CACHE = 20000

UNKNOWN = {"country": "", "province": "", "city": "", "isp": "", "lat": None, "lon": None}


def _open():
    global _reader, _reader_tried
    if _reader is not None or _reader_tried:
        return _reader
    _reader_tried = True
    try:
        import maxminddb
    except ImportError:
        return None
    for p in CANDIDATES:
        if os.path.exists(p):
            try:
                _reader = maxminddb.open_database(p)
                return _reader
            except Exception:
                continue
    return None


def db_info():
    r = _open()
    if r is None:
        return {"available": False, "path": ""}
    for p in CANDIDATES:
        if os.path.exists(p):
            try:
                return {"available": True, "path": p, "size": os.path.getsize(p)}
            except OSError:
                break
    return {"available": True, "path": ""}


def _is_private(ip):
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local or o.is_reserved or o.is_multicast
    except ValueError:
        return True


def lookup(ip):
    """返回 {'country','province','city','isp','lat','lon','text'}"""
    if not ip:
        return dict(UNKNOWN, text="")
    with _lock:
        if ip in _cache:
            return _cache[ip]

    result = dict(UNKNOWN)
    if _is_private(ip):
        result["country"] = "内网"
        result["text"] = "内网 IP"
    else:
        r = _open()
        rec = None
        if r is not None:
            try:
                rec = r.get(ip)
            except Exception:
                rec = None
        if rec:
            # 兼容宝塔自定义结构 {"country": {...}} 与标准结构
            c = rec.get("country") if isinstance(rec, dict) else None
            if isinstance(c, dict):
                result["country"] = c.get("country", "") or ""
                result["province"] = c.get("province", "") or ""
                result["city"] = c.get("city", "") or ""
                result["isp"] = c.get("operator", "") or ""
                result["lat"] = c.get("latitude")
                result["lon"] = c.get("longitude")
            else:
                # 标准 GeoLite2 结构
                names = (rec.get("country") or {}).get("names") or {}
                result["country"] = names.get("zh-CN") or names.get("en") or ""
                sub = (rec.get("subdivisions") or [{}])[0].get("names") or {}
                result["province"] = sub.get("zh-CN") or sub.get("en") or ""
                cnames = (rec.get("city") or {}).get("names") or {}
                result["city"] = cnames.get("zh-CN") or cnames.get("en") or ""
                loc = rec.get("location") or {}
                result["lat"] = loc.get("latitude")
                result["lon"] = loc.get("longitude")
        parts = [x for x in (result["country"], result["province"], result["city"]) if x]
        result["text"] = " ".join(parts) if parts else "未知"
        if result["isp"]:
            result["text"] += " · " + result["isp"]

    with _lock:
        if len(_cache) > MAX_CACHE:
            _cache.clear()
        _cache[ip] = result
    return result


def enrich(rows, ip_field="ip"):
    """给一批记录补充 geo 字段（原地）。"""
    for row in rows:
        g = lookup(row.get(ip_field, ""))
        row["geo"] = g.get("text", "")
        row["country"] = g.get("country", "")
        row["province"] = g.get("province", "")
        row["city"] = g.get("city", "")
        row["isp"] = g.get("isp", "")
    return rows
