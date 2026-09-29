#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 配置管理

配置保存在 data/frpwaf.json，首次运行自动生成（含默认管理员 admin/123456）。
"""
import json
import os
import secrets
import threading
import time

BASE = os.environ.get("FRPWAF_HOME", "/opt/frpwaf")
DATA_DIR = os.path.join(BASE, "data")
DB_PATH = os.path.join(DATA_DIR, "frpwaf.db")
CONF_PATH = os.path.join(DATA_DIR, "frpwaf.json")
LOG_PATH = os.path.join(DATA_DIR, "frpwaf.log")
PID_PATH = os.path.join(DATA_DIR, "frpwaf.pid")

DEFAULTS = {
    # 管理/WAF 监听地址（frps httpPlugins 会回调到这里）
    "http_addr": "0.0.0.0",
    "http_port": 7080,
    # 是否启用「网页端」（WAF 管理面板）。关闭后仅停用网页访问（/ 与 /api/*），
    # frps 回调（/frp/handler）与 WAF 防护照常运行，可从宝塔插件端随时重新开启。
    "web_enabled": True,
    # 管理员账号（默认 admin / 123456，安装后请在面板内及时修改）
    "admin_user": "admin",
    "admin_password": "123456",
    # 会话签名密钥（首次生成后固定）
    "secret": "",
    # 名单开关
    "blacklist_enabled": True,
    "whitelist_enabled": False,
    # 自动封禁（按来源 IP 在窗口内的连接次数）
    # 注意：frp 代理端口（尤其 HTTP/HTTPS vhost）天然会有大量并发连接，
    # 阈值过低会误封正常用户，默认关闭，按需在面板中开启并谨慎设置阈值。
    "auto_ban_enabled": False,
    "auto_ban_window": 60,
    "auto_ban_threshold": 200,
    "auto_ban_seconds": 600,
    # 简单限速（单 IP 每秒新连接数上限，0 表示关闭）
    "rate_limit_enabled": False,
    "rate_limit_per_sec": 0,
    # 日志保留条数
    "log_max_rows": 50000,
    # 内核级封禁：把黑名单/封禁同步到 ipset+iptables，在内核直接丢包，
    # 被禁 IP 连不到 frps，连接计数不再增长（需要 root + ipset/iptables）
    "fw_sync_enabled": True,
    # ---- AI 自动 IP 审查 ----
    "ai_enabled": False,
    "ai_protocol": "openai",              # openai / anthropic
    "ai_base_url": "",                    # 如 http://127.0.0.1:3000
    "ai_api_key": "",
    "ai_model": "claude-haiku-4.5",
    "ai_interval": 300,                   # 审查间隔（秒），最短 60
    "ai_window": 300,                     # 每次审查分析的最近时间窗口（秒）
    "ai_min_conns": 20,                   # 窗口内连接数低于此值的 IP 不送审
    "ai_max_ips": 20,                     # 每次最多送审的 IP 数
    "ai_auto_ban": True,                  # AI 判定为恶意时是否自动封禁
    "ai_ban_seconds": 1800,               # AI 封禁时长（秒）
    "ai_timeout": 120,                    # 单次模型调用超时（秒）
    "ai_last_run": 0,                     # 上次运行时间戳
    "ai_last_result": "",                 # 上次结果摘要
}


def _ensure_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def load():
    _ensure_dir()
    cfg = dict(DEFAULTS)
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    if not cfg.get("secret"):
        cfg["secret"] = secrets.token_hex(32)
        save(cfg)
    return cfg


def save(cfg):
    _ensure_dir()
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONF_PATH)
    try:
        os.chmod(CONF_PATH, 0o600)
    except Exception:
        pass
    invalidate()  # 写盘后立即失效缓存


# 短 TTL 内存缓存：连接决策路径每次都要读配置，避免每连接都读盘。
# 管理端修改后调用 invalidate() 立即失效，保证改完即生效。
_cache = {"cfg": None, "at": 0.0}
_cache_lock = threading.Lock()
CACHE_TTL = 1.0  # 秒


def invalidate():
    """使配置缓存立即失效（写配置后调用）。"""
    with _cache_lock:
        _cache["cfg"] = None
        _cache["at"] = 0.0


def get():
    """带短 TTL 缓存的读取；未过期直接返回内存副本，过期则重新加载。"""
    now = time.time()
    with _cache_lock:
        if _cache["cfg"] is not None and now - _cache["at"] < CACHE_TTL:
            return dict(_cache["cfg"])
    cfg = load()
    with _cache_lock:
        _cache["cfg"] = dict(cfg)
        _cache["at"] = time.time()
    return cfg
