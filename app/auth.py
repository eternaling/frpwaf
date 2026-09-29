#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 认证与会话

会话令牌 = base64(payload) + "." + HMAC-SHA256(payload, secret)
payload = {"u": user, "exp": 过期时间戳}
无需数据库，进程重启后旧会话自动失效（secret 固定时仍有效）。
"""
import base64
import hashlib
import hmac
import json
import time

from . import config

COOKIE_NAME = "frpwaf_sid"
SESSION_TTL = 12 * 3600


def _sign(payload_bytes, secret):
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


def create_token(user):
    cfg = config.get()
    payload = json.dumps({"u": user, "exp": int(time.time()) + SESSION_TTL}).encode()
    b = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return b + "." + _sign(payload, cfg["secret"])


def verify_token(token):
    if not token or "." not in token:
        return None
    b, sig = token.rsplit(".", 1)
    try:
        pad = "=" * (-len(b) % 4)
        payload = base64.urlsafe_b64decode(b + pad)
    except Exception:
        return None
    cfg = config.get()
    if not hmac.compare_digest(sig, _sign(payload, cfg["secret"])):
        return None
    try:
        data = json.loads(payload)
    except Exception:
        return None
    if int(data.get("exp", 0)) < time.time():
        return None
    return data.get("u")


def check_login(user, password):
    cfg = config.get()
    return (user == cfg.get("admin_user")
            and hmac.compare_digest(str(password), str(cfg.get("admin_password"))))


def change_password(old, new):
    cfg = config.get()
    if not hmac.compare_digest(str(old), str(cfg.get("admin_password"))):
        return False, "原密码错误"
    if not new or len(str(new)) < 4:
        return False, "新密码至少 4 位"
    cfg["admin_password"] = str(new)
    config.save(cfg)
    return True, "修改成功"
