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
import re
import secrets
import time

from . import config

COOKIE_NAME = "frpwaf_sid"
SESSION_TTL = 12 * 3600


def _sign(payload_bytes, secret):
    return hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


def create_token(user):
    cfg = config.load()
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
    # 宝塔插件与守护进程分属不同进程；认证不使用决策路径的 1 秒配置缓存。
    cfg = config.load()
    try:
        # 非 ASCII 签名（如构造的 "abc.中文"）会让 compare_digest 抛 TypeError，
        # 必须捕获返回 None，否则未登录请求会 500（信息泄露面 + 噪声）。
        if not hmac.compare_digest(sig, _sign(payload, cfg["secret"])):
            return None
    except (TypeError, KeyError):
        return None
    try:
        data = json.loads(payload)
    except Exception:
        return None
    try:
        if int(data.get("exp", 0)) < time.time():
            return None
    except (TypeError, ValueError):
        return None
    return data.get("u")


def check_login(user, password):
    cfg = config.load()
    return (user == cfg.get("admin_user")
            and hmac.compare_digest(str(password), str(cfg.get("admin_password"))))


def change_password(old, new):
    cfg = config.load()
    if not hmac.compare_digest(str(old), str(cfg.get("admin_password"))):
        return False, "原密码错误"
    if not new or len(str(new)) < 4:
        return False, "新密码至少 4 位"
    config.save({"admin_password": str(new), "secret": secrets.token_hex(32)})
    return True, "修改成功"


def change_credentials(old, new, new_user="", old_user=""):
    """修改管理员账号：用户名与/或密码（与宝塔插件端 change_admin_pwd 逻辑一致）。

    参数：old（原密码，必填校验）、new（新密码，可空=不改）、
          new_user（新用户名，可空=不改）、old_user（原用户名，可选二次校验）。
    """
    cfg = config.load()
    if not hmac.compare_digest(str(old), str(cfg.get("admin_password"))):
        return False, "原密码错误"
    old_user = (old_user or "").strip()
    if old_user and not hmac.compare_digest(old_user, str(cfg.get("admin_user"))):
        return False, "原用户名错误"
    new_user = (new_user or "").strip()
    patch = {}
    if new_user:
        if len(new_user) < 2:
            return False, "用户名至少 2 位"
        if not re.match(r"^[A-Za-z0-9_.@-]+$", new_user):
            return False, "用户名只能包含字母、数字、_ . @ -"
        patch["admin_user"] = new_user
    if new:
        if len(str(new)) < 4:
            return False, "新密码至少 4 位"
        patch["admin_password"] = str(new)
    if not patch:
        return False, "未修改任何内容"
    patch["secret"] = secrets.token_hex(32)
    config.save(patch)   # 改账号或密码时撤销全部旧会话
    return True, "账号已更新"
