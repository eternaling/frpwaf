#!/usr/bin/env python3
# coding: utf-8
"""跨进程共用的文本/配置工具（守护进程与宝塔插件端共用，单一来源）。

**为什么单独抽这个模块**：`app/daemon.py`（7080 面板后端）与 `frpwaf_main.py`
（宝塔插件后端）是**两个进程、两套入口，但面对同一份配置与日志**。历史上
`_log_text` / `_strip_masked` / `_to_bool` 在两边各写了一份，随后出现漂移——
最典型的一次：升级失败时守护进程报「升级失败」、插件端却报「升级完成」，
用户看到成功但版本号没变。同一语义有两份实现就是这类问题的温床。

因此把「纯函数、无副作用、两边语义必须一致」的工具集中在这里：

- `log_text()`      日志/回显净化（注入防护）：`\\r` `\\n` 转义、控制字符剥离、可选截断
- `strip_masked()`  丢弃等于回显掩码的机密字段（防止「读-改-写」把 `******` 写回覆盖真密钥）
- `to_bool()`       宽松布尔解析（`"false"` 不能被 `bool()` 当成 True）

依赖方向：本模块只依赖标准库与 `app.config`，**不导入 daemon / firewall / store**，
所以插件端可以安全导入，不会顺带拉起守护进程的副作用。
"""
import re

from . import config

__all__ = [
    "LOG_FIELD_MAX", "MASKED_VALUE", "MASKED_KEYS",
    "log_text", "strip_masked", "to_bool",
]

# 不可信字段（代理名/用户名/代理类型）落日志时的截断长度。
# 来自 frpc 客户端的 NewUserConn 回调，客户端可控。
LOG_FIELD_MAX = 64

# 机密字段的回显掩码与键名：定义在 config 里，这里只做转发，
# 避免出现「两处各写一份、改一处忘另一处」。
MASKED_VALUE = config.MASKED_VALUE
MASKED_KEYS = config.MASKED_KEYS

# 除 \t（0x09）与 \n \r（单独转义）之外的控制字符，进日志前一律丢弃
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def log_text(v, maxlen=0):
    """净化一段要进日志/回显的文本：`\\r` `\\n` 转义为字面量，其它控制字符丢弃。

    为什么必须净化：`proxy_name` / `proxy_type` / `user` 来自 frpc 客户端的
    `NewUserConn` 回调（客户端可控）。其中含 `\\n` 就能凭空插入一整行看似可信的
    日志（例如伪造的 `[审计]` 记录），而 `/api/syslog` 与插件端「运行日志」页
    会原样展示 —— 取证链被污染。

    maxlen > 0 时按字符截断并补 `...`（不可信字段统一传 `LOG_FIELD_MAX`）。
    """
    s = "" if v is None else str(v)
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    s = _CTRL_RE.sub("", s)
    if maxlen and len(s) > maxlen:
        s = s[:maxlen] + "..."
    return s


def strip_masked(patch):
    """丢弃等于回显掩码的机密字段；原地修改并返回同一个 dict。

    「读配置 → 改一项 → 整体回写」的客户端会把 GET 拿到的 `******` 原样提交，
    若照写就会把真实密钥覆盖成 `******`（AI 审查从此静默失效，且用户看不出异常）。
    非 dict 入参原样返回，便于调用方无脑透传。
    """
    if not isinstance(patch, dict):
        return patch
    for k in MASKED_KEYS:
        if k in patch and str(patch[k]) == MASKED_VALUE:
            patch.pop(k, None)
    return patch


def to_bool(v):
    """宽松布尔解析：字符串 `"false"`/`"0"`/`"off"` 判为 False。

    `bool("false")` 是 True —— 直接套 `bool()` 会把前端传来的字符串 `"false"`
    当成开启，配置项语义正好反过来。
    """
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "on", "yes")
    return bool(v)
