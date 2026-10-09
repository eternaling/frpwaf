#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF 守护进程

一个进程、一个端口同时承担：
  1) frps httpPlugins 回调端：  POST /frp/handler?version=..&op=..
     -> 按 IP 名单/自动封禁决定 allow / reject
  2) 独立管理界面 + API：       /  以及  /api/...
     -> 用默认账号（admin / 123456，可改）登录后管理 WAF
"""
import json
import os
import socket
import sys
import threading
import time
import traceback
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 相对导入：无论本包以 app 还是 frpwaf_app 名字载入都能正确解析，
# 避免在面板常驻进程里与外部通用 "app" 包冲突。
from . import (__author__, __version__, ai, auth, blockpage, config, engine,  # noqa: E402
               firewall, geo, store, upgrade)

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

# 内存中的当日计数器（用于概览，不落库）
_mem = {"started": int(time.time()), "engine_errors": 0, "frp_remote_denied": 0}
_mem_lock = threading.Lock()

# 运行日志（写入 data/frpwaf.log，供插件「运行日志」页查看）
_log_lock = threading.Lock()
_LOG_MAX = 2 * 1024 * 1024      # 超过 2MB 时截断保留尾部 1MB


def _audit(msg):
    """操作审计：写入运行日志（data/frpwaf.log），带 [审计] 标记，便于追溯高危操作。"""
    try:
        _log("[审计] %s" % msg)
    except Exception:
        pass


def _log(msg):
    try:
        line = "[%s] %s\n" % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
        with _log_lock:
            with open(config.LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line)
            try:
                if os.path.getsize(config.LOG_PATH) > _LOG_MAX:
                    with open(config.LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                        data = f.read()
                    with open(config.LOG_PATH, "w", encoding="utf-8") as f:
                        f.write(data[-1024 * 1024:])
            except OSError:
                pass
    except Exception:
        pass

# 登录失败限速：来源 IP -> (窗口起点, 失败次数, 锁定到)
_login_fail = {}
_login_lock = threading.Lock()
_LOGIN_WINDOW = 300      # 统计窗口（秒）
_LOGIN_MAX_FAIL = 10     # 窗口内最大失败次数
_LOGIN_LOCK = 300        # 超限后锁定（秒）


def _login_locked(ip):
    now = time.time()
    with _login_lock:
        rec = _login_fail.get(ip)
        if not rec:
            return 0
        if rec[2] > now:
            return int(rec[2] - now)
        return 0


def _login_record(ip, ok):
    now = time.time()
    with _login_lock:
        if ok:
            _login_fail.pop(ip, None)
            return
        start, cnt, lock = _login_fail.get(ip, (now, 0, 0.0))
        if now - start > _LOGIN_WINDOW:
            start, cnt, lock = now, 0, 0.0
        cnt += 1
        if cnt >= _LOGIN_MAX_FAIL:
            lock = now + _LOGIN_LOCK
            cnt = 0
            start = now
        _login_fail[ip] = (start, cnt, lock)
        # 有界增长：先清过期项；仍超硬上限时按窗口起点淘汰最旧的一半，
        # 防止「持续换 IP 攻击」时字典无界膨胀（旧实现仅清过期，不设硬上限）。
        if len(_login_fail) > 5000:
            for k in [k for k, v in _login_fail.items() if now - v[0] > _LOGIN_WINDOW]:
                _login_fail.pop(k, None)
        if len(_login_fail) > 5000:
            oldest = sorted(_login_fail.items(), key=lambda kv: kv[1][0])
            for k, _ in oldest[:len(oldest) // 2]:
                _login_fail.pop(k, None)


def _split_addr(remote_addr):
    """'1.2.3.4:5678' 或 '[::1]:5678' -> (ip, port)"""
    if not remote_addr:
        return "", 0
    addr = remote_addr
    if addr.startswith("["):
        host, _, port = addr.rpartition("]:")
        return host.lstrip("["), _int(port)
    if addr.count(":") == 1:
        host, _, port = addr.rpartition(":")
        return host, _int(port)
    return addr, 0  # 纯 IPv6


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _fw_sync():
    """按当前配置同步内核处置（DROP / REDIRECT / 清理，失败静默）。

    不再区分「开关开则 sync、关则 teardown」：sync_from_store() 内部按
    fw_sync_enabled 与 block_page_enabled 决定模式——关闭内核封禁但开启
    拦截页时需改为 nat REDIRECT（让被封 IP 看到页面），两者都关才清理。
    """
    try:
        firewall.sync_from_store()
        _mem["fw_on"] = bool(config.get().get("fw_sync_enabled", True))
    except Exception:
        pass


class _QuietHTTPServer(ThreadingHTTPServer):
    """请求线程异常处理：抑制「客户端断连」类噪声。

    http.server 默认的 handle_error 会把请求线程中的任何异常打印完整 traceback
    到 stderr；服务脚本以 `2>&1` 追加日志，扫描器/客户端半途断开连接
    （ConnectionResetError 等）就会刷满运行日志。此类异常与业务无关，这里静默并
    按窗口汇总一条计数日志；其余异常仍按默认方式打印，保证真实故障可排查。
    """
    _NET_ERR_TYPES = (ConnectionResetError, ConnectionAbortedError,
                      BrokenPipeError, TimeoutError, socket.timeout)
    _QUIET_WINDOW = 600          # 汇总记录窗口（秒）
    _quiet_lock = threading.Lock()
    _quiet_count = 0
    _quiet_last = 0.0

    def handle_error(self, request, client_address):
        etype = sys.exc_info()[0]
        if etype is not None and issubclass(etype, self._NET_ERR_TYPES):
            now = time.time()
            with _QuietHTTPServer._quiet_lock:
                _QuietHTTPServer._quiet_count += 1
                if now - _QuietHTTPServer._quiet_last >= self._QUIET_WINDOW:
                    _QuietHTTPServer._quiet_last = now
                    n = _QuietHTTPServer._quiet_count
                    _QuietHTTPServer._quiet_count = 0
                    _log("已静默 %d 条客户端断连异常（扫描器/连接提前关闭，不影响防护）" % n)
            return
        ThreadingHTTPServer.handle_error(self, request, client_address)


class Handler(BaseHTTPRequestHandler):
    server_version = "frpwaf/" + __version__
    protocol_version = "HTTP/1.1"
    # 每连接 socket 超时，缓解 slowloris 慢连接长期占用
    timeout = 30

    # ---------- 工具 ----------
    def log_message(self, format, *args):  # 静音默认访问日志
        pass

    def _send(self, code, body: "bytes | str" = b"", ctype="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj, ensure_ascii=False), headers=headers)

    def _body(self):
        n = _int(self.headers.get("Content-Length"))
        if n <= 0:
            return {}
        if n > 2 * 1024 * 1024:   # 上限 2MB，防止超大请求体耗尽内存
            raise ValueError("request body too large")
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _user(self):
        return auth.verify_token(self._cookie(auth.COOKIE_NAME))

    def _require_login(self):
        if not self._user():
            self._json({"code": 401, "msg": "未登录或会话已过期"}, 401)
            return False
        return True

    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    def _is_local(self):
        """回调来源是否为本机（frps 回调固定走 127.0.0.1/::1）。"""
        ip = self._client_ip()
        return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _cookie_secure(self):
        """是否给会话 Cookie 加 Secure 标记。

        面板默认走明文 HTTP（7080），若给 Cookie 加 Secure，浏览器在 http://
        下不会回传该 Cookie，会出现「登录成功却立刻 401、面板不可用」。
        故默认不加：仅当请求经 HTTPS 到达（反向代理设置 X-Forwarded-Proto）
        或配置显式开启 cookie_secure 时才加。
        """
        try:
            if config.get().get("cookie_secure"):
                return "; Secure"
        except Exception:
            pass
        if (self.headers.get("X-Forwarded-Proto", "") or "").lower() == "https":
            return "; Secure"
        return ""

    # ---------- 路由 ----------
    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method):
        try:
            u = urlparse(self.path)
            path = u.path
            qs = parse_qs(u.query)

            # frp 插件回调（始终放行：关闭网页端不影响 WAF 防护与 frps 回调）
            # 仅接受本机来源：frps 回调固定走 127.0.0.1；否则任何可达 7080 的
            # 来源都能伪造 remote_addr 触发封禁（可把任意 IP 打入黑名单）。
            if path == "/frp/handler":
                if not self._is_local():
                    with _mem_lock:
                        _mem["frp_remote_denied"] += 1
                    return self._send(403, "forbidden", ctype="text/plain; charset=utf-8")
                return self._frp_handler(qs)

            # 网页端开关：关闭时仅屏蔽网页与 /api/*，回调照常运行
            if not config.get().get("web_enabled", True):
                return self._send(403, "网页端已关闭", ctype="text/plain; charset=utf-8")

            # 静态资源
            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path == "/favicon.ico":
                return self._send(204, b"")

            # 认证
            if path == "/api/login" and method == "POST":
                return self._api_login()
            if path == "/api/logout" and method == "POST":
                return self._json({"code": 0, "msg": "已退出"},
                                  headers={"Set-Cookie": "%s=; Max-Age=0; Path=/"
                                           % auth.COOKIE_NAME})

            # 需要登录的 API
            if path.startswith("/api/"):
                if not self._require_login():
                    return
                return self._api(path, method, qs)

            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        except BrokenPipeError:
            pass
        except Exception:
            # 细节只进日志，不回显给请求方（未认证可达，traceback 会泄露内部结构）
            _log("请求处理异常：" + traceback.format_exc()[-500:])
            try:
                self._json({"code": 500, "msg": "服务器内部错误"}, 500)
            except Exception:
                pass

    # ---------- frp 插件回调 ----------
    def _frp_handler(self, qs):
        if self.command != "POST":
            return self._send(405, "method not allowed", ctype="text/plain")
        body = self._body()
        op = (qs.get("op", [body.get("op", "")])[0]) or ""
        content = body.get("content") or {}
        user_info = content.get("user") or {}
        user = user_info.get("user", "") if isinstance(user_info, dict) else ""

        # 目前仅对 NewUserConn 做按来源 IP 的准入控制
        if op == "NewUserConn":
            remote_addr = content.get("remote_addr", "")
            ip, port = _split_addr(remote_addr)
            proxy_name = content.get("proxy_name", "")
            proxy_type = content.get("proxy_type", "")
            if not ip:
                # 字段缺失/格式异常：无法决策时放行，但必须留痕（协议变更排查线索）
                _log("回调字段异常：remote_addr=%r，已放行" % (remote_addr,))
            try:
                allow, reason = engine.decide(ip, port, proxy_name, proxy_type, user)
            except Exception:
                # 决策异常时放行（避免 WAF 逻辑错误导致 frp 全线拒绝）；
                # 计数 + 限频日志：连续出现说明防护在静默失效，便于从概览/日志发现。
                with _mem_lock:
                    _mem["engine_errors"] += 1
                    n = _mem["engine_errors"]
                if n <= 3 or n % 100 == 0:
                    _log("决策异常（fail-open，累计 %d 次）：%s"
                         % (n, traceback.format_exc()[-300:]))
                allow, reason = True, "engine-error"
            try:
                # 日志 + 代理统计合并为单事务（原为两次独立写库，高并发下写放大）
                store.add_log_and_bump(ip, port, proxy_name, proxy_type, user,
                                       "allow" if allow else "reject", reason,
                                       rejected=not allow)
            except Exception:
                pass
            if allow:
                return self._json({"reject": False, "unchange": True})
            _log("拒绝连接 %s -> %s/%s%s 原因=%s" % (
                ip, proxy_name, proxy_type,
                (" user=%s" % user) if user else "", reason or "blocked"))
            return self._json({"reject": True, "reject_reason": reason or "blocked"})

        # 其他 op（Login / NewWorkConn / CloseProxy / Ping）暂不改动
        return self._json({"reject": False, "unchange": True})

    # ---------- 静态 ----------
    def _static(self, name):
        path = os.path.join(WEB_DIR, name)
        if not os.path.abspath(path).startswith(os.path.abspath(WEB_DIR)) or not os.path.exists(path):
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, "not found", ctype="text/plain; charset=utf-8")
        ctype = "text/html; charset=utf-8" if name.endswith(".html") else "application/octet-stream"
        return self._send(200, data, ctype=ctype)

    # ---------- 认证 API ----------
    def _api_login(self):
        body = self._body()
        user = str(body.get("username", ""))
        pwd = str(body.get("password", ""))
        ip = self._client_ip()
        wait = _login_locked(ip)
        if wait > 0:
            _log("登录被拒（限速中）来自 %s，剩余 %d 秒" % (ip, wait))
            return self._json({"code": 429, "msg": "尝试过于频繁，请 %d 秒后再试" % wait}, 429)
        if not auth.check_login(user, pwd):
            _login_record(ip, False)
            _log("登录失败 来自 %s 用户名=%s" % (ip, user))
            time.sleep(0.3)
            return self._json({"code": 401, "msg": "用户名或密码错误"}, 401)
        _login_record(ip, True)
        _log("登录成功 来自 %s 用户名=%s" % (ip, user))
        token = auth.create_token(user)
        return self._json(
            {"code": 0, "msg": "登录成功", "user": user},
            headers={"Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Lax%s; Max-Age=%d"
                     % (auth.COOKIE_NAME, token, self._cookie_secure(), auth.SESSION_TTL)},
        )

    # ---------- 管理 API ----------
    def _api(self, path, method, qs):
        cfg = config.get()
        if path == "/api/overview":
            st = store.stats()
            st.update({
                "version": __version__,
                "uptime": int(time.time()) - _mem["started"],
                "http_addr": cfg["http_addr"],
                "http_port": cfg["http_port"],
                "blacklist_enabled": cfg["blacklist_enabled"],
                "whitelist_enabled": cfg["whitelist_enabled"],
                "auto_ban_enabled": cfg["auto_ban_enabled"],
                "auto_ban_cc_enabled": bool(cfg.get("auto_ban_cc_enabled", False)),
                "auto_ban_scan_enabled": bool(cfg.get("auto_ban_scan_enabled", False)),
                "auto_ban_ssh_enabled": bool(cfg.get("auto_ban_ssh_enabled", False)),
                "rate_limit_enabled": cfg["rate_limit_enabled"],
                "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
                "admin_user": cfg.get("admin_user", "admin"),
            })
            with _mem_lock:
                st["engine_errors"] = _mem["engine_errors"]
                st["frp_remote_denied"] = _mem["frp_remote_denied"]
            st["geo_available"] = geo.db_info().get("available", False)
            return self._json({"code": 0, "data": st})

        if path == "/api/config":
            if method == "GET":
                # 过滤机密字段，避免明文泄露管理密码 / AI 密钥
                _SECRET_KEYS = ("secret", "admin_password", "ai_api_key")
                safe = {k: v for k, v in cfg.items() if k not in _SECRET_KEYS}
                safe["ai_api_key"] = "******" if cfg.get("ai_api_key") else ""
                return self._json({"code": 0, "data": safe})
            body = self._body()
            patch = {}
            allowed = {
                "blacklist_enabled": bool, "whitelist_enabled": bool,
                "auto_ban_enabled": bool, "auto_ban_window": int,
                "auto_ban_threshold": int, "auto_ban_seconds": int,
                "auto_ban_cc_enabled": bool, "auto_ban_cc_window": int,
                "auto_ban_cc_threshold": int, "auto_ban_cc_seconds": int,
                "auto_ban_scan_enabled": bool, "auto_ban_scan_window": int,
                "auto_ban_scan_threshold": int, "auto_ban_scan_seconds": int,
                "auto_ban_ssh_enabled": bool, "auto_ban_ssh_window": int,
                "auto_ban_ssh_threshold": int,
                "rate_limit_enabled": bool, "rate_limit_per_sec": int,
                "log_max_rows": int, "fw_sync_enabled": bool,
                # 静态拦截页（404/封禁/风控）与 GitHub 在线升级
                "block_page_enabled": bool, "block_page_404_enabled": bool,
                "block_page_ban_enabled": bool, "block_page_risk_enabled": bool,
                "block_page_port": int, "block_page_redirect_ports": str,
                "github_repo": str,
                # 分布式突发观测与代理级冷却
                "burst_window": int, "proxy_cool_enabled": bool,
                "proxy_cool_min_conns": int, "proxy_cool_uniq_threshold": int,
                "proxy_cool_single_pct": int, "proxy_cool_seconds": int,
                "ai_enabled": bool, "ai_protocol": str, "ai_base_url": str,
                "ai_api_key": str, "ai_model": str, "ai_interval": int,
                "ai_window": int, "ai_min_conns": int, "ai_max_ips": int,
                "ai_auto_ban": bool, "ai_cdn_guard": bool, "ai_ban_seconds": int,
                "ai_suspicious_ban": bool, "ai_ssh_strict": bool,
                "ai_ssh_permanent_suspicious": bool, "ai_timeout": int,
            }
            for k, typ in allowed.items():
                if k in body:
                    try:
                        if typ is bool:
                            patch[k] = bool(body[k])
                        elif typ is int:
                            patch[k] = max(0, int(body[k]))
                        else:
                            patch[k] = str(body[k]).strip()
                    except (TypeError, ValueError):
                        pass
            if patch.get("auto_ban_window", 60) < 1:
                patch["auto_ban_window"] = 1
            # 攻击类型封禁：窗口参数与既有 auto_ban 同样强制 ≥1 秒；
            # 开关开启时参数为「未设置形态」（阈值/时长 0、窗口 ≤1）的回退默认值，
            # 由 config.save() 内统一的 normalize_auto_ban() 完成（对所有写入路径生效）。
            for _w in ("auto_ban_cc_window", "auto_ban_scan_window", "auto_ban_ssh_window"):
                if patch.get(_w, 60) < 1:
                    patch[_w] = 1
            # 突发观测/冷却：窗口与时长参数钳制；开关开启时参数为「未设置形态」
            # 的回退默认值由 config.save() 内统一的 normalize_burst_cool() 完成。
            # 冷却时长下限 10s 与引擎运行时（max(10, ...)）一致，避免显示/行为不符。
            if patch.get("burst_window", 60) < 2:
                patch["burst_window"] = 2
            if patch.get("proxy_cool_seconds", 60) < 10:
                patch["proxy_cool_seconds"] = 10
            if patch.get("proxy_cool_single_pct", 80) > 100:
                patch["proxy_cool_single_pct"] = 100
            if patch.get("ai_interval", 300) < 60:
                patch["ai_interval"] = 60
            if patch.get("ai_window", 300) < 30:
                patch["ai_window"] = 30
            config.save(patch)   # patch 语义：锁内合并磁盘现状，避免覆盖并发写入方字段
            _fw_sync()   # 开关/名单变化立即生效（关闭内核封禁时同步清理残留）
            blockpage.ensure()   # 拦截页端口/开关变更后立即生效
            return self._json({"code": 0, "msg": "保存成功"})

        if path == "/api/password":
            body = self._body()
            # 支持同时修改用户名与密码（与宝塔插件端保持一致）
            ok, msg = auth.change_credentials(
                body.get("old", ""), body.get("new", ""),
                body.get("new_user", ""), body.get("old_user", ""))
            return self._json({"code": 0 if ok else 1, "msg": msg})

        if path == "/api/iplist":
            if method == "GET":
                lt = qs.get("type", [None])[0]
                # 面板展示接口：限制返回条数（缺省/非法 = 默认上限 5000，
                # 显式传入也不超过硬上限）。名单正常为几百条，此上限仅防异常增长。
                lim = _int(qs.get("limit", [0])[0])
                if lim <= 0 or lim > store.PANEL_LIST_CAP:
                    lim = store.PANEL_LIST_CAP
                rows = store.list_ips(lt, limit=lim)
                for r in rows:
                    # 名单条目可能是 CIDR，取网络地址做归属地查询
                    base = (r.get("cidr") or "").split("/")[0]
                    g = geo.lookup(base)
                    r["geo"] = g.get("text", "")
                return self._json({"code": 0, "data": rows})
            if method == "POST":
                body = self._body()
                action = body.get("action")
                try:
                    if action == "add":
                        store.add_ip(body.get("cidr", ""),
                                     body.get("list_type", "black"),
                                     body.get("remark", ""))
                        engine.invalidate_cache()
                        _fw_sync()
                        return self._json({"code": 0, "msg": "添加成功"})
                    if action == "del":
                        store.del_ip(body.get("id"))
                        engine.invalidate_cache()
                        _fw_sync()
                        return self._json({"code": 0, "msg": "删除成功"})
                    if action == "clear_black":
                        # 一键解封全部黑名单（误封恢复；仅黑名单，不动白名单）
                        n = store.clear_blacklist()
                        engine.invalidate_cache()
                        _fw_sync()
                        return self._json({"code": 0, "msg": "已解封全部黑名单（%d 条）" % n})
                    if action == "batch":
                        # 多行文本批量导入： 每行  cidr[,备注]
                        text = body.get("text", "")
                        lt = body.get("list_type", "black")
                        ok = fail = 0
                        for line in text.splitlines():
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split(",", 1)
                            cidr = parts[0].strip()
                            remark = parts[1].strip() if len(parts) > 1 else ""
                            try:
                                store.add_ip(cidr, lt, remark)
                                ok += 1
                            except ValueError:
                                fail += 1
                        engine.invalidate_cache()
                        _fw_sync()
                        return self._json({"code": 0, "msg": "导入完成：成功 %d，跳过 %d" % (ok, fail)})
                except ValueError as e:
                    return self._json({"code": 1, "msg": str(e)})
                return self._json({"code": 1, "msg": "未知操作"})

        if path == "/api/logs":
            if method == "GET":
                limit = max(1, min(1000, _int(qs.get("limit", [100])[0])))
                offset = max(0, _int(qs.get("offset", [0])[0]))
                ip = qs.get("ip", [None])[0]
                action = qs.get("action", [None])[0]
                proxy = qs.get("proxy", [None])[0]
                rows = store.list_logs(limit, offset, ip, action, proxy)
                total = store.count_logs(ip, action, proxy)
                geo.enrich(rows)
                return self._json({"code": 0, "data": rows, "total": total})
            if method == "POST":
                body = self._body()
                if body.get("action") == "purge":
                    store.purge_logs()
                    return self._json({"code": 0, "msg": "日志已清空"})

        if path == "/api/logs/proxies":
            # 连接日志中出现过的代理名（供筛选下拉框）
            return self._json({"code": 0, "data": store.log_proxy_names()})

        if path == "/api/logs/summary":
            # 按代理聚合视图（窗口钳制 60s ~ 24h；非法值回退默认 1 小时）
            window = _int(qs.get("window", [3600])[0])
            if window <= 0:
                window = 3600
            window = max(60, min(86400, window))
            res = store.summary_by_proxy(window)
            return self._json({"code": 0, "data": res["rows"], "window": window,
                               "total_proxies": res["total_proxies"]})

        if path == "/api/burst":
            # 代理级突发观测快照（纯内存）+ 冷却阈值与状态（供面板展示）
            cfg = config.get()
            return self._json({"code": 0, "data": engine.burst_snapshot(), "config": {
                "burst_window": int(cfg.get("burst_window") or 60),
                "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
                "proxy_cool_min_conns": int(cfg.get("proxy_cool_min_conns") or 300),
                "proxy_cool_uniq_threshold": int(cfg.get("proxy_cool_uniq_threshold") or 200),
                "proxy_cool_single_pct": int(cfg.get("proxy_cool_single_pct") or 80),
                "proxy_cool_seconds": int(cfg.get("proxy_cool_seconds") or 60),
            }})

        if path == "/api/bans":
            if method == "GET":
                act = store.active_bans()
                his = store.ban_history(100)
                geo.enrich(act)
                geo.enrich(his)
                return self._json({"code": 0, "data": act, "history": his})
            body = self._body()
            action = body.get("action")
            if action == "unban":
                store.unban_ip(body.get("ip", ""))
                firewall.remove(body.get("ip", ""))
                _fw_sync()
                return self._json({"code": 0, "msg": "已解封"})
            if action == "unban_all":
                # 一键解封全部生效中的临时封禁（与黑名单解封独立）
                n = store.release_all_bans()
                _fw_sync()
                return self._json({"code": 0, "msg": "已解封全部临时封禁（%d 条）" % n})
            if action == "ban":
                ip = (body.get("ip") or "").strip()
                if not ip:
                    return self._json({"code": 1, "msg": "请输入 IP"})
                try:
                    store.add_ban(ip, "manual", int(body.get("seconds") or 3600))
                except ValueError as e:
                    return self._json({"code": 1, "msg": str(e)})
                _fw_sync()
                return self._json({"code": 0, "msg": "已封禁"})

        if path == "/api/proxies":
            return self._json({"code": 0, "data": store.list_proxy_stat()})

        if path == "/api/geo":
            # 单 IP 归属地查询（含当日连接次数）
            ip = (qs.get("ip", [""])[0] or "").strip()
            if not ip:
                return self._json({"code": 1, "msg": "请输入 IP"})
            try:
                import ipaddress
                ipaddress.ip_address(ip)
            except ValueError:
                return self._json({"code": 1, "msg": "无效的 IP 地址"})
            g = geo.lookup(ip)
            try:
                conns = store.count_logs(ip=ip)
                recent = store.recent_count_by_ip(ip, 86400)
            except Exception:
                conns = recent = 0
            return self._json({"code": 0, "data": {
                "ip": ip, "geo": g.get("text", ""), "country": g.get("country", ""),
                "province": g.get("province", ""), "city": g.get("city", ""),
                "isp": g.get("isp", ""), "lat": g.get("lat"), "lon": g.get("lon"),
                "total_conns": conns, "today_conns": recent,
            }})

        if path == "/api/geo/db":
            return self._json({"code": 0, "data": geo.db_info()})

        if path == "/api/kernban":
            st = firewall.status()
            st["enabled"] = bool(cfg.get("fw_sync_enabled", True))
            return self._json({"code": 0, "data": st})

        if path == "/api/kernban/sync" and method == "POST":
            _audit("Web 端手动同步内核封禁")
            ok = firewall.sync_from_store()
            st = firewall.status()
            if ok:
                return self._json({"code": 0, "msg": "已同步", "data": st})
            if st.get("mode") == "off":
                return self._json({"code": 0, "msg": "内核封禁与拦截页均已关闭，已清理内核规则",
                                   "data": st})
            return self._json({"code": 1,
                               "msg": "当前环境不支持（需 root + ipset/iptables）",
                               "data": st})

        if path == "/api/ai/review":
            if method == "POST":
                _audit("Web 端手动触发 AI 审查")
                try:
                    res = ai.review(force=True)
                except Exception:
                    return self._json({"code": 1, "msg": "审查异常：" + traceback.format_exc()[-300:]})
                return self._json({"code": 0 if res.get("ok") else 1, "msg": res.get("msg", ""),
                                   "data": res})
            return self._json({"code": 0, "data": store.list_ai_review(200)})

        if path == "/api/ai/results":
            return self._json({"code": 0, "data": store.list_ai_review(200)})

        if path == "/api/ai/test":
            # 测试 AI 连接
            body = self._body()
            cfg = config.get()
            tmp = dict(cfg)
            for k in ("ai_protocol", "ai_base_url", "ai_api_key", "ai_model"):
                if body.get(k):
                    tmp[k] = str(body[k]).strip()
            if not tmp.get("ai_base_url") or not tmp.get("ai_api_key"):
                return self._json({"code": 1, "msg": "请先填写接口地址与密钥"})
            ok, res = ai.call_model(tmp, [{"ip": "8.8.8.8", "geo": "美国", "conns": 1,
                                           "rejected": 0, "proxies": "test"}])
            if ok:
                return self._json({"code": 0, "msg": "连接成功，模型返回正常"})
            return self._json({"code": 1, "msg": "连接失败：" + str(res)[:300]})

        if path == "/api/blockpage":
            return self._json({"code": 0, "data": blockpage.status()})

        if path == "/api/about":
            return self._json({"code": 0, "data": {
                "name": "FRP WAF", "version": __version__, "author": __author__,
                "repo": str(cfg.get("github_repo") or ""), "license": "MIT",
                "runtime": "Python 3 标准库 + SQLite + 原生 JS（零第三方依赖）",
            }})

        if path == "/api/upgrade/check":
            body = self._body() if method == "POST" else {}
            repo = str(body.get("repo") or cfg.get("github_repo") or "").strip()
            res = upgrade.check(repo)
            return self._json({"code": 0 if res.get("ok") else 1, "data": res,
                               "msg": res.get("error") or res.get("msg") or ""})

        if path == "/api/upgrade/apply" and method == "POST":
            body = self._body()
            repo = str(body.get("repo") or cfg.get("github_repo") or "").strip()
            _audit("Web 端触发 GitHub 在线升级（仓库 %s）" % (repo or "未配置"))
            res = upgrade.apply(repo)
            _audit("GitHub 在线升级结果：%s" % (res.get("msg") or res.get("error") or "未知"))
            return self._json({"code": 0 if res.get("ok") else 1, "data": res,
                               "msg": res.get("error") or res.get("msg") or ""})

        if path == "/api/service" and method == "POST":
            body = self._body()
            action = str(body.get("action") or "").strip()
            if action not in ("restart", "stop"):
                return self._json({"code": 1, "msg": "不支持的操作（仅 restart / stop）"})
            _audit("Web 端服务控制：%s" % action)
            ok = upgrade.schedule_init(action, delay=2)
            if not ok:
                return self._json({"code": 1, "msg": "无法执行（未找到服务脚本 /etc/init.d/frpwaf）"})
            return self._json({"code": 0,
                               "msg": "已提交，服务将在约 2 秒后%s" % ("重启" if action == "restart" else "停止")})

        if path == "/api/syslog":
            lim = _int(qs.get("limit", [200])[0])
            if lim <= 0 or lim > 2000:
                lim = 200
            try:
                with open(config.LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
            except OSError:
                lines = []
            return self._json({"code": 0, "data": {"lines": lines[-lim:], "total": len(lines)}})

        if path == "/api/version":
            return self._json({"code": 0, "version": __version__})

        return self._json({"code": 404, "msg": "接口不存在"}, 404)


def _write_burst_snapshot(cfg):
    """把突发观测/冷却快照写入 data/burst_snapshot.json（供插件端面板进程读取）。

    观测与冷却状态都在本进程内存中，宝塔插件端运行在另一个进程，
    无法直接访问；由后台每 10s 周期落盘一次（原子替换），
    插件端 burst_status 读该文件。写失败不中断主流程，但按窗口记一次
    运行日志（磁盘满/权限问题可排查）；文件权限与配置/DB 一致收紧为 0600。
    """
    try:
        data = {
            "ts": int(time.time()),
            "data": engine.burst_snapshot(),
            "config": {
                "burst_window": int(cfg.get("burst_window") or 60),
                "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
                "proxy_cool_min_conns": int(cfg.get("proxy_cool_min_conns") or 300),
                "proxy_cool_uniq_threshold": int(cfg.get("proxy_cool_uniq_threshold") or 200),
                "proxy_cool_single_pct": int(cfg.get("proxy_cool_single_pct") or 80),
                "proxy_cool_seconds": int(cfg.get("proxy_cool_seconds") or 60),
            },
        }
        tmp = "%s.tmp.%d" % (config.BURST_SNAPSHOT_PATH, os.getpid())
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, config.BURST_SNAPSHOT_PATH)
        try:
            os.chmod(config.BURST_SNAPSHOT_PATH, 0o600)   # 含代理名/观测指标，收紧权限
        except OSError:
            pass
    except Exception:
        # 写失败按窗口限流记日志（避免每 10s 刷屏）
        now = time.time()
        if now - _snap_fail_log["at"] >= 600:
            _snap_fail_log["at"] = now
            try:
                _log("突发观测快照写入失败（插件端将看到过期数据）：%s"
                     % traceback.format_exc()[-200:])
            except Exception:
                pass


_snap_fail_log = {"at": 0.0}


def _bg_loop():
    """后台：释放到期封禁、裁剪日志、同步内核封禁、WAL checkpoint、写心跳日志。"""
    tick = 0
    while True:
        try:
            for b in engine.auto_release():
                _log("自动解封 %s（封禁到期）" % b["ip"])
            # 代理级冷却判定（默认关闭；开关开启时进入/续期/清理）
            for name in engine.cool_check():
                _log("代理级冷却：%s 触发分布式突发阈值，冷却期内新 IP 将被拒绝" % name)
            cfg = config.get()
            _write_burst_snapshot(cfg)   # 观测/冷却快照落盘（插件端面板进程读取）
            store.trim_logs(int(cfg.get("log_max_rows") or 50000))
            store.trim_bans(20000)
            store.trim_ai_review(5000)
            _fw_sync()
            blockpage.ensure()   # 兜底：其它进程（宝塔插件端）改了拦截页配置也能生效
            tick += 1
            if tick % 6 == 0:
                store.checkpoint(truncate=True)
            # 每 10 分钟写一条心跳（含内存占用），便于确认服务存活
            if tick % 60 == 0:
                try:
                    with open("/proc/self/statm") as f:
                        rss = int(f.read().split()[1]) * 4096 // 1024
                    _log("心跳：服务正常，生效封禁 %d，内存 %dKB" % (
                        len(store.active_bans()), rss))
                except Exception:
                    _log("心跳：服务正常")
        except Exception:
            _log("后台任务异常：" + traceback.format_exc()[-300:])
        time.sleep(10)


def write_pid():
    try:
        with open(config.PID_PATH, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass


def main():
    config.load()
    store.init()
    write_pid()
    cfg = config.get()
    addr = cfg["http_addr"]
    port = int(cfg["http_port"])
    t = threading.Thread(target=_bg_loop, daemon=True)
    t.start()
    threading.Thread(target=ai.loop_forever, daemon=True).start()
    blockpage.ensure()   # 拦截页服务（独立端口，受 block_page_enabled 控制）
    httpd = _QuietHTTPServer((addr, port), Handler)
    httpd.daemon_threads = True
    httpd.timeout = 30
    print("[frpwaf] listening on %s:%d  (pid=%d)" % (addr, port, os.getpid()), flush=True)
    _log("服务启动，监听 %s:%d（pid=%d，版本 %s）" % (addr, port, os.getpid(), __version__))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _log("服务停止（pid=%d）" % os.getpid())


if __name__ == "__main__":
    main()
