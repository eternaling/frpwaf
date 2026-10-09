#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 静态拦截页服务（404 / 封禁 / 风控）

背景（为什么需要独立服务）：
  frp 服务端插件（httpPlugins / NewUserConn）只能返回 allow/reject，协议里
  没有 HTML 字段；frps 的 custom404Page 只对「Host 未匹配任何 frpc 域名」的
  路由失败生效（frp#5015）。因此「被封 IP 展示页面」只能让流量到达一个能返回
  HTML 的服务：内核级封禁关闭时，用 iptables -t nat REDIRECT 把命中封禁的 IP
  在其访问端口上引导到本服务（见 app/firewall.py）。

端口与隔离：
  监听配置 block_page_port（默认 7081），与面板 http_port 解耦；不受
  web_enabled 与登录态影响，也不会误挡正常面板访问。任意路径默认返回封禁页
  （REDIRECT 会保留原始路径），显式 /risk、/404 返回对应页。

仅使用标准库；页面为独立静态资源，不回显任何内部路径 / 堆栈 / 请求细节。
"""
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

# 显式路径 -> (静态文件, 开关键)。未列出的路径默认走封禁页。
_PAGES = {
    "/blocked": ("blocked.html", "block_page_ban_enabled"),
    "/risk": ("risk.html", "block_page_risk_enabled"),
    "/404": ("404.html", "block_page_404_enabled"),
}
_DEFAULT = "/blocked"

_state = {"server": None, "thread": None, "port": 0}
_lock = threading.Lock()
# 静态页缓存：{文件名: (mtime, html)}；文件被替换后自动重载（便于升级/调试）
_page_cache = {}


def _page(name):
    """读取静态页（按 mtime 缓存；文件缺失返回 None）。"""
    path = os.path.join(WEB_DIR, name)
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return None
    cached = _page_cache.get(name)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        with open(path, "rb") as f:
            html = f.read().decode("utf-8")
    except OSError:
        return None
    _page_cache[name] = (mtime, html)
    return html


class _Handler(BaseHTTPRequestHandler):
    server_version = "frpwaf-blockpage"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass   # 静默：被封 IP 的访问不刷面板/系统日志

    def do_GET(self):
        self._respond(head=False)

    def do_HEAD(self):
        self._respond(head=True)

    def _respond(self, head):
        from . import config
        cfg = config.get()
        if not cfg.get("block_page_enabled", True):
            return self._send(404, b"not found", "text/plain; charset=utf-8", head)
        path = urlparse(self.path).path or "/"
        page = _PAGES.get(path, _PAGES[_DEFAULT])
        # 该页开关关闭：回退 404 页；404 也关则纯文本 404（避免展示被禁用的页面）
        if not cfg.get(page[1], True):
            if path != "/404" and cfg.get("block_page_404_enabled", True):
                page = _PAGES["/404"]
            else:
                return self._send(404, b"not found", "text/plain; charset=utf-8", head)
        html = _page(page[0])
        if html is None:
            return self._send(404, b"not found", "text/plain; charset=utf-8", head)
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8", head)

    def _send(self, code, body, ctype, head):
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if not head:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def _start_locked(addr, port):
    srv = ThreadingHTTPServer((addr, port), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, name="frpwaf-blockpage", daemon=True)
    t.start()
    _state.update(server=srv, thread=t, port=port)


def _stop_locked():
    srv = _state.get("server")
    if srv is not None:
        try:
            srv.shutdown()
        except Exception:
            pass
        try:
            srv.server_close()
        except Exception:
            pass
    _state.update(server=None, thread=None, port=0)


def ensure():
    """按当前配置确保监听状态正确（幂等；配置变更后调用即可）。"""
    from . import config
    cfg = config.get()
    enabled = bool(cfg.get("block_page_enabled", True))
    try:
        port = int(cfg.get("block_page_port") or 7081)
    except (TypeError, ValueError):
        port = 7081
    addr = cfg.get("http_addr") or "0.0.0.0"
    with _lock:
        if not enabled:
            _stop_locked()
            return False
        if _state["server"] is not None and _state["port"] == port:
            return True
        _stop_locked()
        try:
            _start_locked(addr, port)
        except OSError:
            return False
    return True


def stop():
    with _lock:
        _stop_locked()


def status():
    from . import config
    cfg = config.get()
    try:
        cfg_port = int(cfg.get("block_page_port") or 7081)
    except (TypeError, ValueError):
        cfg_port = 7081
    with _lock:
        running = _state["server"] is not None
        port = _state["port"] or cfg_port
    return {"enabled": bool(cfg.get("block_page_enabled", True)),
            "running": running, "port": port}
