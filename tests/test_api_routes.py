#!/usr/bin/env python3
# coding: utf-8
"""HTTP 路由层（`Handler._route` / `Handler._api`）行为回归测试。

**这个文件是 32 分支 if 链改路由表（P2-3.14）的安全网。** 它不测业务算法，
只钉住「请求进来之后被哪条分支接住、回了什么状态码、返回什么结构」，
这样重构时任何一条路由的行为漂移都会立刻变成红灯。P2-3.14 已落地：`_api`
现在按模块级 `daemon._ROUTES` 路由表分发（路径精确匹配），方法不允许统一
回 405 + `Allow` 头，只有未知路径才回 404。

测试方式：起真实 `_QuietHTTPServer` + `Handler`（随机端口、临时 `FRPWAF_HOME`），
用 `http.client` 打真实 HTTP。**刻意不 mock `_route`/`_api` 本身**——路由分发
正是被测对象。只打桩两类东西（见 `_stub_externals`）：进程外副作用（内核
ipset/iptables、拦截页监听、`/etc/init.d` 服务脚本）与网络调用（GitHub
Release、AI 模型接口），保证测试离线、可重复、不碰宿主环境。

覆盖范围：
  1. 路由契约表：每条 path 的 GET/POST 实际状态码（含「方法不匹配时实际是
     404 还是 405」这个 3.14 必须保持/修正的差异）；
  2. 鉴权边界：未登录 401、免登录端点可访问、`password_changed=False` 时
     除白名单外全部 403；
  3. 入参校验：异常取值一律 400（不能变成 500 + traceback）；
  4. 关键端点返回结构：`/api/metrics`、`/api/upgrade/status`、
     `/api/ai/test/status`、`/api/export`、`/api/config`；
  5. 协议边界：PUT/DELETE/PATCH/OPTIONS → 405、HEAD 走 GET 路由、
     未知路径 404、安全响应头在所有出口都存在。

已知缺陷用 `@unittest.expectedFailure` 标出（`InvalidConfigValueBugTest`），
修好后会变成 unexpected success 提醒更新本文件。
"""
import http.client
import json
import secrets
import threading
import time
import unittest
from unittest import mock

from . import new_home
from app import auth, config, daemon, job, store

# 需要检查的安全响应头（`_send` 统一加；任何绕过 `_send` 的出口都会缺它们）
SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

# 路由契约表：路径 -> (GET 期望状态码, POST 期望状态码)
#
#   200 = 落到 handler（业务结果由 code 字段表达，HTTP 层仍是 200）
#   400 = 入参本身有问题（缺参 / 取值非法）
#   405 = 路径存在、方法不允许（必须带 Allow 头）
#   404 = 没有这条路由（只有未知路径与 /api/login|logout 的 GET 还会 404）
#
# 404/405 的差异在 P2-3.14 已经统一：方法约束声明在 `daemon._ROUTES` 里，
# 「`if path == X and method == "POST"` 写法回 404」那种偏差不再存在。
# 本表同时是路由集合的契约——`test_route_table_matches_routes_constant`
# 会拿它跟 `daemon._ROUTES` 逐条对账，新增路由忘了同步这里会直接红。
ROUTES = {
    # ---- 只读 / 状态 ----
    "/api/health": (200, 200),            # 安全水位：GET/POST 都落到 handler
    "/api/metrics": (200, 200),            # 无方法约束
    "/api/overview": (200, 200),
    "/api/version": (200, 200),
    "/api/about": (200, 200),
    "/api/geo": (400, 400),                # 缺 ip / 非法 ip 一律 400（原来是 200+code1）
    "/api/geo/db": (200, 200),
    "/api/kernban": (200, 200),
    "/api/blockpage": (200, 200),
    "/api/syslog": (200, 200),
    "/api/sysdetect": (200, 200),         # GET 状态+事件 / POST action=clear，未知 action 回 200+code1
    "/api/burst": (200, 200),
    "/api/proxies": (200, 200),
    # ---- 名单 / 日志 / 封禁 ----
    "/api/iplist": (200, 200),
    "/api/logs": (200, 200),               # GET 列表 / POST 仅 action=purge，未知 action 回 200+code1
    "/api/logs/proxies": (200, 200),
    "/api/logs/summary": (200, 200),
    "/api/bans": (200, 200),               # GET 列表 / POST 已知 action，未知 action 回 200+code1
    "/api/export": (200, 405),             # 仅 GET
    "/api/config": (200, 200),             # GET 读取 / POST 保存，两方法都有分支
    "/api/password": (405, 200),           # 仅 POST（P2-3.14 收窄：原来 GET 也会进改密分支）
    # ---- 内核 / AI / 升级 / 服务 ----
    "/api/kernban/sync": (405, 200),       # 仅 POST
    "/api/ai/review": (200, 200),
    "/api/ai/review/status": (200, 200),   # 补全：原先契约表漏了这条路由
    "/api/ai/results": (200, 200),
    "/api/ai/test": (405, 200),            # 仅 POST
    "/api/ai/test/status": (200, 405),     # 仅 GET
    "/api/upgrade/check": (200, 200),
    "/api/upgrade/status": (200, 405),     # 仅 GET
    "/api/upgrade/apply": (405, 200),      # 仅 POST
    "/api/service": (405, 200),            # 仅 POST
    # ---- 认证（在 /api/* 门禁之前匹配，但只认 POST） ----
    "/api/login": (404, 200),
    "/api/logout": (404, 200),
}

# `/api/metrics` 的字段契约（面板与插件端都按这些名字读）
METRICS_KEYS = ("engine_errors", "invalid_addr", "db_write_fail", "fw_sync_fail",
                "fw_sync_ms", "ai_call_ms", "uptime_s")

# `job.status()` 的字段契约（前端提交+轮询据此渲染）
JOB_KEYS = ("job_id", "kind", "running", "percent", "msg", "done", "ok",
            "error", "ts", "started", "finished", "ms")


# ---------------------------------------------------------------- 传输层工具
def _header(headers, name):
    """大小写不敏感取响应头（http.client 保留服务端原始大小写）。"""
    want = name.lower()
    for k, v in headers.items():
        if k.lower() == want:
            return v
    return ""


def _request(port, method, path, body=None, cookie=None, raw=None, timeout=20):
    """发一个请求，返回 (状态码, 响应头 dict, 响应体文本)。

    每次新建连接：服务端是 HTTP/1.1 + keep-alive，复用连接会让「上一条响应
    没读完」这类问题混进被测行为里，而路由测试只关心单次请求的结果。
    """
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {}
        data = None
        if cookie:
            headers["Cookie"] = cookie
        if raw is not None:
            data = raw
            headers["Content-Type"] = "application/json"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


class _Server:
    """真实监听（127.0.0.1 + 系统分配端口），封装成好用的请求客户端。"""

    def __init__(self, handler_cls=None, max_concurrent=8):
        self.srv = daemon._QuietHTTPServer(("127.0.0.1", 0), handler_cls or daemon.Handler,
                                          max_concurrent=max_concurrent)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        # poll_interval 调小：shutdown() 要等 serve_forever 的轮询窗口结束才返回，
        # 用默认 0.5s 时每个用例光关服务就要半秒（整套测试会慢几十秒）。
        self.th = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02},
                                   daemon=True)
        self.th.start()

    def stop(self):
        # 先 shutdown 让 serve_forever 退出，再关监听（与 daemon._stop_listener 同序）
        for fn in (self.srv.shutdown, self.srv.server_close):
            try:
                fn()
            except Exception:
                pass

    def call(self, method, path, body=None, cookie=None, raw=None):
        return _request(self.port, method, path, body=body, cookie=cookie, raw=raw)

    def json(self, method, path, body=None, cookie=None, raw=None):
        """返回 (状态码, 解析后的 JSON 或 None)。"""
        status, _, text = self.call(method, path, body=body, cookie=cookie, raw=raw)
        try:
            return status, json.loads(text)
        except ValueError:
            return status, None


class _RemoteSourceHandler(daemon.Handler):
    """把来源 IP 伪装成非本机地址。

    `/frp/handler` 的「仅本机」限制按 `_client_ip()` 判定，本机测试连接永远
    是 127.0.0.1，只能通过覆盖这一个取值函数来验证拒绝分支。
    """

    def _client_ip(self):
        return "203.0.113.9"


# ---------------------------------------------------------------- 公共夹层
class RouteTestCase(unittest.TestCase):
    """隔离 HOME + 真实监听 + 外部副作用打桩。"""

    # 子类置 True 时把 job.start 打桩：契约表里有提交后台任务的端点，
    # 但那张表只关心状态码，不需要真的起线程。
    stub_job_start = False

    def setUp(self):
        new_home(self)
        store.init()
        # 登录失败计数是模块级状态，跨用例会累积（同一进程里跑 10 次失败就会
        # 触发 127.0.0.1 的限速，后续用例拿到 429）。每个用例开始前清空。
        daemon._login_fail.clear()
        # 口令现生成：写死字面量会触发硬编码口令审计，也没有额外价值。
        self.pwd = "pwd-" + secrets.token_hex(6)
        # 非默认口令 => password_changed 自动为 True（config.normalize_password_flag），
        # 否则 /api/* 会被「首次登录强制改密」门禁拦成 403。
        config.save({"admin_password": self.pwd})
        self._stub_externals()
        if self.stub_job_start:
            self._patch(job, "start", lambda kind, worker, msg="", job_id="": (
                True, "已提交", {"job_id": "job-test", "kind": kind, "running": True}))
        self.web = _Server()
        self.addCleanup(self.web.stop)
        self.ck = self.cookie()

    def _patch(self, target, attr, value):
        p = mock.patch.object(target, attr, value)
        p.start()
        self.addCleanup(p.stop)

    def _stub_externals(self):
        """打桩进程外副作用与网络调用（其余一律走真实代码路径）。"""
        # 内核处置：非 root/Windows 上本来就不执行；显式打桩保证在 root 环境的
        # Linux 上跑测试也不会真的调 ipset/iptables。
        self._patch(daemon.firewall, "available", lambda: False)
        # 拦截页：会在 0.0.0.0 起真监听，测试里不启。
        self._patch(daemon.blockpage, "ensure", lambda: True)
        # GitHub 在线升级：绝不联网。
        self._patch(daemon.upgrade, "check",
                    lambda repo: {"ok": True, "msg": "已是最新版本",
                                  "from": "1.4.2", "to": "1.4.2"})
        self._patch(daemon.upgrade, "apply",
                    lambda repo: {"ok": True, "msg": "已是最新版本"})
        # /etc/init.d 服务脚本：测试里不碰宿主服务管理。
        self._patch(daemon.upgrade, "schedule_init", lambda action, delay=2: True)
        # AI 模型接口：绝不联网。
        self._patch(daemon.ai, "call_model", lambda cfg, rows: (True, "ok"))
        self._patch(daemon.ai, "review", lambda force=False: {"ok": True, "msg": "已审查"})

    # ---- 便捷方法 ----
    def cookie(self, user="admin"):
        """直接签一个会话 Cookie（等价于登录后的 Cookie，省一次 HTTP 往返）。"""
        return "%s=%s" % (auth.COOKIE_NAME, auth.create_token(user))

    def login(self, password, user="admin"):
        """走真实 POST /api/login 拿 Cookie，返回 (状态码, 响应头, Cookie 或 "")。"""
        status, headers, text = self.web.call(
            "POST", "/api/login", body={"username": user, "password": password})
        raw = _header(headers, "Set-Cookie")
        return status, headers, (raw.split(";")[0] if raw else "")

    def post_body(self, path):
        """契约表默认请求体；登录要带真口令，否则拿不到 200。"""
        if path == "/api/login":
            return {"username": "admin", "password": self.pwd}
        return {}

    def assert_sec_headers(self, headers):
        for name, value in SEC_HEADERS.items():
            self.assertEqual(_header(headers, name), value, "缺少安全响应头 " + name)
        self.assertIn("frame-ancestors 'none'", _header(headers, "Content-Security-Policy"))

    def assert_json(self, status, headers, text, expect_status=200):
        self.assertEqual(status, expect_status, text[:300])
        self.assertIn("application/json", _header(headers, "Content-Type"), text[:300])
        return json.loads(text)


# ---------------------------------------------------------------- 1. 路由契约
class RouteContractTest(RouteTestCase):
    """每条 path 在 GET/POST 下的实际状态码（3.14 路由表的安全网主体）。"""

    stub_job_start = True

    def test_route_status_table(self):
        """逐条比对路由契约表；200 的必须是 JSON（不能回 HTML 错误页）。"""
        for path, (get_status, post_status) in ROUTES.items():
            with self.subTest(path=path, method="GET"):
                status, headers, text = self.web.call("GET", path, cookie=self.ck)
                self._check(path, "GET", get_status, status, headers, text)
            with self.subTest(path=path, method="POST"):
                status, headers, text = self.web.call(
                    "POST", path, body=self.post_body(path), cookie=self.ck)
                self._check(path, "POST", post_status, status, headers, text)

    def _check(self, path, method, expect, status, headers, text):
        """单条契约断言（含 405 必带 Allow、且 Allow 不得包含被拒方法）。"""
        self.assertEqual(status, expect, text[:300])
        if expect == 200 and path.startswith("/api/"):
            self.assertIn("application/json",
                          _header(headers, "Content-Type"), text[:300])
        if expect == 404:
            self.assertIn("接口不存在", text)
        if expect == 405:
            allow = _header(headers, "Allow")
            self.assertTrue(allow.strip(), "405 必须带 Allow 头：" + path)
            listed = [m.strip() for m in allow.split(",")]
            self.assertNotIn(method, listed,
                             "%s 收到 %s 却把 %s 列进 Allow" % (path, method, method))
            for m in listed:
                self.assertIn(m, ("GET", "POST"), "Allow 里出现意料外方法：" + m)

    def test_route_table_matches_routes_constant(self):
        """`daemon._ROUTES` 与本文件的契约表必须逐条对账。

        反过来也钉住「新增路由不能只存在于代码里」：代码里多一条而本表没加，
        或者表里写的 path 在代码里不存在，都会立刻红。`/api/login`、
        `/api/logout` 在 `_route` 里就处理掉了（不会到 `_api`），故排除。
        """
        self.assertEqual(set(daemon._ROUTES), set(ROUTES) - {"/api/login", "/api/logout"})
        self.assertEqual(len(daemon._ROUTES), len(ROUTES) - 2)
        for path, (allowed, handler_name) in daemon._ROUTES.items():
            with self.subTest(path=path):
                self.assertTrue(allowed, path + " 的方法集合不能为空")
                self.assertTrue(set(allowed) <= {"GET", "POST"},
                                "%s 声明了不可能到达的方法：%s" % (path, sorted(allowed)))
                self.assertTrue(callable(getattr(daemon.Handler, handler_name, None)),
                                "%s 指向不存在的方法 %s" % (path, handler_name))

    def test_every_route_is_registered(self):
        """契约表覆盖 `_api` 里的每一条 path（漏测的路由会在重构时裸奔）。"""
        # 33 = `daemon._ROUTES` 的 31 条 + `/api/login` + `/api/logout`
        # （后两者在 `_route` 里就处理掉了，不会到 `_api`）
        self.assertEqual(len(ROUTES), 33)
        # 前缀相近的几组路由：路由表是 dict.get 精确匹配，长路径不会被短路径吃掉。
        # 断言保留在这里，防止将来有人改回 startswith 前缀匹配。
        for long_path, short_path in (
                ("/api/ai/test/status", "/api/ai/test"),
                ("/api/ai/review/status", "/api/ai/review"),
                ("/api/logs/proxies", "/api/logs"),
                ("/api/logs/summary", "/api/logs")):
            self.assertIn(long_path, ROUTES)
            self.assertIn(short_path, ROUTES)
            self.assertTrue(long_path.startswith(short_path))
            # 相邻前缀必须各自独立命中自己的 handler（不是同一份逻辑）
            self.assertNotEqual(daemon._ROUTES[long_path][1],
                                daemon._ROUTES[short_path][1])

    def test_unknown_paths_are_404(self):
        """不存在的路径：/api/* 下回 JSON 404，其余回纯文本 404。"""
        for path in ("/api/nope", "/api/version/x", "/api/", "/api"):
            with self.subTest(path=path):
                status, headers, text = self.web.call("GET", path, cookie=self.ck)
                self.assertEqual(status, 404, text[:200])
        status, body = self.web.json("GET", "/api/nope", cookie=self.ck)
        self.assertEqual(status, 404)
        self.assertEqual(body.get("code"), 404)

        for path in ("/nope", "/index.htm", "/api2/version"):
            with self.subTest(path=path):
                status, headers, text = self.web.call("GET", path, cookie=self.ck)
                self.assertEqual(status, 404, text[:200])
                self.assertIn("not found", text)
                self.assertIn("text/plain", _header(headers, "Content-Type"))

    def test_trailing_slash_is_not_normalized(self):
        """/api/version/ 不匹配 /api/version（现状：回 JSON 404）。

        3.14 若加尾斜杠归一化，这里会变红——那时应当顺手让前端不再拼错。
        """
        status, _, text = self.web.call("GET", "/api/version/", cookie=self.ck)
        self.assertEqual(status, 404, text[:200])

    def test_other_methods_are_405_everywhere(self):
        """PUT/DELETE/PATCH/OPTIONS → 405（含不存在的路径），且带安全响应头。"""
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            for path in ("/api/metrics", "/api/version", "/nope"):
                with self.subTest(method=method, path=path):
                    status, headers, text = self.web.call(method, path, cookie=self.ck)
                    self.assertEqual(status, 405, text[:200])
                    self.assertIn("method not allowed", text)
                    self.assertIn("text/plain", _header(headers, "Content-Type"))
                    self.assert_sec_headers(headers)

    def test_head_follows_get_route_and_sends_no_body(self):
        """HEAD 走 GET 路由：不能是 501（stdlib 默认页会缺安全响应头）。"""
        status, headers, text = self.web.call("HEAD", "/api/version", cookie=self.ck)
        self.assertEqual(status, 200)
        self.assertEqual(text, "")
        self.assert_sec_headers(headers)
        status, _, text = self.web.call("HEAD", "/api/metrics", cookie=self.ck)
        self.assertEqual(status, 200)
        self.assertEqual(text, "")
        status, _, _ = self.web.call("HEAD", "/nope", cookie=self.ck)
        self.assertEqual(status, 404)

    def test_static_entry_points(self):
        """/ 与 /index.html 回 HTML，/favicon.ico 回 204（免登录）。"""
        for path in ("/", "/index.html"):
            with self.subTest(path=path):
                status, headers, text = self.web.call("GET", path)
                self.assertEqual(status, 200)
                self.assertIn("text/html", _header(headers, "Content-Type"))
                self.assertIn("<!DOCTYPE html>", text[:200])
        status, headers, text = self.web.call("GET", "/favicon.ico")
        self.assertEqual(status, 204)
        self.assertEqual(text, "")


class MethodSemanticsTest(RouteTestCase):
    """方法语义：路径存在但方法不允许时必须是 405 + Allow（不是 404）。

    重构前两种写法行为不同：`if path == X and method == "POST"` 在方法不匹配时
    会掉到链尾回 404「接口不存在」（把「方法用错」报成「路径不存在」），只有
    `/api/export`、`/api/ai/test` 两处显式回了 405。现在方法约束统一声明在
    `daemon._ROUTES` 里，两种写法不再有行为差异；本类原先的两个
    `@unittest.expectedFailure`（钉住那个偏差）已随修复去掉。
    """

    stub_job_start = True

    def test_post_only_routes_reject_get_with_405(self):
        """仅 POST 的路由收到 GET → 405，且 `Allow: POST`。"""
        for path in ("/api/kernban/sync", "/api/upgrade/apply", "/api/service",
                     "/api/ai/test", "/api/password"):
            with self.subTest(path=path):
                status, headers, text = self.web.call("GET", path, cookie=self.ck)
                self.assertEqual(status, 405, "%s 期望 405，实际 %s" % (path, status))
                self.assertIn("application/json",
                              _header(headers, "Content-Type"), text[:200])
                self.assertEqual(_header(headers, "Allow"), "POST", text[:200])

    def test_get_only_routes_reject_post_with_405(self):
        """仅 GET 的路由收到 POST → 405，且 `Allow: GET`。"""
        for path in ("/api/upgrade/status", "/api/ai/test/status", "/api/export"):
            with self.subTest(path=path):
                status, headers, text = self.web.call(
                    "POST", path, body={}, cookie=self.ck)
                self.assertEqual(status, 405, "%s 期望 405，实际 %s" % (path, status))
                self.assertEqual(_header(headers, "Allow"), "GET", text[:200])

    def test_head_is_judged_as_get(self):
        """HEAD 走 GET 路由（`do_HEAD` -> `_route("GET")`），故 POST-only 路由回 405。

        这条钉住 dispatch 用的是 `_route` 传入的 method，而不是 `self.command`：
        若误用 `self.command`，HEAD 会被当成一个第三种方法。
        """
        status, headers, text = self.web.call("HEAD", "/api/upgrade/apply", cookie=self.ck)
        self.assertEqual(status, 405)
        self.assertEqual(text, "")
        self.assertEqual(_header(headers, "Allow"), "POST")

    def test_405_keeps_security_headers(self):
        """405 必须走 `_send`：stdlib 默认 error 响应会绕过它并丢安全响应头。"""
        for method, path in (("GET", "/api/upgrade/apply"),
                             ("POST", "/api/upgrade/status")):
            with self.subTest(method=method, path=path):
                kwargs = {"body": {}} if method == "POST" else {}
                _, headers, _ = self.web.call(method, path, cookie=self.ck, **kwargs)
                self.assert_sec_headers(headers)

    def test_unknown_post_action_is_not_reported_as_missing_route(self):
        """未知 action 不再报「接口不存在」：口径与 /api/iplist 一致。

        原先 `/api/logs`、`/api/bans` 收到未知 action 时分支没有 else，直接掉到
        链尾回 404「接口不存在」，把「action 写错」报成「路径不存在」。
        """
        for path in ("/api/logs", "/api/bans", "/api/iplist"):
            with self.subTest(path=path):
                status, body = self.web.json(
                    "POST", path, {"action": "zzz"}, cookie=self.ck)
                self.assertEqual(status, 200, body)
                self.assertEqual(body["code"], 1, body)
                self.assertIn("未知操作", body["msg"])


# ---------------------------------------------------------------- 2. 鉴权边界
class AuthGateTest(RouteTestCase):
    """未登录 401 / 免登录端点 / 会话 Cookie 校验。"""

    stub_job_start = True

    def test_every_api_route_rejects_anonymous(self):
        """所有 /api/* 未登录一律 401（既不能 200，也不能 500）。"""
        for path in ROUTES:
            with self.subTest(path=path):
                status, headers, text = self.web.call("GET", path)
                self.assertEqual(status, 401, text[:200])
                self.assertEqual(json.loads(text)["code"], 401)
                self.assert_sec_headers(headers)

    def test_write_routes_reject_anonymous(self):
        """写操作未登录同样是 401（不能被「先查方法再查登录」的顺序漏掉）。"""
        for path in ("/api/config", "/api/iplist", "/api/bans", "/api/password",
                     "/api/kernban/sync", "/api/service", "/api/upgrade/apply"):
            with self.subTest(path=path):
                status, _, text = self.web.call("POST", path, body={})
                self.assertEqual(status, 401, text[:200])

    def test_anonymous_401_does_not_disclose_password_state(self):
        """未登录的 401 不泄露「默认口令未改」这个状态（门禁在认证之后）。"""
        status, _, text = self.web.call("GET", "/api/metrics")
        self.assertEqual(status, 401)
        body = json.loads(text)
        self.assertNotIn("password_change_required", body)
        self.assertEqual(sorted(body), ["code", "msg"])

    def test_login_returns_usable_cookie(self):
        """POST /api/login 正常路径：200 + 可直接用于后续请求的 Cookie。"""
        status, headers, cookie = self.login(self.pwd)
        self.assertEqual(status, 200)
        raw = _header(headers, "Set-Cookie")
        self.assertIn(auth.COOKIE_NAME + "=", raw)
        self.assertIn("HttpOnly", raw)
        self.assertIn("SameSite=Lax", raw)
        self.assertIn("Path=/", raw)
        self.assertTrue(cookie)
        status, body = self.web.json("GET", "/api/version", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body["code"], 0)

    def test_login_with_wrong_password_is_401(self):
        """口令错误 → 401（不能是 200，也不能 500）。"""
        status, _, text = self.web.call(
            "POST", "/api/login", body={"username": "admin", "password": self.pwd + "x"})
        self.assertEqual(status, 401, text[:200])
        self.assertEqual(json.loads(text)["code"], 401)

    def test_login_reports_password_change_required(self):
        """登录体里带 password_change_required（前端据此渲染强制改密引导）。"""
        status, body = self.web.json(
            "POST", "/api/login", {"username": "admin", "password": self.pwd})
        self.assertEqual(status, 200)
        self.assertIn("password_change_required", body)
        self.assertFalse(body["password_change_required"])

    def test_forged_cookie_is_401(self):
        """伪造/损坏的会话 Cookie → 401（含签名不对、结构不对两种）。"""
        good = auth.create_token("admin")
        body, sig = good.rsplit(".", 1)
        forged = [
            "%s=garbage" % auth.COOKIE_NAME,
            "%s=%s.%s" % (auth.COOKIE_NAME, body, sig[:-1] + ("0" if sig[-1] != "0" else "1")),
            "%s=%s" % (auth.COOKIE_NAME, "a.b.c"),
            "%s=" % auth.COOKIE_NAME,
        ]
        for cookie in forged:
            with self.subTest(cookie=cookie[:40]):
                status, _, text = self.web.call("GET", "/api/version", cookie=cookie)
                self.assertEqual(status, 401, text[:200])

    def test_logout_is_reachable_without_login(self):
        """POST /api/logout 免登录可访问，且回一份清除 Cookie 的头。"""
        status, headers, text = self.web.call("POST", "/api/logout", body={})
        self.assertEqual(status, 200, text[:200])
        self.assertEqual(json.loads(text)["code"], 0)
        self.assertIn("Max-Age=0", _header(headers, "Set-Cookie"))

    def test_callback_endpoint_is_anonymous(self):
        """POST /frp/handler 免登录（关闭网页端也不影响 WAF 防护）。"""
        status, _, text = self.web.call(
            "POST", "/frp/handler", body={"op": "Ping"})
        self.assertEqual(status, 200, text[:200])
        self.assertEqual(json.loads(text), {"reject": False, "unchange": True})


class PasswordGateTest(RouteTestCase):
    """`password_changed=False`（仍在用默认口令）时的 403 门禁。"""

    stub_job_start = True
    default_pwd = config.DEFAULTS["admin_password"]

    def setUp(self):
        super().setUp()
        # 换回出厂口令：normalize_password_flag 会把 password_changed 归一为 False
        config.save({"admin_password": self.default_pwd})
        self.assertFalse(config.get().get("password_changed"))

    def test_gate_blocks_everything_but_whitelist(self):
        """除 /api/password、/api/overview 外全部 403，且带明确提示。"""
        status, _, cookie = self.login(self.default_pwd)
        self.assertEqual(status, 200)
        blocked = [p for p in ROUTES
                   if p not in ("/api/password", "/api/overview", "/api/login", "/api/logout")]
        for path in blocked:
            with self.subTest(path=path):
                status, _, text = self.web.call("GET", path, cookie=cookie)
                self.assertEqual(status, 403, text[:200])
                body = json.loads(text)
                self.assertEqual(body["code"], 403)
                self.assertTrue(body.get("password_change_required"))

    def test_whitelisted_routes_still_work(self):
        """/api/overview（渲染引导）与 /api/password（改密）不被门禁拦。"""
        status, _, cookie = self.login(self.default_pwd)
        self.assertEqual(status, 200)
        status, body = self.web.json("GET", "/api/overview", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["data"]["password_change_required"])
        status, body = self.web.json("POST", "/api/password", {"old": "x"}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 1)

    def test_anonymous_is_401_not_403(self):
        """未登录时仍是 401：不能因为门禁在前而泄露「口令未改」。"""
        status, _, text = self.web.call("GET", "/api/metrics")
        self.assertEqual(status, 401, text[:200])

    def test_changing_password_lifts_gate(self):
        """改密成功后门禁解除；旧会话随 secret 轮换一起失效。"""
        status, _, cookie = self.login(self.default_pwd)
        self.assertEqual(status, 200)
        new_pwd = "pwd-" + secrets.token_hex(6)
        status, body = self.web.json(
            "POST", "/api/password", {"old": self.default_pwd, "new": new_pwd}, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertTrue(config.get().get("password_changed"))
        # secret 已轮换：旧 Cookie 失效（401），需要重新登录
        status, _, text = self.web.call("GET", "/api/metrics", cookie=cookie)
        self.assertEqual(status, 401, text[:200])
        status, _, cookie2 = self.login(new_pwd)
        self.assertEqual(status, 200)
        status, body = self.web.json("GET", "/api/metrics", cookie=cookie2)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0)


class WebDisabledTest(RouteTestCase):
    """`web_enabled=False`：网页端与 /api/* 一律 403，回调照常。"""

    stub_job_start = True

    def setUp(self):
        super().setUp()
        config.save({"web_enabled": False})

    def test_web_endpoints_are_closed(self):
        for method, path in (("GET", "/"), ("GET", "/index.html"),
                             ("GET", "/favicon.ico"), ("GET", "/api/version"),
                             ("GET", "/api/metrics"), ("GET", "/nope"),
                             ("POST", "/api/login"), ("POST", "/api/config")):
            with self.subTest(method=method, path=path):
                kwargs = {"body": {}} if method == "POST" else {}
                status, _, text = self.web.call(method, path, cookie=self.ck, **kwargs)
                self.assertEqual(status, 403, text[:200])
                self.assertIn("网页端已关闭", text)

    def test_callback_still_works(self):
        """/frp/handler 在网页端关闭时仍然放行（否则关网页端等于关防护）。"""
        status, _, text = self.web.call("POST", "/frp/handler", body={"op": "Ping"})
        self.assertEqual(status, 200, text[:200])


class HandlerOnlyListenerTest(RouteTestCase):
    """回调专用监听（`_HandlerOnlyHandler`）不提供面板与其它 API。"""

    stub_job_start = True

    def setUp(self):
        super().setUp()
        self.cb = _Server(daemon._HandlerOnlyHandler)
        self.addCleanup(self.cb.stop)

    def test_only_callback_path_is_served(self):
        for path in ("/", "/index.html", "/api/version", "/api/metrics", "/nope"):
            with self.subTest(path=path):
                status, _, text = self.cb.call("GET", path)
                self.assertEqual(status, 404, text[:200])
                self.assertIn("not found", text)

    def test_callback_path_is_served(self):
        status, _, text = self.cb.call("POST", "/frp/handler", body={"op": "Ping"})
        self.assertEqual(status, 200, text[:200])
        self.assertEqual(json.loads(text), {"reject": False, "unchange": True})


# ---------------------------------------------------------------- 3. 入参校验
class InputValidationTest(RouteTestCase):
    """异常取值 → 400（不能变成 500 + traceback 灌日志）。"""

    stub_job_start = True

    CASES = (
        # (路径, 请求体, 说明)
        ("/api/iplist", {"action": "del", "id": {}}, "id 是对象"),
        ("/api/iplist", {"action": "del", "id": "abc"}, "id 是字符串"),
        ("/api/iplist", {"action": "del", "id": 0}, "id 小于下限"),
        ("/api/iplist", {"action": "add", "cidr": 123}, "cidr 是数字"),
        ("/api/iplist", {"action": "add", "cidr": {}}, "cidr 是对象"),
        ("/api/iplist", {"action": "add", "cidr": "not-a-cidr"}, "cidr 无法解析"),
        ("/api/iplist", {"action": "add", "cidr": "1.2.3.4", "list_type": 5},
         "list_type 不是字符串"),
        ("/api/iplist", {"action": "add", "cidr": "1.2.3.4", "list_type": "gray"},
         "list_type 不在枚举内"),
        ("/api/iplist", {"action": "add", "cidr": "1.2.3.4", "remark": "x" * 501},
         "remark 超长"),
        ("/api/iplist", {"action": "batch", "text": {}}, "text 是对象"),
        ("/api/bans", {"action": "ban", "ip": "1.2.3.4", "seconds": "abc"},
         "seconds 是字符串"),
        ("/api/bans", {"action": "ban", "ip": "1.2.3.4", "seconds": {}}, "seconds 是对象"),
        ("/api/bans", {"action": "ban", "ip": "1.2.3.4", "seconds": 1.5},
         "seconds 是小数"),
        ("/api/bans", {"action": "ban", "ip": "1.2.3.4", "seconds": 400 * 86400},
         "seconds 超上限"),
        ("/api/bans", {"action": "ban", "ip": "not-an-ip"}, "ip 无法解析"),
        ("/api/bans", {"action": "unban", "ip": {}}, "ip 是对象"),
    )

    def test_invalid_values_return_400(self):
        for path, body, note in self.CASES:
            with self.subTest(path=path, note=note):
                status, headers, text = self.web.call(
                    "POST", path, body=body, cookie=self.ck)
                self.assertEqual(status, 400, "%s -> %s %s" % (note, status, text[:200]))
                parsed = json.loads(text)
                self.assertEqual(parsed["code"], 1, parsed)
                self.assertTrue(str(parsed.get("msg") or "").strip())
                self.assertNotIn("Traceback", text)
                self.assertIn("application/json", _header(headers, "Content-Type"))

    def test_task_specified_regressions(self):
        """上批改成 400 的三个点（id 对象 / seconds 字符串 / cidr 数字）。"""
        cases = (
            ("/api/iplist", {"action": "del", "id": {}}),
            ("/api/bans", {"action": "ban", "ip": "1.2.3.4", "seconds": "abc"}),
            ("/api/iplist", {"action": "add", "cidr": 123}),
        )
        for path, body in cases:
            with self.subTest(path=path):
                status, _, text = self.web.call("POST", path, body=body, cookie=self.ck)
                self.assertEqual(status, 400, text[:200])

    def test_valid_values_are_not_rejected(self):
        """合法取值不能被校验误伤（400 只该留给异常取值）。"""
        status, body = self.web.json(
            "POST", "/api/iplist", {"action": "add", "cidr": "192.0.2.0/24",
                                    "list_type": "black", "remark": "ok"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        status, body = self.web.json(
            "POST", "/api/bans", {"action": "ban", "ip": "192.0.2.7", "seconds": 60},
            cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)

    def test_malformed_bodies_do_not_crash(self):
        """非 JSON / 数组 / 空体一律当空对象处理，不能 500。"""
        for raw in (b"", b"[]", b"not json", b"null", b'{"a": 1}'):
            with self.subTest(raw=raw):
                status, _, text = self.web.call(
                    "POST", "/api/config", raw=raw, cookie=self.ck)
                self.assertEqual(status, 200, text[:200])
                self.assertNotIn("Traceback", text)

    def test_query_edge_values_do_not_crash(self):
        """查询串里的异常取值（非数字/负数/超范围）回落到默认值，不能 500。"""
        for path in ("/api/logs?limit=abc", "/api/logs?limit=-5",
                     "/api/logs/summary?window=abc", "/api/logs/summary?window=0",
                     "/api/syslog?limit=abc", "/api/iplist?limit=abc",
                     "/api/iplist?type=zzz"):
            with self.subTest(path=path):
                status, _, text = self.web.call("GET", path, cookie=self.ck)
                self.assertEqual(status, 200, text[:200])


class InvalidConfigValueBugTest(RouteTestCase):
    """`/api/config` 静默吞掉非法取值并回「保存成功」——已知缺陷。"""

    stub_job_start = True

    def test_invalid_numeric_value_is_not_reported_as_success(self):
        """已知缺陷：数值型字段收到对象/字符串时 `int(...)` 失败被 pass 掉，
        接口回 code=0「保存成功」，而配置根本没变——用户以为生效了。
        期望：至少回 code=1 并指明哪个字段非法（与 http_port/http_addr 的处理一致）。
        """
        before = config.get().get("log_max_rows")
        status, body = self.web.json(
            "POST", "/api/config", {"log_max_rows": {"bad": 1}}, cookie=self.ck)
        self.assertEqual(status, 200)
        self.assertEqual(config.get().get("log_max_rows"), before)   # 值确实没变
        self.assertNotEqual(body.get("code"), 0, "非法取值不应回「保存成功」")

    def test_invalid_repo_value_is_not_reported_as_success(self):
        """已知缺陷：`github_repo` 收到数字时被 str() 成 "12345" 并保存成功。

        升级时 valid_repo() 才会拒绝，用户要等到点「升级」才发现配置是垃圾。
        """
        status, body = self.web.json(
            "POST", "/api/config", {"github_repo": 12345}, cookie=self.ck)
        self.assertEqual(status, 200)
        self.assertNotEqual(config.get().get("github_repo"), "12345")
        self.assertNotEqual(body.get("code"), 0)


# ---------------------------------------------------------------- 4. 返回结构
class ResponseShapeTest(RouteTestCase):
    """关键端点的返回结构（前端与插件端都按这些字段名取数）。"""

    def test_metrics_fields(self):
        """/api/metrics：字段齐全，且顶层与 data 镜像一致。"""
        original = daemon._mem["engine_errors"]
        self.addCleanup(daemon._mem.__setitem__, "engine_errors", original)
        daemon._mem["engine_errors"] = 7
        status, headers, text = self.web.call("GET", "/api/metrics", cookie=self.ck)
        body = self.assert_json(status, headers, text)
        self.assertEqual(body["code"], 0)
        for key in METRICS_KEYS:
            self.assertIn(key, body, "缺少字段 " + key)
            self.assertIn(key, body["data"], "data 里缺少字段 " + key)
            self.assertIsInstance(body[key], int, key)
            self.assertGreaterEqual(body[key], 0, key)
            self.assertEqual(body["data"][key], body[key], key)
        self.assertEqual(body["engine_errors"], 7)
        self.assertEqual(body["invalid_addr"], 0)
        self.assertGreaterEqual(body["uptime_s"], 0)

    def test_overview_fields(self):
        """/api/overview：页面渲染依赖的布尔/地址字段齐全。"""
        status, body = self.web.json("GET", "/api/overview", cookie=self.ck)
        self.assertEqual(status, 200, body)
        data = body["data"]
        for key in ("version", "uptime", "http_addr", "http_port", "frp_handler_port",
                    "blacklist_enabled", "whitelist_enabled", "auto_ban_enabled",
                    "rate_limit_enabled", "password_change_required", "admin_user",
                    "engine_errors", "invalid_addr", "strict_addr", "geo_available",
                    "kern_dropped", "kern_dropped_bytes", "kern_drop_available"):
            self.assertIn(key, data, "缺少字段 " + key)
        self.assertIsInstance(data["password_change_required"], bool)
        self.assertEqual(data["admin_user"], "admin")
        # 内核丢弃计数：本测试把 firewall.available 打桩为 False（不碰宿主内核），
        # 所以这里必须是「降级为不可用」而不是报错或返回 None。
        self.assertIs(data["kern_drop_available"], False)
        self.assertEqual(data["kern_dropped"], 0)
        self.assertEqual(data["kern_dropped_bytes"], 0)

    def test_job_status_structure(self):
        """/api/upgrade/status 与 /api/ai/test/status 回 job 状态结构。"""
        # 真跑一次后台任务（worker 立即返回），确认轮询接口拿到终态
        ok, _, _ = job.start("upgrade", lambda progress: {"ok": True, "msg": "完成"},
                             "检查更新…")
        self.assertTrue(ok)
        ok, _, _ = job.start("ai_test", lambda progress: {"ok": True, "msg": "连接成功"},
                             "正在调用模型…")
        self.assertTrue(ok)
        deadline = time.time() + 5
        while time.time() < deadline:
            if not job.status("upgrade").get("running") \
                    and not job.status("ai_test").get("running"):
                break
            time.sleep(0.05)
        for path, kind in (("/api/upgrade/status", "upgrade"),
                           ("/api/ai/test/status", "ai_test")):
            with self.subTest(path=path):
                status, body = self.web.json("GET", path, cookie=self.ck)
                self.assertEqual(status, 200, body)
                self.assertEqual(body["code"], 0)
                data = body["data"]
                for key in JOB_KEYS:
                    self.assertIn(key, data, "缺少字段 " + key)
                self.assertEqual(data["kind"], kind)
                self.assertFalse(data["running"])
                self.assertTrue(data["done"])
                self.assertTrue(data["ok"])
                self.assertIsInstance(data["percent"], int)
                self.assertIsInstance(data["ms"], int)

    def test_export_masks_secrets(self):
        """/api/export：机密字段掩码，真实值不出现在响应体里。"""
        real_key = "sk-" + secrets.token_hex(16)
        config.save({"ai_api_key": real_key})
        status, headers, text = self.web.call("GET", "/api/export", cookie=self.ck)
        body = self.assert_json(status, headers, text)
        self.assertIn("attachment", _header(headers, "Content-Disposition"))
        self.assertIn(".json", _header(headers, "Content-Disposition"))
        self.assertTrue(body["ok"])
        self.assertIsInstance(body["exported_at"], int)
        masked = body["config_masked"]
        self.assertEqual(masked["ai_api_key"], daemon.MASKED_VALUE)
        self.assertEqual(masked["admin_password"], daemon.MASKED_VALUE)
        self.assertEqual(masked["secret"], daemon.MASKED_VALUE)
        self.assertNotIn(real_key, text)
        self.assertNotIn(self.pwd, text)
        self.assertEqual(masked["admin_user"], "admin")
        self.assertIn("ip_list", body)
        self.assertIn("bans", body)

    def test_export_keeps_empty_secret_empty(self):
        """空密钥保持空值（填掩码会让人误以为「配了一个密钥」）。"""
        config.save({"ai_api_key": ""})
        status, body = self.web.json("GET", "/api/export", cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["config_masked"]["ai_api_key"], "")

    def test_config_get_masks_secrets(self):
        """/api/config：GET 不回写真密钥，机密字段整体不出现在 data 里。"""
        real_key = "sk-" + secrets.token_hex(16)
        config.save({"ai_api_key": real_key})
        status, _, text = self.web.call("GET", "/api/config", cookie=self.ck)
        body = json.loads(text)
        self.assertEqual(status, 200)
        data = body["data"]
        self.assertEqual(data["ai_api_key"], daemon.MASKED_VALUE)
        self.assertNotIn("admin_password", data)
        self.assertNotIn("secret", data)
        self.assertNotIn(real_key, text)
        self.assertNotIn(self.pwd, text)

    def test_security_headers_on_every_outlet(self):
        """安全响应头覆盖 JSON / HTML / 404 文本 / 405 文本 / 401 / 204。"""
        cases = (
            ("GET", "/api/version", self.ck),
            ("GET", "/", None),
            ("GET", "/nope", None),
            ("PUT", "/api/version", self.ck),
            ("GET", "/api/metrics", None),
            ("GET", "/favicon.ico", None),
        )
        for method, path, cookie in cases:
            with self.subTest(method=method, path=path):
                _, headers, _ = self.web.call(method, path, cookie=cookie)
                self.assert_sec_headers(headers)
        # 缓存控制：面板数据不应被中间层缓存
        _, headers, _ = self.web.call("GET", "/api/version", cookie=self.ck)
        self.assertEqual(_header(headers, "Cache-Control"), "no-store")


# ---------------------------------------------------------------- 5. 写操作
class WriteRouteTest(RouteTestCase):
    """写操作端点的实际落库效果（路由表重构不能把分支接到别处）。"""

    stub_job_start = True

    def test_add_and_delete_ip(self):
        status, body = self.web.json(
            "POST", "/api/iplist",
            {"action": "add", "cidr": "203.0.113.0/24", "list_type": "black",
             "remark": "r"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        rows = store.list_ips("black")
        self.assertEqual([r["cidr"] for r in rows], ["203.0.113.0/24"])
        ip_id = rows[0]["id"]
        status, body = self.web.json(
            "POST", "/api/iplist", {"action": "del", "id": ip_id}, cookie=self.ck)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(store.list_ips("black"), [])

    def test_batch_import_reports_counters(self):
        status, body = self.web.json(
            "POST", "/api/iplist",
            {"action": "batch", "text": "198.51.100.1\nnot-a-cidr\n# 注释\n198.51.100.2,r",
             "list_type": "white"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertIn("成功 2", body["msg"])
        self.assertIn("跳过 1", body["msg"])
        self.assertEqual(len(store.list_ips("white")), 2)

    def test_clear_blacklist(self):
        store.add_ip("203.0.113.5", "black", "")
        status, body = self.web.json(
            "POST", "/api/iplist", {"action": "clear_black"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(store.list_ips("black"), [])

    def test_unknown_action_on_iplist(self):
        """未知 action 回 200 + code=1「未知操作」（与 /api/logs 的 404 不一致）。"""
        status, body = self.web.json(
            "POST", "/api/iplist", {"action": "whatever"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 1)
        self.assertIn("未知操作", body["msg"])

    def test_ban_and_release(self):
        status, body = self.web.json(
            "POST", "/api/bans", {"action": "ban", "ip": "203.0.113.9", "seconds": 60},
            cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual([b["ip"] for b in store.active_bans()], ["203.0.113.9"])
        status, body = self.web.json(
            "POST", "/api/bans", {"action": "unban", "ip": "203.0.113.9"}, cookie=self.ck)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(store.active_bans(), [])

    def test_unban_all(self):
        store.add_ban("203.0.113.10", "auto", 60)
        store.add_ban("203.0.113.11", "auto", 60)
        status, body = self.web.json(
            "POST", "/api/bans", {"action": "unban_all"}, cookie=self.ck)
        self.assertEqual(body["code"], 0, body)
        self.assertIn("2", body["msg"])
        self.assertEqual(store.active_bans(), [])

    def test_purge_logs(self):
        store.add_log("203.0.113.12", 7000, "p", "tcp", "u", "allow")
        status, body = self.web.json(
            "POST", "/api/logs", {"action": "purge"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(store.count_logs(), 0)

    def test_config_save_persists(self):
        """POST /api/config 普通保存：落盘且在 overview 里可见（不触发重绑）。"""
        status, body = self.web.json(
            "POST", "/api/config", {"log_max_rows": 1234}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(config.get().get("log_max_rows"), 1234)

    def test_config_listen_change_rebinds(self):
        """改监听端口会触发重绑（重绑本身打桩，只验证路由把 patch 送到了）。"""
        calls = []

        def fake_rebind(role, addr, port, cap, cls, label):
            calls.append((role, port))
            return True, ""

        self._patch(daemon, "_rebind_role", fake_rebind)
        status, body = self.web.json(
            "POST", "/api/config", {"http_port": 17080}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertIn("保存成功", body["msg"])
        self.assertEqual(body["data"]["http_port"], 17080)
        self.assertIn(("panel", 17080), calls)

    def test_config_rejects_bad_listen_values(self):
        """监听地址/端口有白名单与范围校验：非法值回 code=1 且不保存。"""
        cases = (
            ({"http_addr": "10.1.2.3"}, "监听地址"),
            ({"http_addr": 123}, "监听地址"),
            ({"http_port": "abc"}, "必须是数字"),
            ({"http_port": {}}, "必须是数字"),
            ({"frp_handler_port": 0}, "1~65535"),
            ({"frp_handler_port": 70000}, "1~65535"),
        )
        for body, expect in cases:
            with self.subTest(body=str(body)):
                status, parsed = self.web.json("POST", "/api/config", body, cookie=self.ck)
                self.assertEqual(status, 200, parsed)
                self.assertEqual(parsed["code"], 1, parsed)
                self.assertIn(expect, parsed["msg"])

    def test_config_rejects_port_collision(self):
        """面板端口与回调端口相同 → 拒绝（避免服务起不来或回调打到面板）。"""
        cfg = config.get()
        status, body = self.web.json(
            "POST", "/api/config", {"frp_handler_port": cfg["http_port"]}, cookie=self.ck)
        self.assertEqual(body["code"], 1, body)
        self.assertIn("不能相同", body["msg"])

    def test_config_rejects_unsafe_ai_url(self):
        """`ai_base_url` 变更即时校验（SSRF 防护），非 http/https 一律拒。"""
        for url in ("file:///etc/passwd", "http://169.254.169.254/", "gopher://127.0.0.1"):
            with self.subTest(url=url):
                status, body = self.web.json(
                    "POST", "/api/config", {"ai_base_url": url}, cookie=self.ck)
                self.assertEqual(body["code"], 1, body)
                self.assertIn("AI 接口地址不可用", body["msg"])

    def test_config_ignores_masked_secret_writeback(self):
        """「读配置→改一项→整体回写」不得把 ****** 写进真实密钥。"""
        real_key = "sk-" + secrets.token_hex(16)
        config.save({"ai_api_key": real_key})
        status, body = self.web.json(
            "POST", "/api/config", {"ai_api_key": daemon.MASKED_VALUE,
                                    "log_max_rows": 1234}, cookie=self.ck)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(config.get().get("ai_api_key"), real_key)

    def test_password_route_keeps_default_value_out(self):
        """改密接口拒绝把新口令设回出厂默认值（否则门禁永远解不开）。"""
        status, body = self.web.json(
            "POST", "/api/password",
            {"old": self.pwd, "new": config.DEFAULTS["admin_password"]}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 1, body)
        self.assertIn("不能继续使用默认值", body["msg"])

    def test_kernban_sync_when_kernel_unsupported(self):
        """内核不可用时 /api/kernban/sync 仍回 200 + 明确说明（不是 500）。"""
        status, body = self.web.json("POST", "/api/kernban/sync", {}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertIn("data", body)

    def test_ai_test_and_upgrade_are_submitted_as_jobs(self):
        """/api/ai/test、/api/upgrade/apply 走「提交 + 轮询」，立即返回 job_id。"""
        config.save({"ai_base_url": "http://127.0.0.1:9/v1", "ai_api_key": "k"})
        status, body = self.web.json("POST", "/api/ai/test", {}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(body["data"]["job_id"], "job-test")
        config.save({"github_repo": "nightsoil/frpwaf"})
        status, body = self.web.json("POST", "/api/upgrade/apply", {}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        self.assertEqual(body["data"]["job_id"], "job-test")

    def test_ai_test_requires_url_and_key(self):
        """未填地址/密钥时提交阶段就拒（不占任务名额）。"""
        config.save({"ai_base_url": "", "ai_api_key": ""})
        status, body = self.web.json("POST", "/api/ai/test", {}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 1, body)
        self.assertIn("接口地址与密钥", body["msg"])

    def test_upgrade_apply_ignores_request_body_repo(self):
        """升级仓库只取自配置：请求体里的 repo 不得生效（否则可装任意代码）。"""
        config.save({"github_repo": "nightsoil/frpwaf"})
        with mock.patch.object(daemon.upgrade, "valid_repo",
                               side_effect=lambda r: r == "nightsoil/frpwaf") as valid:
            status, body = self.web.json(
                "POST", "/api/upgrade/apply", {"repo": "someone/else"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0, body)
        valid.assert_called_with("nightsoil/frpwaf")

    def test_service_control_rejects_unknown_action(self):
        status, body = self.web.json(
            "POST", "/api/service", {"action": "reboot"}, cookie=self.ck)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 1, body)
        self.assertIn("restart", body["msg"])


# ---------------------------------------------------------------- 6. 回调路由
class FrpCallbackRouteTest(RouteTestCase):
    """/frp/handler：方法约束、来源限制、字段异常时的放行/拒绝口径。"""

    def _conn(self, remote_addr="192.0.2.10:5678", proxy="p", ptype="tcp", user="u"):
        return {"op": "NewUserConn",
                "content": {"user": {"user": user}, "remote_addr": remote_addr,
                            "proxy_name": proxy, "proxy_type": ptype}}

    def test_get_is_405(self):
        status, _, text = self.web.call("GET", "/frp/handler")
        self.assertEqual(status, 405, text[:200])
        self.assertIn("method not allowed", text)

    def test_local_new_user_conn_is_allowed(self):
        status, body = self.web.json("POST", "/frp/handler", self._conn())
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"reject": False, "unchange": True})
        self.assertEqual(len(store.list_logs(10)), 1)

    def test_blacklisted_ip_is_rejected(self):
        store.add_ip("192.0.2.10", "black", "")
        status, body = self.web.json("POST", "/frp/handler", self._conn())
        self.assertEqual(status, 200, body)
        self.assertTrue(body["reject"])
        self.assertTrue(body["reject_reason"])

    def test_other_ops_are_untouched(self):
        for op in ("Login", "NewWorkConn", "CloseProxy", "Ping"):
            with self.subTest(op=op):
                status, body = self.web.json("POST", "/frp/handler", {"op": op})
                self.assertEqual(status, 200, body)
                self.assertEqual(body, {"reject": False, "unchange": True})

    def test_op_from_query_string(self):
        """op 也可从查询串取（frps 的 httpPlugins 两种写法都用）。"""
        status, body = self.web.json(
            "POST", "/frp/handler?op=NewUserConn", self._conn())
        self.assertEqual(status, 200, body)
        self.assertFalse(body["reject"])

    def test_bad_remote_addr_is_counted_and_allowed_by_default(self):
        """remote_addr 无法解析：计数 + 默认放行（strict_addr 关闭时）。"""
        before = daemon._mem["invalid_addr"]
        self.addCleanup(daemon._mem.__setitem__, "invalid_addr", before)
        status, body = self.web.json("POST", "/frp/handler", self._conn(remote_addr="bogus"))
        self.assertEqual(status, 200, body)
        self.assertFalse(body["reject"])
        self.assertEqual(daemon._mem["invalid_addr"], before + 1)

    def test_bad_remote_addr_is_rejected_with_strict_addr(self):
        """strict_addr 开启时改为 fail-closed（reject + 明确原因）。"""
        before = daemon._mem["invalid_addr"]
        self.addCleanup(daemon._mem.__setitem__, "invalid_addr", before)
        config.save({"strict_addr": True})
        status, body = self.web.json("POST", "/frp/handler", self._conn(remote_addr="bogus"))
        self.assertEqual(status, 200, body)
        self.assertTrue(body["reject"])
        self.assertEqual(body["reject_reason"], "invalid-addr")

    def test_non_local_source_is_denied(self):
        """非本机来源打回调 → 403（否则可达 7080 者能伪造 remote_addr 触发封禁）。"""
        cb = _Server(_RemoteSourceHandler)
        self.addCleanup(cb.stop)
        before = daemon._mem["frp_remote_denied"]
        self.addCleanup(daemon._mem.__setitem__, "frp_remote_denied", before)
        status, _, text = cb.call("POST", "/frp/handler", body=self._conn())
        self.assertEqual(status, 403, text[:200])
        self.assertIn("forbidden", text)
        self.assertEqual(daemon._mem["frp_remote_denied"], before + 1)


# ---------------------------------------------------------------- 7. 会话防护
class LoginGuardRouteTest(RouteTestCase):
    """登录限速仍然生效（路由层不能把它绕过去）。"""

    # 与本文件其它用例隔离：这里故意制造连续失败，独立的 HOME + 清理避免串味
    def test_repeated_failures_are_rate_limited(self):
        statuses = []
        for _ in range(daemon._LOGIN_MAX_FAIL + 1):
            status, _, _ = self.web.call(
                "POST", "/api/login",
                body={"username": "admin", "password": self.pwd + "-wrong"})
            statuses.append(status)
        self.assertTrue(all(s == 401 for s in statuses[:daemon._LOGIN_MAX_FAIL]), statuses)
        # 超过阈值的下一次必须被限速（429 + Retry-After），而不是继续校验口令
        self.assertEqual(statuses[-1], 429, statuses)
        status, headers, text = self.web.call(
            "POST", "/api/login",
            body={"username": "admin", "password": self.pwd})
        self.assertEqual(status, 429, text[:200])
        self.assertTrue(_header(headers, "Retry-After").isdigit())


if __name__ == "__main__":
    unittest.main()
