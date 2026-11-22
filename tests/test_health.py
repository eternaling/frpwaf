#!/usr/bin/env python3
# coding: utf-8
"""安全水位（`GET /api/health`）与可选告警 webhook 的回归测试。

被测对象是「把进程内失败计数翻成可判读状态」这一段逻辑：

  * `daemon.health_data()` 的逐项定级、最差值汇总、平均速率说明；
  * 两个**必须**处理的误报场景：AI 审查未启用时不报 ai_fail、进程刚启动时
    warn 降级（bad 不降级）；
  * `GET /api/health` 的返回结构与登录门禁；
  * `daemon._alert_check()` 的跨 bad 跳变告警、30 分钟限频、恢复通知；
  * 告警失败的静默计数（alert_fail）与 webhook 地址的 SSRF 校验。

测试方式：定级逻辑直接调 `health_data()`（纯内存，不需要起服务）；
HTTP 层起真实 `daemon._QuietHTTPServer` 打真实请求（会话 Cookie 直接签发，
省一次登录往返）；**不打桩被测逻辑本身**，只打桩进程外副作用与网络。
"""
import http.client
import json
import secrets
import threading
import time
import unittest
from unittest import mock

from . import new_home
from app import auth, config, daemon, store

# `/api/health` 返回结构的字段契约（前端按这些名字渲染，改动先看这批用例）
ITEM_KEYS = {"key", "value", "level", "label", "detail", "action"}
LEVELS = ("ok", "warn", "bad")
# 与 `daemon._HEALTH_SPEC` 对账：顺序即面板里的展示顺序
SPEC_KEYS = tuple(spec[0] for spec in daemon._HEALTH_SPEC)


# ---------------------------------------------------------------- 传输层工具
class _Server:
    """真实监听（127.0.0.1 + 系统分配端口）的最小客户端封装。"""

    def __init__(self):
        self.srv = daemon._QuietHTTPServer(("127.0.0.1", 0), daemon.Handler,
                                           max_concurrent=8)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        # poll_interval 调小：shutdown() 要等 serve_forever 的轮询窗口结束
        self.th = threading.Thread(target=self.srv.serve_forever,
                                   kwargs={"poll_interval": 0.02}, daemon=True)
        self.th.start()

    def stop(self):
        for fn in (self.srv.shutdown, self.srv.server_close):
            try:
                fn()
            except Exception:
                pass

    def json(self, method, path, body=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            headers = {}
            data = None
            if cookie:
                headers["Cookie"] = cookie
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            conn.request(method, path, body=data, headers=headers)
            resp = conn.getresponse()
            text = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(text)
            except ValueError:
                return resp.status, None
        finally:
            conn.close()


# ---------------------------------------------------------------- 公共夹层
class _MemCase(unittest.TestCase):
    """改 `daemon._mem` / `_ALERT_STATE` 后自动还原（它们是模块级共享状态）。"""

    def setUp(self):
        new_home(self)

    # ---- 计数与时间基准 ----
    def set_mem(self, **kw):
        old = {k: daemon._mem.get(k) for k in kw}
        daemon._mem.update(kw)

        def _restore():
            for k, v in old.items():
                if v is None:
                    daemon._mem.pop(k, None)
                else:
                    daemon._mem[k] = v
        self.addCleanup(_restore)

    def set_uptime(self, seconds):
        """把「进程启动时刻」挪到 N 秒前（定级看 uptime，不看真实运行时长）。"""
        old = daemon._mem.get("started")
        daemon._mem["started"] = int(time.time()) - int(seconds)
        self.addCleanup(daemon._mem.__setitem__, "started", old)

    def reset_alert_state(self):
        old = {"level": daemon._ALERT_STATE["level"],
               "url": daemon._ALERT_STATE["url"],
               "at": dict(daemon._ALERT_STATE["at"])}
        daemon._ALERT_STATE.update({"level": "ok", "url": "", "at": {}})

        def _restore():
            daemon._ALERT_STATE.update(old)
        self.addCleanup(_restore)

    def item(self, data, key):
        for it in data["items"]:
            if it["key"] == key:
                return it
        self.fail("items 里缺少 %s" % key)

    def ai_on(self):
        """把 AI 审查配成「真会被调用」的形态（开关 + 地址 + 密钥齐全）。"""
        config.save({"ai_enabled": True,
                     "ai_base_url": "http://127.0.0.1:3000",
                     "ai_api_key": "test-key-" + secrets.token_hex(4)})

    def all_zero(self):
        self.set_mem(**dict.fromkeys(SPEC_KEYS, 0))


# ---------------------------------------------------------------- 1. 逐项定级
class HealthLevelTest(_MemCase):
    """每个指标的 ok / warn / bad 三档边界。"""

    def test_items_cover_every_spec_key_in_order(self):
        self.all_zero()
        data = daemon.health_data()
        self.assertEqual([it["key"] for it in data["items"]], list(SPEC_KEYS))

    def test_three_tiers_at_boundaries(self):
        """0 = ok；1 与 warn 上限 = warn；warn 上限 +1 = bad。"""
        self.ai_on()          # ai_fail 参与定级的前提
        self.set_uptime(3600)  # 越过冷启动宽限，warn 不会被降级
        for key, _label, warn_max, _detail, _action in daemon._HEALTH_SPEC:
            for value, expect in (
                    (0, "ok"),
                    (1, "warn"),
                    (warn_max, "warn"),          # 边界：上限本身仍是 warn
                    (warn_max + 1, "bad")):      # 边界：越界即 bad
                with self.subTest(key=key, value=value):
                    self.all_zero()
                    self.set_mem(**{key: value})
                    data = daemon.health_data()
                    self.assertEqual(self.item(data, key)["level"], expect,
                                     "%s=%d" % (key, value))

    def test_level_takes_worst_item(self):
        self.set_uptime(3600)
        self.all_zero()
        self.set_mem(db_write_fail=1)                    # warn
        self.assertEqual(daemon.health_data()["level"], "warn")
        self.set_mem(engine_errors=9)                    # bad 压过 warn
        self.assertEqual(daemon.health_data()["level"], "bad")
        self.all_zero()
        self.assertEqual(daemon.health_data()["level"], "ok")

    def test_item_shape_and_top_level_fields(self):
        self.all_zero()
        data = daemon.health_data()
        self.assertEqual(set(data), {"level", "since", "uptime_s", "items", "summary"})
        self.assertIn(data["level"], LEVELS)
        self.assertIsInstance(data["uptime_s"], int)
        self.assertGreaterEqual(data["uptime_s"], 0)
        self.assertEqual(data["since"], int(daemon._mem["started"]))
        for it in data["items"]:
            with self.subTest(key=it["key"]):
                self.assertEqual(set(it), ITEM_KEYS)
                self.assertIn(it["level"], LEVELS)
                self.assertIsInstance(it["value"], int)
                self.assertTrue(it["label"])
                self.assertTrue(it["detail"])
                self.assertTrue(it["action"])

    def test_detail_carries_average_rate(self):
        """速率 = value / uptime * 60，写进 detail 供判断「涨得快不快」。"""
        self.set_uptime(600)          # 10 分钟
        self.all_zero()
        self.set_mem(db_write_fail=5)  # 5 次 / 10 分钟 = 0.5 次/分钟
        detail = self.item(daemon.health_data(), "db_write_fail")["detail"]
        self.assertIn("累计 5 次", detail)
        self.assertIn("约 0.50 次/分钟", detail)

    def test_zero_value_has_no_count_or_rate(self):
        self.all_zero()
        detail = self.item(daemon.health_data(), "fw_sync_fail")["detail"]
        self.assertNotIn("累计", detail)
        self.assertNotIn("次/分钟", detail)

    def test_summary_states_the_worst_items(self):
        self.set_uptime(3600)
        self.all_zero()
        self.set_mem(fw_sync_fail=37)
        data = daemon.health_data()
        self.assertEqual(data["level"], "bad")
        self.assertIn("内核封禁同步失败 37 次", data["summary"])
        self.assertIn("需要处理", data["summary"])

    def test_summary_when_all_clean(self):
        self.set_uptime(3600)
        self.all_zero()
        data = daemon.health_data()
        self.assertEqual(data["level"], "ok")
        self.assertIn("正常", data["summary"])


# ---------------------------------------------------------------- 2. 误报场景
class HealthFalsePositiveTest(_MemCase):
    """两个必须处理好的误报场景：AI 未启用、进程刚启动。"""

    def test_ai_disabled_never_reports(self):
        """ai_enabled=False 时 AI 不会被调用，ai_fail 不参与定级（数值仍可见）。"""
        config.save({"ai_enabled": False, "ai_api_key": "", "ai_base_url": ""})
        self.set_uptime(3600)
        self.all_zero()
        self.set_mem(ai_fail=99)
        data = daemon.health_data()
        it = self.item(data, "ai_fail")
        self.assertEqual(it["level"], "ok")
        self.assertEqual(it["value"], 99)          # 数值照实返回，不隐藏
        self.assertIn("AI 审查未启用", it["detail"])
        self.assertEqual(data["level"], "ok")

    def test_ai_enabled_but_unconfigured_never_reports(self):
        """开关打开但地址/密钥没配全，AI 同样不会被调用，也不该报。

        这种情况下计数只可能来自手动的「测试连接」，与自动处置是否失效无关。
        """
        config.save({"ai_enabled": True, "ai_base_url": "", "ai_api_key": ""})
        self.set_uptime(3600)
        self.all_zero()
        self.set_mem(ai_fail=8)
        self.assertEqual(self.item(daemon.health_data(), "ai_fail")["level"], "ok")

    def test_ai_enabled_and_configured_does_report(self):
        """配全之后同一个计数要照常参与定级（否则等于把 AI 失效藏起来）。"""
        self.ai_on()
        self.set_uptime(3600)
        self.all_zero()
        self.set_mem(ai_fail=8)          # > 5 => bad
        data = daemon.health_data()
        self.assertEqual(self.item(data, "ai_fail")["level"], "bad")
        self.assertEqual(data["level"], "bad")

    def test_startup_grace_downgrades_warn_to_ok(self):
        """刚启动（不足 300 秒）的少量失败先降级，并在 detail 里写明原因。"""
        self.set_uptime(60)
        self.all_zero()
        self.set_mem(invalid_addr=3)     # 正常是 warn
        it = self.item(daemon.health_data(), "invalid_addr")
        self.assertEqual(it["level"], "ok")
        self.assertIn("刚启动", it["detail"])

    def test_startup_grace_keeps_bad(self):
        """刚启动就到 bad 量级说明不是瞬时问题，必须照常报。"""
        self.set_uptime(60)
        self.all_zero()
        self.set_mem(invalid_addr=50)    # 正常是 bad
        data = daemon.health_data()
        self.assertEqual(self.item(data, "invalid_addr")["level"], "bad")
        self.assertEqual(data["level"], "bad")
        self.assertIn("刚启动", self.item(data, "invalid_addr")["detail"])

    def test_grace_expires_with_uptime(self):
        """越过 300 秒宽限后，同一个值回到 warn。"""
        self.set_uptime(301)
        self.all_zero()
        self.set_mem(invalid_addr=3)
        self.assertEqual(self.item(daemon.health_data(), "invalid_addr")["level"],
                         "warn")

    def test_grace_does_not_touch_zero(self):
        self.set_uptime(5)
        self.all_zero()
        data = daemon.health_data()
        self.assertEqual(data["level"], "ok")
        self.assertIn("刚启动", data["summary"])


# ---------------------------------------------------------------- 3. HTTP 层
class HealthApiTest(_MemCase):
    """`/api/health` 的登录门禁与返回结构。"""

    def setUp(self):
        super().setUp()
        store.init()
        # 非默认口令 => password_changed 自动为 True，否则 /api/* 会被强制改密门禁 403
        self.pwd = "pwd-" + secrets.token_hex(6)
        config.save({"admin_password": self.pwd})
        for target, attr, value in (
                (daemon.firewall, "available", lambda: False),
                (daemon.blockpage, "ensure", lambda: True)):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.web = _Server()
        self.addCleanup(self.web.stop)
        self.ck = "%s=%s" % (auth.COOKIE_NAME, auth.create_token("admin"))

    def test_requires_login(self):
        status, body = self.web.json("GET", "/api/health")
        self.assertEqual(status, 401)
        self.assertEqual(body["code"], 401)

    def test_returns_contract(self):
        self.set_uptime(3600)
        self.all_zero()
        status, body = self.web.json("GET", "/api/health", cookie=self.ck)
        self.assertEqual(status, 200)
        self.assertEqual(body["code"], 0)
        data = body["data"]
        self.assertEqual(set(data), {"level", "since", "uptime_s", "items", "summary"})
        self.assertEqual(data["level"], "ok")
        self.assertIn(data["level"], LEVELS)
        self.assertGreaterEqual(data["uptime_s"], 3600)
        for it in data["items"]:
            self.assertEqual(set(it), ITEM_KEYS)

    def test_reflects_memory_counters(self):
        self.set_uptime(3600)
        self.all_zero()
        self.set_mem(fw_sync_fail=7, invalid_addr=2)
        status, body = self.web.json("GET", "/api/health", cookie=self.ck)
        self.assertEqual(status, 200)
        data = body["data"]
        self.assertEqual(self.item(data, "fw_sync_fail")["value"], 7)
        self.assertEqual(self.item(data, "fw_sync_fail")["level"], "bad")
        self.assertEqual(self.item(data, "invalid_addr")["level"], "warn")
        self.assertEqual(data["level"], "bad")

    def test_post_is_accepted_like_other_read_endpoints(self):
        """与 /api/metrics 一致：GET/POST 都落到 handler（前端两种写法都能用）。"""
        self.all_zero()
        status, body = self.web.json("POST", "/api/health", body={}, cookie=self.ck)
        self.assertEqual(status, 200)
        self.assertEqual(body["code"], 0)


# ---------------------------------------------------------------- 4. 告警 webhook
class AlertWebhookTest(_MemCase):
    """跨 bad 跳变才发、30 分钟限频、恢复通知、失败静默计数。"""

    HOOK = "http://127.0.0.1:9/alert"

    def setUp(self):
        super().setUp()
        self.reset_alert_state()
        self.all_zero()
        self.set_uptime(3600)
        self.sent = []
        # 真实发送路径的用例要用未打桩的函数，先留一份引用
        self.real_post = daemon._alert_post
        p = mock.patch.object(daemon, "_alert_post",
                              lambda url, payload: self.sent.append((url, payload)))
        p.start()
        self.addCleanup(p.stop)

    def hook_on(self):
        config.save({"alert_webhook": self.HOOK})

    def test_off_by_default_sends_nothing(self):
        self.set_mem(engine_errors=99)
        self.assertIsNone(daemon._alert_check())
        self.assertEqual(self.sent, [])

    def test_bad_transition_sends_once(self):
        self.hook_on()
        self.set_mem(engine_errors=99)
        payload = daemon._alert_check()
        self.assertIsNotNone(payload)
        self.assertEqual(payload["level"], "bad")
        self.assertEqual(payload["event"], "bad")
        self.assertIn("需要处理", payload["summary"])
        # 只带非 ok 项：接收端不需要知道哪些指标是好的
        self.assertTrue(payload["items"])
        self.assertTrue(all(it["level"] != "ok" for it in payload["items"]))
        self.assertEqual(self.sent[0][0], self.HOOK)

    def test_no_repeat_while_still_bad(self):
        """同一故障每轮都发会刷屏：持续 bad 期间只发一次。"""
        self.hook_on()
        self.set_mem(engine_errors=99)
        self.assertIsNotNone(daemon._alert_check())
        for _ in range(3):
            self.assertIsNone(daemon._alert_check())
        self.assertEqual(len(self.sent), 1)

    def test_recovery_sends_once(self):
        self.hook_on()
        self.set_mem(engine_errors=99)
        daemon._alert_check()
        self.all_zero()                       # 指标恢复
        payload = daemon._alert_check()
        self.assertIsNotNone(payload)
        self.assertEqual(payload["event"], "recover")
        self.assertEqual(payload["level"], "ok")
        self.assertEqual(len(self.sent), 2)
        self.assertIsNone(daemon._alert_check())   # 恢复通知也不重复发

    def test_same_event_rate_limited_30min(self):
        self.hook_on()
        self.set_mem(engine_errors=99)
        daemon._alert_check()                 # 第一次 bad
        self.all_zero()
        daemon._alert_check()                 # 恢复
        self.set_mem(engine_errors=99)        # 30 分钟内再次 bad
        self.assertIsNone(daemon._alert_check())
        # 越过限频窗口后可以再发（把上次发送时刻往回拨，并模拟「先恢复、后又变 bad」）
        daemon._ALERT_STATE["at"]["bad"] = time.time() - daemon._ALERT_INTERVAL - 1
        daemon._ALERT_STATE["level"] = "ok"
        self.assertIsNotNone(daemon._alert_check())

    def test_configured_while_already_bad_sends_immediately(self):
        """webhook 刚填上而系统已经异常：基线重置，用户能立刻收到一次。"""
        self.set_mem(engine_errors=99)
        daemon._alert_check()                 # 未配置时只记录状态
        self.hook_on()
        self.assertIsNotNone(daemon._alert_check())

    def test_warn_does_not_trigger_alert(self):
        self.hook_on()
        self.set_mem(invalid_addr=3)          # warn
        self.assertIsNone(daemon._alert_check())
        self.assertEqual(self.sent, [])

    # ---- 真实发送路径（只打桩 urlopen，不打桩 _alert_post）----
    def test_send_failure_is_counted_not_raised(self):
        self.set_uptime(3600)
        before = daemon._mem["alert_fail"]
        self.addCleanup(daemon._mem.__setitem__, "alert_fail", before)
        with mock.patch.object(daemon.urllib.request, "urlopen",
                               side_effect=OSError("connection refused")):
            self.real_post(self.HOOK, {"level": "bad", "summary": "x"})
        self.assertEqual(daemon._mem["alert_fail"], before + 1)

    def test_metadata_address_is_refused_without_request(self):
        """链路本地/云元数据地址永远拒发（无论 ai_allow_private）——不发请求只计数。"""
        before = daemon._mem["alert_fail"]
        self.addCleanup(daemon._mem.__setitem__, "alert_fail", before)
        called = []
        with mock.patch.object(daemon.urllib.request, "urlopen",
                               side_effect=lambda *a, **k: called.append(a)):
            self.real_post("http://169.254.169.254/latest/meta-data/",
                           {"level": "bad", "summary": "x"})
        self.assertEqual(called, [])
        self.assertEqual(daemon._mem["alert_fail"], before + 1)

    def test_send_posts_json_body(self):
        seen = {}

        class _Resp:
            def read(self, n=-1):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def _fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["data"] = json.loads(req.data.decode("utf-8"))
            seen["method"] = req.get_method()
            seen["ctype"] = req.get_header("Content-type")
            seen["timeout"] = timeout
            return _Resp()

        with mock.patch.object(daemon.urllib.request, "urlopen", _fake_urlopen):
            self.real_post(self.HOOK, {"level": "bad", "summary": "s",
                                       "items": []})
        self.assertEqual(seen["url"], self.HOOK)
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["data"]["level"], "bad")
        self.assertIn("application/json", seen["ctype"])
        self.assertLessEqual(seen["timeout"], 10)


# ---------------------------------------------------------------- 5. 配置写入
class AlertConfigTest(_MemCase):
    """`alert_webhook` 的保存与 SSRF 校验（走真实 POST /api/config）。"""

    def setUp(self):
        super().setUp()
        store.init()
        self.pwd = "pwd-" + secrets.token_hex(6)
        config.save({"admin_password": self.pwd})
        for target, attr, value in (
                (daemon.firewall, "available", lambda: False),
                (daemon.blockpage, "ensure", lambda: True)):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.web = _Server()
        self.addCleanup(self.web.stop)
        self.ck = "%s=%s" % (auth.COOKIE_NAME, auth.create_token("admin"))

    def save_hook(self, url):
        return self.web.json("POST", "/api/config",
                             body={"alert_webhook": url}, cookie=self.ck)

    def test_default_is_off(self):
        self.assertEqual(config.DEFAULTS["alert_webhook"], "")

    def test_empty_clears_hook(self):
        status, body = self.save_hook("")
        self.assertEqual(status, 200)
        self.assertEqual(body["code"], 0)
        self.assertEqual(config.get()["alert_webhook"], "")

    def test_private_address_accepted(self):
        """内网通知服务（ntfy/Gotify 这类）必须能存：沿用 ai_allow_private 语义。"""
        status, body = self.save_hook("http://127.0.0.1:9000/hook")
        self.assertEqual(status, 200, body)
        self.assertEqual(body["code"], 0)
        self.assertEqual(config.get()["alert_webhook"], "http://127.0.0.1:9000/hook")

    def test_metadata_address_rejected(self):
        status, body = self.save_hook("http://169.254.169.254/latest/meta-data/")
        self.assertEqual(status, 200)
        self.assertEqual(body["code"], 1)
        self.assertIn("不可用", body["msg"])
        self.assertEqual(config.get()["alert_webhook"], "")

    def test_non_http_scheme_rejected(self):
        status, body = self.save_hook("file:///etc/passwd")
        self.assertEqual(status, 200)
        self.assertEqual(body["code"], 1)


if __name__ == "__main__":
    unittest.main()
