#!/usr/bin/env python3
# coding: utf-8
"""自动封禁的两道豁免：登录即信任（A）与代理豁免（B）。

背景（owner 实际痛点）：他在外面开发时 IP 不固定，远程连数据库/SSH 隧道时
客户端反复重连，很容易命中「敏感服务 20 次/60s -> **永久黑名单**」把自己封掉。
白名单又不现实（IP 一直在变）。

两道豁免都只跳过**自动封禁**，不影响应用层准入与日志记录：
  A. trust_login_ip：面板登录成功即把当前 IP 记为可信（带 TTL），
     换网络后登录一次面板即可，不用手加白名单。
  B. auto_ban_exempt_proxies：指定代理（自己用的库/SSH 隧道）不参与自动封禁。
"""

import os
import tempfile
import time
import unittest

HOME = tempfile.mkdtemp(prefix="frpwaf-exempt-")
os.makedirs(os.path.join(HOME, "data"), exist_ok=True)
os.environ.setdefault("FRPWAF_HOME", HOME)

from app import ai, config, engine, store  # noqa: E402


def _in_blacklist(ip):
    return any((r.get("cidr") or "") in (ip, ip + "/32") for r in store.list_ips("black"))


class LoginTrustTest(unittest.TestCase):
    """A. 登录即信任。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        engine.invalidate_cache()
        self.cfg = dict(config.DEFAULTS)

    def tearDown(self):
        engine.invalidate_cache()

    def test_trust_then_exempt(self):
        store.trust_login_ip("112.48.13.214", 86400)
        engine.invalidate_cache()
        self.assertIn("112.48.13.214", engine._trusted_login_ids())

    def test_trusted_ip_not_banned(self):
        """信任后连 25 次敏感代理（超阈值 20）也不被封。"""
        store.trust_login_ip("1.1.1.1", 86400)
        engine.invalidate_cache()
        for _ in range(25):
            engine._attack_detect(self.cfg, "1.1.1.1", "mysql80-tcp", "tcp")
        self.assertFalse(_in_blacklist("1.1.1.1"))

    def test_untrusted_ip_is_banned(self):
        """对照组：没信任的 IP 同样操作必须被封。"""
        for _ in range(25):
            engine._attack_detect(self.cfg, "2.2.2.2", "mysql80-tcp", "tcp")
        self.assertTrue(_in_blacklist("2.2.2.2"))

    def test_expired_trust_does_not_exempt(self):
        """过期后不再豁免——证明信任是有时效的，不是永久放行。"""
        store.trust_login_ip("3.3.3.3", -1)      # ttl<=0 不写
        engine.invalidate_cache()
        self.assertNotIn("3.3.3.3", engine._trusted_login_ids())
        for _ in range(25):
            engine._attack_detect(self.cfg, "3.3.3.3", "mysql80-tcp", "tcp")
        self.assertTrue(_in_blacklist("3.3.3.3"))

    def test_trust_expiry_filtered(self):
        """写入已过期的记录，读取时应被过滤掉。"""
        now = int(time.time())
        store._exec("INSERT OR REPLACE INTO trust_login_ip(ip, expires_at, created_at) "
                    "VALUES(?,?,?)", ("4.4.4.4", now - 10, now - 100))
        self.assertNotIn("4.4.4.4", store.list_trusted_login_ips())

    def test_clear_trust(self):
        store.trust_login_ip("5.5.5.5", 86400)
        engine.invalidate_cache()
        self.assertIn("5.5.5.5", engine._trusted_login_ids())
        store.clear_trusted_login_ips()
        engine.invalidate_cache()
        self.assertNotIn("5.5.5.5", engine._trusted_login_ids())

    def test_invalid_ip_not_stored(self):
        self.assertIsNone(store.trust_login_ip("not-an-ip", 3600))


class ProxyExemptTest(unittest.TestCase):
    """B. 代理豁免。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        engine.invalidate_cache()
        self.cfg = dict(config.DEFAULTS)

    def test_exact_match(self):
        cfg = dict(self.cfg, auto_ban_exempt_proxies="mysql80-tcp,ssh-tcp")
        self.assertTrue(engine._proxy_exempt("mysql80-tcp", cfg))
        self.assertTrue(engine._proxy_exempt("SSH-tcp", cfg))       # 大小写不敏感
        self.assertFalse(engine._proxy_exempt("gitea_htts2http", cfg))

    def test_wildcards(self):
        cfg = dict(self.cfg, auto_ban_exempt_proxies="codebuddy*,*_tcp,night*prod")
        self.assertTrue(engine._proxy_exempt("codebuddy4-tcp", cfg))
        self.assertTrue(engine._proxy_exempt("redis_tcp", cfg))
        self.assertTrue(engine._proxy_exempt("nightx-prod", cfg))
        self.assertFalse(engine._proxy_exempt("gitea_htts2http", cfg))

    def test_empty_config_no_exempt(self):
        self.assertFalse(engine._proxy_exempt("mysql80-tcp", self.cfg))

    def test_exempt_proxy_not_banned(self):
        cfg = dict(self.cfg, auto_ban_exempt_proxies="mysql80-tcp")
        for _ in range(25):
            engine._attack_detect(cfg, "6.6.6.6", "mysql80-tcp", "tcp")
        self.assertFalse(_in_blacklist("6.6.6.6"))

    def test_non_exempt_proxy_still_banned(self):
        """豁免只对该代理生效，别的敏感代理照旧会被封。"""
        cfg = dict(self.cfg, auto_ban_exempt_proxies="mysql80-tcp")
        for _ in range(25):
            engine._attack_detect(cfg, "7.7.7.7", "redis-tcp", "tcp")
        self.assertTrue(_in_blacklist("7.7.7.7"))


if __name__ == "__main__":
    unittest.main()


class ExemptScopeTest(unittest.TestCase):
    """P1-1：登录信任 / 代理豁免在第 5、6 步的生效范围。

    口径：
      - 登录信任在所有自动封禁决策点生效（第 5 步、6.1 / 6.2 / 6.3）；
      - 代理豁免在第 5 步与 6.1 / 6.2 生效，但**不屏蔽 6.3 端口扫描**——
        同一 IP 访问多个不同代理本身不是「在用我自己的那一个服务」的画像。
    """

    IP = "9.9.9.9"
    # 与生产配置一致的豁免列表
    SCAN_PROXIES = ("ssh-tcp", "mysql80-tcp", "mysql-tcp", "postgres-tcp",
                    "mongodb-tcp", "redis-tcp")

    def setUp(self):
        from tests import new_home
        new_home(self)
        engine.invalidate_cache()
        self.cfg = dict(config.DEFAULTS)
        # 内存攻击计数是模块级状态，逐用例清掉本 IP 的残留，避免用例间串扰
        for d in engine._attack.values():
            d.pop(self.IP, None)
        # 只打开被测的那一项，避免其它检测项干扰结论
        self.cfg.update({
            "whitelist_enabled": False, "rate_limit_enabled": False,
            "auto_ban_enabled": False, "auto_ban_ssh_enabled": False,
            "auto_ban_cc_enabled": False, "auto_ban_scan_enabled": False,
            "auto_ban_exempt_proxies": ",".join(self.SCAN_PROXIES) + ",web-http",
        })

    def tearDown(self):
        engine.invalidate_cache()

    def _banned(self, ip):
        return (any((r.get("ip") or "") == ip for r in store.active_bans())
                or _in_blacklist(ip))

    def _trust(self, ip):
        store.trust_login_ip(ip, 86400)
        engine.invalidate_cache()

    def _decide_n(self, cfg, n, proxy, ptype="tcp"):
        from unittest import mock
        with mock.patch.object(config, "get", return_value=cfg):
            return [engine.decide(self.IP, 50000, proxy, ptype, "") for _ in range(n)]

    def _base_cfg(self):
        return dict(self.cfg, auto_ban_enabled=True, auto_ban_threshold=5,
                    auto_ban_window=60)

    # ---- 第 5 步基础自动封禁 ----
    def test_base_trusted_login_not_banned(self):
        """1. 登录信任的 IP 达到 auto_ban_threshold -> 不封。"""
        self._trust(self.IP)
        res = self._decide_n(self._base_cfg(), 8, "gitea-web")
        self.assertTrue(all(ok for ok, _ in res), res)
        self.assertFalse(self._banned(self.IP))

    def test_base_exempt_proxy_not_banned(self):
        """2. 豁免代理的 IP 达到阈值 -> 不封（P1-1 核心）。"""
        res = self._decide_n(self._base_cfg(), 8, "mysql80-tcp")
        self.assertTrue(all(ok for ok, _ in res), res)
        self.assertFalse(self._banned(self.IP))

    def test_base_non_exempt_still_banned(self):
        """对照组：非豁免代理、未信任 IP 照常被第 5 步封禁。"""
        res = self._decide_n(self._base_cfg(), 8, "gitea-web")
        self.assertIn((False, "auto_ban"), res)
        self.assertTrue(self._banned(self.IP))

    # ---- 第 6 步 ----
    def test_sensitive_exempt_not_counted(self):
        """3. 6.1 敏感爆破：豁免代理高频连接 -> 不封，且完全不进入计数窗口。"""
        cfg = dict(self.cfg, auto_ban_ssh_enabled=True, auto_ban_ssh_threshold=5,
                   auto_ban_ssh_window=60)
        res = [engine._attack_detect(cfg, self.IP, "mysql80-tcp", "tcp") for _ in range(10)]
        self.assertEqual(set(res), {""})
        self.assertFalse(self._banned(self.IP))
        self.assertNotIn(self.IP, engine._attack["ssh"])

    def test_scan_across_exempt_proxies_banned(self):
        """4. 6.3 端口扫描：同一 IP 连续访问多个不同豁免代理达到阈值 -> 封（修漏封核心）。"""
        cfg = dict(self.cfg, auto_ban_scan_enabled=True, auto_ban_scan_threshold=4,
                   auto_ban_scan_window=60)
        res = [engine._attack_detect(cfg, self.IP, p, "tcp") for p in self.SCAN_PROXIES]
        self.assertIn("auto_ban_scan", res)
        self.assertTrue(self._banned(self.IP))

    def test_cc_exempt_not_banned(self):
        """5. 6.2 CC：豁免代理 -> 不封。"""
        cfg = dict(self.cfg, auto_ban_cc_enabled=True, auto_ban_cc_threshold=5,
                   auto_ban_cc_window=60)
        res = [engine._attack_detect(cfg, self.IP, "web-http", "http") for _ in range(10)]
        self.assertEqual(set(res), {""})
        self.assertFalse(self._banned(self.IP))

    def test_scan_trusted_login_not_banned(self):
        """6. 登录信任的 IP 即使触发 6.3 -> 不封（信任优先）。"""
        self._trust(self.IP)
        cfg = dict(self.cfg, auto_ban_scan_enabled=True, auto_ban_scan_threshold=4,
                   auto_ban_scan_window=60)
        res = [engine._attack_detect(cfg, self.IP, p, "tcp") for p in self.SCAN_PROXIES]
        self.assertEqual(set(res), {""})
        self.assertFalse(self._banned(self.IP))
        # 登录信任的 IP 不进入扫描窗口
        self.assertNotIn(self.IP, engine._attack["scan"])

    # ---- 豁免流量完全排除于攻击计数窗口：豁免流量不再吃掉本窗口的认领 ----
    def test_base_exempt_then_non_exempt_same_window_banned(self):
        """第 5 步：豁免代理先超阈值，同窗口内再访问非豁免代理 -> 第 threshold 次即封。"""
        cfg = self._base_cfg()
        res = self._decide_n(cfg, 8, "mysql80-tcp")
        self.assertTrue(all(ok for ok, _ in res), res)
        self.assertNotIn(self.IP, engine._attack["base"])
        res = self._decide_n(cfg, 5, "gitea-web")
        self.assertTrue(all(ok for ok, _ in res[:-1]), res)
        self.assertEqual(res[-1], (False, "auto_ban"))
        self.assertTrue(self._banned(self.IP))

    def test_sensitive_exempt_then_non_exempt_same_window_banned(self):
        """6.1：豁免敏感代理先超阈值，同窗口内访问非豁免敏感代理 -> 第 threshold 次即封。"""
        cfg = dict(self.cfg, auto_ban_ssh_enabled=True, auto_ban_ssh_threshold=5,
                   auto_ban_ssh_window=60)
        for _ in range(10):
            self.assertEqual(engine._attack_detect(cfg, self.IP, "mysql80-tcp", "tcp"), "")
        res = [engine._attack_detect(cfg, self.IP, "ssh-prod", "tcp") for _ in range(5)]
        self.assertEqual(res, ["", "", "", "", "auto_ban_ssh"])
        self.assertTrue(self._banned(self.IP))

    def test_cc_exempt_then_non_exempt_same_window_banned(self):
        """6.2：豁免 HTTP 代理先超阈值，同窗口内访问非豁免 HTTP 代理 -> 第 threshold 次即封。"""
        cfg = dict(self.cfg, auto_ban_cc_enabled=True, auto_ban_cc_threshold=5,
                   auto_ban_cc_window=60)
        for _ in range(10):
            self.assertEqual(engine._attack_detect(cfg, self.IP, "web-http", "http"), "")
        self.assertNotIn(self.IP, engine._attack["cc"])
        res = [engine._attack_detect(cfg, self.IP, "blog-http", "http") for _ in range(5)]
        self.assertEqual(res, ["", "", "", "", "auto_ban_cc"])
        self.assertTrue(self._banned(self.IP))


class AILoginTrustTest(unittest.TestCase):
    """AI 处置侧也要认登录信任。

    生产实况：112.48.13.214 是被 AI 以「临时访问 MySQL/Redis 等非 Web 服务
    且无探测证据」为由临时封的——光豁免引擎的自动封禁不够。
    """

    def setUp(self):
        from tests import new_home
        new_home(self)
        from unittest import mock
        self.mock = mock
        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({"ai_auto_ban": True, "ai_suspicious_ban": True,
                         "ai_cdn_guard": True, "blacklist_enabled": True})
        self.it = {"geo": "中国 浙江", "proxies": "mysql80-tcp", "conns": 80}

    def _apply(self, ip):
        with self.mock.patch.object(store, "list_ips", return_value=[]):
            return ai._apply_action(ip, "suspicious", "other",
                                    "临时访问 MySQL 等非 Web 服务", self.it, self.cfg)

    def test_untrusted_is_actioned(self):
        res = self._apply("112.48.13.214")
        self.assertNotEqual(res["action"], "skipped")

    def test_trusted_is_skipped(self):
        store.trust_login_ip("112.48.13.214", 86400)
        res = self._apply("112.48.13.214")
        self.assertEqual(res["action"], "skipped")
        self.assertEqual(res["mode"], "login")

    def test_expired_trust_restores_action(self):
        store.trust_login_ip("112.48.13.214", -1)     # ttl<=0 不写
        res = self._apply("112.48.13.214")
        self.assertNotEqual(res["action"], "skipped")
