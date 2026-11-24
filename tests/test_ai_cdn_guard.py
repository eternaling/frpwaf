#!/usr/bin/env python3
# coding: utf-8
"""app/ai.py 的 CDN 回源保护与同段熔断（防「封 CDN 边缘节点导致整站 522」）。

背景（2026-11-24 生产事故）：AI 审查把阿里云 ESA 的回源节点 IP 判成
「同源多 IP、同一段集中访问 Web 代理」，批量封了 484 条中国 IP，导致
所有走 HTTPS 回源的站点返回 522。模型自己在理由里写的是「**疑似**」。

这里锁住三道保护，任何一道退化都会让测试变红：
  1. 关键字/模型判定 cdn_origin；
  2. 行为特征：同一 IP 混访 2 个以上站点代理；
  3. **显式可信网段** ai_trusted_cidrs（确定性，不依赖模型）；
  4. **同段批量封禁熔断**：窗口内同一 /24 已被自动封禁多个 IP 时停止继续封。

只测纯函数与 _apply_action 的处置分支，不发起模型调用。
"""

import os
import tempfile
import time
import unittest
from unittest import mock

HOME = tempfile.mkdtemp(prefix="frpwaf-ai-")
os.makedirs(os.path.join(HOME, "data"), exist_ok=True)
os.environ.setdefault("FRPWAF_HOME", HOME)

from app import ai, config, store  # noqa: E402


class CdnGuardTest(unittest.TestCase):
    """_is_cdn_origin：三层判断。"""

    def setUp(self):
        self.cfg = dict(config.DEFAULTS)
        self.cfg["ai_cdn_guard"] = True

    def test_model_category_wins(self):
        self.assertTrue(ai._is_cdn_origin(
            "cdn_origin", {"geo": "", "proxies": "a"}, self.cfg))

    def test_keywords_for_aliyun_esa(self):
        """ESA 的英文名/别名要能命中。

        注意：**「阿里云」单独不算 CDN** —— 阿里云上既有 CDN 节点，也有普通
        云主机（包括攻击者的）。若把「阿里云」当关键字，会放行攻击者。
        阿里云回源靠「混访多站」的行为特征识别（见下一个用例）。
        """
        for geo_text in ("aliyun ESA edge", "边缘安全加速", "aliyun cdn"):
            with self.subTest(geo=geo_text):
                self.assertTrue(ai._is_cdn_origin(
                    "web_scan", {"geo": geo_text, "proxies": "a"}, self.cfg))

    def test_plain_aliyun_alone_is_not_cdn(self):
        """只有「阿里云」不能当 CDN 放行，否则会放过阿里云上的攻击者。"""
        self.assertFalse(ai._is_cdn_origin(
            "web_scan", {"geo": "中国 浙江 杭州 阿里云", "proxies": "nightcc-tcp"},
            self.cfg))

    def test_aliyun_with_multi_proxy_is_cdn(self):
        """阿里云 + 混访多站 = 回源（事故里被误封的就是这种）。"""
        self.assertTrue(ai._is_cdn_origin(
            "web_scan", {"geo": "中国 浙江 杭州 阿里云",
                         "proxies": "gitea_htts2http,portal_htts2http"},
            self.cfg))

    def test_multi_proxy_behavior(self):
        """同一 IP 混访多站 = 回源特征（事故里被误封的 IP 全是这种）。"""
        self.assertTrue(ai._is_cdn_origin(
            "web_scan", {"geo": "中国 浙江 移动",
                         "proxies": "gitea_htts2http,portal_htts2http"},
            self.cfg))

    def test_single_proxy_scanner_not_exempt(self):
        """只打单个代理的扫描器不能被当成 CDN 放行。"""
        self.assertFalse(ai._is_cdn_origin(
            "web_scan", {"geo": "德国", "proxies": "nightcc-tcp"}, self.cfg))

    def test_guard_off_disables_all(self):
        cfg = dict(self.cfg, ai_cdn_guard=False)
        self.assertFalse(ai._is_cdn_origin(
            "cdn_origin", {"geo": "cloudflare", "proxies": "a,b"}, cfg))


class TrustedCidrTest(unittest.TestCase):
    """ai_trusted_cidrs：显式永不封禁网段。"""

    def setUp(self):
        self.cfg = dict(config.DEFAULTS)
        self.cfg["ai_trusted_cidrs"] = "61.241.14.0/24, 8.25.82.0/24"

    def test_inside(self):
        self.assertTrue(ai._in_trusted_cidr("61.241.14.33", self.cfg))
        self.assertTrue(ai._in_trusted_cidr("8.25.82.151", self.cfg))

    def test_outside(self):
        self.assertFalse(ai._in_trusted_cidr("1.2.3.4", self.cfg))

    def test_empty_config_disables(self):
        cfg = dict(config.DEFAULTS)
        cfg["ai_trusted_cidrs"] = ""
        self.assertFalse(ai._in_trusted_cidr("61.241.14.33", cfg))

    def test_invalid_ip(self):
        self.assertFalse(ai._in_trusted_cidr("not-an-ip", self.cfg))


class SubnetBanFuseTest(unittest.TestCase):
    """同段批量封禁熔断。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        self.cfg = dict(config.DEFAULTS)
        self.cfg["ai_subnet_ban_limit"] = 5
        self.cfg["ai_subnet_ban_window"] = 900

    def _ban(self, ip):
        store.add_ban(ip, "ai: 疑似分布式探测", 1800)

    def test_below_limit_not_hot(self):
        for i in range(4):
            self._ban("61.241.14.%d" % (10 + i))
        hit, n = ai._subnet_ban_hot("61.241.14.99", self.cfg)
        self.assertEqual(n, 4)
        self.assertFalse(hit, "未达阈值不应熔断")

    def test_at_limit_hot(self):
        for i in range(5):
            self._ban("61.241.14.%d" % (10 + i))
        hit, n = ai._subnet_ban_hot("61.241.14.99", self.cfg)
        self.assertEqual(n, 5)
        self.assertTrue(hit, "达阈值必须熔断，否则整段会继续被封")

    def test_other_subnet_unaffected(self):
        for i in range(5):
            self._ban("61.241.14.%d" % (10 + i))
        hit, n = ai._subnet_ban_hot("1.2.3.4", self.cfg)
        self.assertFalse(hit)
        self.assertEqual(n, 0)

    def test_manual_bans_not_counted(self):
        """人工手工封禁不应触发自动熔断。"""
        for i in range(6):
            store.add_ban("61.241.14.%d" % (10 + i), "手动封禁", 1800)
        hit, n = ai._subnet_ban_hot("61.241.14.99", self.cfg)
        self.assertFalse(hit)
        self.assertEqual(n, 0)

    def test_fuse_disabled(self):
        for i in range(6):
            self._ban("61.241.14.%d" % (10 + i))
        cfg = dict(self.cfg, ai_subnet_ban_limit=0)
        hit, n = ai._subnet_ban_hot("61.241.14.99", cfg)
        self.assertFalse(hit)
        self.assertEqual(n, 0)


class ApplyActionTest(unittest.TestCase):
    """_apply_action 的处置分支：保护优先于封禁。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({"ai_auto_ban": True, "ai_suspicious_ban": True,
                         "ai_cdn_guard": True, "blacklist_enabled": True,
                         "blacklist_enabled": True})
        self.cfg["ai_trusted_cidrs"] = "61.241.14.0/24"

    def _apply(self, ip, category="web_scan", geo="", proxies=""):
        it = {"geo": geo, "proxies": proxies, "conns": 100}
        with mock.patch.object(store, "list_ips", return_value=[]):
            return ai._apply_action(ip, "suspicious", category, "r", it, self.cfg)

    def _banned(self, ip):
        with mock.patch.object(store, "list_ips", return_value=[]):
            return store.is_banned(ip)

    def test_trusted_cidr_skips_ban(self):
        res = self._apply("61.241.14.33")
        self.assertEqual(res["action"], "skipped")
        self.assertEqual(res["mode"], "trusted")
        self.assertFalse(self._banned("61.241.14.33"))

    def test_multi_proxy_skips_ban(self):
        res = self._apply("1.2.3.4", proxies="a_http,b_http")
        self.assertEqual(res["mode"], "cdn")
        self.assertFalse(self._banned("1.2.3.4"))

    def test_subnet_fuse_skips_ban(self):
        for i in range(5):
            store.add_ban("9.9.9.%d" % (10 + i), "ai: 探测", 1800)
        res = self._apply("9.9.9.99")
        self.assertEqual(res["action"], "skipped")
        self.assertEqual(res["mode"], "subnet")
        self.assertFalse(self._banned("9.9.9.99"))

    def test_normal_scanner_still_banned(self):
        """没有任何保护命中时，扫描器照旧被封禁。"""
        res = self._apply("1.2.3.4", proxies="nightcc-tcp")
        self.assertIn(res["action"], ("temporary", "banned", "permanent"))
        self.assertTrue(self._banned("1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
