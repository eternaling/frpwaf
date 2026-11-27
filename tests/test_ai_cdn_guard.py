#!/usr/bin/env python3
# coding: utf-8
"""app/ai.py 的 CDN 回源保护与同段熔断（防「封 CDN 边缘节点导致整站 522」）。

背景（2026-11-24 生产事故）：AI 审查把阿里云 ESA 的回源节点 IP 判成
「同源多 IP、同一段集中访问 Web 代理」，批量封了 484 条中国 IP，导致
所有走 HTTPS 回源的站点返回 522。模型自己在理由里写的是「**疑似**」。

这里锁住几道保护，任何一道退化都会让测试变红：
  1. 关键字命中，或模型判定 cdn_origin 且有旁证；
  2. 行为特征：代理类型全为 http/https/tcpmux，且同一 IP 混访 2 个以上站点代理；
  3. **显式可信网段** ai_trusted_cidrs（确定性，不依赖模型）；
  4. **同段批量封禁熔断**：窗口内同一 /24 已被自动封禁多个 IP 时停止继续封；
  5. **自动学习表** trusted_cidr：强证据 /32 才学；同段强证据 /32 达到
     `ai._TRUST_SUBNET_MIN_IPS`（当前 3）个才升级为整段可信（24h TTL）。

反向用例同样锁住：出现非 Web 代理类型一律否决（模型判定与关键字都推翻不了）；
弱证据（行为层单独命中、同段熔断）只跳过本次、不写学习表；学习表条目会过期。

只测纯函数与 _apply_action 的处置分支，不发起模型调用。
"""

import os
import sqlite3
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

    def test_model_category_needs_corroboration(self):
        """模型判 cdn_origin 必须有旁证（全 Web 类型 + 多站点，或关键字命中）。"""
        self.assertTrue(ai._is_cdn_origin(
            "cdn_origin", {"geo": "", "proxies": "site-a,site-b", "ptypes": "https"},
            self.cfg))
        self.assertFalse(ai._is_cdn_origin(
            "cdn_origin", {"geo": "", "proxies": "a", "ptypes": "https"}, self.cfg))

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
        """阿里云 + 全 Web 类型 + 混访多站 = 回源（事故里被误封的就是这种）。"""
        self.assertTrue(ai._is_cdn_origin(
            "web_scan", {"geo": "中国 浙江 杭州 阿里云",
                         "proxies": "gitea_htts2http,portal_htts2http",
                         "ptypes": "https"},
            self.cfg))

    def test_multi_proxy_behavior(self):
        """全 Web 类型 + 同一 IP 混访多站 = 回源特征（事故里被误封的 IP 全是这种）。"""
        self.assertTrue(ai._is_cdn_origin(
            "web_scan", {"geo": "中国 浙江 移动",
                         "proxies": "gitea_htts2http,portal_htts2http",
                         "ptypes": "https"},
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

    def test_permanent_blacklist_not_counted(self):
        """已定口径：AI 永久处置（写 ip_list 黑名单）不计入同段熔断。"""
        for i in range(6):
            store.add_ip("61.241.14.%d" % (10 + i), "black", "ai: malicious 永久拉黑")
        hit, n = ai._subnet_ban_hot("61.241.14.99", self.cfg)
        self.assertFalse(hit, "永久黑名单不应推高熔断计数")
        self.assertEqual(n, 0)

    def test_permanent_mixed_with_temp_only_temp_counted(self):
        """临时封禁与永久黑名单混合：只按 ai: 临时封禁计数，未达阈值不熔断。"""
        for i in range(4):
            self._ban("61.241.14.%d" % (10 + i))
        for i in range(3):
            store.add_ip("61.241.14.%d" % (50 + i), "black", "ai: malicious 永久拉黑")
        hit, n = ai._subnet_ban_hot("61.241.14.99", self.cfg)
        self.assertEqual(n, 4)
        self.assertFalse(hit)


class ApplyActionTest(unittest.TestCase):
    """_apply_action 的处置分支：保护优先于封禁。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({"ai_auto_ban": True, "ai_suspicious_ban": True,
                         "ai_cdn_guard": True, "blacklist_enabled": True})
        self.cfg["ai_trusted_cidrs"] = "61.241.14.0/24"

    def _apply(self, ip, category="web_scan", geo="", proxies="", ptypes=""):
        it = {"geo": geo, "proxies": proxies, "ptypes": ptypes, "conns": 100}
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
        res = self._apply("1.2.3.4", proxies="a_http,b_http", ptypes="https")
        self.assertEqual(res["mode"], "cdn")
        self.assertFalse(self._banned("1.2.3.4"))
        self.assertEqual(store.list_trusted_cidr_strings(), [],
                         "行为层单独命中只跳过本次，不得写学习表")

    def test_subnet_fuse_skips_ban(self):
        for i in range(5):
            store.add_ban("9.9.9.%d" % (10 + i), "ai: 探测", 1800)
        res = self._apply("9.9.9.99")
        self.assertEqual(res["action"], "skipped")
        self.assertEqual(res["mode"], "subnet")
        self.assertFalse(self._banned("9.9.9.99"))
        self.assertEqual(store.list_trusted_cidr_strings(), [],
                         "熔断只止血，不得写学习表")

    def test_normal_scanner_still_banned(self):
        """没有任何保护命中时，扫描器照旧被封禁。"""
        res = self._apply("1.2.3.4", proxies="nightcc-tcp", ptypes="tcp")
        self.assertIn(res["action"], ("temporary", "banned", "permanent"))
        self.assertTrue(self._banned("1.2.3.4"))


class LearnTrustedTest(unittest.TestCase):
    """自动学习：强证据判 CDN 回源后记住，后续同段新 IP 也不再被封。

    owner 拿不到 ESA 的回源 IP 列表，所以只能靠程序「遇到过就记住」。
    只有强证据（关键字命中，或模型判 cdn_origin 且有旁证）才学习，
    所以这里默认用「阿里云 ESA」归属地；行为层单独命中不学习，见 WeakEvidenceNoLearnTest。
    """

    def setUp(self):
        from tests import new_home
        new_home(self)
        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({"ai_auto_ban": True, "ai_suspicious_ban": True,
                         "ai_cdn_guard": True, "ai_learn_cdn": True,
                         "blacklist_enabled": True})

    def _apply(self, ip, proxies="site-a", geo="中国 浙江 阿里云 ESA", ptypes="https"):
        it = {"geo": geo, "proxies": proxies, "ptypes": ptypes, "conns": 150}
        with mock.patch.object(store, "list_ips", return_value=[]):
            return ai._apply_action(ip, "suspicious", "web_scan", "x", it, self.cfg)

    def _apply_model_web_multi(self, ip):
        """模型判 cdn_origin + 全 Web 类型 + 2 个代理名（无关键字旁证）。

        这正是本次要挡的形态：模型层把 web_multi 当旁证，所以这种来源也能
        贡献一个「强证据」名额。
        """
        it = {"geo": "中国 移动", "proxies": "site-a,site-b", "ptypes": "https",
              "conns": 150}
        with mock.patch.object(store, "list_ips", return_value=[]):
            return ai._apply_action(ip, "suspicious", "cdn_origin", "x", it, self.cfg)

    def _trust_row(self, cidr):
        rows = [r for r in store.list_trusted_cidrs() if r["cidr"] == cidr]
        self.assertEqual(len(rows), 1, cidr)
        return rows[0]

    def _banned(self, ip):
        with mock.patch.object(store, "list_ips", return_value=[]):
            return store.is_banned(ip)

    def test_cdn_origin_ip_is_learned(self):
        self._apply("61.241.14.33")
        self.assertIn("61.241.14.33/32", store.list_trusted_cidr_strings())

    def test_learned_entry_points_back_to_review_record(self):
        """学到的条目能直接回查到本次审查记录（不用拿时间 + IP 去猜）。"""
        self._apply("61.241.14.33")
        row = self._trust_row("61.241.14.33/32")
        rid = int(row["ai_review_id"] or 0)
        self.assertGreater(rid, 0)
        reviews = {r["id"]: r for r in store.list_ai_review(50)}
        self.assertIn(rid, reviews)                       # id 指向真实存在的审查记录
        self.assertEqual(reviews[rid]["ip"], "61.241.14.33")
        self.assertEqual(reviews[rid]["action"], "skipped")
        self.assertIn("CDN 回源", reviews[rid]["reason"])

    def test_escalated_24_points_back_to_triggering_review(self):
        """整段升级行也带来源 id，且指向触发升级的那次审查。"""
        for ip in ("61.241.16.33", "61.241.16.41"):
            self._apply(ip)
        self._apply("61.241.16.52")                       # 第三个强证据 -> 升级
        self.assertIn("61.241.16.0/24", store.list_trusted_cidr_strings())
        row = self._trust_row("61.241.16.0/24")
        rid = int(row["ai_review_id"] or 0)
        self.assertGreater(rid, 0)
        self.assertEqual(row["source"], "subnet")
        reviews = {r["id"]: r for r in store.list_ai_review(50)}
        self.assertEqual(reviews[rid]["ip"], "61.241.16.52")

    def test_learn_trusted_rejects_removed_subnet_flag(self):
        """已删除的 subnet 开关无人再用：误传必须是显式 TypeError，不能静默变行为。"""
        with self.assertRaises(TypeError):
            ai._learn_trusted("61.241.17.33", "x", subnet=True)

    def test_learned_ip_is_trusted_even_if_heuristic_misses(self):
        """学到之后，即使这次只打 1 个代理（启发式落空）也靠学习表挡住。"""
        self._apply("61.241.14.33")                    # 先学到
        res = self._apply("61.241.14.33", proxies="nightcc-tcp", geo="中国 移动",
                          ptypes="tcp")
        self.assertEqual(res["mode"], "learned")
        self.assertFalse(self._banned("61.241.14.33"))

    def test_second_ip_in_subnet_does_not_escalate(self):
        """同段第 2 个强证据：不再升级（门槛已提到 3）。"""
        self._apply("61.241.14.33")
        self._apply("61.241.14.41")
        self.assertNotIn("61.241.14.0/24", store.list_trusted_cidr_strings())

    def test_third_ip_in_subnet_escalates_to_24(self):
        """同段第 3 个强证据 -> 自动升级为整段可信。"""
        self._apply("61.241.14.33")
        self._apply("61.241.14.41")
        self.assertNotIn("61.241.14.0/24", store.list_trusted_cidr_strings())
        self._apply("61.241.14.52")
        self.assertIn("61.241.14.0/24", store.list_trusted_cidr_strings())

    def test_two_model_web_multi_sources_do_not_escalate(self):
        """反例：同段两条「model + web_multi」来源不得升级整段。

        单条 /32 仍学习（误判只影响一个 IP，14 天自然过期）；第 3 条才到门槛。
        """
        self._apply_model_web_multi("61.241.16.33")
        self._apply_model_web_multi("61.241.16.41")
        self.assertNotIn("61.241.16.0/24", store.list_trusted_cidr_strings())
        self.assertEqual(self._trust_row("61.241.16.33/32")["source"], "model")
        self.assertEqual(store.count_trusted_in_subnet("61.241.16.0/24"), 2)
        self._apply_model_web_multi("61.241.16.52")
        self.assertIn("61.241.16.0/24", store.list_trusted_cidr_strings())

    def test_escalated_24_keeps_short_ttl_and_is_deletable(self):
        """升级出的 /24：source=subnet、24h TTL、面板可删。"""
        for ip in ("61.241.14.33", "61.241.14.41", "61.241.14.52"):
            self._apply(ip)
        row = self._trust_row("61.241.14.0/24")
        self.assertEqual(row["source"], "subnet")
        ttl = int(row["expires_at"]) - int(time.time())
        self.assertLessEqual(ttl, store.TRUST_TTL["subnet"])
        self.assertGreater(ttl, store.TRUST_TTL["subnet"] - 120)
        self.assertEqual(store.del_trusted_cidr("61.241.14.0/24"), 1)
        self.assertEqual(ai._in_learned_cidrs("61.241.14.200"), "")

    def test_escalated_24_not_counted_itself(self):
        """数同段证据只数 /32：已升级的 /24 行不参与，重复数不会自膨胀。"""
        for ip in ("61.241.14.33", "61.241.14.41", "61.241.14.52"):
            self._apply(ip)
        self.assertEqual(store.count_trusted_in_subnet("61.241.14.0/24"), 3)

    def test_unseen_ip_in_learned_subnet_not_banned(self):
        """学成 /24 后，同段从未见过的新节点也不再被封。"""
        for ip in ("61.241.14.33", "61.241.14.41", "61.241.14.52"):
            self._apply(ip)
        res = self._apply("61.241.14.200", proxies="nightcc-tcp", geo="中国 移动",
                          ptypes="tcp")
        self.assertEqual(res["mode"], "learned")
        self.assertFalse(self._banned("61.241.14.200"))

    def test_other_subnet_still_banned(self):
        """学习不能连带放行其它段。"""
        for ip in ("61.241.14.33", "61.241.14.41", "61.241.14.52"):
            self._apply(ip)
        res = self._apply("8.8.4.4", proxies="nightcc-tcp", geo="美国", ptypes="tcp")
        self.assertNotEqual(res["action"], "skipped")
        self.assertTrue(self._banned("8.8.4.4"))

    def test_learning_off_learns_nothing(self):
        self.cfg["ai_learn_cdn"] = False
        self._apply("61.241.14.33")
        self.assertEqual(store.list_trusted_cidr_strings(), [])


class TypeVetoTest(unittest.TestCase):
    """反向用例：代理类型硬否决与关键字词边界（防扫描器被当成 CDN 回源）。"""

    def setUp(self):
        self.cfg = dict(config.DEFAULTS)
        self.cfg["ai_cdn_guard"] = True

    def _cdn(self, category="web_scan", geo="", proxies="", ptypes=""):
        return ai._is_cdn_origin(
            category, {"geo": geo, "proxies": proxies, "ptypes": ptypes}, self.cfg)

    def test_ssh_mysql_tcp_not_cdn(self):
        """1. 访问 ssh/mysql 的纯 tcp IP 不可能是回源。"""
        self.assertFalse(self._cdn(proxies="ssh-tcp,mysql-tcp", ptypes="tcp"))

    def test_three_tcp_proxies_not_cdn(self):
        """2. 哪怕扫了 3 个代理，纯 tcp 也否决。"""
        self.assertFalse(self._cdn(proxies="a-tcp,b-tcp,c-tcp", ptypes="tcp"))

    def test_production_scanner_profile_not_cdn(self):
        """3. 生产 66.132.159.18 的画像：短时间内扫多个 tcp 代理。"""
        self.assertFalse(self._cdn(proxies="mysql-tcp,status-tcp", ptypes="tcp"))

    def test_mixed_types_not_cdn(self):
        """混入任何非 Web 类型即否决，关键字命中也推翻不了。"""
        self.assertFalse(self._cdn(geo="cloudflare", proxies="site-a,ssh-tcp",
                                   ptypes="https,tcp"))

    def test_esa_substring_words_not_cdn(self):
        """4. 含 esa 子串的地名/组织名不能误中关键字。"""
        for geo in ("Empresa", "Mesa", "Telesat", "Teresa"):
            with self.subTest(geo=geo):
                self.assertFalse(self._cdn(geo=geo, proxies="site-a", ptypes="https"))

    def test_aliyun_esa_is_cdn(self):
        """5. 「阿里云 ESA」是明确的 CDN 产品字样。"""
        self.assertTrue(self._cdn(geo="中国 浙江 阿里云 ESA", proxies="site-a",
                                  ptypes="https"))

    def test_model_cdn_origin_vetoed_by_tcp(self):
        """6. 模型判 cdn_origin，类型为 tcp 也要否决。"""
        self.assertFalse(self._cdn(category="cdn_origin", geo="cloudflare",
                                   proxies="site-a,site-b", ptypes="tcp"))

    def test_model_cdn_origin_with_web_multi_site(self):
        """7. 模型判 cdn_origin + 全 https + 多站点 = 回源，命中层记为 model。"""
        it = {"geo": "", "proxies": "site-a,site-b", "ptypes": "https"}
        self.assertTrue(ai._is_cdn_origin("cdn_origin", it, self.cfg))
        self.assertEqual(ai._cdn_origin_hit("cdn_origin", it, self.cfg),
                         (True, "model", "behavior:2"))

    def test_empty_ptypes_behavior_not_enough(self):
        """ptypes 缺失时行为层不成立（证据不足不放行），关键字层不受影响。"""
        self.assertFalse(self._cdn(proxies="site-a,site-b", ptypes=""))
        self.assertTrue(self._cdn(geo="cloudflare", proxies="site-a", ptypes=""))


class WeakEvidenceNoLearnTest(unittest.TestCase):
    """8-10：弱证据（行为层单独命中、同段熔断）只跳过本次，不写学习表。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({"ai_auto_ban": True, "ai_suspicious_ban": True,
                         "ai_cdn_guard": True, "ai_learn_cdn": True,
                         "blacklist_enabled": True, "ai_trusted_cidrs": "",
                         "ai_subnet_ban_limit": 5, "ai_subnet_ban_window": 900})

    def _apply(self, ip, geo="中国 移动", proxies="site-a,site-b", ptypes="https"):
        it = {"geo": geo, "proxies": proxies, "ptypes": ptypes, "conns": 150}
        with mock.patch.object(store, "list_ips", return_value=[]):
            return ai._apply_action(ip, "suspicious", "web_scan", "x", it, self.cfg)

    def test_behavior_hit_skips_but_not_learned(self):
        """8. 行为层命中：本次跳过，学习表无新增。"""
        res = self._apply("61.241.14.33")
        self.assertEqual(res["mode"], "cdn")
        self.assertEqual(store.list_trusted_cidr_strings(), [])

    def test_subnet_fuse_not_learned(self):
        """9. 熔断命中：只止血，学习表无新增，审查记录里留「熔断待复核」。"""
        for i in range(5):
            store.add_ban("9.9.9.%d" % (10 + i), "ai: 探测", 1800)
        res = self._apply("9.9.9.99", proxies="nightcc-tcp", ptypes="tcp")
        self.assertEqual(res["mode"], "subnet")
        self.assertEqual(store.list_trusted_cidr_strings(), [])
        rows = store._query_ro("SELECT * FROM ai_review", ())
        self.assertTrue(any("熔断待复核" in str(v)
                            for r in rows for v in dict(r).values()))

    def test_two_weak_ips_in_subnet_no_24(self):
        """10. 同 /24 两条弱证据：不学 /32，更不升级 /24。"""
        self._apply("61.241.14.33")
        self._apply("61.241.14.41")
        self.assertEqual(store.list_trusted_cidr_strings(), [])

    def test_weak_sources_do_not_count_toward_24(self):
        """10（纵深）：学习表里即使有 behavior 来源的 /32，也不计入 /24 升级。"""
        ai._learn_trusted("61.241.15.33", "x", source="behavior")
        ai._learn_trusted("61.241.15.41", "x", source="behavior")
        self.assertNotIn("61.241.15.0/24", store.list_trusted_cidr_strings())

    def test_keyword_learn_records_layer(self):
        """强证据学习：source 与 reason 写明命中层，不再一律写「AI 判定」。"""
        self._apply("61.241.14.33", geo="中国 浙江 阿里云 ESA", proxies="site-a")
        rows = [r for r in store.list_trusted_cidrs() if r["cidr"] == "61.241.14.33/32"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "keyword")
        self.assertIn("keyword:", rows[0]["reason"])


class TrustedCidrStoreTest(unittest.TestCase):
    """11-13：学习表过期、first_reason 保留与迁移幂等。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        self.cfg = dict(config.DEFAULTS)
        self.cfg["ai_trusted_cidrs"] = ""

    def _row(self, cidr):
        rows = [r for r in store.list_trusted_cidrs() if r["cidr"] == cidr]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_expired_entry_not_matched(self):
        """11. 过期条目不参与 _in_trusted_cidr 匹配。"""
        store.add_trusted_cidr("5.6.7.8", "kw", source="keyword")
        self.assertTrue(ai._in_trusted_cidr("5.6.7.8", self.cfg))
        store._exec("UPDATE trusted_cidr SET expires_at=? WHERE cidr=?",
                    (int(time.time()) - 60, "5.6.7.8/32"))
        self.assertFalse(ai._in_trusted_cidr("5.6.7.8", self.cfg))

    def test_manual_never_expires(self):
        store.add_trusted_cidr("5.6.7.0/24", "运维声明", source="manual")
        self.assertEqual(int(self._row("5.6.7.0/24")["expires_at"]), 0)

    def test_first_reason_not_overwritten(self):
        """12. 冲突更新时 first_reason 不被覆盖。"""
        store.add_trusted_cidr("5.6.7.8", "首次理由", source="keyword")
        store.add_trusted_cidr("5.6.7.8", "后续理由", source="keyword")
        row = self._row("5.6.7.8/32")
        self.assertEqual(row["first_reason"], "首次理由")
        self.assertEqual(row["reason"], "后续理由")
        self.assertEqual(int(row["hits"]), 2)

    def test_migration_idempotent_on_current_db(self):
        """13. 已迁移的库上再跑两次迁移不报错；四列齐全。"""
        c = store._connect()
        store._migrate_trusted_cidr(c)
        store._migrate_trusted_cidr(c)
        cols = {r[1] for r in c.execute("PRAGMA table_info(trusted_cidr)").fetchall()}
        self.assertTrue({"source", "expires_at", "first_reason", "ai_review_id"} <= cols)

    def test_migration_adds_review_id_without_losing_rows(self):
        """14. 缺 ai_review_id 的库：补列后存量条目全部保留，该列为 0。"""
        path = os.path.join(tempfile.mkdtemp(prefix="frpwaf-mig2-"), "mid.db")
        c = sqlite3.connect(path)
        try:
            # 中间版本结构：已有 source / expires_at / first_reason，缺 ai_review_id
            c.execute("CREATE TABLE trusted_cidr (cidr TEXT PRIMARY KEY, reason TEXT, "
                      "hits INTEGER DEFAULT 0, created_at INTEGER, last_seen INTEGER, "
                      "source TEXT NOT NULL DEFAULT 'legacy', "
                      "expires_at INTEGER NOT NULL DEFAULT 0, "
                      "first_reason TEXT DEFAULT '')")
            now = int(time.time())
            c.executemany(
                "INSERT INTO trusted_cidr(cidr, reason, hits, created_at, last_seen, "
                "source, expires_at, first_reason) VALUES(?,?,?,?,?,?,?,?)",
                [("61.241.14.0/24", "旧理由 A", 5, now, now, "keyword", now + 3600, "旧理由 A"),
                 ("66.132.159.18/32", "旧理由 B", 3, now, now, "manual", 0, "旧理由 B")])
            c.commit()
            store._migrate_trusted_cidr(c)
            store._migrate_trusted_cidr(c)   # 第二次必须是空操作
            cols = {r[1] for r in c.execute("PRAGMA table_info(trusted_cidr)").fetchall()}
            self.assertIn("ai_review_id", cols)
            rows = c.execute("SELECT cidr, reason, source, first_reason, ai_review_id "
                             "FROM trusted_cidr ORDER BY cidr").fetchall()
            self.assertEqual(len(rows), 2, rows)        # 存量条目不丢
            for r in rows:
                self.assertEqual(int(r[4] or 0), 0)     # 新列无关联
            self.assertEqual([r[0] for r in rows], ["61.241.14.0/24", "66.132.159.18/32"])
            self.assertEqual(rows[0][1], "旧理由 A")
            self.assertEqual(rows[0][3], "旧理由 A")
        finally:
            c.close()

    def test_new_entry_records_review_id(self):
        """15. 写入路径能带上来源审查记录 id。"""
        rid = store.add_ai_review(0, "5.6.7.8", "suspicious", "CDN 回源（x）",
                                  "skipped", "m")
        self.assertGreater(rid, 0)
        store.add_trusted_cidr("5.6.7.8", "CDN 回源（x）", source="keyword",
                               ai_review_id=rid)
        self.assertEqual(int(self._row("5.6.7.8/32")["ai_review_id"]), rid)

    def test_review_id_not_overwritten_on_relearn(self):
        """15. 同一段再学时保留首次来源 id（只补空值）。"""
        store.add_trusted_cidr("5.6.7.9", "首次", source="keyword", ai_review_id=11)
        store.add_trusted_cidr("5.6.7.9", "后续", source="keyword", ai_review_id=22)
        self.assertEqual(int(self._row("5.6.7.9/32")["ai_review_id"]), 11)

    def test_review_id_filled_when_previously_empty(self):
        """15. 原本无关联的条目（人工/存量）被学到时可补上来源 id。"""
        store.add_trusted_cidr("5.6.7.10", "人工", source="manual")
        self.assertEqual(int(self._row("5.6.7.10/32")["ai_review_id"]), 0)
        store.add_trusted_cidr("5.6.7.10", "学到", source="keyword", ai_review_id=33)
        self.assertEqual(int(self._row("5.6.7.10/32")["ai_review_id"]), 33)

    def test_touch_keeps_review_id(self):
        """15. 命中续期只刷 hits/last_seen，不改写来源 id。"""
        store.add_trusted_cidr("5.6.7.11", "首次", source="keyword", ai_review_id=44)
        before = self._row("5.6.7.11/32")
        self.assertTrue(store.touch_trusted_cidr("5.6.7.11"))
        after = self._row("5.6.7.11/32")
        self.assertEqual(int(after["ai_review_id"]), 44)
        self.assertEqual(int(after["hits"]), int(before["hits"]) + 1)
        self.assertGreaterEqual(int(after["last_seen"]), int(before["last_seen"]))

    def test_migration_idempotent_on_legacy_table(self):
        """13. 旧表结构 + 存量数据：连续迁移两次不报错；存量行标 legacy 后**被清掉**。

        口径变更（2026-11-27）：旧行为是把存量行标 legacy + 给 7 天有效期。但
        legacy 是 P0 修复前「混访多站即算回源」的产物，可能是纯 tcp 来源，留着会同时
        给 AI 侧与引擎侧豁免。现改为启动迁移时直接删除，见
        store.purge_legacy_trusted_cidrs()。
        """
        path = os.path.join(tempfile.mkdtemp(prefix="frpwaf-mig-"), "old.db")
        c = sqlite3.connect(path)
        try:
            c.execute("CREATE TABLE trusted_cidr (cidr TEXT PRIMARY KEY, reason TEXT, "
                      "hits INTEGER DEFAULT 0, created_at INTEGER, last_seen INTEGER)")
            now = int(time.time())
            c.executemany("INSERT INTO trusted_cidr VALUES(?,?,?,?,?)",
                          [("61.241.14.0/24", "旧理由 A", 5, now, now),
                           ("66.132.159.18/32", "旧理由 B", 3, now, now)])
            c.commit()
            store._migrate_trusted_cidr(c)
            store._migrate_trusted_cidr(c)   # 第二次必须是空操作
            cols = {r[1] for r in c.execute("PRAGMA table_info(trusted_cidr)").fetchall()}
            self.assertTrue({"source", "expires_at", "first_reason", "ai_review_id"} <= cols)
            # 存量行已被清：旧结构没有 source 列，补列后全部落为 legacy，随即被删
            rows = c.execute("SELECT source, expires_at, first_reason, reason "
                             "FROM trusted_cidr").fetchall()
            self.assertEqual(len(rows), 0)
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
