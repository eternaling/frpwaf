#!/usr/bin/env python3
# coding: utf-8
"""P1：可信回源网段在**引擎侧**自动封禁的豁免（原缺口）。

背景：CDN/ESA 回源 IP 是共享边缘节点，封一个等于封该 CDN 背后的整站用户
（2026-11 封掉 ESA 回源段 -> 整站 522，事故形态）。AI 侧（`app/ai.py`）早就
不处置这类来源，但引擎的四条自动封禁路径**原来完全不查** `trusted_cidr` /
`ai_trusted_cidrs`：

  第 5 步 基础自动封禁 / 6.1 敏感服务（永久黑名单）/ 6.2 CC / 6.3 多代理探测

于是「AI 不封」形同虚设——CC 默认 300/60s，共享回源节点很容易达标。

本文件锁住修复后的口径：
  - 学习表（/32 与 /24 升级）与人工 `ai_trusted_cidrs` 在四条路径上**一律生效**；
  - 6.3 多代理探测也认回源段（回源节点访问多站点正是误封高发场景）；
  - 过期条目、被删除条目立即不再豁免；
  - 对照组：不在可信段内的 IP 照旧被封，证明豁免不是「全放行」。
"""

import os
import tempfile
import time
import unittest

HOME = tempfile.mkdtemp(prefix="frpwaf-cdnexempt-")
os.makedirs(os.path.join(HOME, "data"), exist_ok=True)
os.environ.setdefault("FRPWAF_HOME", HOME)

from app import config, engine, store  # noqa: E402


def _in_blacklist(ip):
    return any((r.get("cidr") or "") in (ip, ip + "/32") for r in store.list_ips("black"))


def _banned(ip):
    """生效中的封禁（永久黑名单或临时封禁都算）。"""
    return engine._is_banned(ip)


class CdnTrustEngineExemptTest(unittest.TestCase):
    """学习表 / 人工配置在引擎四条自动封禁路径上的豁免。"""

    def setUp(self):
        from tests import new_home
        new_home(self)
        engine.invalidate_cache()
        self.cfg = dict(config.DEFAULTS)

    def tearDown(self):
        engine.invalidate_cache()

    # ---- 6.1 敏感服务（永久黑名单路径） ----
    def test_learned_single_ip_not_banned(self):
        """学到 /32 后，连 25 次敏感代理（阈值 20）也不再被封。"""
        store.add_trusted_cidr("203.0.113.7", "回源", source="keyword")
        engine.invalidate_cache()
        for _ in range(25):
            engine._attack_detect(self.cfg, "203.0.113.7", "mysql80-tcp", "tcp")
        self.assertFalse(_in_blacklist("203.0.113.7"))

    def test_control_unlearned_ip_still_banned(self):
        """对照组：没学到的 IP 同样操作必须被封。"""
        for _ in range(25):
            engine._attack_detect(self.cfg, "203.0.113.99", "mysql80-tcp", "tcp")
        self.assertTrue(_in_blacklist("203.0.113.99"))

    def test_learned_subnet_covers_other_ip(self):
        """/24 升级后，同段内**没学过**的 IP 也不被封。"""
        store.add_trusted_cidr("198.51.100.0/24", "同段升级", source="subnet")
        engine.invalidate_cache()
        for _ in range(25):
            engine._attack_detect(self.cfg, "198.51.100.42", "redis-tcp", "tcp")
        self.assertFalse(_in_blacklist("198.51.100.42"))

    def test_manual_config_cidr_exempt(self):
        """人工配置 ai_trusted_cidrs 同样在引擎侧生效。"""
        cfg = dict(self.cfg, ai_trusted_cidrs="192.0.2.0/24")
        for _ in range(25):
            engine._attack_detect(cfg, "192.0.2.5", "ssh-tcp", "tcp")
        self.assertFalse(_in_blacklist("192.0.2.5"))

    # ---- 6.2 CC（临时封禁路径） ----
    def test_cc_path_exempt(self):
        store.add_trusted_cidr("203.0.113.8", "回源", source="keyword")
        engine.invalidate_cache()
        cfg = dict(self.cfg, auto_ban_cc_enabled=True,
                   auto_ban_cc_threshold=3, auto_ban_cc_window=60)
        for _ in range(10):
            engine._attack_detect(cfg, "203.0.113.8", "site_https", "https")
        self.assertFalse(_banned("203.0.113.8"))

    def test_cc_path_control_still_banned(self):
        cfg = dict(self.cfg, auto_ban_cc_enabled=True,
                   auto_ban_cc_threshold=3, auto_ban_cc_window=60)
        for _ in range(10):
            engine._attack_detect(cfg, "203.0.113.98", "site_https", "https")
        self.assertTrue(_banned("203.0.113.98"))

    # ---- 6.3 多代理探测（proxy=False 分支也要认回源段） ----
    def test_scan_path_exempt(self):
        """回源节点访问多站点不按「多代理探测」处置（默认阈值 20 个不同代理）。"""
        store.add_trusted_cidr("203.0.113.9", "回源", source="keyword")
        engine.invalidate_cache()
        for i in range(25):
            engine._attack_detect(self.cfg, "203.0.113.9", "site%d_https" % i, "https")
        self.assertFalse(_banned("203.0.113.9"))

    def test_scan_path_control_still_banned(self):
        """对照组：普通来源访问同样多个代理仍被判多代理探测。"""
        for i in range(25):
            engine._attack_detect(self.cfg, "203.0.113.97", "site%d_https" % i, "https")
        self.assertTrue(_banned("203.0.113.97"))

    # ---- 失效语义 ----
    def test_expired_entry_does_not_exempt(self):
        """过期条目不再豁免：误学的段不活跃即失效，不会被永久信任。"""
        store.add_trusted_cidr("203.0.113.10", "回源", source="keyword")
        now = int(time.time())
        store._exec("UPDATE trusted_cidr SET expires_at=? WHERE cidr=?",
                    (now - 10, "203.0.113.10/32"))
        engine.invalidate_cache()
        for _ in range(25):
            engine._attack_detect(self.cfg, "203.0.113.10", "mysql80-tcp", "tcp")
        self.assertTrue(_in_blacklist("203.0.113.10"))

    def test_deleted_entry_does_not_exempt(self):
        """面板删掉该段后，invalidate_cache() 立即让它重新受管。"""
        store.add_trusted_cidr("203.0.113.11", "回源", source="keyword")
        engine.invalidate_cache()
        for _ in range(25):
            engine._attack_detect(self.cfg, "203.0.113.11", "mysql80-tcp", "tcp")
        self.assertFalse(_in_blacklist("203.0.113.11"))

        store.del_trusted_cidr("203.0.113.11")
        engine.invalidate_cache()
        for _ in range(25):
            engine._attack_detect(self.cfg, "203.0.113.11", "mysql80-tcp", "tcp")
        self.assertTrue(_in_blacklist("203.0.113.11"))

    # ---- 缓存口径 ----
    def test_index_cache_and_invalidate(self):
        """索引走 3 秒缓存，invalidate_cache() 后立即重建。"""
        store.add_trusted_cidr("203.0.113.12", "回源", source="keyword")
        engine.invalidate_cache()
        exact, _nets = engine._trusted_cidr_index()
        self.assertIn((4, int(__import__("ipaddress").ip_address("203.0.113.12"))), exact)

        store.del_trusted_cidr("203.0.113.12")
        # 未失效：仍命中缓存（这正是热路径不查库的证据）
        exact_cached, _ = engine._trusted_cidr_index()
        self.assertIn((4, int(__import__("ipaddress").ip_address("203.0.113.12"))), exact_cached)
        # 失效后重建
        engine.invalidate_cache()
        exact_fresh, _ = engine._trusted_cidr_index()
        self.assertNotIn((4, int(__import__("ipaddress").ip_address("203.0.113.12"))), exact_fresh)


if __name__ == "__main__":
    unittest.main()


class LegacyCleanupTest(unittest.TestCase):
    """旧版本误学的 legacy 条目必须被清掉，不能继续提供豁免。

    legacy 是 2026-11 P0 修复之前的产物：那时判回源不看 proxy_type，
    纯 tcp 来源也会被写成可信回源段（生产实证：177 次全 tcp、零拒绝）。
    """

    def setUp(self):
        from tests import new_home
        new_home(self)
        engine.invalidate_cache()
        self.cfg = dict(config.DEFAULTS)
        now = int(time.time())
        store._exec(
            "INSERT OR REPLACE INTO trusted_cidr(cidr, reason, hits, created_at, last_seen, "
            "source, expires_at, first_reason) VALUES(?,?,?,?,?,?,?,?)",
            ("3.107.172.137/32", "AI 判回源（旧逻辑）", 3, now, now, "legacy",
             now + 86400 * 7, "AI 判回源（旧逻辑）"))

    def tearDown(self):
        engine.invalidate_cache()

    def test_legacy_entry_exempts_before_cleanup(self):
        """前提确认：清之前它确实提供豁免（否则下面的用例没意义）。"""
        engine.invalidate_cache()
        import ipaddress
        self.assertTrue(engine._in_trusted_cidr(
            ipaddress.ip_address("3.107.172.137"), self.cfg))

    def test_purge_drops_legacy(self):
        self.assertEqual(1, store.purge_legacy_trusted_cidrs())
        self.assertEqual([], store.list_trusted_cidr_strings())

    def test_purge_keeps_strong_evidence(self):
        """只删 legacy：keyword / manual 是强证据，不能被误清。"""
        now = int(time.time())
        for cidr, src in (("198.51.100.0/24", "keyword"), ("192.0.2.1/32", "manual")):
            store._exec(
                "INSERT OR REPLACE INTO trusted_cidr(cidr, reason, hits, created_at, "
                "last_seen, source, expires_at, first_reason) VALUES(?,?,?,?,?,?,?,?)",
                (cidr, "回源", 1, now, now, src, 0 if src == "manual" else now + 86400,
                 "回源"))
        self.assertEqual(1, store.purge_legacy_trusted_cidrs())
        left = store.list_trusted_cidr_strings()
        self.assertIn("198.51.100.0/24", left)
        self.assertIn("192.0.2.1/32", left)
        self.assertNotIn("3.107.172.137/32", left)

    def test_purge_is_idempotent(self):
        store.purge_legacy_trusted_cidrs()
        self.assertEqual(0, store.purge_legacy_trusted_cidrs())

    def test_engine_no_longer_exempts_after_purge(self):
        """清理后这个 IP 重新受管：连 25 次敏感代理就会被封。"""
        import ipaddress
        store.purge_legacy_trusted_cidrs()
        engine.invalidate_cache()
        self.assertEqual("", engine._in_trusted_cidr(
            ipaddress.ip_address("3.107.172.137"), self.cfg))
        for _ in range(25):
            engine._attack_detect(self.cfg, "3.107.172.137", "mysql80-tcp", "tcp")
        self.assertTrue(_in_blacklist("3.107.172.137"))
