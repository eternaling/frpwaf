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

from app import config, engine, store  # noqa: E402


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
