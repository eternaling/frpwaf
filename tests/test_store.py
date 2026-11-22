#!/usr/bin/env python3
# coding: utf-8
"""app/store.py 单元测试（SQLite 存储层）。

全部用例使用 tempfile 下的临时库文件（tests.new_home 保证），不碰真实
data/frpwaf.db。覆盖：名单/日志/封禁 CRUD、合并写入的事务语义、
各 trim_* 的裁剪边界、以及旧库 ip_list 结构迁移。
"""
import os
import sqlite3
import unittest

from . import new_home, under_temp
from app import config, store


class StoreBase(unittest.TestCase):
    def setUp(self):
        new_home(self)
        store.init()

    def teardown_home(self):  # pragma: no cover - 由 new_home 登记的清理负责
        pass


class IpListTest(StoreBase):
    def test_add_list_del(self):
        store.add_ip("1.2.3.4", "black", "扫描")
        store.add_ip("10.0.0.0/8", "white", "内网")
        rows = store.list_ips()
        self.assertEqual(len(rows), 2)
        blacks = store.list_ips("black")
        self.assertEqual([r["cidr"] for r in blacks], ["1.2.3.4/32"])
        store.del_ip(blacks[0]["id"])
        self.assertEqual(store.list_ips("black"), [])

    def test_cidr_is_normalized(self):
        store.add_ip("10.1.2.3/8", "black")
        self.assertEqual(store.list_ips()[0]["cidr"], "10.0.0.0/8")

    def test_duplicate_rejected(self):
        store.add_ip("1.2.3.4", "black")
        with self.assertRaises(ValueError):
            store.add_ip("1.2.3.4", "black")

    def test_same_cidr_allowed_in_both_lists(self):
        store.add_ip("1.2.3.4", "black")
        store.add_ip("1.2.3.4", "white")
        self.assertEqual(len(store.list_ips()), 2)

    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            store.add_ip("not-an-ip")
        with self.assertRaises(ValueError):
            store.add_ip("1.2.3.4", "grey")

    def test_load_rules_split(self):
        store.add_ip("1.1.1.0/24", "black")
        store.add_ip("2.2.2.2", "white")
        blacks, whites = store.load_rules()
        self.assertEqual([str(n) for n in blacks], ["1.1.1.0/24"])
        self.assertEqual([str(n) for n in whites], ["2.2.2.2/32"])

    def test_list_ips_limit(self):
        for i in range(5):
            store.add_ip("10.0.0.%d" % i, "black")
        self.assertEqual(len(store.list_ips("black", limit=3)), 3)

    def test_clear_blacklist_keeps_whitelist(self):
        store.add_ip("1.1.1.1", "black")
        store.add_ip("2.2.2.2", "white")
        self.assertEqual(store.clear_blacklist(), 1)
        self.assertEqual(store.list_ips("black"), [])
        self.assertEqual(len(store.list_ips("white")), 1)


class ConnLogTest(StoreBase):
    def test_add_log_and_bump_single_transaction(self):
        store.add_log_and_bump("1.2.3.4", 80, "web", "http", "u", "allow")
        store.add_log_and_bump("1.2.3.5", 80, "web", "http", "u", "reject",
                               reason="blacklist", rejected=True)
        self.assertEqual(store.count_logs(), 2)
        rows = store.list_proxy_stat()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["proxy_name"], "web")
        self.assertEqual(rows[0]["total"], 2)
        self.assertEqual(rows[0]["rejected"], 1)

    def test_add_log_and_bump_without_proxy_skips_stat(self):
        store.add_log_and_bump("1.2.3.4", 80, "", "", "", "allow")
        self.assertEqual(store.count_logs(), 1)
        self.assertEqual(store.list_proxy_stat(), [])

    def test_list_logs_filters(self):
        store.add_log("1.2.3.4", 80, "a", "http", "", "allow")
        store.add_log("5.6.7.8", 80, "b", "http", "", "reject")
        self.assertEqual(len(store.list_logs(action="reject")), 1)
        self.assertEqual(len(store.list_logs(ip="1.2.3.4")), 1)
        self.assertEqual(len(store.list_logs(proxy="b")), 1)

    def test_recent_count_by_ip_window(self):
        store.add_log("1.2.3.4", 80, "a", "http", "", "allow")
        self.assertEqual(store.recent_count_by_ip("1.2.3.4", 60), 1)
        self.assertEqual(store.recent_count_by_ip("1.2.3.4", -1), 0)


class TrimTest(StoreBase):
    """trim_* 的裁剪边界：等于上限不删，超限按 id 从旧到新删。"""

    def test_trim_logs_at_limit_keeps_all(self):
        for i in range(5):
            store.add_log("10.0.0.%d" % i, 80, "p", "tcp", "", "allow")
        store.trim_logs(5)
        self.assertEqual(store.count_logs(), 5)

    def test_trim_logs_over_limit_drops_oldest(self):
        for i in range(8):
            store.add_log("10.0.0.%d" % i, 80, "p", "tcp", "", "allow")
        store.trim_logs(3)
        self.assertEqual(store.count_logs(), 3)
        keep = sorted(r["ip"] for r in store.list_logs(limit=10))
        self.assertEqual(keep, ["10.0.0.5", "10.0.0.6", "10.0.0.7"])

    def test_trim_ai_review(self):
        for i in range(6):
            store.add_ai_review(1, "10.0.0.%d" % i, "malicious", "", "none", "m")
        store.trim_ai_review(2)
        rows = store.list_ai_review(limit=10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted(r["ip"] for r in rows), ["10.0.0.4", "10.0.0.5"])

    def test_trim_bans_never_drops_active_ban(self):
        store.add_ban("1.1.1.1", "active", 600)          # 仍生效
        for i in range(3):
            store.add_ban("2.2.2.%d" % i, "old", -10)    # 已到期
        store.trim_bans(2)
        rows = store.ban_history(100)
        self.assertEqual(len(rows), 2)
        self.assertIn("1.1.1.1", [r["ip"] for r in rows])

    def test_trim_bans_at_limit_keeps_all(self):
        store.add_ban("1.1.1.1", "a", 600)
        store.add_ban("2.2.2.2", "b", -10)
        store.trim_bans(2)
        self.assertEqual(len(store.ban_history(100)), 2)


class BanTest(StoreBase):
    def test_ban_and_query(self):
        store.add_ban("1.2.3.4", "test", 600)
        self.assertTrue(store.is_banned("1.2.3.4"))
        self.assertFalse(store.is_banned("9.9.9.9"))
        self.assertEqual(store.active_bans_count(), 1)

    def test_cidr_ban_matches_inside_address(self):
        store.add_ban("10.0.0.0/8", "段封禁", 600)
        self.assertTrue(store.is_banned("10.9.8.7"))

    def test_is_banned_tolerates_invalid_ip(self):
        store.add_ban("1.2.3.4", "test", 600)
        self.assertFalse(store.is_banned("::not-an-ip"))
        self.assertFalse(store.is_banned(""))
        self.assertFalse(store.is_banned(None))

    def test_expired_ban_is_not_active(self):
        store.add_ban("1.2.3.4", "test", -1)
        self.assertFalse(store.is_banned("1.2.3.4"))
        self.assertEqual(store.active_bans_count(), 0)
        expired = store.expired_bans()
        self.assertEqual([b["ip"] for b in expired], ["1.2.3.4"])
        store.release_ban(expired[0]["id"])
        self.assertEqual(store.expired_bans(), [])

    def test_unban_releases_all_same_ip(self):
        store.add_ban("1.2.3.4", "a", 600)
        store.add_ban("1.2.3.4", "b", 600)
        store.unban_ip("1.2.3.4")
        self.assertFalse(store.is_banned("1.2.3.4"))

    def test_invalidate_bans_takes_effect_immediately(self):
        self.assertFalse(store.is_banned("1.2.3.4"))
        store.add_ban("1.2.3.4", "test", 600)
        self.assertTrue(store.is_banned("1.2.3.4"))
        store.unban_ip("1.2.3.4")
        self.assertFalse(store.is_banned("1.2.3.4"))

    def test_release_all_bans(self):
        store.add_ban("1.1.1.1", "a", 600)
        store.add_ban("2.2.2.2", "b", 600)
        self.assertEqual(store.release_all_bans(), 2)
        self.assertEqual(store.active_bans_count(), 0)

    def test_add_ban_normalizes_cidr(self):
        store.add_ban("10.1.2.3/8", "x", 600)
        self.assertEqual(store.active_bans()[0]["ip"], "10.0.0.0/8")

    def test_add_ban_invalid_ip_raises(self):
        with self.assertRaises(ValueError):
            store.add_ban("nope", "x", 600)


class MigrateIpListTest(unittest.TestCase):
    """旧库迁移：cidr 全局唯一 -> UNIQUE(cidr,list_type)，数据必须保留。"""

    def setUp(self):
        new_home(self)
        os.makedirs(config.DATA_DIR, exist_ok=True)
        # 造一个「旧结构」库：cidr TEXT NOT NULL UNIQUE
        c = sqlite3.connect(config.DB_PATH)
        c.executescript(
            "CREATE TABLE ip_list ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " cidr TEXT NOT NULL UNIQUE,"
            " list_type TEXT NOT NULL DEFAULT 'black',"
            " remark TEXT DEFAULT '',"
            " created_at INTEGER NOT NULL);"
        )
        c.execute("INSERT INTO ip_list(cidr,list_type,remark,created_at)"
                  " VALUES('1.2.3.4','black','legacy',1)")
        c.commit()
        c.close()

    def test_migration_preserves_rows_and_relaxes_unique(self):
        store.init()   # _connect() 里触发 _migrate_ip_list
        rows = store.list_ips()
        self.assertEqual([(r["cidr"], r["remark"]) for r in rows],
                         [("1.2.3.4", "legacy")])
        # 迁移后同一 CIDR 可以同时进黑白名单（旧结构下会 IntegrityError）
        store.add_ip("1.2.3.4", "white")
        self.assertEqual(len(store.list_ips()), 2)

    def test_migration_is_idempotent(self):
        store.init()
        store.init()
        self.assertEqual(len(store.list_ips()), 1)


class StoreIsolationTest(StoreBase):
    def test_db_is_under_temp(self):
        self.assertTrue(under_temp(config.DB_PATH), config.DB_PATH)
        self.assertNotEqual(config.DB_PATH, "/opt/frpwaf/data/frpwaf.db")

    def test_schema_creates_all_tables(self):
        c = sqlite3.connect(config.DB_PATH)
        names = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        c.close()
        for t in ("ip_list", "conn_log", "ban_log", "proxy_stat", "ai_review"):
            self.assertIn(t, names)


if __name__ == "__main__":
    unittest.main()
