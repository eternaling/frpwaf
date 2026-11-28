#!/usr/bin/env python3
# coding: utf-8
"""概览指标口径单元测试（`store.stats` 的窗口值 / 真累计 / 新增封禁）。

背景（这是口径问题，不是算错数）：
  `conn_log` 有 `log_max_rows` 上限，后台每 10 秒裁一次最旧的行。于是
  `SELECT COUNT(*) FROM conn_log` 只能表示「日志窗口内的现存条数」，在线上一旦
  达到上限就永远停在上限值（实测 50001 = 上限 50000 + 一次写入），既不是
  「最近一天」也不是「历史累计」。

本文件钉住四件事：
  1. `conns_24h` 只数最近 24 小时（滑动窗口，不随裁剪饱和）；
  2. `conns_total` 取 `sqlite_sequence.seq`，**删行/VACUUM 都不回退**——这是它能
     当「真累计」的唯一前提，必须有用例守着；
  3. `bans_24h` 只数最近 24 小时新增的封禁条目（临时 + 永久各一条）；
  4. 老字段（`total_conns` / `today_conns` / `black_count` / `active_bans` …）
     语义不变、一个不少：旧前端与旧插件版本还在读它们。

不写真实数据目录：`tests/__init__.py` 的 `new_home()` 把 DB 指到临时目录。
"""
import time
import unittest

from . import new_home
from app import store


def _log_at(ts, action="allow", ip="192.0.2.1"):
    """按指定时间戳写一条连接日志（add_log 用当前时间，这里需要构造旧数据）。"""
    store._exec(
        "INSERT INTO conn_log(ts,ip,port,proxy_name,proxy_type,user,action,reason)"
        " VALUES(?,?,?,?,?,?,?,?)",
        (int(ts), ip, 443, "web", "http", "", action, ""),
    )


def _ban_at(ts, ip="198.51.100.7"):
    """按指定时间写一条临时封禁记录。"""
    store._exec(
        "INSERT INTO ban_log(ip,reason,banned_at,expire_at,released)"
        " VALUES(?,?,?,?,0)",
        (ip, "测试", int(ts), int(ts) + 86400),
    )


class ConnsWindowTest(unittest.TestCase):
    """`conns_24h`：只数最近 24 小时。"""

    def setUp(self):
        new_home(self)

    def test_only_last_24h_counted(self):
        now = int(time.time())
        _log_at(now - 60)                    # 窗口内
        _log_at(now - 3600 * 20)             # 窗口内（20 小时前）
        _log_at(now - 3600 * 25)             # 窗口外（25 小时前）
        _log_at(now - 3600 * 24 * 4)         # 窗口外（4 天前）
        st = store.stats()
        self.assertEqual(st["conns_24h"], 2)
        self.assertEqual(st["total_conns"], 4, "现存行数仍是 4")

    def test_rejected_conns_are_counted_too(self):
        """口径含被拒绝的连接：近 24h 连接数 = WAF 处理过的全部尝试。"""
        now = int(time.time())
        _log_at(now - 10, action="allow")
        _log_at(now - 20, action="reject")
        _log_at(now - 30, action="rate_limit")
        st = store.stats()
        self.assertEqual(st["conns_24h"], 3)

    def test_empty_db_is_zero(self):
        st = store.stats()
        self.assertEqual(st["conns_24h"], 0)
        self.assertEqual(st["conns_total"], 0)


class ConnsTotalTest(unittest.TestCase):
    """`conns_total`：`sqlite_sequence` 自增序列 = 真累计。"""

    def setUp(self):
        new_home(self)

    def test_equals_insert_count(self):
        for i in range(5):
            _log_at(int(time.time()) - i)
        st = store.stats()
        self.assertEqual(st["conns_total"], 5)
        self.assertEqual(st["total_conns"], 5)

    def test_seq_does_not_roll_back_after_delete(self):
        """关键前提：删行不会让 seq 回退，所以裁剪不影响「真累计」。"""
        now = int(time.time())
        for i in range(10):
            _log_at(now - 3600 * 24 * 30 - i)      # 全是旧数据
        self.assertEqual(store.stats()["conns_total"], 10)

        # 走真实的裁剪路径：只留 2 条 -> 删掉最旧的 8 条
        store.trim_logs(2)
        st = store.stats()
        self.assertEqual(st["total_conns"], 2, "现存行数应被裁到 2")
        self.assertEqual(st["conns_total"], 10, "真累计不能因为裁剪变小")
        self.assertEqual(st["conns_24h"], 0, "旧数据本就不在 24h 窗口里")

    def test_seq_does_not_roll_back_after_vacuum(self):
        """VACUUM 会重写整个库，但同样不回退 AUTOINCREMENT 计数器。

        `sqlite_sequence` 是普通表，VACUUM 后其内容保留；这条用例防止有人误以为
        「VACUUM 之后计数就归零」而在运维上做多余的重置处理。
        """
        for i in range(3):
            _log_at(int(time.time()) - i)
        store._exec("DELETE FROM conn_log")
        try:
            store._exec("VACUUM")
        except Exception as exc:            # pragma: no cover - WAL 下极少失败
            self.skipTest("当前库状态下 VACUUM 不可执行：%s" % exc)
        st = store.stats()
        self.assertEqual(st["total_conns"], 0)
        self.assertEqual(st["conns_total"], 3)

    def test_total_continues_after_trim_then_insert(self):
        """裁剪后继续写入：seq 继续递增，不会从裁剪后的行数重新开始。"""
        now = int(time.time())
        for i in range(6):
            _log_at(now - 3600 * 24 * 10 - i)
        store.trim_logs(1)
        _log_at(now)
        st = store.stats()
        # 插入 6 条 + 裁剪后新增 1 条 = 7；现存 2 条
        self.assertEqual(st["conns_total"], 7)
        self.assertEqual(st["total_conns"], 2)
        self.assertEqual(st["conns_24h"], 1)


class Bans24hTest(unittest.TestCase):
    """`bans_24h`：最近 24 小时新增的封禁条目数。"""

    def setUp(self):
        new_home(self)

    def test_only_last_24h_counted(self):
        now = int(time.time())
        _ban_at(now - 60)                       # 窗口内临时封禁
        _ban_at(now - 3600 * 25, ip="203.0.113.9")   # 窗口外临时封禁
        store._exec(
            "INSERT INTO ip_list(cidr,list_type,remark,created_at)"
            " VALUES(?,?,?,?)", ("198.51.100.20/32", "black", "", now - 120))
        store._exec(
            "INSERT INTO ip_list(cidr,list_type,remark,created_at)"
            " VALUES(?,?,?,?)", ("198.51.100.21/32", "black", "", now - 3600 * 30))
        st = store.stats()
        self.assertEqual(st["bans_24h"], 2, "一条临时 + 一条永久")
        self.assertEqual(st["black_count"], 2, "黑名单总数仍是累计值")

    def test_whitelist_entries_are_not_counted(self):
        now = int(time.time())
        store._exec(
            "INSERT INTO ip_list(cidr,list_type,remark,created_at)"
            " VALUES(?,?,?,?)", ("198.51.100.30/32", "white", "", now - 60))
        self.assertEqual(store.stats()["bans_24h"], 0)

    def test_old_entries_do_not_count(self):
        """文件里那条「499 条累计、最早 2026-10」的现状：24h 窗口应为 0。"""
        now = int(time.time())
        for i in range(20):
            store._exec(
                "INSERT INTO ip_list(cidr,list_type,remark,created_at)"
                " VALUES(?,?,?,?)",
                ("198.51.100.%d/32" % (100 + i), "black", "", now - 3600 * 24 * 5))
        st = store.stats()
        self.assertEqual(st["bans_24h"], 0)
        self.assertEqual(st["black_count"], 20)


class LegacyFieldsTest(unittest.TestCase):
    """老字段一个不少（旧前端/旧插件版本仍在读）。"""

    def setUp(self):
        new_home(self)

    def test_all_fields_present_with_int_type(self):
        st = store.stats()
        for key in ("total_conns", "conns_24h", "conns_total", "bans_24h",
                    "today_conns", "today_rejected", "today_uniq_ip",
                    "black_count", "white_count", "active_bans"):
            self.assertIn(key, st, "缺少字段 " + key)
            self.assertIsInstance(st[key], int, key)


if __name__ == "__main__":
    unittest.main()
