#!/usr/bin/env python3
# coding: utf-8
"""ipset 集合 counters（按来源归因）与存量集合一次性重建的单元测试。

背景：
  集合加 `counters` 后，`ipset save` / `ipset list` 的成员行会多出
  `packets N bytes N`（有 timeout 的条目还会带上 `timeout N`）。旧的成员解析
  按固定列取字段，一旦启用 counters 就会把成员解析错/解析空——同步与审计都会
  受害。本文件钉住：

    1. 两种输出格式（**有 counters / 无 counters**）都能解析出成员与计数；
    2. `ipset create` 必须带 `counters`（v4/v6 都要）；
    3. 存量集合（无 counters）走一次性重建，且**重建不丢成员**：先建临时集合
       填满、再摘规则、destroy+rename、最后立刻重挂规则；任一步失败都要回填，
       绝不能留下「集合空了但没有重新填充」的状态；
    4. 归因接口按丢弃包数排序，且「读不到 / 计数未启用 / 暂无命中」三态可分。

全程打桩 `firewall._run`，不碰真实 ipset/iptables。
"""
import unittest
from unittest import mock

from . import new_home
from app import firewall

# `ipset save frpwaf_block`（集合未启用 counters）
SAVE_PLAIN = (
    "create frpwaf_block hash:net family inet hashsize 1024 maxelem 65536 timeout 0\n"
    "add frpwaf_block 192.0.2.10 timeout 3500\n"
    "add frpwaf_block 198.51.100.0/24\n"
)

# `ipset save`（启用 counters）：成员行尾多了 packets/bytes
SAVE_COUNTERS = (
    "create frpwaf_block hash:net family inet hashsize 1024 maxelem 65536"
    " timeout 0 counters\n"
    "add frpwaf_block 192.0.2.10 packets 42 bytes 3528 timeout 3500\n"
    "add frpwaf_block 198.51.100.0/24 packets 7 bytes 588\n"
    "add frpwaf_block 203.0.113.5 bytes 120 packets 3\n"      # 键顺序故意颠倒
)

# `ipset list frpwaf_block`（启用 counters）
LIST_COUNTERS = (
    "Name: frpwaf_block\n"
    "Type: hash:net\n"
    "Revision: 7\n"
    "Header: family inet hashsize 1024 maxelem 65536 timeout 0 counters\n"
    "Size in memory: 1088\n"
    "References: 1\n"
    "Number of entries: 3\n"
    "Members:\n"
    "192.0.2.10 timeout 3500 packets 42 bytes 3528\n"
    "198.51.100.0/24 packets 7 bytes 588\n"
    "203.0.113.5\n"
)

# `ipset list`（未启用 counters，旧格式）
LIST_PLAIN = (
    "Name: frpwaf_block\n"
    "Type: hash:net\n"
    "Revision: 7\n"
    "Header: family inet hashsize 1024 maxelem 65536 timeout 0\n"
    "Number of entries: 2\n"
    "Members:\n"
    "192.0.2.10 timeout 3500\n"
    "198.51.100.0/24\n"
)

# `ipset list -t`（只表头；存量集合无 counters）
HEADER_PLAIN = (
    "Name: frpwaf_block\n"
    "Type: hash:net\n"
    "Revision: 7\n"
    "Header: family inet hashsize 1024 maxelem 65536 timeout 0\n"
)

HEADER_COUNTERS = HEADER_PLAIN.replace("timeout 0", "timeout 0 counters")


class Recorder:
    """记录 `firewall._run` 调用；按 argv 前缀脚本化返回输出与返回码。"""

    def __init__(self, out=None, rc=None):
        self.calls = []
        self.out = out or {}
        self.rc = rc or {}

    def __call__(self, args, timeout=10, input_data=None):
        self.calls.append({"args": list(args), "input": input_data})
        rc = 0
        for key, val in self.rc.items():
            if key in args:
                rc = val
        text = ""
        for key, val in self.out.items():
            if key in args:
                text = val
        return rc, text, ""

    @property
    def n(self):
        return len(self.calls)

    def argvs(self):
        return [c["args"] for c in self.calls]

    def payload(self):
        parts = []
        for c in self.calls:
            raw = c["input"]
            if raw is None:
                continue
            parts.append(raw.decode("utf-8", "replace")
                         if isinstance(raw, bytes) else str(raw))
        return "\n".join(parts)


class ParseMembersTest(unittest.TestCase):
    """`_parse_members`：两种输出格式、有/无 counters 都要解析正确。"""

    def test_save_without_counters(self):
        got = firewall._parse_members(SAVE_PLAIN, "frpwaf_block")
        self.assertEqual(set(got), {"192.0.2.10", "198.51.100.0/24"})
        self.assertEqual(got["192.0.2.10"], {"timeout": 3500, "packets": 0, "bytes": 0})
        self.assertEqual(got["198.51.100.0/24"]["timeout"], 0, "缺 timeout 视为永久")

    def test_save_with_counters(self):
        got = firewall._parse_members(SAVE_COUNTERS, "frpwaf_block")
        self.assertEqual(set(got), {"192.0.2.10", "198.51.100.0/24", "203.0.113.5"})
        self.assertEqual(got["192.0.2.10"],
                         {"timeout": 3500, "packets": 42, "bytes": 3528})
        self.assertEqual(got["198.51.100.0/24"],
                         {"timeout": 0, "packets": 7, "bytes": 588})
        # 键顺序颠倒也要认（真机不同 ipset 版本的打印顺序不一致）
        self.assertEqual(got["203.0.113.5"],
                         {"timeout": 0, "packets": 3, "bytes": 120})

    def test_list_with_counters(self):
        got = firewall._parse_members(LIST_COUNTERS, "frpwaf_block")
        self.assertEqual(set(got), {"192.0.2.10", "198.51.100.0/24", "203.0.113.5"})
        self.assertEqual(got["192.0.2.10"]["packets"], 42)
        self.assertEqual(got["203.0.113.5"], {"timeout": 0, "packets": 0, "bytes": 0})

    def test_list_without_counters(self):
        """旧格式（一行只有成员，或成员 + timeout）同样不能丢成员。"""
        got = firewall._parse_members(LIST_PLAIN, "frpwaf_block")
        self.assertEqual(set(got), {"192.0.2.10", "198.51.100.0/24"})
        self.assertEqual(got["192.0.2.10"]["timeout"], 3500)

    def test_table_headers_are_skipped(self):
        """表头行（Name:/Type:/Header:/Members:/Number of entries:）不能被当成员。"""
        got = firewall._parse_members(LIST_COUNTERS, "frpwaf_block")
        for junk in ("Name:", "Header:", "Members:", "Number of entries:"):
            self.assertFalse(any(m.startswith(junk) for m in got), junk)

    def test_other_sets_are_ignored(self):
        text = SAVE_PLAIN + "add frpwaf_block6 2001:db8::1 packets 1 bytes 100\n"
        got = firewall._parse_members(text, "frpwaf_block")
        self.assertNotIn("2001:db8::1", got)

    def test_garbage_lines_are_dropped(self):
        text = ("add frpwaf_block not-an-ip timeout 100\n"
                "add frpwaf_block\n"
                "192.0.2.77 packets abc bytes def\n")
        got = firewall._parse_members(text, "frpwaf_block")
        self.assertEqual(set(got), {"192.0.2.77"})
        # 非法计数值不能被当成数字吃掉，退化为 0
        self.assertEqual(got["192.0.2.77"]["packets"], 0)

    def test_members_wrapper_keeps_timeout_only(self):
        """`_members()` 的对外契约不变：{成员: timeout}。"""
        rec = Recorder({"save": SAVE_COUNTERS})
        with mock.patch.object(firewall, "_run", rec):
            got = firewall._members("frpwaf_block")
        self.assertEqual(got, {"192.0.2.10": 3500, "198.51.100.0/24": 0,
                               "203.0.113.5": 0})

    def test_members_missing_set_returns_none(self):
        rec = Recorder(rc={"save": 1})
        with mock.patch.object(firewall, "_run", rec):
            self.assertIsNone(firewall._members("frpwaf_block"))


class CreateSetArgsTest(unittest.TestCase):
    """`ipset create` 必须带 counters，v4/v6 都要，且保留 -exist 幂等。"""

    def setUp(self):
        new_home(self)

    def test_both_families_get_counters(self):
        rec = Recorder()
        with mock.patch.object(firewall, "_run", rec), \
                mock.patch.object(firewall, "_have", lambda name: True):
            firewall._ensure_sets(force=True)
        creates = [a for a in rec.argvs() if a[:2] == ["ipset", "create"]]
        self.assertEqual(len(creates), 2, rec.argvs())
        for argv in creates:
            self.assertIn("counters", argv, argv)
            self.assertIn("-exist", argv, argv)
        v6 = [a for a in creates if "inet6" in a]
        self.assertEqual(len(v6), 1, creates)
        self.assertIn(firewall.SET6, v6[0])
        v4 = [a for a in creates if "inet6" not in a][0]
        self.assertIn(firewall.SET4, v4)
        self.assertEqual(v4[:4], ["ipset", "create", firewall.SET4, "hash:net"])

    def test_counters_can_be_disabled(self):
        argv = firewall._set_args(firewall.SET4, counters=False)
        self.assertNotIn("counters", argv)
        self.assertIn("-exist", argv)


class CountersProbeTest(unittest.TestCase):
    """`_set_has_counters`：Header 行里有没有 counters。"""

    def setUp(self):
        new_home(self)

    def _probe(self, header, rc=0):
        rec = Recorder({"list": header}, {"list": rc})
        with mock.patch.object(firewall, "_run", rec):
            return firewall._set_has_counters(firewall.SET4)

    def test_true_when_header_has_counters(self):
        self.assertIs(self._probe(HEADER_COUNTERS), True)

    def test_false_when_header_lacks_counters(self):
        self.assertIs(self._probe(HEADER_PLAIN), False)

    def test_none_when_unreadable(self):
        self.assertIsNone(self._probe("", rc=1))
        self.assertIsNone(self._probe("Name: frpwaf_block\n"))   # 没有 Header 行


class MigrateCountersTest(unittest.TestCase):
    """存量集合（无 counters）的一次性重建：时序正确且不丢成员。"""

    def setUp(self):
        new_home(self)
        self.rec = Recorder()
        for patcher in (
            mock.patch.object(firewall, "_run", self.rec),
            mock.patch.object(firewall, "_have", lambda name: True),
            mock.patch.object(firewall, "available", lambda: True),
            mock.patch.object(firewall, "_set_has_counters", lambda name: False),
            mock.patch.object(firewall, "_ensure_drop", lambda: True),
            mock.patch.object(firewall, "_clear_drop", lambda: True),
            mock.patch.object(firewall, "_clear_redirect", lambda: True),
            mock.patch.object(firewall, "_restore_rules", lambda: True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        firewall._counters_state = "unknown"
        self.want4 = {"192.0.2.10": 0, "198.51.100.0/24": 0}
        self.want6 = {"2001:db8::1": 0}

    def test_temporary_set_is_filled_before_old_set_is_destroyed(self):
        """核心时序：先建 _mig 并填满 → 才允许 destroy 旧集合。"""
        self.assertTrue(firewall._ensure_counters(self.want4, self.want6))
        argvs = self.rec.argvs()
        idx_create = next(i for i, a in enumerate(argvs)
                          if a[:2] == ["ipset", "create"] and a[2].endswith("_mig"))
        idx_destroy = next(i for i, a in enumerate(argvs)
                           if a[:2] == ["ipset", "destroy"])
        idx_rename = next(i for i, a in enumerate(argvs)
                          if a[:2] == ["ipset", "rename"])
        self.assertLess(idx_create, idx_destroy, "必须先在临时集合里把成员填满")
        self.assertLess(idx_destroy, idx_rename, "destroy 之后才有位置让新集合顶上")
        # 临时集合带 counters
        self.assertIn("counters", argvs[idx_create])

    def test_members_are_filled_into_temporary_set(self):
        firewall._ensure_counters(self.want4, self.want6)
        payload = self.rec.payload()
        for member in list(self.want4) + list(self.want6):
            self.assertIn(member, payload, "临时集合没有填入成员：" + member)
        self.assertIn("frpwaf_block_mig", payload)
        self.assertIn("frpwaf_block6_mig", payload)

    def test_rename_targets_canonical_names(self):
        firewall._ensure_counters(self.want4, self.want6)
        renames = [a for a in self.rec.argvs() if a[:2] == ["ipset", "rename"]]
        self.assertIn(["ipset", "rename", "frpwaf_block_mig", "frpwaf_block"], renames)
        self.assertIn(["ipset", "rename", "frpwaf_block6_mig", "frpwaf_block6"],
                      renames)
        self.assertEqual(firewall._counters_state, "ok")

    def test_memory_snapshot_matches_after_swap(self):
        firewall._ensure_counters(self.want4, self.want6)
        self.assertEqual(firewall._MEMBERS.get(firewall.SET4), self.want4)
        self.assertEqual(firewall._MEMBERS.get(firewall.SET6), self.want6)
        self.assertNotIn("frpwaf_block_mig", firewall._MEMBERS,
                         "临时集合换名后不该留在记忆里")
        # 稳态不再探测：第二次调用 0 调用
        before = self.rec.n
        firewall._ensure_counters(self.want4, self.want6)
        self.assertEqual(self.rec.n, before, "已确认 counters 后不应再 fork")

    def test_unsupported_create_keeps_old_set_untouched(self):
        """内核不支持 counters：旧集合原封不动，只标记 unsupported。"""
        self.rec.rc = {"create": 1}
        self.assertTrue(firewall._ensure_counters(self.want4, self.want6))
        self.assertEqual(firewall._counters_state, "unsupported")
        destroyed = [a[2] for a in self.rec.argvs() if a[:2] == ["ipset", "destroy"]]
        self.assertNotIn(firewall.SET4, destroyed,
                         "建不出临时集合时绝不能去 destroy 正在生效的集合")
        self.assertNotIn(firewall.SET6, destroyed,
                         "建不出临时集合时绝不能去 destroy 正在生效的集合")
        self.assertFalse(
            [a for a in self.rec.argvs() if a[:2] == ["ipset", "rename"]],
            "放弃改造时不该出现换名")

    def test_rename_failure_refills_members(self):
        """换名失败：必须按目标快照回填成员，不能留下空集合。"""
        self.rec.rc = {"rename": 1}
        firewall._ensure_counters(self.want4, self.want6)
        self.assertEqual(firewall._counters_state, "failed")
        payload = self.rec.payload()
        for member in list(self.want4) + list(self.want6):
            self.assertIn(member, payload, "迁移失败后没有回填成员：" + member)
        creates = [a for a in self.rec.argvs() if a[:2] == ["ipset", "create"]]
        self.assertTrue(any(a[2] == firewall.SET4 for a in creates),
                        "回填前必须先把正式集合建回来")


class RestoreAfterLossTest(unittest.TestCase):
    """`_sync_sets` 在审计轮发现「内核集合为空」时必须把全部成员补回去。

    这是重建路径的安全网：即使重建过程把集合弄空了，下一轮对账（同一轮也会走到）
    只要拿到 want 就能全量恢复，不会有「集合空了但没人填」的长期状态。
    """

    def setUp(self):
        new_home(self)
        self.rec = Recorder()
        for patcher in (
            mock.patch.object(firewall, "_run", self.rec),
            mock.patch.object(firewall, "_have", lambda name: True),
            mock.patch.object(firewall, "_members", lambda name: {}),   # 内核为空
            mock.patch.object(firewall, "_ensure_sets", lambda force=False: True),
            mock.patch.object(firewall, "_ensure_counters", lambda w4, w6: True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        firewall._sets_checked_at = 0.0        # 强制走审计轮

    def test_all_members_are_pushed_back(self):
        want4 = {"192.0.2.10": 0, "198.51.100.0/24": 0, "203.0.113.7": 0}
        want6 = {"2001:db8::1": 0}
        self.assertTrue(firewall._sync_sets(want4, want6))
        payload = self.rec.payload()
        for member in list(want4) + list(want6):
            self.assertIn(member, payload, "对账没有把成员补回：" + member)


class TopSourcesTest(unittest.TestCase):
    """`top_sources`：按丢弃包数排序的归因数据。"""

    def setUp(self):
        new_home(self)

    def _top(self, listing, limit=10, have=("ip6tables",), available=True):
        rec = Recorder({"list": listing})
        with mock.patch.object(firewall, "_run", rec), \
                mock.patch.object(firewall, "available", lambda: available), \
                mock.patch.object(firewall, "_have", lambda name: name in have):
            return firewall.top_sources(limit=limit), rec

    def test_sorted_by_packets_desc(self):
        out, _rec = self._top(LIST_COUNTERS)
        self.assertTrue(out["available"])
        self.assertTrue(out["counters"])
        packets = [x["packets"] for x in out["items"]]
        self.assertEqual(packets, sorted(packets, reverse=True))
        self.assertEqual(out["items"][0]["member"], "192.0.2.10")
        self.assertEqual(out["items"][0]["bytes"], 3528)

    def test_limit_is_applied_and_clamped(self):
        out, _rec = self._top(LIST_COUNTERS, limit=1)
        self.assertEqual(len(out["items"]), 1)
        out, _rec = self._top(LIST_COUNTERS, limit=0)
        self.assertEqual(len(out["items"]), 1, "limit 至少 1 条")

    def test_without_counters_flag_items_are_empty(self):
        """集合没启用 counters：items 空，但 counters=False 必须与「无命中」区分开。"""
        out, _rec = self._top(LIST_PLAIN)
        self.assertTrue(out["available"])
        self.assertFalse(out["counters"])
        self.assertEqual(out["items"], [])

    def test_unavailable_environment(self):
        out, rec = self._top(LIST_COUNTERS, available=False)
        self.assertFalse(out["available"])
        self.assertEqual(out["items"], [])
        self.assertEqual(rec.n, 0, "非 root 时不应 fork")

    def test_repeated_calls_use_cache(self):
        """同一 TTL 窗口内只真正读一次（每族一次 ipset list）。"""
        out1, rec = self._top(LIST_COUNTERS)
        first_n = rec.n
        self.assertEqual(first_n, 2, "IPv4/IPv6 各读一次")
        out2, _ = self._top(LIST_COUNTERS)
        self.assertEqual(rec.n, first_n, "TTL 内重复调用不应再 fork")
        self.assertEqual(out1["items"], out2["items"])

    def test_returns_copies(self):
        out, _ = self._top(LIST_COUNTERS)
        out["items"][0]["packets"] = -1
        again, _ = self._top(LIST_COUNTERS)
        self.assertNotEqual(again["items"][0]["packets"], -1,
                            "调用方改返回值不能污染缓存")


if __name__ == "__main__":
    unittest.main()
