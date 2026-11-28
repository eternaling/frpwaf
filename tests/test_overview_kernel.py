#!/usr/bin/env python3
# coding: utf-8
"""概览「内核层已丢弃」取数（`firewall.drop_stats` / `drop_fields`）单元测试。

背景（口径问题，不是算错数）：
  `conn_log` 的唯一写入点是 frp 的 `NewUserConn` 回调，而内核链
  `FRPWAF_BLOCK` 在 INPUT 直接用 ipset 命中 DROP —— 被丢弃的包到不了 frps，
  既不产生回调也不写日志。所以「今日拦截」只能反映到达 WAF 的那部分，
  内核丢了多少只能另读 `iptables -L` 计数器。

本文件钉住四件事：
  1. `-L <chain> -v -n` 的输出按 `pkts` / `bytes` 两列解析（IPv4+IPv6 相加）；
  2. 任何取不到数的情形（非 root、无 iptables、链不存在、命令超时、输出异常）
     都只降级为 `available=False`，**不抛异常**，概览接口照常 200；
  3. 概览会轮询，所以必须有短 TTL 缓存：连续调用只 fork 一次；
  4. `/api/overview` 的其余字段语义不变（本次只增不改）。

不写真实数据目录，不调用真实 ipset/iptables：`firewall._run` 全程打桩。
"""
import subprocess
import time
import unittest
from unittest import mock

from . import new_home
from app import config, daemon, firewall

# 真实样本：`iptables -L FRPWAF_BLOCK -v -n` 的输出（含表头与 Chain 行）。
# 列顺序来自 iptables -L -v：pkts bytes target prot opt in out source destination
IPT_OUT = (
    "Chain FRPWAF_BLOCK (1 references)\n"
    "    pkts      bytes target     prot opt in     out     source               destination\n"
    " 3310123  203423744 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set frpwaf_block src\n"
)

# ip6tables 侧：同一条链的 IPv6 DROP 规则
IP6T_OUT = (
    "Chain FRPWAF_BLOCK (1 references)\n"
    "    pkts      bytes target     prot opt in     out     source               destination\n"
    "    2048       8192 DROP       all      *      *       ::/0                 ::/0                 match-set frpwaf_block6 src\n"
)

# 链存在但一条规则都没有（例如刚建好链、DROP 规则还没下发）
IPT_EMPTY = (
    "Chain FRPWAF_BLOCK (1 references)\n"
    "    pkts      bytes target     prot opt in     out     source               destination\n"
)


class RunStub:
    """打桩 `firewall._run`，按 argv[0] 返回预设输出，并统计调用次数。"""

    def __init__(self, stdout_map=None, rc_map=None):
        self.stdout_map = stdout_map or {}
        self.rc_map = rc_map or {}
        self.calls = []

    def __call__(self, args, timeout=10, input_data=None):
        self.calls.append({"args": list(args), "timeout": timeout})
        name = args[0] if args else ""
        rc = self.rc_map.get(name, 0)
        return rc, self.stdout_map.get(name, ""), ""

    @property
    def n(self):
        return len(self.calls)


class ParseDropCountersTest(unittest.TestCase):
    """`_parse_drop_counters`：跳过 Chain/表头，只吃 pkts/bytes 两列。"""

    def test_parses_real_sample(self):
        pkts, nbytes, rows = firewall._parse_drop_counters(IPT_OUT)
        self.assertEqual(pkts, 3310123)
        self.assertEqual(nbytes, 203423744)
        self.assertEqual(rows, 1)

    def test_parses_abbreviated_counters_like_real_iptables(self):
        """真机 `-v`（不加 -x）输出是 3311K/194M 这种缩写，必须能解析。

        这是上线即失效的那个坑：xtables 的 K/M/G 是**十进制**（1000/1e6/1e9），
        不是 1024；早先实现直接 int() 会抛 ValueError 被吞掉，卡片恒显示 0。
        """
        text = (
            "Chain FRPWAF_BLOCK (1 references)\n"
            " pkts bytes target     prot opt in     out     source               destination\n"
            "3311K  194M DROP       0    --  *      *       0.0.0.0/0            0.0.0.0/0            match-set frpwaf_block src\n"
        )
        pkts, nbytes, rows = firewall._parse_drop_counters(text)
        self.assertEqual(rows, 1)
        self.assertEqual(pkts, 3311 * 1000)
        self.assertEqual(nbytes, 194 * 1000 * 1000)

    def test_parse_counter_accepts_both_forms(self):
        """精确值与缩写值都要认；非法值返回 None，不抛异常。"""
        self.assertEqual(firewall._parse_counter("3310526"), 3310526)
        self.assertEqual(firewall._parse_counter("3311K"), 3311000)
        self.assertEqual(firewall._parse_counter("194M"), 194000000)
        self.assertEqual(firewall._parse_counter("2G"), 2000000000)
        for bad in ("", None, "abc", "-5", "3.5.1"):
            self.assertIsNone(firewall._parse_counter(bad), bad)

    def test_row_needs_both_columns_parsable(self):
        """两列必须同时可解析；否则会被拼成不同行的组合。"""
        text = (
            "Chain FRPWAF_BLOCK (1 references)\n"
            "3311K  194M DROP 0 -- * * 0.0.0.0/0 0.0.0.0/0 match-set frpwaf_block src\n"
            "0.0.0.0/0  ->  destination\n"
        )
        pkts, nbytes, rows = firewall._parse_drop_counters(text)
        self.assertEqual((pkts, nbytes, rows), (3311000, 194000000, 1))

    def test_padded_header_is_skipped(self):
        """真实输出表头是空格补齐的 `    pkts      bytes target ...`。"""
        self.assertEqual(firewall._parse_drop_counters(IPT_EMPTY), (0, 0, 0))

    def test_multiple_rows_are_summed(self):
        text = IPT_OUT.replace(
            "Chain FRPWAF_BLOCK (1 references)",
            "Chain FRPWAF_BLOCK (1 references)", 1
        ).rstrip("\n") + "\n 10 20 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n"
        pkts, nbytes, rows = firewall._parse_drop_counters(text)
        self.assertEqual((pkts, nbytes, rows), (3310133, 203423764, 2))

    def test_garbage_lines_do_not_raise(self):
        junk = ("Chain FRPWAF_BLOCK (2 references)\n"
                " pkts bytes target prot opt in out source destination\n"
                "Target     prot opt source               destination\n"
                "abc def DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n"
                " 7 8 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n")
        self.assertEqual(firewall._parse_drop_counters(junk), (7, 8, 1))

    def test_none_and_empty_text(self):
        self.assertEqual(firewall._parse_drop_counters(""), (0, 0, 0))
        self.assertEqual(firewall._parse_drop_counters(None), (0, 0, 0))


class ReadDropCountersTest(unittest.TestCase):
    """`_read_drop_counters`：取数成功/各fail路径都不得抛异常。"""

    def setUp(self):
        new_home(self)

    def _read(self, stub, available=True, have=("iptables", "ip6tables")):
        with mock.patch.object(firewall, "available", lambda: available), \
                mock.patch.object(firewall, "_have", lambda name: name in have), \
                mock.patch.object(firewall, "_run", stub):
            return firewall._read_drop_counters()

    def test_ipv4_and_ipv6_are_summed(self):
        stub = RunStub({"iptables": IPT_OUT, "ip6tables": IP6T_OUT})
        out = self._read(stub)
        self.assertTrue(out["available"])
        self.assertEqual(out["pkts"], 3310123 + 2048)
        self.assertEqual(out["bytes"], 203423744 + 8192)
        # 只读 -L，超时必须短（概览轮询不能被它拖住）；必须带 -x 取精确计数
        self.assertEqual(stub.n, 2)
        for call in stub.calls:
            self.assertEqual(call["args"][1:], ["-L", "FRPWAF_BLOCK", "-v", "-n", "-x"])
            self.assertNotIn("-Z", call["args"], "绝不能清零别人的计数")
            self.assertLessEqual(call["timeout"], 3)

    def test_no_ip6tables_binary_only_reads_v4(self):
        stub = RunStub({"iptables": IPT_OUT})
        out = self._read(stub, have=("iptables",))
        self.assertTrue(out["available"])
        self.assertEqual(out["pkts"], 3310123)
        self.assertEqual([c["args"][0] for c in stub.calls], ["iptables"])

    def test_command_line_includes_dash_x(self):
        """必须带 `-x`：否则 `-v` 下的计数是 3311K 这种缩写，解析会拿到 0。

        这条是防回归的——真机上不加 -x 会静默显示「内核层已丢弃 0」，
        而只测解析函数是发现不了的。
        """
        stub = RunStub({"iptables": IPT_OUT})
        self._read(stub, have=("iptables",))
        self.assertTrue(stub.calls, "应当调用过一次 iptables")
        argv = stub.calls[0]["args"]
        self.assertIn("-x", argv, "读计数必须加 -x 以取得精确值")
        self.assertIn("-L", argv)
        self.assertNotIn("-Z", argv, "绝不能清零别人的计数")
    def test_empty_chain_is_available_with_zero(self):
        """链在、一条规则都没有：这是真正的 0，不是「读不到」。"""
        out = self._read(RunStub({"iptables": IPT_EMPTY}), have=("iptables",))
        self.assertTrue(out["available"])
        self.assertEqual((out["pkts"], out["bytes"]), (0, 0))

    def test_chain_missing_is_not_available(self):
        """iptables 报「No chain/target/match」→ rc 非 0 → 降级，不抛。"""
        out = self._read(RunStub(rc_map={"iptables": 1, "ip6tables": 1}))
        self.assertFalse(out["available"])
        self.assertEqual((out["pkts"], out["bytes"]), (0, 0))

    def test_not_root_skips_subprocess_entirely(self):
        stub = RunStub({"iptables": IPT_OUT})
        out = self._read(stub, available=False)
        self.assertEqual(out, {"available": False, "pkts": 0, "bytes": 0})
        self.assertEqual(stub.n, 0, "非 root 时不应 fork 任何子进程")

    def test_iptables_missing_skips_subprocess(self):
        stub = RunStub({"iptables": IPT_OUT})
        out = self._read(stub, have=())
        self.assertFalse(out["available"])
        self.assertEqual(stub.n, 0)

    def test_command_timeout_degrades(self):
        """超时由 `_run` 内部转成 rc=1；这里直接打桩抛 TimeoutExpired 验证兜底。"""
        def boom(args, timeout=10, input_data=None):
            raise subprocess.TimeoutExpired(args, timeout)
        # _run 自己会吞异常，所以先验证真实 _run 的行为
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: True), \
                mock.patch.object(firewall.subprocess, "run", boom):
            out = firewall._read_drop_counters()
        self.assertFalse(out["available"])
        self.assertEqual((out["pkts"], out["bytes"]), (0, 0))

    def test_unexpected_exception_degrades(self):
        out = self._read(mock.Mock(side_effect=RuntimeError("boom")))
        self.assertEqual(out, {"available": False, "pkts": 0, "bytes": 0})


class DropStatsCacheTest(unittest.TestCase):
    """`drop_stats`：短时间连续调用只 fork 一次（概览页会轮询）。"""

    def setUp(self):
        new_home(self)

    def _stats(self, stub):
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: name == "iptables"), \
                mock.patch.object(firewall, "_run", stub):
            return firewall.drop_stats()

    def test_repeated_calls_fork_once(self):
        stub = RunStub({"iptables": IPT_OUT})
        first = self._stats(stub)
        self.assertEqual(first["pkts"], 3310123)
        self.assertEqual(stub.n, 1)
        for _ in range(3):
            again = self._stats(stub)
            self.assertEqual(again, first)
        self.assertEqual(stub.n, 1, "TTL 内重复调用不应再次 fork")

    def test_returned_dict_is_a_copy(self):
        """调用方改返回值不能污染缓存（否则概览字段会被就地篡改）。"""
        stub = RunStub({"iptables": IPT_OUT})
        first = self._stats(stub)
        first["pkts"] = -1
        self.assertEqual(self._stats(stub)["pkts"], 3310123)

    def test_ttl_expiry_refetches(self):
        stub = RunStub({"iptables": IPT_OUT})
        self._stats(stub)
        self.assertEqual(stub.n, 1)
        # 手动把缓存时间推回 TTL 之外，模拟「窗口过期」
        firewall._drop_stat["at"] -= firewall.DROP_STATS_TTL + 1
        self._stats(stub)
        self.assertEqual(stub.n, 2)

    def test_force_refetches(self):
        stub = RunStub({"iptables": IPT_OUT})
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: name == "iptables"), \
                mock.patch.object(firewall, "_run", stub):
            firewall.drop_stats()
            firewall.drop_stats(force=True)
        self.assertEqual(stub.n, 2)

    def test_failure_is_cached_too(self):
        """读不到时也要缓存，否则每次轮询都白 fork 一圈。"""
        stub = RunStub(rc_map={"iptables": 1})
        out = self._stats(stub)
        self.assertFalse(out["available"])
        self._stats(stub)
        self.assertEqual(stub.n, 1)


class DropFieldsTest(unittest.TestCase):
    """`drop_fields`：两个面板共用的字段名与类型。"""

    def setUp(self):
        new_home(self)

    def test_field_names_and_types(self):
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: name == "iptables"), \
                mock.patch.object(firewall, "_run", RunStub({"iptables": IPT_OUT})):
            out = firewall.drop_fields()
        self.assertEqual(set(out), {"kern_dropped", "kern_dropped_bytes",
                                    "kern_drop_available", "kern_drop_rate",
                                    "kern_drop_rate_window", "kern_drop_mode"})
        self.assertEqual(out["kern_dropped"], 3310123)
        self.assertEqual(out["kern_dropped_bytes"], 203423744)
        self.assertIs(out["kern_drop_available"], True)
        # 首个采样还没有可用的差分窗口：必须是 None（面板显示 —），不能是 0
        self.assertIsNone(out["kern_drop_rate"])
        self.assertEqual(out["kern_drop_rate_window"], 0.0)
        self.assertIn(out["kern_drop_mode"], ("drop", "redirect", "off", ""))

    def test_unavailable_maps_to_false_and_zero(self):
        with mock.patch.object(firewall, "available", lambda: False):
            out = firewall.drop_fields()
        self.assertEqual(out["kern_dropped"], 0)
        self.assertEqual(out["kern_dropped_bytes"], 0)
        self.assertIs(out["kern_drop_available"], False)
        self.assertIsNone(out["kern_drop_rate"], "读不到内核计数时速率必须是未知")
        self.assertEqual(out["kern_drop_rate_window"], 0.0)


class DropRateTest(unittest.TestCase):
    """近 1 分钟丢弃速率：差分、计数回退、redirect 静默为 0。

    计数回退是真实事故现场：`flush()` / 规则重建 / teardown 会 `iptables -F CHAIN`
    把链计数归零，直接相减会得到 `-3310614 包/秒` 这种值；本类就是钉住
    「宁可显示 —，绝不显示负数」。
    """

    def setUp(self):
        new_home(self)

    def _ringsample(self, at, pkts):
        return firewall._drop_rate_sample(at, pkts)

    def test_rate_is_positive_over_window(self):
        self.assertEqual(self._ringsample(1000.0, 1000), (None, 0.0))
        rate, window = self._ringsample(1030.0, 1300)
        self.assertAlmostEqual(rate, 10.0, places=3)
        self.assertAlmostEqual(window, 30.0, places=1)

    def test_counter_rollback_never_returns_negative(self):
        """计数变小（链被 flush 过）：丢弃旧样本、重新对齐基线，返回 None。"""
        self._ringsample(1000.0, 3310614)
        rate, window = self._ringsample(1008.0, 0)
        self.assertIsNone(rate, "计数回退时必须返回未知，不能算出负数")
        self.assertEqual(window, 0.0)
        self.assertEqual(firewall._drop_ring, [(1008.0, 0)], "应以本次采样为新基线")

    def test_aligned_again_after_rollback(self):
        """回退后重新对齐，后续采样又能算出正常速率。"""
        self._ringsample(1000.0, 5000)
        self._ringsample(1008.0, 0)              # 回退 -> 新基线 (1008, 0)
        rate, window = self._ringsample(1068.0, 120)
        self.assertAlmostEqual(rate, 2.0, places=3)
        self.assertAlmostEqual(window, 60.0, places=1)

    def test_ring_only_keeps_last_60s(self):
        self._ringsample(0.0, 100)
        self._ringsample(30.0, 130)
        self._ringsample(70.0, 170)
        self.assertEqual([s[0] for s in firewall._drop_ring], [30.0, 70.0],
                         "超过 60 秒的旧样本应被丢弃")

    def test_short_span_reports_unknown(self):
        """两个采样相隔太近（强刷）时不出速率，避免用噪声当结论。"""
        self._ringsample(1000.0, 100)
        rate, window = self._ringsample(1000.5, 101)
        self.assertIsNone(rate)
        self.assertEqual(window, 0.0)

    def test_static_zero_counters_give_zero_not_none(self):
        """redirect 模式（DROP 规则已摘）计数静默为 0：这是真的 0，不是未知。"""
        self._ringsample(1000.0, 0)
        rate, window = self._ringsample(1060.0, 0)
        self.assertEqual(rate, 0.0)
        self.assertAlmostEqual(window, 60.0, places=1)

    def test_drop_stats_exposes_rate_through_cache(self):
        """集成路径：drop_stats 把速率一并缓存，drop_fields 原样透出。"""
        now = time.time()
        firewall._drop_ring.append((now - 30.0, 1000))
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: name == "iptables"), \
                mock.patch.object(firewall, "_run",
                                  RunStub({"iptables": IPT_OUT.replace(
                                      "3310123", "1300")})):
            out = firewall.drop_fields(force=True)
        self.assertIsNotNone(out["kern_drop_rate"])
        self.assertGreaterEqual(out["kern_drop_rate"], 0.0)
        self.assertGreater(out["kern_drop_rate_window"], 0.0)
        # 缓存命中时不会重复采样（环长度不变）
        before = len(firewall._drop_ring)
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: name == "iptables"), \
                mock.patch.object(firewall, "_run",
                                  RunStub({"iptables": IPT_OUT})):
            firewall.drop_fields()
        self.assertEqual(len(firewall._drop_ring), before, "TTL 缓存内不应新增采样")

    def test_unavailable_clears_ring(self):
        """读不到计数时清空采样环，避免恢复后拿陈样本算差分。"""
        firewall._drop_ring.append((1000.0, 500))
        with mock.patch.object(firewall, "available", lambda: False):
            out = firewall.drop_fields(force=True)
        self.assertIsNone(out["kern_drop_rate"])
        self.assertEqual(firewall._drop_ring, [], "不可用时必须清空采样环")


class OverviewHandlerTest(unittest.TestCase):
    """`/api/overview` 组装层：新字段就位、旧字段语义不变、取数失败也回 200。"""

    def setUp(self):
        new_home(self)

    def _overview(self):
        """直接调 handler 方法（不经 socket），只捕获它交给 `_json` 的载荷。"""
        handler = object.__new__(daemon.Handler)
        handler._json = lambda obj, status=200: {"status": status, "body": obj}
        return handler._api_overview(config.get(), {}, "GET")

    def test_new_fields_present(self):
        with mock.patch.object(firewall, "available", lambda: True), \
                mock.patch.object(firewall, "_have", lambda name: name == "iptables"), \
                mock.patch.object(firewall, "_run", RunStub({"iptables": IPT_OUT})):
            res = self._overview()
        self.assertEqual(res["status"], 200)
        data = res["body"]["data"]
        self.assertEqual(data["kern_dropped"], 3310123)
        self.assertEqual(data["kern_dropped_bytes"], 203423744)
        self.assertIs(data["kern_drop_available"], True)

    def test_existing_fields_unchanged(self):
        """只增不改：原有统计字段一个都不能少、类型不变。"""
        with mock.patch.object(firewall, "available", lambda: False):
            data = self._overview()["body"]["data"]
        for key in ("total_conns", "today_conns", "today_rejected", "today_uniq_ip",
                    "black_count", "white_count", "active_bans"):
            self.assertIn(key, data, "缺少字段 " + key)
            self.assertIsInstance(data[key], int, key)
        self.assertEqual(data["black_count"], 0)
        self.assertEqual(data["active_bans"], 0)

    def test_degraded_when_reading_fails(self):
        """取数抛异常：概览照常 200，三个字段降级为不可用。"""
        with mock.patch.object(firewall, "drop_fields",
                               mock.Mock(side_effect=RuntimeError("iptables 炸了"))):
            res = self._overview()
        self.assertEqual(res["status"], 200)
        data = res["body"]["data"]
        self.assertIs(data["kern_drop_available"], False)
        self.assertEqual(data["kern_dropped"], 0)
        self.assertEqual(data["kern_dropped_bytes"], 0)
        # 其余字段仍在
        self.assertIn("today_rejected", data)


if __name__ == "__main__":
    unittest.main()
