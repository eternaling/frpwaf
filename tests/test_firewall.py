#!/usr/bin/env python3
# coding: utf-8
"""app/firewall.py 内核同步逻辑单元测试。

`firewall` 把「黑名单 + 生效封禁」同步进 ipset/iptables。真跑这些命令需要 root
与内核模块，所以这里把 `firewall._run` 全部打桩，只验证纯逻辑：

  - `_reconcile` 的差量计算：目标与内核现状一致时 0 次调用
  - 临时封禁到期时刻被延长时必须重建条目（`ipset add -exist` 不刷新 timeout，
    不重建会让内核提前放行）
  - `sync_from_store` 稳态（名单不变）的第二轮不应 fork 任何命令
  - 配置变化后必须重新对账（记忆化不能吃掉真变更）

不写真实数据目录，不调用真实 ipset / iptables。
"""
import time
import unittest
from unittest import mock

from . import new_home
from app import config, firewall, store


class RunRecorder:
    """记录 firewall._run 的调用；stdout_map 可按命令名脚本化返回。"""

    def __init__(self, stdout_map=None):
        self.calls = []
        self.stdout_map = stdout_map or {}

    def __call__(self, args, timeout=10, input_data=None):
        self.calls.append({"args": list(args), "input": input_data})
        if input_data is None and args and args[0] in self.stdout_map:
            return 0, self.stdout_map[args[0]], ""
        return 0, "", ""

    @property
    def n(self):
        return len(self.calls)

    def argvs(self):
        return [c["args"] for c in self.calls]

    def payload(self):
        """把所有 ipset restore 的 payload 拼成一个字符串（bytes 安全）。"""
        parts = []
        for c in self.calls:
            raw = c["input"]
            if raw is None:
                continue
            if isinstance(raw, bytes):
                parts.append(raw.decode("utf-8", "replace"))
            else:
                parts.append(str(raw))
        return "\n".join(parts)


class ReconcileTest(unittest.TestCase):
    """_reconcile(setname, want, cur=...) 的差量逻辑。"""

    def setUp(self):
        new_home(self)
        self.rec = RunRecorder()
        p = mock.patch.object(firewall, "_run", side_effect=self.rec)
        p.start()
        self.addCleanup(p.stop)

    def test_identical_state_makes_no_calls(self):
        now = int(time.time())
        firewall._reconcile("frpwaf_block", {"192.0.2.10": now + 600},
                            cur={"192.0.2.10": 600})
        self.assertEqual(self.rec.n, 0, self.rec.argvs())

    def test_new_member_is_pushed(self):
        now = int(time.time())
        firewall._reconcile("frpwaf_block",
                            {"192.0.2.10": now + 600, "198.51.100.7": 0}, cur={})
        body = self.rec.payload()
        self.assertIn("192.0.2.10", body)
        self.assertIn("198.51.100.7", body)
        self.assertIn("timeout", body)
        # 正常情况下应当是「一次事务」而不是逐条 fork
        self.assertEqual(self.rec.n, 1, self.rec.argvs())

    def test_extra_member_is_removed(self):
        firewall._reconcile("frpwaf_block", want={}, cur={"203.0.113.9": 300})
        body = self.rec.payload()
        self.assertIn("del", body)
        self.assertIn("203.0.113.9", body)

    def test_extended_deadline_rebuilds_member(self):
        """延长封禁必须 del + add，否则内核按旧 timeout 提前放行。"""
        now = int(time.time())
        firewall._reconcile("frpwaf_block", {"192.0.2.20": now + 900},
                            cur={"192.0.2.20": 60})
        body = self.rec.payload()
        self.assertIn("192.0.2.20", body)
        self.assertIn("del", body, "延长封禁却未重建条目")
        self.assertIn("add", body)

    def test_tiny_deadline_drift_is_ignored(self):
        """到期时刻只有极小偏差时不重建，避免每轮抖动。"""
        now = int(time.time())
        firewall._reconcile("frpwaf_block", {"192.0.2.30": now + 600},
                            cur={"192.0.2.30": 599})
        self.assertEqual(self.rec.n, 0, self.rec.argvs())


class SyncFromStoreTest(unittest.TestCase):
    """sync_from_store 的记忆化行为。"""

    def setUp(self):
        new_home(self)
        self.rec = RunRecorder()
        p = mock.patch.object(firewall, "_run", side_effect=self.rec)
        p.start()
        self.addCleanup(p.stop)
        self.have = mock.patch.object(firewall, "_have", return_value=True)
        self.have.start()
        self.addCleanup(self.have.stop)
        # available() 需要 root：Windows 无 os.geteuid，非 root 一律视为不支持。
        # 测试要验证同步逻辑而不是权限，故把整个 available() 打桩。
        self.avail = mock.patch.object(firewall, "available", return_value=True)
        self.avail.start()
        self.addCleanup(self.avail.stop)

        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({
            "fw_sync_enabled": True,
            "blacklist_enabled": True,
            "whitelist_enabled": False,
            "block_page_enabled": False,
        })
        self.cfgp = mock.patch.object(config, "get", side_effect=lambda: dict(self.cfg))
        self.cfgp.start()
        self.addCleanup(self.cfgp.stop)
        firewall.invalidate()

    def test_first_round_pushes_then_steady_state_is_quiet(self):
        store.add_ip("192.0.2.40", "black")
        firewall.invalidate()
        firewall.sync_from_store()
        first = self.rec.n
        self.assertGreater(first, 0, "第一轮竟然没有下发任何命令")

        self.rec.calls.clear()
        firewall.sync_from_store()
        self.assertEqual(self.rec.n, 0, self.rec.argvs())

    def test_invalidate_forces_reconcile_again(self):
        """invalidate() 后记忆失效，下一轮必须重新对账（不能被记忆吃掉）。"""
        store.add_ip("192.0.2.41", "black")
        firewall.invalidate()
        firewall.sync_from_store()
        self.rec.calls.clear()
        firewall.invalidate()
        firewall.sync_from_store()
        self.assertGreater(self.rec.n, 0, "invalidate 后没有重新对账")

    def test_blacklist_switch_off_stops_pushing(self):
        store.add_ip("192.0.2.50", "black")
        firewall.invalidate()
        self.cfg["blacklist_enabled"] = False
        firewall.invalidate()
        self.rec.calls.clear()
        firewall.sync_from_store()
        self.assertNotIn("192.0.2.50", self.rec.payload())


if __name__ == "__main__":
    unittest.main()
