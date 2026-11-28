#!/usr/bin/env python3
# coding: utf-8
"""系统端口检测的「面板层」测试：只读接口、配置写入语义、保护网段校验、两端文案。

为什么单独一个文件：`tests/test_sysdetect.py` 钉的是**检测算法**（解析/滑窗/
豁免），本文件钉的是**面板能用它**这条链路：

  1. `store.list_sys_event` 的分页偏移与 `store.summary_sys_event` 的汇总口径
     （面板顶部的「本应封禁 / 已封禁 / 被豁免」分布，是 owner 判断阈值的唯一依据）；
  2. `/api/sysdetect` 的查询参数（limit / offset / page / ip / action / hours）与
     返回结构（total / pages / summary …）；
  3. `/api/config` 的写入语义：**合并**而不是覆盖（改 sys_* 不能动其它键），
     保护网段的非法 CIDR 必须被整批拒绝，阈值 0 不能悄悄把检测关掉；
  4. 插件端 `save_policy` 走同一套校验（两个进程写同一份配置，口径必须一致）；
  5. 两端 HTML 都出现新卡片的关键文案（沿用 test_panel_overview_copy 的断言方式）——
     两端是两份独立单文件，没有共享模板，只改一端不会报错，只能靠文本断言钉住。
"""
import importlib.util
import os
import sys
import time
import types
import unittest
from unittest import mock

from . import new_home
from .test_api_routes import RouteTestCase
from app import config, store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PANEL = os.path.join(ROOT, "index.html")
WEB = os.path.join(ROOT, "web", "index.html")

# 真实的公网来源（不用 203.0.113.x / 2001:db8:: 这类文档地址：
# Python 3.12 把 TEST-NET 段判为 is_private=True，会被「只处理公网地址」挡掉）。
IP_A = "183.222.230.188"
IP_B = "111.29.52.71"
OWNER_IP = "112.48.13.214"


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------- 1) 存储层
class SysEventPagingTest(unittest.TestCase):
    """分页与汇总（面板展示层的两个基础能力）。"""

    def setUp(self):
        new_home(self)
        store.init()
        # 造 25 条：id 递增，ts 递增；action 覆盖三种处置结果（含两种豁免原因）
        for i in range(25):
            action = ("observed" if i % 3 == 0 else
                      "banned" if i % 3 == 1 else
                      ("skipped:whitelist" if i % 2 == 0 else "skipped:circuit"))
            store.add_sys_event(ts=1000 + i, ip=IP_A if i % 2 else IP_B,
                                source="sshd", port=22, hits=8, window_sec=600,
                                action=action, reason="r%d" % i)

    def test_offset_paging_has_no_overlap(self):
        p1 = store.list_sys_event(limit=10, offset=0)
        p2 = store.list_sys_event(limit=10, offset=10)
        p3 = store.list_sys_event(limit=10, offset=20)
        self.assertEqual([len(p1), len(p2), len(p3)], [10, 10, 5])
        ids = [r["id"] for r in p1 + p2 + p3]
        self.assertEqual(len(ids), len(set(ids)), "分页出现重复行")
        self.assertEqual(len(ids), 25)
        # 排序契约：id DESC（最新写在最前）
        self.assertGreater(ids[0], ids[1])

    def test_offset_beyond_end_returns_empty(self):
        self.assertEqual(store.list_sys_event(limit=10, offset=999), [])

    def test_filter_and_offset_compose(self):
        rows = store.list_sys_event(limit=5, ip=IP_A, offset=0)
        self.assertTrue(rows)
        self.assertTrue(all(r["ip"] == IP_A for r in rows))

    def test_summary_groups_skipped_reasons(self):
        out = store.summary_sys_event(0)
        self.assertEqual(out["total"], 25)
        self.assertEqual(out["observed"] + out["banned"] + out["skipped"], 25)
        self.assertIn("whitelist", out["skipped_reasons"])
        self.assertIn("circuit", out["skipped_reasons"])
        # 分组计数之和必须等于 skipped 总数（否则面板顶部数字自相矛盾）
        self.assertEqual(sum(out["skipped_reasons"].values()), out["skipped"])

    def test_summary_since_filters_by_ts(self):
        # 全部事件 ts 在 1000..1024；取 since=1020 只应命中最后 5 条
        out = store.summary_sys_event(1020)
        self.assertEqual(out["total"], 5)
        self.assertEqual(out["since"], 1020)

    def test_summary_empty_table(self):
        store.purge_sys_event()
        out = store.summary_sys_event(0)
        self.assertEqual(out["total"], 0)
        self.assertEqual(out["skipped_reasons"], {})


# ---------------------------------------------------------------- 2) Web 端接口
class SysdetectApiTest(RouteTestCase):
    """`/api/sysdetect` 的分页/筛选参数与返回结构（走真实 HTTP）。"""

    def _seed(self, n=12):
        # 时间戳用「现在」：汇总默认看最近 24 小时，用 1970 的假 ts 会被
        # 时间窗过滤掉（列表不看时间窗，汇总看）。仅为了断言分页可预测，
        # 递增 1 秒保证 id 与 ts 同序。
        now = int(time.time())
        for i in range(n):
            store.add_sys_event(ts=now - n + i, ip=(IP_A if i % 2 else IP_B),
                                source="sshd", port=22, hits=8, window_sec=600,
                                action=("observed" if i % 2 else "banned"),
                                reason="r")

    def test_get_returns_paging_contract(self):
        self._seed()
        st, j = self.web.json("GET", "/api/sysdetect?limit=5&page=2", cookie=self.ck)
        self.assertEqual(st, 200)
        self.assertEqual(j["code"], 0)
        for key in ("events", "total", "limit", "offset", "page", "pages",
                    "summary", "data"):
            self.assertIn(key, j, "缺少字段 " + key)
        self.assertEqual(j["total"], 12)
        self.assertEqual(j["limit"], 5)
        self.assertEqual(j["offset"], 5)
        self.assertEqual(j["page"], 2)
        self.assertEqual(j["pages"], 3)
        self.assertEqual(len(j["events"]), 5)

    def test_offset_param_takes_precedence_over_page(self):
        self._seed()
        _, j = self.web.json("GET", "/api/sysdetect?limit=5&offset=10&page=1",
                             cookie=self.ck)
        self.assertEqual(j["offset"], 10)
        self.assertEqual(j["page"], 3)
        self.assertEqual(len(j["events"]), 2)

    def test_get_filters_by_ip_and_action(self):
        self._seed()
        _, j = self.web.json("GET", "/api/sysdetect?ip=" + IP_A, cookie=self.ck)
        self.assertTrue(j["events"])
        self.assertTrue(all(e["ip"] == IP_A for e in j["events"]))
        self.assertEqual(j["total"], 6)
        _, j2 = self.web.json("GET", "/api/sysdetect?action=banned", cookie=self.ck)
        self.assertTrue(all(e["action"] == "banned" for e in j2["events"]))
        self.assertEqual(j2["total"], 6)

    def test_summary_ignores_list_filters(self):
        """汇总口径与列表筛选解耦（否则「阈值是否合适」的判断失去依据）。"""
        self._seed()
        _, j = self.web.json("GET", "/api/sysdetect?ip=" + IP_A, cookie=self.ck)
        self.assertEqual(j["summary"]["total"], 12)
        self.assertEqual(j["summary"]["observed"] + j["summary"]["banned"], 12)
        self.assertEqual(j["summary"]["hours"], 24)

    def test_bad_params_fall_back_to_defaults(self):
        self._seed()
        st, j = self.web.json("GET", "/api/sysdetect?limit=abc&page=-3&hours=0",
                              cookie=self.ck)
        self.assertEqual(st, 200)
        self.assertEqual(j["code"], 0)
        self.assertEqual(j["limit"], 50)
        self.assertEqual(j["offset"], 0)
        self.assertEqual(j["summary"]["hours"], 24)

    def test_summary_only_counts_recent_window(self):
        """超出 hours 窗口的旧事件不进入汇总（列表仍然看得到）。"""
        now = int(time.time())
        store.add_sys_event(ts=now - 90000, ip=IP_A, source="sshd", action="observed")
        _, j = self.web.json("GET", "/api/sysdetect?hours=1", cookie=self.ck)
        self.assertEqual(j["summary"]["total"], 0)
        self.assertEqual(j["total"], 1)   # 列表不看时间窗


class SysdetectConfigWriteTest(RouteTestCase):
    """`/api/config` 写 sys_* 的语义：合并、校验、审计。"""

    def _cfg(self):
        st, j = self.web.json("GET", "/api/config", cookie=self.ck)
        self.assertEqual(st, 200)
        return j["data"]

    def test_write_merges_and_keeps_other_keys(self):
        before = self._cfg()
        body = {"sys_detect_enabled": True, "sys_detect_dry_run": True,
                "sys_ssh_threshold": 5, "sys_ssh_window": 300,
                "sys_ssh_ban_seconds": 900, "sys_ban_max_per_hour": 12,
                "sys_ssh_poll_interval": 3,
                "sys_protect_ips": OWNER_IP,
                "sys_trust_ssh_login": True}
        st, j = self.web.json("POST", "/api/config", body=body, cookie=self.ck)
        self.assertEqual(st, 200)
        self.assertEqual(j["code"], 0, j.get("msg"))
        after = self._cfg()
        # 本次改的键生效
        self.assertEqual(after["sys_ssh_threshold"], 5)
        self.assertEqual(after["sys_ssh_window"], 300)
        self.assertEqual(after["sys_ssh_ban_seconds"], 900)
        self.assertEqual(after["sys_ban_max_per_hour"], 12)
        self.assertEqual(after["sys_ssh_poll_interval"], 3)
        self.assertIs(after["sys_detect_enabled"], True)
        # 单个 IP 被规范成 /32（内核判定用的同一串）
        self.assertEqual(after["sys_protect_ips"], OWNER_IP + "/32")
        # 其它键一个都没被覆盖：逐个比对（排除本次提交的 sys_* 与掩码字段）
        changed = [k for k in before
                   if k not in body and k != "sys_protect_ips"
                   and before[k] != after.get(k)]
        self.assertEqual(changed, [], "非 sys_* 配置键被改动：%s" % changed)

    def test_invalid_cidr_is_rejected_and_nothing_written(self):
        before = self._cfg()
        st, j = self.web.json("POST", "/api/config",
                              body={"sys_protect_ips": "112.48.13.214, 1.2.3.4/99, abc"},
                              cookie=self.ck)
        self.assertEqual(st, 200)
        self.assertEqual(j["code"], 1)
        self.assertIn("非法 CIDR", j["msg"])
        self.assertIn("1.2.3.4/99", j["msg"])
        self.assertEqual(self._cfg()["sys_protect_ips"],
                         before["sys_protect_ips"], "非法输入竟然写进了配置")

    def test_empty_cidr_list_is_allowed(self):
        self.web.json("POST", "/api/config", body={"sys_protect_ips": OWNER_IP},
                      cookie=self.ck)
        st, j = self.web.json("POST", "/api/config", body={"sys_protect_ips": "  "},
                              cookie=self.ck)
        self.assertEqual(j["code"], 0)
        self.assertEqual(self._cfg()["sys_protect_ips"], "")

    def test_cidr_list_is_normalized_and_deduped(self):
        st, j = self.web.json(
            "POST", "/api/config",
            body={"sys_protect_ips": "10.0.0.0/8\n112.48.13.214\n10.0.0.0/8; 192.168.1.0/24"},
            cookie=self.ck)
        self.assertEqual(j["code"], 0, j.get("msg"))
        got = self._cfg()["sys_protect_ips"]
        self.assertEqual(got, "10.0.0.0/8, 112.48.13.214/32, 192.168.1.0/24")

    def test_threshold_zero_is_preserved_as_count_only(self):
        """阈值 0 是已文档化的「只计数不处置」，**不得**被静默抬高成默认值。

        否则用户「把触发关掉」的明确意图会被反向执行（又开始按 8 次触发封禁），
        正好凑出他本来在避免的误封。窗口 0 无此语义，仍回退默认值。
        """
        st, j = self.web.json("POST", "/api/config",
                             body={"sys_ssh_threshold": 0, "sys_ssh_window": 0},
                             cookie=self.ck)
        self.assertEqual(j["code"], 0, j.get("msg"))
        after = self._cfg()
        self.assertEqual(after["sys_ssh_threshold"], 0)
        self.assertEqual(after["sys_ssh_window"], config.DEFAULTS["sys_ssh_window"])

    def test_non_numeric_threshold_falls_back_to_default(self):
        st, j = self.web.json("POST", "/api/config",
                             body={"sys_ssh_threshold": "abc"}, cookie=self.ck)
        self.assertEqual(j["code"], 1)   # 类型不对：直接拒（不能静默丢弃）

    def test_wrong_type_is_rejected(self):
        st, j = self.web.json("POST", "/api/config",
                              body={"sys_ssh_threshold": {"a": 1}}, cookie=self.ck)
        self.assertEqual(st, 200)
        self.assertEqual(j["code"], 1)

    def test_turning_dry_run_off_is_audited(self):
        """关闭观察模式 = 从只观察变成真封禁：必须留审计（且只记跳变）。"""
        self.web.json("POST", "/api/config",
                      body={"sys_detect_enabled": True, "sys_detect_dry_run": True},
                      cookie=self.ck)
        log = config.LOG_PATH
        base = os.path.getsize(log) if os.path.exists(log) else 0
        self.web.json("POST", "/api/config", body={"sys_detect_dry_run": False},
                      cookie=self.ck)
        with open(log, encoding="utf-8") as f:
            f.seek(base)
            text = f.read()
        self.assertIn("[审计]", text)
        self.assertIn("关闭观察模式", text)
        # 再存一次（已经不是跳变）不应重复写
        base2 = os.path.getsize(log)
        self.web.json("POST", "/api/config", body={"sys_detect_dry_run": False},
                      cookie=self.ck)
        with open(log, encoding="utf-8") as f:
            f.seek(base2)
            text2 = f.read()
        self.assertNotIn("关闭观察模式", text2)

    def test_clearing_protect_ips_is_audited(self):
        self.web.json("POST", "/api/config", body={"sys_protect_ips": OWNER_IP},
                      cookie=self.ck)
        log = config.LOG_PATH
        base = os.path.getsize(log) if os.path.exists(log) else 0
        self.web.json("POST", "/api/config", body={"sys_protect_ips": ""}, cookie=self.ck)
        with open(log, encoding="utf-8") as f:
            f.seek(base)
            text = f.read()
        self.assertIn("[审计]", text)
        self.assertIn("清空保护网段", text)


# ---------------------------------------------------------------- 3) 插件端
_MAIN_PATH = os.path.join(ROOT, "frpwaf_main.py")
_main = None
_saved_path = None


def _fake_public():
    pub = types.ModuleType("public")
    pub.returnMsg = lambda status, msg: {"status": status, "msg": msg}
    return pub


def setUpModule():
    """加载 frpwaf_main（它依赖宝塔环境：模块级 os.chdir + import public）。

    与 test_main_fail 同一套装载方式：chdir 换成空操作、注入假 public。
    """
    global _main, _saved_path
    _saved_path = list(sys.path)
    had = "public" in sys.modules
    old = sys.modules.get("public")
    sys.modules["public"] = _fake_public()
    try:
        spec = importlib.util.spec_from_file_location("frpwaf_main_panel_under_test",
                                                      _MAIN_PATH)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.object(os, "chdir", lambda p: None):
            spec.loader.exec_module(mod)
        _main = mod
    finally:
        if had:
            sys.modules["public"] = old
        else:
            sys.modules.pop("public", None)


def tearDownModule():
    if _saved_path is not None:
        sys.path[:] = _saved_path


class PluginPolicyTest(unittest.TestCase):
    """插件端 `get_policy` / `save_policy` 对 sys_* 的口径（与 /api/config 一致）。"""

    def setUp(self):
        from app import (ai, blockpage as bp, engine, firewall, frp, geo, job,
                         sysdetect, textutil, upgrade)
        self.home = new_home(self)
        store.init()
        self.mods = {"config": config, "engine": engine, "firewall": firewall,
                     "store": store, "sysdetect": sysdetect, "geo": geo,
                     "blockpage": bp, "ai": ai, "job": job, "frp": frp,
                     "textutil": textutil, "upgrade": upgrade}
        for target, attr, value in (
                (_main, "WAF_HOME", self.home),
                (_main, "_app", lambda name: self.mods[name]),
                (bp, "ensure", lambda: True),
                (_main.frpwaf_main, "_fw_sync", lambda self: None)):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.obj = _main.frpwaf_main()

    class _Get(object):
        """最小 get 替身：按键存在性模拟插件端请求参数。"""

        def __init__(self, **kw):
            self.__dict__.update(kw)

    def _get_policy(self):
        return self.obj.get_policy()["data"]

    def test_defaults_are_echoed_with_safe_values(self):
        d = self._get_policy()
        self.assertIs(d["sys_detect_enabled"], False)   # 默认关闭
        self.assertIs(d["sys_detect_dry_run"], True)    # 默认只观察
        self.assertIs(d["sys_trust_ssh_login"], True)
        self.assertEqual(d["sys_ssh_threshold"], config.DEFAULTS["sys_ssh_threshold"])
        self.assertEqual(d["sys_ssh_window"], config.DEFAULTS["sys_ssh_window"])
        self.assertEqual(d["sys_protect_ips"], "")

    def test_save_policy_merges_and_keeps_other_keys(self):
        before = config.get()
        r = self.obj.save_policy(self._Get(sys_ssh_threshold=6, sys_ssh_window=120,
                                           sys_detect_enabled=1, sys_detect_dry_run=1,
                                           sys_protect_ips=OWNER_IP))
        self.assertTrue(r["status"], r)
        after = config.get()
        self.assertEqual(after["sys_ssh_threshold"], 6)
        self.assertEqual(after["sys_ssh_window"], 120)
        self.assertIs(after["sys_detect_enabled"], True)
        self.assertEqual(after["sys_protect_ips"], OWNER_IP + "/32")
        # 未被本次提交的键不能被动到
        for k in ("admin_user", "http_port", "frp_handler_port", "ai_model",
                  "auto_ban_threshold", "github_repo"):
            self.assertEqual(before.get(k), after.get(k), "非 sys_* 键被改动：" + k)

    def test_save_policy_rejects_invalid_cidr(self):
        before = config.get()
        r = self.obj.save_policy(self._Get(sys_protect_ips="not-a-cidr, 1.2.3.4/99"))
        self.assertFalse(r["status"])
        self.assertIn("非法 CIDR", r["msg"])
        self.assertEqual(config.get().get("sys_protect_ips"),
                         before.get("sys_protect_ips"), "非法输入竟然写进了配置")

    def test_save_policy_preserves_threshold_zero(self):
        r = self.obj.save_policy(self._Get(sys_ssh_threshold=0, sys_ssh_window=0))
        self.assertTrue(r["status"], r)
        after = config.get()
        # 0 = 只计数不处置：显式意图必须保留
        self.assertEqual(after["sys_ssh_threshold"], 0)
        # 窗口 0 无此语义，回退默认值（避免「显示 0 秒、实际 600 秒」）
        self.assertEqual(after["sys_ssh_window"], config.DEFAULTS["sys_ssh_window"])

    def test_turning_dry_run_off_is_audited(self):
        config.save({"sys_detect_enabled": True, "sys_detect_dry_run": True})
        log = os.path.join(self.home, "data", "frpwaf.log")
        self.obj.save_policy(self._Get(sys_detect_dry_run=0))
        with open(log, encoding="utf-8") as f:
            self.assertIn("关闭观察模式", f.read())


class PluginSysdetectReadTest(unittest.TestCase):
    """插件端 `sysdetect` / `sysdetect_clear` 只读接口。"""

    def setUp(self):
        from app import (ai, blockpage as bp, engine, firewall, frp, geo, job,
                         sysdetect, textutil, upgrade)
        self.home = new_home(self)
        store.init()
        self.mods = {"config": config, "engine": engine, "firewall": firewall,
                     "store": store, "sysdetect": sysdetect, "geo": geo,
                     "blockpage": bp, "ai": ai, "job": job, "frp": frp,
                     "textutil": textutil, "upgrade": upgrade}
        for target, attr, value in (
                (_main, "WAF_HOME", self.home),
                (_main, "_app", lambda name: self.mods[name]),
                (bp, "ensure", lambda: True)):
            p = mock.patch.object(target, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.obj = _main.frpwaf_main()

    class _Get(object):
        def __init__(self, **kw):
            self.__dict__.update(kw)

    def _seed(self, n=9):
        now = int(time.time())
        for i in range(n):
            store.add_sys_event(ts=now - n + i, ip=(IP_A if i % 2 else IP_B),
                                source="sshd", port=22, hits=8, window_sec=600,
                                action=("observed" if i % 3 == 0 else
                                        "banned" if i % 3 == 1 else
                                        "skipped:protect-cidr"),
                                reason="r")

    def test_paging_and_summary(self):
        self._seed()
        r = self.obj.sysdetect(self._Get(limit=4, page=2))
        self.assertTrue(r["status"])
        d = r["data"]
        self.assertEqual(d["total"], 9)
        self.assertEqual(d["limit"], 4)
        self.assertEqual(d["offset"], 4)
        self.assertEqual(d["page"], 2)
        self.assertEqual(d["pages"], 3)
        self.assertEqual(len(d["events"]), 4)
        self.assertEqual(d["summary"]["total"], 9)
        self.assertEqual(d["summary"]["skipped_reasons"].get("protect-cidr"), 3)
        self.assertIn("sys_ssh_threshold", d["status"]["config"])

    def test_offset_wins_over_page(self):
        self._seed()
        d = self.obj.sysdetect(self._Get(limit=4, offset=8, page=1))["data"]
        self.assertEqual(d["offset"], 8)
        self.assertEqual(len(d["events"]), 1)

    def test_filter_by_ip_and_action(self):
        self._seed()
        d = self.obj.sysdetect(self._Get(ip=IP_A))["data"]
        self.assertTrue(all(e["ip"] == IP_A for e in d["events"]))
        d2 = self.obj.sysdetect(self._Get(action="skipped"))["data"]
        self.assertTrue(all(str(e["action"]).startswith("skipped")
                            for e in d2["events"]))

    def test_bad_params_fall_back(self):
        self._seed()
        d = self.obj.sysdetect(self._Get(limit="x", offset="-1", hours="x"))["data"]
        self.assertEqual(d["limit"], 50)
        self.assertEqual(d["offset"], 0)
        self.assertEqual(d["summary"]["hours"], 24)

    def test_clear_only_removes_events(self):
        self._seed()
        r = self.obj.sysdetect_clear()
        self.assertTrue(r["status"])
        self.assertEqual(store.count_sys_event(), 0)
        # 不解封：开关与保护名单必须原样还在
        self.assertEqual(config.get().get("sys_protect_ips"),
                         config.get().get("sys_protect_ips"))


# ---------------------------------------------------------------- 4) 两端文案
class PanelSysdetectCopyTest(unittest.TestCase):
    """两端都必须出现同一批关键文案与字段名（两份单文件，没有共享模板）。"""

    # 卡片必须有的表单字段（缺一个就说明某一端没改完）
    FIELDS = ("s_sys_detect_enabled", "s_sys_detect_dry_run", "s_sys_ssh_threshold",
              "s_sys_ssh_window", "s_sys_ssh_ban_seconds", "s_sys_ban_max_per_hour",
              "s_sys_ssh_poll_interval", "s_sys_protect_ips",
              "s_sys_trust_ssh_login")

    @classmethod
    def setUpClass(cls):
        cls.panel = _read(PANEL)
        cls.web = _read(WEB)

    def test_fields_present_in_both(self):
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            for f in self.FIELDS:
                self.assertIn('id="%s"' % f, text, "%s 缺少字段 %s" % (name, f))

    def test_risk_copy_present_in_both(self):
        """关闭观察模式的风险提示：必须讲清「真会封」+「DROP 是全端口的」。"""
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("关闭观察模式 = 真的会封 IP", text, name)
            self.assertIn("DROP 是全端口的", text, name)
            self.assertIn("22 / 7080 / 8888 会一起进不去", text, name)
            self.assertIn("VNC 救机器", text, name)

    def test_records_copy_present_in_both(self):
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            self.assertIn("观察记录", text, name)
            self.assertIn("本应封禁", text, name)
            self.assertIn("被豁免", text, name)
            self.assertIn("观察期尚未触发", text, name)

    def test_summary_and_pager_ids_present_in_both(self):
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            for ident in ("fwSysSummary", "fwSysEventBody", "fwSysPager",
                          "fwSysIp", "fwSysAction", "fwSysLimit"):
                self.assertIn(ident, text, "%s 缺少 %s" % (name, ident))

    def test_no_framework_or_cdn_introduced(self):
        """红线：两端都是原生单文件，不得引入框架或 CDN 资源。"""
        for name, text in (("index.html", self.panel), ("web/index.html", self.web)):
            for bad in ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                        "vue.min.js", "react.production.min.js"):
                self.assertNotIn(bad, text, "%s 引入了外部资源 %s" % (name, bad))

    def test_panel_policy_str_list_declared(self):
        """`FW_POLICY_STR` 曾被误删 → fwSavePolicy 抛 ReferenceError 且静默不保存。

        这里钉住「声明存在且包含新增的 sys_* 字符串字段」。
        """
        self.assertIn("var FW_POLICY_STR=[" , self.panel)
        seg = self.panel[self.panel.index("var FW_POLICY_STR=["):]
        seg = seg[:seg.index("];")]
        for key in ("sys_ssh_log", "sys_protect_ips"):
            self.assertIn("'%s'" % key, seg, "FW_POLICY_STR 缺少 " + key)

    def test_main_save_skips_sys_fields_in_both(self):
        """主「保存策略」按钮不得一并提交 sys_*（否则绕过高危操作的二次确认）。

        两端的「系统端口检测」卡片自带保存按钮，那里才有「关闭观察模式 /
        清空保护名单」的确认；主按钮若也能写同一批字段，就有两条路径、
        其中一条无确认。用「保存函数体内存在 sys_ 前缀过滤」把这个约束钉住。
        """
        panel_seg = self.panel[self.panel.index("function fwSavePolicy()"):]
        panel_seg = panel_seg[1:panel_seg.index("function ", 1)]
        self.assertIn("indexOf('sys_')===0", panel_seg)
        self.assertIn("delete b[k]", panel_seg)

        web_seg = self.web[self.web.index("async function saveSettings()"):]
        web_seg = web_seg[1:web_seg.index("async function ", 1)]
        self.assertIn("indexOf('sys_')===0", web_seg)
        self.assertIn("delete b[k]", web_seg)


if __name__ == "__main__":
    unittest.main()
