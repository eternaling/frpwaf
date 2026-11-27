#!/usr/bin/env python3
# coding: utf-8
"""插件端「ESA 回源段」列表接口（`frpwaf_main.cdn_trust_list`）的返回结构。

只钉住一件事：学习条目里记录的**来源审查编号**（`trusted_cidr.ai_review_id`）
必须原样出现在面板返回的 items 里。面板靠它把「学过这个网段」回查到具体那次
AI 审查；接口漏字段 = 排障线索静默消失，前端列恒为空也不会报错。

加载方式与 `tests/test_main_fail.py` 相同：`frpwaf_main.py` 依赖宝塔环境
（模块级 `os.chdir("/www/server/panel")`、`import public`），这里把 chdir 换成
空操作、注入假的 public 模块，避免碰生产路径。

`_store()` 换成测试自己的 `app.store`：插件正常走私有包名加载运行代码，
这里只验返回结构，不需要把两份模块实例都指向同一个临时库。
"""

import importlib.util
import os
import sys
import types
import unittest
from unittest import mock

from tests import new_home
from app import config, store

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_PATH = os.path.join(ROOT, "frpwaf_main.py")

main = None


def _fake_public():
    pub = types.ModuleType("public")
    pub.returnMsg = lambda status, msg: {"status": status, "msg": msg}
    return pub


def setUpModule():
    global main
    had_public = "public" in sys.modules
    old_public = sys.modules.get("public")
    sys.modules["public"] = _fake_public()
    try:
        spec = importlib.util.spec_from_file_location("frpwaf_main_panel_under_test",
                                                      MAIN_PATH)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.object(os, "chdir", lambda p: None):
            spec.loader.exec_module(mod)
        main = mod
    finally:
        if had_public:
            sys.modules["public"] = old_public
        else:
            sys.modules.pop("public", None)


class CdnTrustListPayloadTest(unittest.TestCase):
    """cdn_trust_list 必须回传 ai_review_id（0 = 无关联）。"""

    def setUp(self):
        new_home(self)
        self.obj = main.frpwaf_main()
        for attr, value in (("_store", lambda: store),
                            ("_cfg_effective", lambda: dict(config.DEFAULTS))):
            p = mock.patch.object(self.obj, attr, value)
            p.start()
            self.addCleanup(p.stop)

    def _item(self):
        r = self.obj.cdn_trust_list({})
        self.assertTrue(r.get("status"), r)
        items = r["data"]["items"]
        self.assertEqual(len(items), 1, items)
        return items[0]

    def test_ai_review_id_exposed(self):
        """新学条目：返回结构里带上来源审查编号。"""
        store.add_trusted_cidr("61.241.14.33", "CDN 回源（keyword:x）", source="keyword",
                               ai_review_id=42)
        item = self._item()
        self.assertEqual(item["cidr"], "61.241.14.33/32")
        self.assertEqual(item["ai_review_id"], 42)

    def test_missing_review_id_is_zero(self):
        """无关联条目（人工/升级/存量）：给 0 而不是缺字段或 null。"""
        store.add_trusted_cidr("5.6.7.0/24", "运维声明", source="manual")
        item = self._item()
        self.assertEqual(item["ai_review_id"], 0)

    def test_existing_fields_kept(self):
        """加字段不破原有结构：面板已在用的键一个不少。"""
        store.add_trusted_cidr("203.0.113.9", "x", source="keyword", ai_review_id=7)
        item = self._item()
        self.assertTrue({"cidr", "hits", "reason", "first_reason", "source",
                         "expires_at", "remaining_s", "created_at", "last_seen",
                         "ai_review_id"} <= set(item), sorted(item))
        self.assertEqual(item["source"], "keyword")
        self.assertEqual(item["reason"], "x")


if __name__ == "__main__":
    unittest.main()
