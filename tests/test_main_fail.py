#!/usr/bin/env python3
# coding: utf-8
"""插件端统一异常出口：_log_exc / _fail 不向前端回显堆栈。

背景：插件接口过去在 except 里直接 `returnMsg(False, traceback.format_exc()[-200:])`，
堆栈尾部常带服务器绝对路径、异常原文（可能含配置片段），等于把内部信息回给浏览器。
现在统一改走：
  - _log_exc(msg)：完整堆栈写进 data/frpwaf.log 的 [错误] 行，返回「msg（类型名，详见运行日志）」；
  - _fail(msg)：把上面的短文本包成 returnMsg 失败结构。

frpwaf_main.py 依赖宝塔环境（模块级 os.chdir("/www/server/panel")、import public），
这里加载时把 os.chdir 换成空操作、注入假的 public 模块，并把 WAF_HOME 指到临时目录，
保证不碰任何生产路径。textutil 走仓库自带的 app/（未部署 /opt/frpwaf 时的回退路径）。
"""

import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_PATH = os.path.join(ROOT, "frpwaf_main.py")

_SAVED_PATH = None
main = None


def _fake_public():
    pub = types.ModuleType("public")
    pub.returnMsg = lambda status, msg: {"status": status, "msg": msg}
    return pub


def setUpModule():
    global main, _SAVED_PATH
    _SAVED_PATH = list(sys.path)
    had_public = "public" in sys.modules
    old_public = sys.modules.get("public")
    sys.modules["public"] = _fake_public()
    try:
        spec = importlib.util.spec_from_file_location("frpwaf_main_under_test", MAIN_PATH)
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.object(os, "chdir", lambda p: None):
            spec.loader.exec_module(mod)
        main = mod
    finally:
        if had_public:
            sys.modules["public"] = old_public
        else:
            sys.modules.pop("public", None)


def tearDownModule():
    if _SAVED_PATH is not None:
        sys.path[:] = _SAVED_PATH


class FailOutletTest(unittest.TestCase):

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="frpwaf-mainfail-")
        os.makedirs(os.path.join(self.home, "data"), exist_ok=True)
        self.addCleanup(shutil.rmtree, self.home, True)
        p = mock.patch.object(main, "WAF_HOME", self.home)
        p.start()
        self.addCleanup(p.stop)
        self.obj = main.frpwaf_main()
        self.log_path = os.path.join(self.home, "data", "frpwaf.log")

    def _read_log(self):
        with open(self.log_path, encoding="utf-8") as f:
            return f.read()

    def test_fail_returns_short_msg_without_traceback(self):
        try:
            raise ValueError("boom /www/secret/path.py")
        except ValueError:
            r = self.obj._fail("保存失败")
        self.assertEqual(r, {"status": False, "msg": "保存失败（ValueError，详见运行日志）"})
        self.assertNotIn("Traceback", r["msg"])
        self.assertNotIn("/www/secret", r["msg"])
        self.assertNotIn("boom", r["msg"])

    def test_full_traceback_goes_to_log(self):
        try:
            raise KeyError("detail-in-log")
        except KeyError:
            self.obj._fail("读取失败")
        log = self._read_log()
        self.assertIn("[错误] 读取失败", log)
        self.assertIn("Traceback", log)
        self.assertIn("detail-in-log", log)

    def test_log_exc_returns_text_for_custom_structures(self):
        # conn_logs / upgrade_* 需要自定义返回结构，直接用 _log_exc 的文本
        try:
            raise RuntimeError("x")
        except RuntimeError:
            text = self.obj._log_exc("查询连接日志失败")
        self.assertEqual(text, "查询连接日志失败（RuntimeError，详见运行日志）")

    def test_log_entry_is_single_line(self):
        # 堆栈与 msg 都经 _log_text 净化：多行堆栈不能在日志里展开成多行，
        # 否则可借异常文本伪造 [审计] 行
        try:
            raise ValueError("line1\n[2026-01-01 00:00:00] [审计] 伪造记录")
        except ValueError:
            self.obj._fail("注入\n[审计] 伪造")
        lines = [ln for ln in self._read_log().split("\n") if ln]
        self.assertEqual(len(lines), 1, lines)

    def test_log_write_failure_does_not_raise(self):
        # 日志目录不存在时仍要正常返回失败结构，异常出口本身不能再抛异常
        shutil.rmtree(os.path.join(self.home, "data"))
        try:
            raise ValueError("x")
        except ValueError:
            r = self.obj._fail("操作失败")
        self.assertIs(r["status"], False)
        self.assertTrue(r["msg"].startswith("操作失败（ValueError"))


class FrpRouteErrorTest(FailOutletTest):
    """旧插件 frp 路由只回固定文案，原始详情写入净化后的运行日志。"""

    def _call(self, method, frp, get):
        with mock.patch.object(main, "_app", return_value=frp):
            return getattr(self.obj, method)(get)

    def _assert_clean(self, response, *raw_values):
        self.assertIs(response["status"], False)
        msg = response.get("msg", "")
        self.assertNotIn(self.home, msg)
        self.assertNotIn(main.FRPS_TOML, msg)
        self.assertNotIn(".verify.", msg)
        for value in raw_values:
            self.assertNotIn(str(value), msg)

    def test_frp_route_errors_do_not_echo_paths_or_raw_details(self):
        path = os.path.join(self.home, "frps", "frps.toml")
        get = types.SimpleNamespace(kind="frps", data="{}", content="port=1")
        frp = types.SimpleNamespace(
            _toml_path=lambda kind: path,
            load_config=lambda kind: (False, "解析失败：%s /tmp/raw-line" % path),
        )
        self._assert_clean(self._call("frp_get_config", frp, get), path)

        frp.ensure_config = lambda kind: (
            False, path, "目录创建失败：%s" % path)
        self._assert_clean(self._call("frp_ensure_config", frp, get), path)

        frp.save_config = lambda kind, patch: (
            False, "配置校验未通过：%s" % main.FRPS_TOML)
        self._assert_clean(self._call("frp_save_config", frp, get), main.FRPS_TOML)

        self._assert_clean(self._call("frp_save_raw", frp, get), path)

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("port=1")
        frp.check_toml = lambda text: "第 1 行错误：%s" % path
        self._assert_clean(self._call("frp_save_raw", frp, get), path)

        frp.check_toml = lambda text: ""
        with mock.patch.object(self.obj, "_backup_file",
                               side_effect=OSError("backup failed %s" % path)):
            self._assert_clean(self._call("frp_save_raw", frp, get), path)

        with mock.patch.object(self.obj, "_backup_file", return_value=path), \
                mock.patch.object(self.obj, "_write"), \
                mock.patch.object(self.obj, "_toml_verify_path",
                                  return_value="frps verify failed %s" % path):
            self._assert_clean(self._call("frp_save_raw", frp, get), path)

        frp.verify = lambda kind: "frps verify failed %s" % path
        self._assert_clean(self._call("frp_verify", frp, get), path)
        self.assertIn("frps verify failed", self._read_log())


class NoTracebackEchoGuardTest(unittest.TestCase):
    """回归守卫：format_exc 只允许出现在 _log_exc 写日志的那一处。"""

    def test_format_exc_only_inside_log_exc(self):
        with open(MAIN_PATH, encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(src.count("format_exc"), 1,
                         "接口禁止回显堆栈，异常请走 self._fail / self._log_exc")
        start = src.index("    def _log_exc(self, msg):")
        end = src.index("\n    def ", start + 1)
        self.assertIn("format_exc", src[start:end])


if __name__ == "__main__":
    unittest.main()
