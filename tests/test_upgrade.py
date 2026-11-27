#!/usr/bin/env python3
# coding: utf-8
"""app/upgrade.py 解包与结构校验单元测试。

升级流程会以 root 把下载到的压缩包解压并覆盖运行目录，因此「解包环节」
必须拒绝一切越界写法。本文件只测纯逻辑，不发网络请求：

  - `_safe_extract_tar` / `_safe_extract_zip` 拒绝路径回退、绝对路径、链接条目
  - 解包后总字节与文件数超限时抛错
  - `validate_tree` 对缺文件 / info.json 不可解析 / 版本不符的拒绝

全部在临时目录内构造，不碰真实运行目录，不发网络请求。
"""
import io
import json
import os
import shutil as _shutil
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

from . import new_home
from app import config, upgrade


def _tar_bytes(entries):
    """entries: [(name, payload_bytes, kind)]，kind 取 file/symlink。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, payload, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tf.addfile(info)
                continue
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, payload in entries:
            zf.writestr(name, payload)
    return buf.getvalue()


class SafeExtractTarTest(unittest.TestCase):
    def setUp(self):
        new_home(self)
        self.tmp = tempfile.mkdtemp(prefix="frpwaf-tar-")
        self.dest = os.path.join(self.tmp, "out")
        os.makedirs(self.dest, exist_ok=True)

    def _write(self, data):
        p = os.path.join(self.tmp, "pkg.tar.gz")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_normal_archive_extracts(self):
        p = self._write(_tar_bytes([("a/b.txt", b"hello", "file")]))
        upgrade._safe_extract_tar(p, self.dest)
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "a", "b.txt")))

    def test_parent_traversal_rejected(self):
        p = self._write(_tar_bytes([("../outside.txt", b"x", "file")]))
        with self.assertRaises(ValueError) as ctx:
            upgrade._safe_extract_tar(p, self.dest)
        self.assertIn("非法路径", str(ctx.exception))

    def test_absolute_path_rejected(self):
        p = self._write(_tar_bytes([("/etc/cron.d/evil", b"x", "file")]))
        with self.assertRaises(ValueError):
            upgrade._safe_extract_tar(p, self.dest)

    def test_symlink_entry_rejected(self):
        p = self._write(_tar_bytes([("link", b"", "symlink")]))
        with self.assertRaises(ValueError) as ctx:
            upgrade._safe_extract_tar(p, self.dest)
        self.assertIn("链接条目", str(ctx.exception))

    def test_extract_byte_limit(self):
        big = b"A" * (upgrade._MAX_EXTRACT_BYTES + 1024)
        p = self._write(_tar_bytes([("big.bin", big, "file")]))
        with self.assertRaises(ValueError) as ctx:
            upgrade._safe_extract_tar(p, self.dest)
        self.assertIn("体积超限", str(ctx.exception))

    def test_extract_file_count_limit(self):
        n = upgrade._MAX_EXTRACT_FILES + 5
        entries = [("f%d.txt" % i, b"x", "file") for i in range(n)]
        p = self._write(_tar_bytes(entries))
        with self.assertRaises(ValueError) as ctx:
            upgrade._safe_extract_tar(p, self.dest)
        self.assertIn("文件数超限", str(ctx.exception))


class SafeExtractZipTest(unittest.TestCase):
    def setUp(self):
        new_home(self)
        self.tmp = tempfile.mkdtemp(prefix="frpwaf-zip-")
        self.dest = os.path.join(self.tmp, "out")
        os.makedirs(self.dest, exist_ok=True)

    def _write(self, data):
        p = os.path.join(self.tmp, "pkg.zip")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_normal_archive_extracts(self):
        p = self._write(_zip_bytes([("a/b.txt", b"hello")]))
        upgrade._safe_extract_zip(p, self.dest)
        self.assertTrue(os.path.isfile(os.path.join(self.dest, "a", "b.txt")))

    def test_parent_traversal_rejected(self):
        p = self._write(_zip_bytes([("../outside.txt", b"x")]))
        with self.assertRaises(ValueError):
            upgrade._safe_extract_zip(p, self.dest)

    def test_absolute_path_rejected(self):
        p = self._write(_zip_bytes([("/etc/cron.d/evil", b"x")]))
        with self.assertRaises(ValueError):
            upgrade._safe_extract_zip(p, self.dest)


class ValidateTreeTest(unittest.TestCase):
    """validate_tree：关键文件齐全 + 最小结构断言 + 版本对齐。"""

    def setUp(self):
        new_home(self)
        self.root = tempfile.mkdtemp(prefix="frpwaf-tree-")

    def _write(self, rel, text):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)

    def _minimal_tree(self, version="1.4.2"):
        # validate_tree 除了查文件名，还要求文件达到最小长度（防止同名占位文件）。
        # frpwaf_main.py 需 >=2000 字符且含 class frpwaf_main；daemon.py 需 >=1000 且含 def main(。
        filler = "# pad\n" * 400
        self._write("frpwaf_main.py",
                    "class frpwaf_main(object):\n    pass\n" + filler)
        self._write("app/daemon.py", "def main():\n    pass\n" + filler)
        self._write("info.json", json.dumps({"versions": version}))

    def test_minimal_valid_tree_passes(self):
        self._minimal_tree()
        ok, problems = upgrade.validate_tree(self.root, expect_version="1.4.2")
        self.assertTrue(ok, problems)

    def test_missing_main_file(self):
        self._minimal_tree()
        os.remove(os.path.join(self.root, "frpwaf_main.py"))
        ok, problems = upgrade.validate_tree(self.root)
        self.assertFalse(ok)
        self.assertTrue(problems)

    def test_missing_daemon_file(self):
        self._minimal_tree()
        os.remove(os.path.join(self.root, "app", "daemon.py"))
        ok, _ = upgrade.validate_tree(self.root)
        self.assertFalse(ok)

    def test_broken_info_json(self):
        self._minimal_tree()
        self._write("info.json", "{not json")
        ok, _ = upgrade.validate_tree(self.root)
        self.assertFalse(ok)

    def test_info_json_without_versions(self):
        self._minimal_tree()
        self._write("info.json", json.dumps({"name": "frpwaf"}))
        ok, _ = upgrade.validate_tree(self.root)
        self.assertFalse(ok)

    def test_version_mismatch_rejected(self):
        self._minimal_tree(version="1.4.0")
        ok, problems = upgrade.validate_tree(self.root, expect_version="1.4.2")
        self.assertFalse(ok)
        self.assertTrue(any("版本" in p for p in problems), problems)


class OverwriteTargetTest(unittest.TestCase):
    """`_overwrite` 对不同目标目录的落地范围：

    - 插件目录 = 面板集成层，`_PANEL_PAYLOAD` 里的载荷文件必须照常写入
      （否则一次在线升级就把面板端 UI 与安装脚本留在旧版本）；
    - 运行目录（config.BASE）= 运行层，那 7 个只从插件目录读，不写副本，
      并把已有的同名文件清掉（否则升级一次也不会变干净）；
    - `app/` 与 `web/` 两个目标都要写（`web/` 是独立 Web 端的静态目录）。

    全部在临时目录内构造，不碰真实运行目录。
    """

    #: 任务约定的 7 个面板载荷文件名（顺序无关，只用于逐项断言）
    PAYLOAD = ("frpwaf_main.py", "index.html", "info.json", "install.sh",
               "uninstall.sh", "frpwaf.init", "frpwaf.service")

    def setUp(self):
        # new_home 会把 config.BASE 指到一个临时目录，这里它就充当运行目录
        new_home(self)
        self.base = config.BASE
        self.pkg = tempfile.mkdtemp(prefix="frpwaf-pkg-")
        self.plugin = tempfile.mkdtemp(prefix="frpwaf-plugin-")
        self._write_pkg()

    def _write(self, root, rel, text="x\n"):
        p = os.path.join(root, rel)
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def _write_pkg(self):
        """构造一个「结构完整」的发布包：7 个载荷 + app/ + web/ + 不该落地的 data/。"""
        for name in self.PAYLOAD:
            self._write(self.pkg, name)
        self._write(self.pkg, "app/daemon.py")
        self._write(self.pkg, "app/engine.py")
        self._write(self.pkg, os.path.join("web", "index.html"))
        # data/ 属于 _EXCLUDE_DIRS，无论如何都不应被覆盖
        self._write(self.pkg, os.path.join("data", "frpwaf.json"), '{"pkg":1}')

    def test_payload_set_is_the_documented_seven(self):
        """排除名单就是这 7 个，不多不少（多了会弄坏插件端，少了会留下副本）。"""
        self.assertEqual(set(self.PAYLOAD), set(upgrade._PANEL_PAYLOAD))

    def test_plugin_target_receives_payload(self):
        """目标是插件目录时，7 个载荷文件照常写入（不能把面板端弄坏）。"""
        _n, removed = upgrade._overwrite(self.pkg, self.plugin)
        for name in self.PAYLOAD:
            self.assertTrue(os.path.isfile(os.path.join(self.plugin, name)),
                            "插件目录缺少 %s" % name)
        self.assertEqual([], removed)

    def _copied_rels(self, target):
        """跑一遍 _overwrite，返回真正被 copy2 写入到 target 下的相对路径集合。

        只看最终文件在不在挡不住「先写再删」——那同样会留下空的目标目录，
        所以这里哨兵 copy2 的落盘目标，直接断言「没写」而不只是「最后不存在」。
        """
        real = _shutil.copy2
        written = []
        def spy(src, dst, *a, **kw):
            written.append(os.path.relpath(dst, target))
            return real(src, dst, *a, **kw)
        with mock.patch.object(upgrade.shutil, "copy2", spy):
            n, removed = upgrade._overwrite(self.pkg, target)
        self.assertEqual(len(written), n, "写入计数与实际落盘次数不一致")
        return set(written), removed

    def test_runtime_target_skips_payload(self):
        """目标是运行目录时，这 7 个从未被写入（不是「写了又删」）。"""
        written, _removed = self._copied_rels(self.base)
        for name in self.PAYLOAD:
            self.assertNotIn(name, written, "运行目录不应写入 %s" % name)
            self.assertFalse(os.path.exists(os.path.join(self.base, name)),
                             "运行目录不应出现 %s" % name)

    def test_plugin_target_writes_payload(self):
        """插件目录正好相反：这 7 个确实被 copy2 写入。"""
        written, _removed = self._copied_rels(self.plugin)
        for name in self.PAYLOAD:
            self.assertIn(name, written, "插件目录必须写入 %s" % name)

    def test_runtime_target_purges_existing_payload(self):
        """运行目录里已存在的同名旧副本会被清掉，并登记为已清理。"""
        for name in self.PAYLOAD:
            self._write(self.base, name, "stale\n")
        _n, removed = upgrade._overwrite(self.pkg, self.base)
        for name in self.PAYLOAD:
            self.assertFalse(os.path.exists(os.path.join(self.base, name)),
                             "旧副本未被清理：%s" % name)
            self.assertIn(name, removed)

    def test_app_and_web_written_to_both_targets(self):
        """app/ 与 web/ 在两个目标都要落地（web/ 缺失会让独立 Web 端 404）。"""
        upgrade._overwrite(self.pkg, self.base)
        upgrade._overwrite(self.pkg, self.plugin)
        for root in (self.base, self.plugin):
            self.assertTrue(os.path.isfile(os.path.join(root, "app", "daemon.py")), root)
            self.assertTrue(os.path.isfile(os.path.join(root, "app", "engine.py")), root)
            self.assertTrue(os.path.isfile(os.path.join(root, "web", "index.html")), root)

    def test_non_payload_root_files_still_reach_runtime(self):
        """排除的是固定 7 个，不是「所有根目录文件」——其它文件仍旧覆盖。"""
        self._write(self.pkg, "build.sh")
        self._write(self.pkg, "README.md")
        upgrade._overwrite(self.pkg, self.base)
        self.assertTrue(os.path.isfile(os.path.join(self.base, "build.sh")))
        self.assertTrue(os.path.isfile(os.path.join(self.base, "README.md")))

    def test_runtime_data_dir_untouched(self):
        """运行目录的 data/ 既不被覆盖也不被清理。"""
        self._write(self.base, os.path.join("data", "frpwaf.json"), '{"keep":1}')
        upgrade._overwrite(self.pkg, self.base)
        p = os.path.join(self.base, "data", "frpwaf.json")
        with open(p, "r", encoding="utf-8") as f:
            self.assertEqual('{"keep":1}', f.read())

    def test_runtime_stale_module_still_pruned(self):
        """跳过载荷后，陈旧的 .py 模块清理仍然生效（不能退化成「保留旧副本」）。"""
        stale_rel = os.path.join("app", "legacy_module.py")
        self._write(self.base, stale_rel)
        _n, removed = upgrade._overwrite(self.pkg, self.base)
        self.assertFalse(os.path.exists(os.path.join(self.base, stale_rel)))
        self.assertIn(stale_rel, removed)

    def test_backup_still_captures_payload(self):
        """备份走 _iter_files，改动后仍能把目标里的载荷文件全部备到（回滚不缺文件）。"""
        for name in self.PAYLOAD:
            self._write(self.base, name, "old\n")
        self._write(self.base, os.path.join("app", "daemon.py"), "old\n")
        bdir = tempfile.mkdtemp(prefix="frpwaf-bk-")
        n = upgrade._backup(self.base, bdir)
        # 4 个无扩展名/非排除后缀的文件 + frpwaf_main.py + index.html + info.json
        # + app/daemon.py = 8；data/ 已被排除，不计入。
        self.assertEqual(len(self.PAYLOAD) + 1, n)
        for name in self.PAYLOAD:
            self.assertTrue(os.path.isfile(os.path.join(bdir, name)),
                            "备份缺少 %s" % name)

    def test_runtime_dir_detected_regardless_of_trailing_separator(self):
        """路径末尾带分隔符也要认得是运行目录（否则排除形同失效）。"""
        self.assertTrue(upgrade._is_runtime_dir(self.base))
        self.assertTrue(upgrade._is_runtime_dir(self.base + os.sep))
        self.assertFalse(upgrade._is_runtime_dir(self.plugin))


if __name__ == "__main__":
    unittest.main()
