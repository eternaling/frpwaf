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
import tarfile
import tempfile
import unittest
import zipfile

from . import new_home
from app import upgrade


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


if __name__ == "__main__":
    unittest.main()
