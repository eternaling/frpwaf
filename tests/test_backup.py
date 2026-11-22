#!/usr/bin/env python3
# coding: utf-8
"""数据快照备份（app/store.py）与名单导出（GET /api/export）的单元测试。

覆盖范围：
  1. 备份文件能生成，且用独立 sqlite3 连接打开后数据完整（逐表行数比对）；
  2. 保留策略：连做 10 次只留最近 7 份，且留下的是最新的；
  3. 中断安全：写入过程失败时不留下半个 .db，临时文件被清掉；
  4. 磁盘空间不足时跳过并返回原因（打桩 shutil.disk_usage）；
  5. 库文件不存在时返回失败原因而不抛异常；
  6. 备份期间并发写入不影响快照一致性（写 100 行后快照里就是 100 行）；
  7. 备份不持全局 _lock（持了就会把回调决策路径堵死）；
  8. /api/export：未登录 401；登录后返回体里不含真实密钥（机密字段必须掩码）。

全部用例使用 tests.new_home 提供的临时 HOME，不碰真实 data/frpwaf.db。
"""
import http.client
import json
import os
import secrets
import sqlite3
import threading
import time
import unittest
from unittest import mock

from . import new_home, under_temp
from app import auth, config, daemon, store


class BackupBase(unittest.TestCase):
    def setUp(self):
        new_home(self)
        store.init()
        self.bdir = store.backup_dir()

    # ---- 造数 ----
    def _seed(self, logs=20):
        store.add_ip("1.2.3.4", "black", "扫描")
        store.add_ip("10.0.0.0/8", "white", "内网")
        for i in range(logs):
            store.add_log("9.9.9.%d" % (i % 250 + 1), 7000, "p1", "tcp", "u1", "allow")
        store.add_ban("5.6.7.8", "auto", 60)

    # ---- 比对（独立连接，不经 store 的连接，避免测到同一个句柄）----
    @staticmethod
    def _all_counts(path):
        """逐表行数。SQL 全部写成字面量（不拼接表名）。"""
        c = sqlite3.connect(path)
        try:
            return {
                "ip_list": c.execute("SELECT COUNT(*) FROM ip_list").fetchone()[0],
                "conn_log": c.execute("SELECT COUNT(*) FROM conn_log").fetchone()[0],
                "ban_log": c.execute("SELECT COUNT(*) FROM ban_log").fetchone()[0],
                "proxy_stat": c.execute("SELECT COUNT(*) FROM proxy_stat").fetchone()[0],
                "ai_review": c.execute("SELECT COUNT(*) FROM ai_review").fetchone()[0],
            }
        finally:
            c.close()

    @staticmethod
    def _conn_log_count(path):
        c = sqlite3.connect(path)
        try:
            return c.execute("SELECT COUNT(*) FROM conn_log").fetchone()[0]
        finally:
            c.close()

    @staticmethod
    def _integrity(path):
        c = sqlite3.connect(path)
        try:
            return c.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            c.close()


class SnapshotTest(BackupBase):
    def test_backup_file_and_data_intact(self):
        """备份文件生成、命名合规、逐表行数与源库一致、库结构可用。"""
        self._seed(50)
        ok, path = store.backup_db()
        self.assertTrue(ok, path)
        self.assertTrue(os.path.exists(path), path)
        # 只写到临时 HOME 里，没有碰真实数据目录
        self.assertTrue(under_temp(path), path)
        self.assertRegex(os.path.basename(path),
                         r"^frpwaf-\d{8}-\d{6}-\d{6}\.db$")
        self.assertEqual(os.path.dirname(path), self.bdir)
        # 数据完整：不是空壳库，行数与源库逐表一致
        self.assertEqual(self._all_counts(path), self._all_counts(config.DB_PATH))
        self.assertEqual(self._conn_log_count(path), 50)
        self.assertEqual(self._integrity(path), "ok")
        if os.name != "nt":       # Windows 不支持 POSIX 权限位
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_retention_keeps_newest_seven(self):
        """连做 10 次只留 7 份，且留下的是最新的 7 份（文件名排序即时间序）。"""
        self._seed(3)
        orig = store._backup_name          # 打桩前留原函数，否则 lambda 会自我递归
        stamps = [1700000000000000 + i * 60000000 for i in range(10)]   # 微秒
        seq = iter(stamps)
        with mock.patch.object(store, "_backup_name",
                               lambda us=None: orig(next(seq))):
            paths = []
            for _ in range(10):
                ok, path = store.backup_db()
                self.assertTrue(ok, path)
                paths.append(path)
        names = store.list_backups()
        expected = [orig(s) for s in stamps[-7:]]
        self.assertEqual(len(names), store.BACKUP_KEEP)
        self.assertEqual(names, expected)          # 顺序也要对，不只是个数
        # 被删掉的正是最早的 3 份
        for stale in [orig(s) for s in stamps[:3]]:
            self.assertNotIn(stale, names)
            self.assertFalse(os.path.exists(os.path.join(self.bdir, stale)))
        # 最新一份仍在
        self.assertTrue(os.path.exists(paths[-1]))

    def test_consecutive_backups_reach_keep_limit(self):
        """真实时钟下连做 12 次（不 sleep）：绝不能撞名，正好留 7 份且是最新 7 份。

        这是上批漏掉的回归点：文件名精确到秒时，同一秒内的备份会互相
        overwrite，连做 10 次只剩 2 个文件，保留策略形同虚设。
        """
        self._seed(2)
        paths = []
        for _ in range(12):
            ok, path = store.backup_db()
            self.assertTrue(ok, path)
            paths.append(path)

        names = store.list_backups()
        self.assertEqual(len(names), store.BACKUP_KEEP)
        # 按顺序验证留下的就是最后 7 次：既比个数也比身份与次序
        self.assertEqual(names, [os.path.basename(p) for p in paths[-7:]])
        self.assertEqual(len({os.path.basename(p) for p in paths}), 12)   # 12 次 12 个名字
        # 最早的 5 份已被裁掉，且新名字严格递增
        for gone in paths[:5]:
            self.assertFalse(os.path.exists(gone))
        self.assertEqual(names, sorted(names))

    def test_prune_spares_foreign_files(self):
        """裁剪只删本程序的 frpwaf-<时间戳>.db，运维自己放的文件一律不动。"""
        self._seed(2)
        foreign = {
            "manual-dump.db": b"admin copy",
            "frpwaf-notes.db": b"not our naming",      # 前缀像但不是时间戳命名
            "frpwaf-20240101-000000.db": b"legacy",    # 旧版（秒精度）名字：可被裁剪
            "keep-me.txt": b"text",
        }
        os.makedirs(self.bdir, exist_ok=True)
        for name, body in foreign.items():
            with open(os.path.join(self.bdir, name), "wb") as f:
                f.write(body)

        for _ in range(12):
            ok, path = store.backup_db()
            self.assertTrue(ok, path)

        names = store.list_backups()
        # 12 份新快照 + 1 份旧版（秒精度）命名 = 13 份匹配，裁到 7
        self.assertEqual(len(names), store.BACKUP_KEEP)
        # 旧版命名属于本程序产物，排序最旧→被裁掉
        self.assertNotIn("frpwaf-20240101-000000.db", names)
        # 运维文件全部原封不动
        for name, body in foreign.items():
            if name == "frpwaf-20240101-000000.db":
                continue                                # 旧版命名属于本程序产物
            p = os.path.join(self.bdir, name)
            self.assertTrue(os.path.exists(p), name)
            with open(p, "rb") as f:
                self.assertEqual(f.read(), body)

    def test_interrupted_backup_leaves_no_partial_db(self):
        """落地步骤失败：返回失败原因，不留半个 .db，临时文件被清掉。"""
        self._seed(3)

        def boom(src, dst):
            raise OSError("模拟写入中断")

        with mock.patch.object(store.os, "replace", boom):
            ok, info = store.backup_db()
        self.assertFalse(ok)
        self.assertIn("备份失败", info)
        self.assertEqual(store.list_backups(), [])       # 没有被当成一份备份
        self.assertEqual([n for n in os.listdir(self.bdir) if n.endswith(".tmp")], [])

    def test_skips_when_disk_low(self):
        """剩余空间低于阈值：跳过备份并返回原因（不让备份把盘塞满）。"""
        self._seed(3)

        class _Usage:
            total = 100 * 1024 * 1024
            used = 90 * 1024 * 1024
            free = 10 * 1024 * 1024         # 10MB << 200MB 阈值

        with mock.patch.object(store.shutil, "disk_usage", lambda p: _Usage()):
            ok, info = store.backup_db()
        self.assertFalse(ok)
        self.assertIn("磁盘剩余空间不足", info)
        self.assertIn("10MB", info)
        self.assertEqual(store.list_backups(), [])

    def test_missing_db_returns_error_without_raise(self):
        """库文件不存在（未初始化/被手删）时返回原因，不抛异常。"""
        config.DB_PATH = os.path.join(config.DATA_DIR, "missing.db")
        ok, info = store.backup_db()
        self.assertFalse(ok)
        self.assertIn("不存在", info)

    def test_snapshot_consistent_with_concurrent_write(self):
        """写 100 行后备份：快照里就是 100 行；备份期间并发写不破坏一致性。"""
        for i in range(100):
            store.add_log("7.7.7.%d" % (i % 200 + 1), 7000, "p", "tcp", "u", "allow")
        self.assertEqual(self._conn_log_count(config.DB_PATH), 100)

        stop = threading.Event()

        def writer():
            while not stop.is_set():
                store.add_log("8.8.8.1", 7000, "p", "tcp", "u", "allow")
                time.sleep(0.002)

        th = threading.Thread(target=writer, daemon=True)
        th.start()
        try:
            ok, path = store.backup_db()
        finally:
            stop.set()
            th.join(5)
        self.assertTrue(ok, path)
        snap = self._conn_log_count(path)
        # 快照是「某一时刻的一致状态」：至少包含备份前的 100 行，且不超过
        # 备份结束时源库的行数（并发写入的可见性取决于拍快照的时刻）
        self.assertGreaterEqual(snap, 100)
        self.assertLessEqual(snap, self._conn_log_count(config.DB_PATH))
        self.assertEqual(self._integrity(path), "ok")

    def test_backup_does_not_take_global_lock(self):
        """备份不得持全局 _lock：持了就会把每连接的决策写入堵在后面。"""
        self._seed(3)

        class _BusyLock:
            def __enter__(self):
                raise AssertionError("备份不应获取全局 store._lock")

            def __exit__(self, *exc):
                return False

        with mock.patch.object(store, "_lock", _BusyLock()):
            ok, path = store.backup_db()
        self.assertTrue(ok, path)

    def test_last_backup_time_and_stale_tmp_cleanup(self):
        """last_backup_time 供 daemon 判断周期；超时残留的 .tmp 会被清掉。"""
        self._seed(1)
        self.assertEqual(store.last_backup_time(), 0)
        ok, path = store.backup_db()
        self.assertTrue(ok, path)
        self.assertLessEqual(abs(store.last_backup_time() - time.time()), 60)

        stale = os.path.join(self.bdir, "frpwaf-20200101-000000.db.tmp")
        with open(stale, "wb") as f:
            f.write(b"half")
        os.utime(stale, (time.time() - 7200, time.time() - 7200))
        fresh = os.path.join(self.bdir, "frpwaf-20200101-000001.db.tmp")
        with open(fresh, "wb") as f:
            f.write(b"writing")

        ok, path2 = store.backup_db()
        self.assertTrue(ok, path2)
        self.assertFalse(os.path.exists(stale))          # 1 小时前的残留被清
        self.assertTrue(os.path.exists(fresh))           # 正在写的不能动


class ExportApiTest(unittest.TestCase):
    """/api/export 的端到端验证（临时 daemon，走真实 HTTP 连接）。"""

    def setUp(self):
        new_home(self)
        store.init()
        # 口令在用例里现生成：写死字面量既触发硬编码口令审计，也没有额外价值。
        # 必须改掉默认口令：否则 /api/* 会被「首次登录强制改密」门禁拦成 403。
        self.admin_pwd = secrets.token_urlsafe(12)
        self.real_ai_key = "sk-" + secrets.token_hex(16)
        config.save({"admin_password": self.admin_pwd,
                     "ai_api_key": self.real_ai_key})
        store.add_ip("1.2.3.4", "black", "扫描")
        store.add_ban("5.6.7.8", "auto", 60)
        self.srv = daemon._QuietHTTPServer(("127.0.0.1", 0), daemon.Handler,
                                           max_concurrent=4)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        self.th = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.th.start()
        self.addCleanup(self._stop)

    def _stop(self):
        for fn in (self.srv.shutdown, self.srv.server_close):
            try:
                fn()
            except Exception:
                pass

    def _get(self, path, cookie=None):
        """返回 (status, headers, raw_text)。用 http.client 直连本机临时端口。"""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        try:
            headers = {"Cookie": cookie} if cookie else {}
            conn.request("GET", path, headers=headers)
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read().decode("utf-8")
        finally:
            conn.close()

    def _cookie(self):
        return "%s=%s" % (auth.COOKIE_NAME, auth.create_token("admin"))

    def test_requires_login(self):
        code, _, _ = self._get("/api/export")
        self.assertEqual(code, 401)

    def test_export_masks_secrets(self):
        code, headers, raw = self._get("/api/export", self._cookie())
        self.assertEqual(code, 200, raw)
        # 浏览器直接存文件
        disp = headers.get("Content-Disposition", "")
        self.assertIn("attachment", disp)
        self.assertIn(".json", disp)

        data = json.loads(raw)
        self.assertTrue(data["ok"])
        self.assertIsInstance(data["exported_at"], int)
        self.assertEqual([r["cidr"] for r in data["ip_list"]], ["1.2.3.4/32"])
        self.assertEqual(len(data["bans"]), 1)
        self.assertEqual(data["bans"][0]["ip"], "5.6.7.8")

        # 机密字段必须是掩码，且真实值不得出现在整个响应体里
        masked = data["config_masked"]
        self.assertEqual(masked["ai_api_key"], daemon.MASKED_VALUE)
        self.assertEqual(masked["admin_password"], daemon.MASKED_VALUE)
        self.assertNotIn(self.real_ai_key, raw)
        self.assertNotIn(self.admin_pwd, raw)
        # 非机密字段照常导出（迁移时还得靠它们）
        self.assertEqual(masked["admin_user"], "admin")


if __name__ == "__main__":
    unittest.main()
