#!/usr/bin/env python3
# coding: utf-8
"""app/sysdetect.py 单元测试：SSH 登录信任 + 系统端口（auth.log）检测。

背景与红线（改代码前先读 app/sysdetect.py 的模块 docstring）：
  - ipset 的 DROP 是**全端口**的，误封一个来源，22/7080/8888 一样进不去，
    面板同端口被封后无法自助解封。所以这里逐条锁住误封防护。
  - 检测必须在后台线程、默认关闭、默认只观察；本文件用 tick() 驱动，
    不起真实线程（确定性断言）。

覆盖：
  1. 三种真实 auth.log 样本（Failed password / Invalid user /
     Connection closed by authenticating）都能取到正确来源 IP，且不会把
     `port` 后面的数字当成 IP；
  2. `Accepted publickey` / `Accepted password` 写入登录信任，
     **失败登录绝不写入**（否则等于给攻击方发豁免）；
  3. 增量 tail：首次从末尾开始、轮转（inode 变化）/ 截断（文件变小）从头重读、
     半行不消费、单轮行数上限；
  4. 滑窗阈值 → 走现有链路写临时封禁（ban_log + 触发内核同步），只认领一次；
  5. 五道豁免（非公网 / 白名单 / 登录信任 / 可信回源段+人工段 / 活跃会话）
     与全局熔断；
  6. 试运行只记录不封禁；配置默认值。
"""
import os
import time
import unittest
from unittest import mock

from . import new_home
from app import config, engine, store, sysdetect

# 真实的公网来源（取自方案文档里的现场样本）：
# 注意不要用 203.0.113.x / 2001:db8:: 之类文档地址——Python 3.12 的
# ipaddress 把 TEST-NET 段判为 is_private=True，会被「只处理公网地址」挡掉。
IP_A = "183.222.230.188"
IP_B = "111.29.52.71"
IP_C = "43.143.9.47"
IP_OK = "45.140.13.21"
IP_V6 = "2408:8000:1234::5678"

TS = "2026-11-28T14:00:09.425722+08:00"


def line_failed(ip=IP_A, user="root", port=5512):
    return ("%s host sshd[160087]: Failed password for %s from %s port %d ssh2"
            % (TS, user, ip, port))


def line_invalid(ip=IP_B, user="admin", port=3312):
    return ("%s host sshd[160087]: Invalid user %s from %s port %d"
            % (TS, user, ip, port))


def line_closed(ip=IP_C, user="root", port=22):
    return ("%s host sshd[160087]: Connection closed by authenticating user %s "
            "%s port %d [preauth]" % (TS, user, ip, port))


def line_accepted(ip=IP_OK, method="publickey", user="root", port=5596):
    return ("%s host sshd[160087]: Accepted %s for %s from %s port %d ssh2: "
            "RSA SHA256:abcdef" % (TS, method, user, ip, port))


class _Base(unittest.TestCase):
    """公共夹层：独立临时 HOME + 日志文件 + 可控配置 + 拦截内核同步。"""

    def setUp(self):
        new_home(self)
        self.log = os.path.join(config.DATA_DIR, "auth.log")
        self.cfg = dict(config.DEFAULTS)
        self.cfg.update({
            "sys_detect_enabled": True,
            "sys_detect_dry_run": False,
            "sys_ssh_log": self.log,
            "sys_ssh_window": 600,
            "sys_ssh_threshold": 3,
            "sys_ssh_ban_seconds": 600,
            "sys_ban_max_seconds": 3600,
            "sys_ban_max_per_hour": 30,
            "sys_protect_ips": "",
            "sys_trust_ssh_login": True,
            "trust_login_ttl": 86400,
            "fw_sync_enabled": True,
            "whitelist_enabled": False,     # 默认关闭：白名单仍必须被尊重
            "ai_trusted_cidrs": "",
        })
        p = mock.patch.object(config, "get", side_effect=lambda: dict(self.cfg))
        p.start()
        self.addCleanup(p.stop)
        # 不真起内核同步线程（sync 会 spawn ipset 子进程）
        self.syncs = []
        p2 = mock.patch.object(engine, "_request_fw_sync",
                               side_effect=lambda: self.syncs.append(time.time()))
        p2.start()
        self.addCleanup(p2.stop)

    def write(self, *lines, mode="a"):
        with open(self.log, mode, encoding="utf-8") as f:
            for ln in lines:
                f.write(ln + "\n")

    def tick(self):
        return sysdetect.tick()

    def ban_rows(self):
        return store.active_bans()

    def events(self, **kw):
        return store.list_sys_event(200, **kw)


# ---------------- 1) 日志解析 ----------------

class ParseTest(_Base):
    """三种真实样本 + 成功登录 + 反向用例。"""

    def test_failed_password(self):
        ev = sysdetect.parse_line(line_failed())
        self.assertEqual(ev["kind"], "fail")
        self.assertEqual(ev["ip"], IP_A)          # 不是 port 后的 5512
        self.assertEqual(ev["note"], "failed-auth")

    def test_failed_password_invalid_user(self):
        ev = sysdetect.parse_line(
            line_failed(user="invalid user admin"))
        self.assertEqual(ev["kind"], "fail")
        self.assertEqual(ev["ip"], IP_A)

    def test_invalid_user(self):
        ev = sysdetect.parse_line(line_invalid())
        self.assertEqual(ev["kind"], "fail")
        self.assertEqual(ev["ip"], IP_B)
        self.assertEqual(ev["note"], "invalid-user")
        self.assertEqual(ev["user"], "admin")

    def test_connection_closed_by_authenticating(self):
        ev = sysdetect.parse_line(line_closed())
        self.assertEqual(ev["kind"], "fail")
        self.assertEqual(ev["ip"], IP_C)          # 不是 port 后的 22
        self.assertEqual(ev["note"], "closed-auth")

    def test_failed_publickey_is_failure_not_accept(self):
        """`Failed publickey` 是失败事件，绝不能写成登录信任。"""
        ev = sysdetect.parse_line(
            "%s host sshd[1]: Failed publickey for root from %s port 5596 "
            "ssh2: RSA SHA256:abc" % (TS, IP_OK))
        self.assertEqual(ev["kind"], "fail")
        self.assertEqual(ev["ip"], IP_OK)

    def test_accepted_publickey(self):
        ev = sysdetect.parse_line(line_accepted())
        self.assertEqual(ev["kind"], "accept")
        self.assertEqual(ev["method"], "publickey")
        self.assertEqual(ev["ip"], IP_OK)
        self.assertEqual(ev["port"], 5596)

    def test_accepted_password(self):
        ev = sysdetect.parse_line(line_accepted(method="password"))
        self.assertEqual(ev["kind"], "accept")
        self.assertEqual(ev["method"], "password")
        self.assertEqual(ev["ip"], IP_OK)

    def test_disconnect_line(self):
        ev = sysdetect.parse_line(
            "%s host sshd[1]: Disconnected from user root %s port 5596"
            % (TS, IP_OK))
        self.assertEqual(ev["kind"], "disconnect")
        self.assertEqual(ev["ip"], IP_OK)

    def test_non_sshd_lines_ignored(self):
        """auth.log 里还有 cron/systemd 的条目，不能被当成登录事件。"""
        for raw in (
            "%s host cron[123]: (root) CMD (Failed password from 1.2.3.4)" % TS,
            "%s host systemd-logind[1]: New session 5 of user root." % TS,
            "garbage line without ident",
            "",
        ):
            with self.subTest(raw=raw[:40]):
                self.assertIsNone(sysdetect.parse_line(raw))

    def test_non_ip_source_returns_empty_ip(self):
        """from 后面不是地址时不能瞎猜，交给上层跳过。"""
        ev = sysdetect.parse_line(
            "%s host sshd[1]: Invalid user a from not-an-ip port 22" % TS)
        self.assertEqual(ev["kind"], "fail")
        self.assertEqual(ev["ip"], "")

    def test_ipv6_source(self):
        ev = sysdetect.parse_line(
            "%s host sshd[1]: Failed password for root from %s port 2222 ssh2"
            % (TS, IP_V6))
        self.assertEqual(ev["ip"], IP_V6)

    def test_timestamp_parsed(self):
        import datetime
        now = 1800000000
        ev = sysdetect.parse_line(line_failed(), now)
        # 2026-11-28T14:00:09.425722+08:00 应换算成同一时刻的 epoch
        want = int(datetime.datetime(
            2026, 11, 28, 14, 0, 9,
            tzinfo=datetime.timezone(datetime.timedelta(hours=8))).timestamp())
        self.assertEqual(ev["ts"], want)
        self.assertNotEqual(ev["ts"], now)

    def test_bad_timestamp_falls_back_to_now(self):
        ev = sysdetect.parse_line(
            "not-a-timestamp host sshd[1]: Failed password for root from %s "
            "port 22 ssh2" % IP_A, 1700000000)
        self.assertEqual(ev["ts"], 1700000000)


# ---------------- 2) 第一部分：SSH 登录信任 ----------------

class SshTrustTest(_Base):
    """成功 SSH 登录写入 trust_login_ip；失败登录绝不写入。"""

    def test_accepted_publickey_writes_trust(self):
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.write(line_accepted(ip=IP_OK, method="publickey"))  # 触发一次「非首轮」
        self.tick()
        self.assertGreater(store.trusted_login_expiry(IP_OK), int(time.time()))

    def test_accepted_publickey_writes_trust_when_detect_disabled(self):
        """检测关闭也必须写登录信任：这是「别把自己锁在门外」的前提。"""
        self.cfg["sys_detect_enabled"] = False
        self.write(line_accepted(ip=IP_OK), line_failed())   # 首轮从末尾开始
        self.tick()
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.assertGreater(store.trusted_login_expiry(IP_OK), int(time.time()))
        # 检测关闭时失败事件不计数（也不封禁）
        self.assertEqual(sysdetect.current_counts(), {})

    def test_failed_login_never_writes_trust(self):
        self.write(line_failed(ip=IP_A))
        self.tick()
        for _ in range(5):
            self.write(line_failed(ip=IP_A))
            self.tick()
        self.assertEqual(store.trusted_login_expiry(IP_A), 0)
        self.assertEqual(store.list_trusted_login_ips(), [])

    def test_private_source_never_trusted(self):
        self.write(line_accepted(ip="10.1.2.3"))
        self.tick()
        self.write(line_accepted(ip="10.1.2.3"))
        self.tick()
        self.assertEqual(store.list_trusted_login_ips(), [])

    def test_trust_disabled_by_ttl(self):
        self.cfg["trust_login_ttl"] = 0
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.assertEqual(store.list_trusted_login_ips(), [])

    def test_trust_disabled_by_switch(self):
        self.cfg["sys_trust_ssh_login"] = False
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.assertEqual(store.list_trusted_login_ips(), [])

    def test_trust_ttl_uses_existing_config(self):
        self.cfg["trust_login_ttl"] = 120
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        remaining = store.trusted_login_expiry(IP_OK) - int(time.time())
        self.assertTrue(0 < remaining <= 120, remaining)

    def test_trust_write_is_rate_limited_by_remaining_ttl(self):
        """剩余有效期还长就不重写（避免每条日志都刷一次库）。"""
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        first = store.trusted_login_expiry(IP_OK)
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.assertEqual(store.trusted_login_expiry(IP_OK), first)


# ---------------- 3) 增量 tail ----------------

class TailTest(_Base):
    """首次从末尾开始 / 轮转 / 截断 / 半行 / 单轮上限。"""

    def test_first_run_starts_at_end(self):
        self.write(*[line_failed() for _ in range(5)])
        self.assertEqual(self.tick(), 0)          # 历史行不处理
        self.assertEqual(sysdetect.current_counts(), {})
        self.assertEqual(self.ban_rows(), [])

    def test_only_new_lines_processed(self):
        self.write(line_failed())
        self.tick()                               # 首轮：跳到末尾
        self.write(line_failed(), line_invalid())
        self.assertEqual(self.tick(), 2)
        self.assertEqual(sysdetect.current_counts()[IP_A]["n"], 1)
        self.assertEqual(sysdetect.current_counts()[IP_B]["n"], 1)

    def test_rotation_inode_change_reads_from_start(self):
        self.write(line_failed())
        self.tick()
        # 模拟 logrotate：新文件替换旧文件（inode 变化）
        tmp = self.log + ".new"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(line_invalid() + "\n")
        os.replace(tmp, self.log)
        self.assertEqual(self.tick(), 1)
        self.assertEqual(sysdetect.current_counts()[IP_B]["n"], 1)
        # 不重复计数：再读一轮没有新行
        self.assertEqual(self.tick(), 0)
        self.assertEqual(sysdetect.current_counts()[IP_B]["n"], 1)

    def test_truncation_same_inode_reads_from_start(self):
        self.write(line_failed())
        self.tick()
        # 同一 inode 被清空重写（copytruncate 形态），文件变小
        self.write(line_invalid(), mode="w")
        self.assertEqual(self.tick(), 1)
        self.assertEqual(sysdetect.current_counts()[IP_B]["n"], 1)

    def test_partial_line_not_consumed(self):
        self.write(line_failed())
        self.tick()
        # 写一行但没有换行：必须等完整行，绝不能把半行当一行解析
        with open(self.log, "a", encoding="utf-8") as f:
            f.write(line_invalid()[:-1])
        self.assertEqual(self.tick(), 0)
        self.assertEqual(sysdetect.current_counts(), {})
        with open(self.log, "a", encoding="utf-8") as f:
            f.write("%s\n" % line_invalid()[-1])
        self.assertEqual(self.tick(), 1)
        self.assertEqual(sysdetect.current_counts()[IP_B]["n"], 1)

    def test_max_lines_per_round(self):
        self.write(line_failed())
        self.tick()
        self.cfg["sys_ssh_max_lines"] = 3
        self.write(*[line_failed() for _ in range(7)])
        # 每轮最多 3 行：分 3/3/1 三轮读完，不丢行、不重复
        self.assertEqual(self.tick(), 3)
        self.assertEqual(sysdetect.current_counts()[IP_A]["n"], 3)
        self.assertEqual(self.tick(), 3)
        self.assertEqual(self.tick(), 1)
        self.assertEqual(self.tick(), 0)          # 读完了
        # 计数在阈值处封顶（threshold=3），不会因分批读而多算
        self.assertEqual(sysdetect.current_counts()[IP_A]["n"], 3)

    def test_missing_log_is_silent(self):
        self.cfg["sys_ssh_log"] = os.path.join(config.DATA_DIR, "nope.log")
        self.assertEqual(self.tick(), 0)          # 不抛异常
        self.assertEqual(self.tick(), 0)

    def test_relative_or_traversal_path_rejected(self):
        self.assertEqual(sysdetect._safe_log_path("relative/auth.log"), "")
        self.assertEqual(sysdetect._safe_log_path("/var/log/../../etc/shadow"), "")
        self.assertEqual(sysdetect._safe_log_path("/var/log/auth.log"),
                         "/var/log/auth.log")

    def test_seek_end_when_both_disabled(self):
        self.cfg["sys_detect_enabled"] = False
        self.cfg["sys_trust_ssh_login"] = False
        self.write(line_failed())
        self.assertEqual(self.tick(), 0)
        self.write(line_failed())
        self.assertEqual(self.tick(), 0)          # 关闭期间不处理
        self.assertEqual(sysdetect.current_counts(), {})


# ---------------- 4) 阈值 → 临时封禁 ----------------

class BanTest(_Base):
    """达阈值走现有写入路径，且只认领一次。"""

    def _fail(self, n=1, ip=IP_A, ts=None):
        cfg = dict(self.cfg)
        obj = sysdetect._norm_ip(ip)
        base = time.time() if ts is None else ts
        out = None
        for n_i in range(n):
            out = sysdetect.handle_fail(obj, base + n_i, cfg)
        return out

    def test_below_threshold_no_ban(self):
        self.assertEqual(self._fail(2), "counted")
        self.assertEqual(self.ban_rows(), [])

    def test_threshold_writes_temp_ban(self):
        self.assertEqual(self._fail(3), "banned")
        rows = self.ban_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], IP_A)
        self.assertTrue(rows[0]["reason"].startswith("sys: authlog"),
                        rows[0]["reason"])
        # 临时封禁而非永久黑名单
        self.assertEqual(store.list_ips("black"), [])
        # 触发了内核同步（走 engine._request_fw_sync，不新起线程做 sync）
        self.assertEqual(len(self.syncs), 1)

    def test_ban_claimed_only_once_per_window(self):
        self._fail(8)
        self.assertEqual(len(self.ban_rows()), 1)

    def test_ban_seconds_clamped_to_max(self):
        self.cfg["sys_ssh_ban_seconds"] = 999999
        self.cfg["sys_ban_max_seconds"] = 3600
        self._fail(3)
        row = self.ban_rows()[0]
        self.assertLessEqual(row["expire_at"] - row["banned_at"], 3600)

    def test_window_expired_resets_count(self):
        base = time.time()
        self._fail(2, ts=base)                       # 未达阈值
        self.assertEqual(self.ban_rows(), [])
        # 窗口过期：旧计数作废，重新从 1 开始（不会因为上次的 2 次直接触发）
        out = sysdetect.handle_fail(sysdetect._norm_ip(IP_A), base + 601,
                                    dict(self.cfg))
        self.assertEqual(out, "counted")
        self.assertEqual(sysdetect.current_counts()[IP_A]["n"], 1)
        self.assertEqual(self.ban_rows(), [])

    def test_dry_run_only_records(self):
        self.cfg["sys_detect_dry_run"] = True
        self.assertEqual(self._fail(3), "observed")
        self.assertEqual(self.ban_rows(), [])
        self.assertEqual(self.syncs, [])
        evs = self.events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["action"], "observed")
        self.assertEqual(evs[0]["ip"], IP_A)
        self.assertEqual(evs[0]["hits"], 3)
        self.assertEqual(evs[0]["source"], "sshd")

    def test_fw_sync_skipped_when_disabled(self):
        self.cfg["fw_sync_enabled"] = False
        self._fail(3)
        self.assertEqual(len(self.ban_rows()), 1)
        self.assertEqual(self.syncs, [])

    def test_circuit_breaker_stops_new_bans(self):
        self.cfg["sys_ban_max_per_hour"] = 1
        self.assertEqual(self._fail(3, ip=IP_A), "banned")
        self.assertEqual(self._fail(3, ip=IP_B), "skipped:circuit")
        self.assertEqual(len(self.ban_rows()), 1)
        evs = self.events(action="skipped")
        self.assertTrue(any(e["action"] == "skipped:circuit" for e in evs))


# ---------------- 5) 误封防护 ----------------

class ProtectTest(_Base):
    """五道豁免 + 排序：任一命中都不封。"""

    def _fail(self, n=3, ip=IP_A):
        obj = sysdetect._norm_ip(ip)
        now = time.time()
        out = None
        for i in range(n):
            out = sysdetect.handle_fail(obj, now + i, dict(self.cfg))
        return out

    def test_non_public_skipped(self):
        self.assertEqual(self._fail(ip="10.0.0.5"), "skipped:non-public")
        self.assertEqual(self._fail(ip="127.0.0.1"), "skipped:non-public")
        self.assertEqual(self.ban_rows(), [])

    def test_whitelist_always_respected(self):
        """whitelist_enabled=False（默认）时也必须尊重白名单。"""
        self.assertFalse(self.cfg["whitelist_enabled"])
        store.add_ip(IP_A, "white", "owner 出口")
        self.assertEqual(self._fail(), "skipped:whitelist")
        self.assertEqual(self.ban_rows(), [])
        evs = self.events(action="skipped")
        self.assertEqual(evs[0]["action"], "skipped:whitelist")

    def test_whitelist_cidr_respected(self):
        store.add_ip("183.222.230.0/24", "white", "整段")
        self.assertEqual(self._fail(), "skipped:whitelist")
        self.assertEqual(self.ban_rows(), [])

    def test_login_trust_skipped(self):
        store.trust_login_ip(IP_A, 3600)
        self.assertEqual(self._fail(), "skipped:trust-login")
        self.assertEqual(self.ban_rows(), [])

    def test_ai_trusted_cidrs_skipped(self):
        self.cfg["ai_trusted_cidrs"] = "183.222.0.0/16"
        self.assertEqual(self._fail(), "skipped:trusted-cidr")
        self.assertEqual(self.ban_rows(), [])

    def test_learned_trusted_cidr_skipped(self):
        store.add_trusted_cidr(IP_A, reason="CDN 回源", source="behavior")
        self.assertEqual(self._fail(), "skipped:trusted-cidr")
        self.assertEqual(self.ban_rows(), [])

    def test_protect_ips_skipped(self):
        self.cfg["sys_protect_ips"] = "111.29.0.0/16, 43.143.9.47"
        self.assertEqual(self._fail(ip=IP_B), "skipped:protect-cidr")
        self.assertEqual(self._fail(ip=IP_C), "skipped:protect-cidr")
        self.assertEqual(self.ban_rows(), [])

    def test_active_session_skipped(self):
        """正在 SSH 里操作的来源永不封（最致命的场景）。"""
        sysdetect.session_add(IP_A, time.time())
        self.assertEqual(self._fail(), "skipped:active-session")
        self.assertEqual(self.ban_rows(), [])
        self.assertEqual(sysdetect.active_session_ips(), {IP_A})

    def test_session_tracking_accepted_then_disconnected(self):
        self.write(line_accepted(ip=IP_OK))     # 首轮从末尾开始
        self.tick()
        self.write(line_accepted(ip=IP_OK))
        self.tick()
        self.assertIn(IP_OK, sysdetect.active_session_ips())
        self.write("%s host sshd[1]: Disconnected from user root %s port 5596"
                   % (TS, IP_OK))
        self.tick()
        self.assertEqual(sysdetect.active_session_ips(), set())

    def test_ended_session_no_longer_protected(self):
        now = time.time()
        sysdetect.session_add(IP_A, now)
        sysdetect.session_remove(IP_A, now)
        self.assertNotIn(IP_A, sysdetect.active_session_ips())
        self.assertEqual(self._fail(), "banned")

    def test_already_banned_skipped(self):
        store.add_ban(IP_A, "manual", 600)
        self.assertEqual(self._fail(), "already-banned")
        self.assertEqual(len(self.ban_rows()), 1)

    def test_protected_reason_order(self):
        """白名单优先于登录信任（顺序即短路优先级）。"""
        store.add_ip(IP_A, "white", "")
        store.trust_login_ip(IP_A, 3600)
        obj = sysdetect._norm_ip(IP_A)
        self.assertEqual(sysdetect._protected_reason(obj, dict(self.cfg)),
                         "whitelist")


# ---------------- 6) sys_event 存储 ----------------

class SysEventStoreTest(_Base):
    """sys_event 表：写入 / 过滤 / 裁剪 / 清空。"""

    def test_add_and_list(self):
        store.add_sys_event(1000, IP_A, "sshd", 22, 8, 600, "observed", "r1")
        store.add_sys_event(1001, IP_B, "sshd", 22, 9, 600, "banned", "r2")
        rows = store.list_sys_event(10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ip"], IP_B)      # 倒序
        self.assertEqual(store.count_sys_event(), 2)

    def test_filter_by_ip_and_action(self):
        store.add_sys_event(1000, IP_A, "sshd", 22, 8, 600, "observed", "")
        store.add_sys_event(1001, IP_A, "sshd", 22, 9, 600, "banned", "")
        store.add_sys_event(1002, IP_B, "sshd", 22, 9, 600, "skipped:whitelist", "")
        self.assertEqual(len(store.list_sys_event(10, ip=IP_A)), 2)
        self.assertEqual(len(store.list_sys_event(10, action="observed")), 1)
        # 前缀过滤：skipped 命中 skipped:<原因>
        self.assertEqual(len(store.list_sys_event(10, action="skipped")), 1)
        self.assertEqual(store.count_sys_event(action="banned"), 1)

    def test_trim_keeps_latest(self):
        for i in range(10):
            store.add_sys_event(1000 + i, IP_A, "sshd", 22, 1, 600, "observed", "")
        store.trim_sys_event(4)
        rows = store.list_sys_event(100)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["ts"], 1009)

    def test_purge(self):
        store.add_sys_event(1000, IP_A, "sshd", 22, 1, 600, "observed", "")
        self.assertEqual(store.purge_sys_event(), 1)
        self.assertEqual(store.count_sys_event(), 0)

    def test_trim_empty_table_noop(self):
        store.trim_sys_event(10)                  # 空表不抛异常
        self.assertEqual(store.count_sys_event(), 0)


# ---------------- 7) 配置默认值与状态 ----------------

class ApiTest(_Base):
    """`/api/sysdetect` 的 handler 输出（不走 HTTP 层，传输形态由 test_api_routes 钉）。"""

    class _Stub(object):
        """最小 self 替身：handler 只用到 _json / _body。"""

        def __init__(self, body=None):
            self.body = body or {}
            self.payload = None

        def _json(self, payload, code=200, headers=None):
            self.payload = payload
            return payload

        def _body(self):
            return self.body

    def _call(self, method, qs=None, body=None):
        from app import daemon
        stub = self._Stub(body)
        return daemon.Handler._api_sysdetect(stub, dict(self.cfg), qs or {}, method)

    def test_get_returns_status_and_events(self):
        store.add_sys_event(1000, IP_A, "sshd", 22, 8, 600, "observed", "r")
        out = self._call("GET", {"limit": ["5"]})
        self.assertEqual(out["code"], 0)
        self.assertEqual(out["total"], 1)
        self.assertEqual(len(out["events"]), 1)
        self.assertEqual(out["events"][0]["ip"], IP_A)
        # 状态里带当前配置（只读展示，本接口不提供修改）
        self.assertEqual(out["data"]["config"]["sys_ssh_threshold"], 3)

    def test_get_filters(self):
        store.add_sys_event(1000, IP_A, "sshd", 22, 8, 600, "observed", "")
        store.add_sys_event(1001, IP_B, "sshd", 22, 8, 600, "banned", "")
        out = self._call("GET", {"ip": [IP_B]})
        self.assertEqual([e["ip"] for e in out["events"]], [IP_B])

    def test_post_clear(self):
        store.add_sys_event(1000, IP_A, "sshd", 22, 8, 600, "observed", "")
        out = self._call("POST", body={"action": "clear"})
        self.assertEqual(out["code"], 0)
        self.assertEqual(store.count_sys_event(), 0)

    def test_post_unknown_action(self):
        out = self._call("POST", body={"action": "nope"})
        self.assertEqual(out["code"], 1)


class ConfigTest(unittest.TestCase):
    """默认值即安全默认：关闭 + 只观察。"""

    def test_defaults(self):
        d = config.DEFAULTS
        self.assertFalse(d["sys_detect_enabled"])     # 默认关闭
        self.assertTrue(d["sys_detect_dry_run"])      # 打开后先观察
        self.assertTrue(d["sys_trust_ssh_login"])     # 登录信任默认开
        self.assertEqual(d["sys_ssh_log"], "")
        self.assertEqual(d["sys_ssh_window"], 600)
        self.assertEqual(d["sys_ssh_threshold"], 8)
        self.assertEqual(d["sys_ssh_ban_seconds"], 600)
        self.assertEqual(d["sys_ssh_poll_interval"], 5)
        self.assertEqual(d["sys_ssh_max_lines"], 2000)
        self.assertEqual(d["sys_ban_max_per_hour"], 30)
        self.assertEqual(d["sys_ban_max_seconds"], 3600)
        self.assertEqual(d["sys_protect_ips"], "")

    def test_status_shape(self):
        new_home(self)
        st = sysdetect.status()
        self.assertIn("config", st)
        self.assertIn("tail", st)
        self.assertIn("counts", st)
        self.assertIn("active_sessions", st)
        self.assertEqual(st["config"]["sys_ssh_threshold"], 8)


if __name__ == "__main__":
    unittest.main()
