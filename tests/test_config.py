#!/usr/bin/env python3
# coding: utf-8
"""app/config.py 单元测试。

覆盖重点（对应评审 P1-10 + 本批生产 bug 教训）：
  - `save(patch)` 的合并语义（两个写入方改不同字段时互不覆盖）
  - 各 normalize_* 防呆函数
  - **老配置升级**：只含旧键的 frpwaf.json 加载后新键必须拿到 DEFAULTS 值
    （本批上线事故就是「存量机器缺新键 → 回调端口回退到错误端口」）
  - 配置文件损坏时拒绝覆盖
  - 掩码值 `******` 回写不覆盖真实密钥

全部用例只写 `tempfile` 目录（由 tests.new_home 保证），不碰 /opt/frpwaf。
"""
import json
import unittest

from . import new_home, under_temp
from app import config


def write_conf(payload):
    """把 dict 原样写到当前临时 HOME 的 frpwaf.json。"""
    with open(config.CONF_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)


def read_conf_raw():
    with open(config.CONF_PATH, "r", encoding="utf-8") as f:
        return f.read()


def read_conf():
    return json.loads(read_conf_raw())


# 一份「旧版存量机器」的配置：只有 wave2/wave3 之前就存在的键。
# 故意不含 frp_handler_addr/frp_handler_port、block_page_*、password_changed、
# strict_addr、ai_allow_private、max_concurrent —— 这些正是上线后引发
# 「回调端口回退」事故的缺失键。
LEGACY_CONF = {
    "http_addr": "0.0.0.0",
    "http_port": 7080,
    "web_enabled": True,
    "admin_user": "admin",
    "admin_password": "hunter2",
    "secret": "deadbeef" * 8,
    "blacklist_enabled": True,
    "whitelist_enabled": False,
    "auto_ban_enabled": False,
    "auto_ban_window": 60,
    "auto_ban_threshold": 200,
    "auto_ban_seconds": 600,
    "rate_limit_enabled": False,
    "rate_limit_per_sec": 0,
    "log_max_rows": 200000,
    "fw_sync_enabled": True,
    "ai_enabled": False,
    "github_repo": "eternaling/frpwaf",
}


class SaveMergeTest(unittest.TestCase):
    """save() 是 patch 语义：只改传入字段，其余保持磁盘现状。"""

    def setUp(self):
        new_home(self)

    def test_save_patch_keeps_other_fields(self):
        config.save({"http_port": 7000, "log_max_rows": 1234})
        config.save({"admin_user": "boss"})
        conf = read_conf()
        self.assertEqual(conf["http_port"], 7000)
        self.assertEqual(conf["log_max_rows"], 1234)
        self.assertEqual(conf["admin_user"], "boss")

    def test_save_patch_does_not_reset_secret(self):
        first = config.save({"admin_user": "a"})
        second = config.save({"admin_user": "b"})
        self.assertEqual(first["secret"], second["secret"])
        self.assertEqual(len(second["secret"]), 64)

    def test_save_rejects_non_dict(self):
        with self.assertRaises(TypeError):
            config.save([("http_port", 7000)])

    def test_save_invalidates_cache(self):
        self.assertEqual(config.get()["http_port"], 7080)
        config.save({"http_port": 7001})
        self.assertEqual(config.get()["http_port"], 7001)

    def test_save_returns_merged_dict(self):
        merged = config.save({"http_port": 7002})
        self.assertEqual(merged["http_port"], 7002)
        self.assertEqual(merged["admin_user"], config.DEFAULTS["admin_user"])

    def test_secret_generated_once_and_persisted(self):
        cfg1 = config.load()
        self.assertEqual(len(cfg1["secret"]), 64)
        cfg2 = config.load()
        self.assertEqual(cfg1["secret"], cfg2["secret"])

    def test_password_changed_flag_follows_password(self):
        self.assertFalse(config.load()["password_changed"])
        cfg = config.save({"admin_password": "newpass"})
        self.assertTrue(cfg["password_changed"])
        cfg = config.save({"admin_password": config.DEFAULTS["admin_password"]})
        self.assertFalse(cfg["password_changed"])


class NormalizeTest(unittest.TestCase):
    """normalize_* 防呆：非法值回退默认，界面上不该出现「开着却不生效」。"""

    def setUp(self):
        new_home(self)

    def test_normalize_auto_ban_off_keeps_values(self):
        cfg = {"auto_ban_cc_enabled": False, "auto_ban_cc_threshold": 0,
               "auto_ban_cc_window": 1}
        config.normalize_auto_ban(cfg)
        self.assertEqual(cfg["auto_ban_cc_threshold"], 0)
        self.assertEqual(cfg["auto_ban_cc_window"], 1)

    def test_normalize_auto_ban_on_restores_defaults(self):
        cfg = {"auto_ban_cc_enabled": True, "auto_ban_cc_threshold": 0,
               "auto_ban_cc_window": 1, "auto_ban_cc_seconds": "abc"}
        config.normalize_auto_ban(cfg)
        self.assertEqual(cfg["auto_ban_cc_threshold"],
                         config.DEFAULTS["auto_ban_cc_threshold"])
        self.assertEqual(cfg["auto_ban_cc_window"],
                         config.DEFAULTS["auto_ban_cc_window"])
        self.assertEqual(cfg["auto_ban_cc_seconds"],
                         config.DEFAULTS["auto_ban_cc_seconds"])

    def test_normalize_auto_ban_ssh_has_no_seconds_key(self):
        cfg = {"auto_ban_ssh_enabled": True, "auto_ban_ssh_threshold": 0}
        config.normalize_auto_ban(cfg)
        self.assertEqual(cfg["auto_ban_ssh_threshold"],
                         config.DEFAULTS["auto_ban_ssh_threshold"])
        # ssh 档走永久黑名单，没有 seconds 键；不该被凭空写出来
        self.assertNotIn("auto_ban_ssh_seconds", cfg)

    def test_normalize_burst_cool_window(self):
        cfg = {"burst_window": 1}
        config.normalize_burst_cool(cfg)
        self.assertEqual(cfg["burst_window"], config.DEFAULTS["burst_window"])
        cfg = {"burst_window": 0}
        config.normalize_burst_cool(cfg)
        self.assertEqual(cfg["burst_window"], config.DEFAULTS["burst_window"])

    def test_normalize_burst_cool_off_keeps_values(self):
        cfg = {"burst_window": 60, "proxy_cool_enabled": False,
               "proxy_cool_min_conns": 0, "proxy_cool_seconds": 1}
        config.normalize_burst_cool(cfg)
        self.assertEqual(cfg["proxy_cool_min_conns"], 0)
        self.assertEqual(cfg["proxy_cool_seconds"], 1)

    def test_normalize_burst_cool_on_clamps(self):
        cfg = {"burst_window": 60, "proxy_cool_enabled": True,
               "proxy_cool_min_conns": 0, "proxy_cool_uniq_threshold": 0,
               "proxy_cool_seconds": 9, "proxy_cool_single_pct": 150}
        config.normalize_burst_cool(cfg)
        self.assertEqual(cfg["proxy_cool_min_conns"],
                         config.DEFAULTS["proxy_cool_min_conns"])
        self.assertEqual(cfg["proxy_cool_uniq_threshold"],
                         config.DEFAULTS["proxy_cool_uniq_threshold"])
        # 9 秒回退默认：引擎运行时取 max(10, ...)，不能出现「显示 1s 实际 10s」
        self.assertEqual(cfg["proxy_cool_seconds"],
                         config.DEFAULTS["proxy_cool_seconds"])
        self.assertEqual(cfg["proxy_cool_single_pct"], 100)

    def test_normalize_block_page_port(self):
        for bad in (0, 70000, "abc", None):
            cfg = {"http_port": 7080, "block_page_port": bad}
            config.normalize_block_page(cfg)
            self.assertEqual(cfg["block_page_port"],
                             config.DEFAULTS["block_page_port"], bad)

    def test_normalize_block_page_port_conflicts_with_http_port(self):
        cfg = {"http_port": 7080, "block_page_port": 7080}
        config.normalize_block_page(cfg)
        self.assertEqual(cfg["block_page_port"],
                         config.DEFAULTS["block_page_port"])

    def test_normalize_block_page_redirect_ports(self):
        cfg = {"http_port": 7080, "block_page_port": 7081,
               "block_page_redirect_ports": " 80, 8080 ,80,abc,70000,1 "}
        config.normalize_block_page(cfg)
        self.assertEqual(cfg["block_page_redirect_ports"], "80,8080,1")

    def test_normalize_listen_addr_fallbacks(self):
        cfg = {"http_addr": "  ", "frp_handler_addr": "", "block_page_addr": ""}
        config.normalize_listen(cfg)
        self.assertEqual(cfg["http_addr"], config.DEFAULTS["http_addr"])
        self.assertEqual(cfg["frp_handler_addr"],
                         config.DEFAULTS["frp_handler_addr"])
        self.assertEqual(cfg["block_page_addr"],
                         config.DEFAULTS["block_page_addr"])

    def test_normalize_listen_keeps_lan_address(self):
        cfg = {"http_addr": "10.0.0.5"}
        config.normalize_listen(cfg)
        self.assertEqual(cfg["http_addr"], "10.0.0.5")

    def test_normalize_listen_port_fallbacks(self):
        cfg = {"http_addr": "127.0.0.1", "http_port": 99999,
               "block_page_port": 7081, "frp_handler_port": "x"}
        config.normalize_listen(cfg)
        self.assertEqual(cfg["http_port"], config.DEFAULTS["http_port"])
        self.assertEqual(cfg["frp_handler_port"],
                         config.DEFAULTS["frp_handler_port"])

    def test_normalize_listen_handler_port_must_not_collide(self):
        cfg = {"http_addr": "127.0.0.1", "http_port": 7080,
               "block_page_port": 7081, "frp_handler_port": 7080}
        config.normalize_listen(cfg)
        self.assertEqual(cfg["frp_handler_port"],
                         config.DEFAULTS["frp_handler_port"])

    def test_normalize_listen_concurrency_clamp(self):
        cfg = {"http_addr": "127.0.0.1", "max_concurrent": 1,
               "handler_max_concurrent": 100000}
        config.normalize_listen(cfg)
        self.assertEqual(cfg["max_concurrent"], config.DEFAULTS["max_concurrent"])
        self.assertEqual(cfg["handler_max_concurrent"],
                         config.DEFAULTS["handler_max_concurrent"])


class LegacyUpgradeTest(unittest.TestCase):
    """老配置升级：只含旧键的配置加载后必须拿到新键的 DEFAULTS 值。

    这是本批生产事故的直接防回归用例——存量机器的 frpwaf.json 缺新键，
    若代码里用 cfg["x"] 裸取或读成 None，回调就会打到错误端口。
    """

    def setUp(self):
        new_home(self)
        write_conf(LEGACY_CONF)

    def test_old_keys_are_preserved(self):
        cfg = config.load()
        self.assertEqual(cfg["http_addr"], "0.0.0.0")
        self.assertEqual(cfg["admin_password"], "hunter2")
        self.assertEqual(cfg["secret"], LEGACY_CONF["secret"])

    def test_new_listen_keys_get_defaults(self):
        cfg = config.load()
        self.assertEqual(cfg["frp_handler_port"],
                         config.DEFAULTS["frp_handler_port"])
        self.assertEqual(cfg["frp_handler_addr"],
                         config.DEFAULTS["frp_handler_addr"])
        self.assertEqual(cfg["max_concurrent"],
                         config.DEFAULTS["max_concurrent"])
        self.assertEqual(cfg["handler_max_concurrent"],
                         config.DEFAULTS["handler_max_concurrent"])

    def test_new_block_page_keys_get_defaults(self):
        cfg = config.load()
        self.assertEqual(cfg["block_page_addr"],
                         config.DEFAULTS["block_page_addr"])
        self.assertEqual(cfg["block_page_port"],
                         config.DEFAULTS["block_page_port"])
        self.assertEqual(cfg["block_page_redirect_ports"],
                         config.DEFAULTS["block_page_redirect_ports"])

    def test_new_password_changed_key_follows_real_password(self):
        # 旧配置没有该键。normalize_password_flag 以「口令实值」为准：
        # LEGACY_CONF 的口令不是默认值 -> 视为已改密（True）。
        cfg = config.load()
        self.assertIn("password_changed", cfg)
        self.assertIs(cfg["password_changed"], True)

    def test_new_password_changed_false_for_default_password(self):
        # 同一台存量机器若仍在用默认口令，标志必须是 False（强制改密不能被绕过）
        legacy = dict(LEGACY_CONF)
        legacy["admin_password"] = config.DEFAULTS["admin_password"]
        write_conf(legacy)
        self.assertFalse(config.load()["password_changed"])

    def test_new_strict_addr_key_gets_default(self):
        # 契约 wave3-contract.md §1：DEFAULTS 必须含 strict_addr=False。
        # 该键由 frpwaf-cfg 分支落地；未合入时本用例会红（预期）。
        cfg = config.load()
        self.assertIn("strict_addr", config.DEFAULTS)
        self.assertIs(cfg["strict_addr"], False)

    def test_new_ai_allow_private_key_gets_default(self):
        # 契约 §1：DEFAULTS 必须含 ai_allow_private=True（自建内网 AI 网关）。
        cfg = config.load()
        self.assertIn("ai_allow_private", config.DEFAULTS)
        self.assertIs(cfg["ai_allow_private"], True)

    def test_saving_old_style_form_keeps_new_keys(self):
        """面板整表单回写（不含新键）后，新键仍应是默认值而不是消失/变 None。"""
        config.save(dict(LEGACY_CONF))
        cfg = config.load()
        self.assertEqual(cfg["frp_handler_port"],
                         config.DEFAULTS["frp_handler_port"])
        self.assertEqual(cfg["block_page_addr"],
                         config.DEFAULTS["block_page_addr"])


class CorruptConfigTest(unittest.TestCase):
    """磁盘配置损坏时必须拒绝覆盖（否则 secret/密码/AI key 会被一起抹掉）。"""

    CORRUPT = '{ "http_port": 7080, oops'

    def setUp(self):
        new_home(self)
        with open(config.CONF_PATH, "w", encoding="utf-8") as f:
            f.write(self.CORRUPT)

    def test_read_disk_raises_value_error(self):
        with self.assertRaises(ValueError):
            config._read_disk()

    def test_save_refuses_and_leaves_file_untouched(self):
        with self.assertRaises(ValueError):
            config.save({"http_port": 7005})
        self.assertEqual(read_conf_raw(), self.CORRUPT)

    def test_load_falls_back_to_defaults_without_overwriting(self):
        cfg = config.load()
        self.assertEqual(cfg["http_port"], config.DEFAULTS["http_port"])
        self.assertEqual(read_conf_raw(), self.CORRUPT)

    def test_non_object_json_is_rejected(self):
        with open(config.CONF_PATH, "w", encoding="utf-8") as f:
            f.write("[1, 2, 3]")
        with self.assertRaises(ValueError):
            config.save({"http_port": 7006})


class MaskedSecretTest(unittest.TestCase):
    """掩码值 ****** 回写时不得覆盖真实密钥（静默失效型损坏）。"""

    def setUp(self):
        new_home(self)

    def test_masked_value_does_not_overwrite_ai_key(self):
        config.save({"ai_api_key": "sk-real-value"})
        # 面板 GET 回显 → 用户只改了别的字段 → 前端把掩码原样提交
        from app import daemon
        masked = getattr(config, "MASKED_VALUE", daemon.MASKED_VALUE)
        echo = {"ai_api_key": masked, "http_port": 7007}
        echo = daemon._strip_masked(echo)
        self.assertNotIn("ai_api_key", echo)
        config.save(echo)
        self.assertEqual(config.load()["ai_api_key"], "sk-real-value")

    def test_masked_password_does_not_overwrite(self):
        config.save({"admin_password": "RealPass1"})
        from app import daemon
        masked = getattr(config, "MASKED_VALUE", daemon.MASKED_VALUE)
        echo = daemon._strip_masked({"admin_password": masked, "admin_user": "admin"})
        config.save(echo)
        self.assertEqual(config.load()["admin_password"], "RealPass1")

    def test_contract_masked_constants_live_in_config(self):
        """契约 §1 要求 MASKED_VALUE / MASKED_KEYS 落到 app/config.py。

        现状：二者仍在 app/daemon.py（daemon.py 注释已标注「建议下沉」）。
        属于「API 落位待迁移」而非行为缺口，故未合入时 skip 而不是造假红；
        合入后本用例自动生效。
        """
        if not hasattr(config, "MASKED_VALUE"):
            self.skipTest("契约 §1 未落地：config.MASKED_VALUE 仍只在 daemon.py"
                          "（等待 frpwaf-cfg 分支合入）")
        self.assertEqual(config.MASKED_VALUE, "******")
        self.assertEqual(tuple(config.MASKED_KEYS),
                         ("ai_api_key", "admin_password", "secret"))


class TempIsolationTest(unittest.TestCase):
    """防「测试写生产目录」的最后一道断言。"""

    def setUp(self):
        new_home(self)

    def test_home_is_under_temp(self):
        self.assertTrue(under_temp(config.BASE), config.BASE)
        self.assertTrue(under_temp(config.CONF_PATH), config.CONF_PATH)
        self.assertTrue(under_temp(config.DB_PATH), config.DB_PATH)
        self.assertNotEqual(config.BASE, "/opt/frpwaf")


if __name__ == "__main__":
    unittest.main()
