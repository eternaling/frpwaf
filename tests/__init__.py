#!/usr/bin/env python3
# coding: utf-8
"""frpwaf 自动化测试包：测试引导与公共夹层（fixtures）。

**本文件是测试隔离的第一道防线**，它承担两件事：

1. 在导入 `app.*` 之前把 `FRPWAF_HOME` 指到临时目录。
   `app/config.py` 的 `BASE` / `DATA_DIR` / `CONF_PATH` / `DB_PATH` 都是
   **模块级常量**，一 import 就固定；默认值是生产路径 `/opt/frpwaf`，
   若不先改环境变量，测试一 import 就会盯着生产数据目录。包 `__init__`
   先于任何测试模块被导入（`python -m unittest discover` 与
   `python -m unittest tests.test_x` 都是如此），所以这里设置最早。
2. 提供 `new_home()` / `reset_caches()`：每个用例一个独立临时 HOME，
   并清掉模块级缓存（sqlite 连接、规则缓存、封禁快照、内核同步记忆等），
   避免用例之间串味。

只依赖标准库；不写任何真实数据目录，不调用 ipset/iptables。
"""
import os
import shutil
import tempfile

_BOOT_HOME = tempfile.mkdtemp(prefix="frpwaf-tests-boot-")
# 必须在 import app.* 之前设置（见模块 docstring）
os.environ["FRPWAF_HOME"] = _BOOT_HOME

from app import config, engine, firewall, store, sysdetect  # noqa: E402


def new_home(test=None):
    """为当前用例准备一个全新的临时 HOME，返回该目录路径。

    会就地改写 `app.config` 的路径常量（其余模块都在**调用时**才读这些
    常量，所以改写即生效），并清空所有模块级缓存。传入 `test`（TestCase）
    时自动登记清理。
    """
    base = tempfile.mkdtemp(prefix="frpwaf-test-")
    data = os.path.join(base, "data")
    os.makedirs(data, exist_ok=True)
    config.BASE = base
    config.DATA_DIR = data
    config.DB_PATH = os.path.join(data, "frpwaf.db")
    config.CONF_PATH = os.path.join(data, "frpwaf.json")
    config.LOG_PATH = os.path.join(data, "frpwaf.log")
    config.PID_PATH = os.path.join(data, "frpwaf.pid")
    config.BURST_SNAPSHOT_PATH = os.path.join(data, "burst_snapshot.json")
    # 跨进程锁文件路径同样是模块级常量（import 时由 CONF_PATH 派生），
    # 不跟着改写就会把锁文件留在上一个临时目录里。
    config._LOCK_PATH = config.CONF_PATH + ".lock"
    reset_caches()
    if test is not None:
        # LIFO：先登记 rmtree，再登记 reset_caches，保证清理时先关连接再删目录
        test.addCleanup(shutil.rmtree, base, True)
        test.addCleanup(reset_caches)
    return base


def reset_caches():
    """清空 app 各模块的模块级缓存/计数器（测试之间必须互不影响）。"""
    config.invalidate()
    # store：全局 sqlite 连接 + 封禁快照
    try:
        if store._conn is not None:
            store._conn.close()
    except Exception:
        pass
    store._conn = None
    store._bans["ips"] = ()
    store._bans["at"] = 0.0
    store._bans["gen"] += 1
    # engine：规则缓存 / 限速计数 / 攻击计数 / 突发观测 / 冷却状态
    engine._cache["black"] = []
    engine._cache["white"] = []
    engine._cache["loaded_at"] = 0
    engine._rl.clear()
    for _kind in engine._attack:
        engine._attack[_kind].clear()
    engine._burst.clear()
    engine._cool.clear()
    # firewall：内核同步记忆
    firewall._MEMBERS.clear()
    firewall._RULES.update({"mode": None, "ports": (), "block_port": 0,
                            "checked_at": 0.0})
    firewall._sets_ok = False
    firewall._sets_checked_at = 0.0
    firewall._which_cache.clear()
    firewall._fail_log.clear()
    # 集合 counters 能力探测状态（否则上个用例的「已确认 / 已放弃」会漏到下一个用例）
    firewall._counters_state = "unknown"
    # 概览用的内核计数器缓存与速率采样环（否则上个用例的打桩结果会漏到下一个用例）
    firewall._drop_stat["at"] = 0.0
    firewall._drop_stat["cached"] = None
    del firewall._drop_ring[:]
    # 来源归因缓存
    firewall._top_stat["at"] = 0.0
    firewall._top_stat["cached"] = None
    # 系统端口检测：tail 位置 / 滑窗计数 / 活跃会话 / 限频告警时间
    # （不清就会把上个用例的「已认领」计数与跳末尾位置带进下一个用例）
    sysdetect.reset_state()
    sysdetect._alert_at.clear()


def under_temp(path):
    """路径是否落在系统临时目录内（用于断言「没有写真实数据目录」）。"""
    tmp = os.path.abspath(tempfile.gettempdir())
    return os.path.abspath(path).startswith(tmp + os.sep)
