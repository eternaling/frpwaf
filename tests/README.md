# frpwaf 自动化测试

标准库 `unittest`，零第三方依赖。不需要网络、不需要 root、不碰真实 `ipset`/`iptables`，
也不会写到真实的 `/opt/frpwaf`（`tests/__init__.py` 在 import `app.*` 之前就把
`FRPWAF_HOME` 指到临时目录）。

## 怎么跑

在仓库根目录执行：

```bash
python -m unittest discover -s tests -t .
```

`-t .` 让 `tests` 按包导入（测试之间用相对导入共享夹具）。
当前全量 **202 个用例**，其中 4 个是 `@unittest.expectedFailure`（跑了仍然报
`OK (expected failures=4)`；某个用例变成 unexpected success 说明对应缺陷已修，
该去更新断言或去掉标记）。单独跑一组：

```bash
python -m unittest tests.test_engine -v
```

## 各组测什么

| 文件 | 覆盖 |
|---|---|
| `test_config.py` | `DEFAULTS` 完整性、`save(patch)` 合并语义、各 `normalize_*` 防呆、**老配置升级补默认值**、配置损坏时拒绝写、掩码值不覆盖真实密钥 |
| `test_store.py` | 名单/封禁/连接日志的基本读写、`trim_*` 裁剪边界、计数与统计 |
| `test_engine.py` | `decide()` 的优先级（白名单 > 黑名单 > 生效封禁 > 限速 > 自动封禁 > 类型封禁 > 冷却）、IPv4-mapped 归一化、地址解析失败时 `strict_addr` 两种策略 |
| `test_firewall.py` | `_reconcile` 差量计算、延长封禁必须重建条目、`sync_from_store` 稳态零调用、`invalidate()` 后重新对账、名单开关关闭后不下发 |
| `test_upgrade.py` | 解包时拒绝路径回退/绝对路径/链接条目、解包体积与文件数上限、`validate_tree` 的文件存在性与最小结构断言、版本对齐；`_overwrite` 按目标目录分两种：插件目录全量写入 7 个面板载荷、运行目录（`config.BASE`）不写入并清掉已有同名副本、`app/`+`web/` 两边都落、`data/` 两者都不碰、跳过后陈旧 `.py` 仍被清理、`_backup` 不因排除少备文件 |
| `test_backup.py` | `backup_db` 快照文件生成与逐表行数比对、保留策略（连做 10 次只留最近 7 份且留最新）、写入中断不留半个 `.db`、磁盘不足跳过并返回原因、库文件缺失不抛异常、并发写入下快照一致、备份不持全局锁；`/api/export` 未登录 401 与机密字段一律掩码 |
| `test_api_routes.py` | HTTP 路由层回归：每条 path 的 GET/POST 实际状态码（含「方法不匹配时是 404 还是 405」这一现状差异）、鉴权边界（未登录 401、`password_changed=False` 时除白名单外全 403）、入参异常一律 400 而不是 500、关键端点（`/api/metrics`、两个 `status`、`/api/export`、`/api/config`）返回结构、协议边界与安全响应头；只打桩进程外副作用与外部网络调用，**不 mock 路由分发本身** |

## 几条约定（改测试时请遵守）

**打桩优先，不碰内核。** `firewall` 的测试全部把 `_run` 打桩，断言的是"应该下发什么
命令"，不是"命令真的执行了"。`available()` 也要打桩——它要求 root，Windows 上
`os.geteuid` 不存在会直接返回 False，不打桩的话测试会被跳过掉。

**`store` 的桩要反映写入效果。** 例如 `add_ban` 的桩除了记录调用，还必须把 IP 加进
"已封禁"集合，否则后续连接仍会被判为未封禁，测出来的行为和真实环境不符。

**不要让测试迁就实现。** 测试失败先判断是真 bug 还是测试写错：

- 真 bug → 用 `@unittest.expectedFailure` 标记，并在提交说明里写清楚
- 测试写错 → 修测试，但修的方向必须是"更贴近真实行为"，不是"改成记录当前输出"

**每个用例独立 HOME。** 统一用 `tests/__init__.py` 的 `new_home(self)`，它会建临时目录、
改写 `app.config` 的路径常量并清空模块级缓存（sqlite 连接、规则缓存、封禁快照、
内核同步记忆）。不调用它会串味——上一个用例的数据漏到下一个。

**别写真实网段。** IP 常量用文档保留段：`192.0.2.x`、`198.51.100.x`、`203.0.113.x`；
本机用 `127.0.0.1`。
