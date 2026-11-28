# 概览统计口径修正 + 新增「内核层已丢弃」卡片 — 交付报告

- 日期：2026-11-28
- 范围：仅仓库代码 + 测试 + 文档；**未 commit / 未 push / 未 tag / 未触碰服务器**
- 基线：`python -m unittest discover -s tests -t .` → **370 OK**
- 交付后：同一条命令 → **393 OK**（370 + 新增 23 条）
- 任务卡：`docs/tasks/active/task-20261128-120328-概览口径修正与内核丢弃卡片.md`

## 0. 结论先行

没有数字算错，两处都是**口径与标注**问题：

1. `today_rejected` 只能统计「到达 WAF 的连接」——命中 ipset 的包在 `INPUT` 链
   被 `DROP`，到不了 frps，因此不产生 `NewUserConn` 回调、不写 `conn_log`。
2. `total_conns` 是 `conn_log` **现存行数**，而 `conn_log` 被 `trim_logs()` 裁到
   `log_max_rows`（默认 50000）；线上 50008 正好卡上限，它是「日志窗口内连接数」。

本次只改文案 + 新增三个字段，**`stats()` 里 `active_bans` / `today_*` 的算法一行未动**。

## 1. 文案改动对照（两端一致）

### 1.1 插件端 `index.html`（宝塔插件端，owner 主用）

| 位置 | 改前 | 改后 |
|---|---|---|
| `index.html:980` | `['今日拦截', d.today_rejected\|\|0, 'err']` | `['今日应用层拦截', d.today_rejected\|\|0, 'err']` |
| `index.html:985` | `['累计连接', d.total_conns\|\|0, '']` | `['日志窗口连接', d.total_conns\|\|0, '']` |
| `index.html:986` | （无此卡片） | `['内核层已丢弃', kern, d.kern_drop_available?'err':'', kernSub]` |
| `index.html:992-995` | 只有「攻击类型封禁」一行 tip | 新增统计口径说明行（见下） |

新增说明行文案（`index.html:992-995`）：

> 统计口径：「今日应用层拦截」只统计到达 WAF 的连接；被内核链 FRPWAF_BLOCK 直接丢弃的包
> 连不到 frps，不会产生日志，单独记在「内核层已丢弃」（IPv4+IPv6 合计；显示 — 表示当前
> 环境读不到内核计数，如非 root、未启用内核封禁或缺少 iptables）。「日志窗口连接」是 WAF
> 日志现存条数（超出 log_max_rows 上限后会裁掉最早的记录），不是历史累计连接数。

### 1.2 Web 端 `web/index.html`

| 位置 | 改前 | 改后 |
|---|---|---|
| `web/index.html:678` | `['今日拦截', d.today_rejected, 'err']` | `['今日应用层拦截', d.today_rejected, 'err']` |
| `web/index.html:681` | 卡片列表只有 6 张（无 `total_conns`） | 补 `['日志窗口连接', d.total_conns, '']` + `['内核层已丢弃', kern, …, kernSub]` |
| `web/index.html:1085` | `['历史连接', d.total_conns]`（归属地查询） | `['日志窗口连接', d.total_conns]` |
| `web/index.html:191` | （无说明） | `<div class="dash-note">` 说明行，措辞与插件端逐字一致 |

> 归属地查询那一格原来叫「历史连接」，取的是同一份被裁剪的 `conn_log` 计数，
> 属同一处名不副实，一并改成「日志窗口连接」，保证全站同一口径同一叫法。

### 1.3 两端字段对照（截图式）

插件端 `#fwStats` 与 Web 端 `#statCards` 现在的卡片序列逐项相同：

```
今日连接 | 今日应用层拦截 | 今日独立IP | 生效封禁 | 黑名单 | 白名单 | 日志窗口连接 | 内核层已丢弃
   1 245 |              0 |         37 |        3 |     12 |      2 |        50 008 | 331.0 万
                                                                                    194.0 MB   ← 副行
```

读不到内核计数时：

```
… 日志窗口连接 | 内核层已丢弃
         50 008 |            —            ← 无副行
```

格式化函数两端同口径：`fwFmtBig`/`fwFmtBytes`（`index.html:1002,1008`）与
`fmtBig`/`fmtBytes`（`web/index.html:602,606`），阈值与小数位完全一致
（≥1e8 → 亿/2 位，≥1e4 → 万/1 位；≥1GiB → GB/2 位，≥1MiB → MB/1 位，≥1KiB → KB/1 位）。

## 2. 新字段：取数实现 / 缓存 / 降级

### 2.1 字段（只增不改）

`/api/overview`（Web 端）与 `waf_overview`（插件端 s= 方法）同时返回：

| 字段 | 类型 | 含义 |
|---|---|---|
| `kern_dropped` | int | `FRPWAF_BLOCK` 链累计丢弃**包数**（IPv4 + IPv6 合计） |
| `kern_dropped_bytes` | int | 对应**字节数** |
| `kern_drop_available` | bool | 是否读到计数；false 时前端显示 `—` |

原有字段（`total_conns` / `today_*` / `active_bans` / `black_count` / `white_count` 等）
名字与语义**一个都没改**，`stats()` 的 SQL 也未改。

### 2.2 取数实现（`app/firewall.py:859-953`）

放在 `firewall.py`（内核域）而不是 `engine`/`daemon`：`/api/overview` 是面板接口，
与每连接判定无关，**绝不进决策路径**。

| 函数 | 行 | 作用 |
|---|---|---|
| `_parse_drop_counters(text)` | 866 | 解析 `-L <chain> -v -n` 输出；只吃「前两列是整数」的行，跳过 `Chain …` 与 `pkts bytes target …` 表头，怪行一律忽略（宁可少算一行也不让概览失败） |
| `_read_drop_counters()` | 895 | 先 `available()`（root + ipset + iptables），再按 `_have()` 逐个读 `iptables -L FRPWAF_BLOCK -v -n`，有 `ip6tables` 时一并读并**相加**；只用 `-L`，**绝不 `-Z`** |
| `drop_stats(force=False)` | 930 | TTL 缓存外壳，返回 `{available, pkts, bytes}` |
| `drop_fields(force=False)` | 949 | 映射成三个 API 字段，两面板共用，防口径漂移 |

命令形态固定为 `[tool, "-L", CHAIN, "-v", "-n"]`（列表参数，无字符串拼接），
`timeout=DROP_STATS_TIMEOUT=3`。

### 2.3 缓存策略

| 项 | 值 / 条件 |
|---|---|
| TTL | `DROP_STATS_TTL = 8.0` 秒（与 `config._cache` 1s、`engine._cache` 3s 同风格） |
| 失效条件 | ① TTL 到期；② 显式 `force=True`（人工刷新/同步后回显用） |
| 锁 | 只锁缓存读写；**fork 在锁外**，并发概览请求不会相互串行等待 |
| 失败也缓存 | 读不到的结果同样缓存 8 秒，避免每次轮询白 fork 一圈 |
| 返回值 | 每次返回 `dict` 副本，调用方改返回值不会污染缓存 |
| 不阻塞决策 | `drop_stats` 只被 `/api/overview` 与 `waf_overview` 调用；`engine.decide()` 无引用 |
| 测试隔离 | `tests/__init__.py::reset_caches()` 清 `_drop_stat`（`tests/__init__.py:88-90`） |

### 2.4 降级路径（三层）

1. `_read_drop_counters()` 内部 `try/except` → 任何异常返回
   `{"available": False, "pkts": 0, "bytes": 0}`，不抛；
2. `_run()` 本身把 `TimeoutExpired`/`OSError` 转成 `rc=1`（既有行为）→ 该协议族跳过；
3. `daemon._api_overview()`（`app/daemon.py:1394-1402`）与
   `frpwaf_main.waf_overview()`（`frpwaf_main.py:2040-2047`）各自再包一层 try/except，
   取数炸了只把这**三个字段**置为不可用，概览其余内容照常 200。

非 root / 无 iptables / 链不存在 / 命令超时 → `kern_drop_available=false` + 值 0 +
前端 `—`；接口**不会 500**（有单测钉住，见 §3）。

## 3. 测试用例与断言（`tests/test_overview_kernel.py`，23 条）

| 类 | 用例 | 关键断言 |
|---|---|---|
| `ParseDropCountersTest` | `test_parses_real_sample` | 真实样本（含 `Chain …` 与 ` pkts bytes target prot opt in out source destination` 表头）→ `(3310123, 203423744, 1)` |
| | `test_padded_header_is_skipped` | 只有表头的输出 → `(0,0,0)` |
| | `test_multiple_rows_are_summed` | 多规则行相加 → `(3310133, 203423764, 2)` |
| | `test_garbage_lines_do_not_raise` | 混入 `Target prot opt …`、`abc def DROP …` → 只取合法行 `(7,8,1)` |
| | `test_none_and_empty_text` | `""` / `None` → `(0,0,0)` |
| `ReadDropCountersTest` | `test_ipv4_and_ipv6_are_summed` | v4+v6 相加；断言 argv 恰为 `-L FRPWAF_BLOCK -v -n` 且 `timeout<=3`（保证只读、不 `-Z`） |
| | `test_no_ip6tables_binary_only_reads_v4` | 无 `ip6tables` 时只执行 1 次 `iptables` |
| | `test_empty_chain_is_available_with_zero` | 链在但无规则 → `available=True`、计数 0（「真 0」≠「读不到」） |
| | `test_chain_missing_is_not_available` | rc≠0 → `available=False`、计数 0，不抛 |
| | `test_not_root_skips_subprocess_entirely` | `available()` false → **0 次子进程** |
| | `test_iptables_missing_skips_subprocess` | `_have()` 全 false → **0 次子进程**、`available=False` |
| | `test_command_timeout_degrades` | 打桩 `subprocess.run` 抛 `TimeoutExpired` → `available=False` |
| | `test_unexpected_exception_degrades` | `_run` 抛 `RuntimeError` → 三字段全降级 |
| `DropStatsCacheTest` | `test_repeated_calls_fork_once` | 连续 4 次调用 → **只执行 1 次子进程**（打桩计数） |
| | `test_returned_dict_is_a_copy` | 改返回值后缓存不变 |
| | `test_ttl_expiry_refetches` | `_drop_stat["at"] -= TTL+1` → 第 2 次 fork |
| | `test_force_refetches` | `force=True` → 立即重读 |
| | `test_failure_is_cached_too` | 失败结果也缓存（1 次 fork） |
| `DropFieldsTest` | `test_field_names_and_types` | 键集合恰为三个、类型 int/int/bool |
| | `test_unavailable_maps_to_false_and_zero` | 不可用映射为 `0/0/False` |
| `OverviewHandlerTest` | `test_new_fields_present` | 直接调 `_api_overview` → 三字段按样本正确 |
| | `test_existing_fields_unchanged` | 7 个原有统计字段仍在且都是 int、黑名单/封禁数为 0 |
| | `test_degraded_when_reading_fails` | 打桩 `drop_fields` 抛异常 → HTTP 仍 200、`available=False`、其余字段仍在 |

另外扩展 `tests/test_api_routes.py::test_overview_fields`（真 HTTP 路径）：
字段清单补 `kern_dropped` / `kern_dropped_bytes` / `kern_drop_available`，
并断言该环境下（`available` 被打桩为 False）必须降级为 `False/0/0`。

**现有 `stats()` 语义不变**的证据：`test_existing_fields_unchanged` 逐字段校验类型与初值；
`app/store.py` 的 `stats()` 本次**零改动**（`git diff app/store.py` 为空）。

## 4. 全套测试结果

```
$ python -m unittest discover -s tests -t .
Ran 393 tests in 50.924s

OK
```

- 基线 370 OK → 交付后 393 OK（+23，无跳过、无 expectedFailure 新增）
- `python -m py_compile app/firewall.py app/daemon.py frpwaf_main.py` → OK
- `node scripts/audit-agent-migration.cjs` → ✅ 审计通过（未见旧技术栈残留/同步漂移）
- HTML 结构检查：`index.html` / `web/index.html` 编辑后均为 clean
- 卡片渲染逻辑用 node 复刻跑过 3 组载荷（正常/不可用/空对象）：
  两端标签序列一致、无 JS 异常、`—` 与副行按预期出现

## 5. 文档同步

| 文件 | 改动 |
|---|---|
| `docs/04-数据模型与配置项.md` §5 | `total_conns` 说明改为「现存行数/受 `log_max_rows` 裁剪，不是历史累计」；补 `today_rejected` 只覆盖到达 WAF 的连接；补一段说明内核计数不属于 `store.stats()` |
| `docs/05-内核级封禁.md` §7.1/§7.3 | 工具函数表补 `drop_stats` / `drop_fields`；新增 §7.3 说明取数命令、只读约束（不 `-Z`）、3s 超时、8s 缓存、降级、IPv4+IPv6 相加 |
| `docs/07-管理面板与插件功能.md` | 插件端概览行与 Web 端概览行按新卡片文案重写 |
| `docs/10-HTTP_API参考.md` | `/api/overview` 字段清单补三个新键；新增字段说明表 + 口径注解；返回示例补新字段；插件端 `waf_overview` 说明「与 Web 端同源」 |

未改 `docs/12-Bug修复记录.md`：本次不是 Bug 修复，是口径与展示的修正（避免错误归档）。

## 6. 明确未做（与业主边界一致）

- 未改 `stats()` 里 `active_bans` / `today_*` 的算法；
- 未改数据库结构，未做「真累计计数器」（后续可选项）；
- 未 `commit` / `push` / `tag`，未碰服务器、未动 `data/`、未部署。

## 7. 留给业主的验证

1. 服务器跑 `iptables -L FRPWAF_BLOCK -v -n`，与面板「内核层已丢弃」主数值（包数）对比；
   有 IPv6 时确认两族相加后与 `-L` 输出之和吻合。
2. 非 root 或 `fw_sync_enabled` 关闭后，卡片应显示 `—`，且 `/api/overview` 仍返回 200。
3. 观察概览轮询期间 `iptables` 进程频率：应为「每 8 秒最多一次」量级，
   而不是每次刷新一次（可用 `ps` 抽样或 strace 观察）。
