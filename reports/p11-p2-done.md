# P11 第三轮交付报告（P1-1 + P2）

- 分支：`frpwaf-p11b`，已推送到 `origin/frpwaf-p11b`
- 基线：`db1d832`
- 提交：
  - `240c643` fix(engine): 统一豁免口径到所有自动封禁决策点（代码与测试，6 个文件，+292/−66）
  - 本报告单独一次提交（docs(report)），提交号见 `git log --oneline -2` 与 worker_done
- 测试：全量 `python -m unittest discover -s tests -t .` 由 300 增至 307，全部通过（`Ran 307 tests ... OK`）
- 部署：**未部署，部署由 ali 做。** 本轮未连接服务器，未操作 frpwaf / frps 进程。

## 1. P1-1 引擎豁免口径（`app/engine.py`）

### 实现方式

- 新增 `_exempt_hit(ip, proxy_name, cfg, proxy=True)`（`app/engine.py:754-763`）：登录信任始终生效；`proxy=False` 时不看代理豁免。
- 豁免判定下沉到各检测项的认领点，只在 `claimed=True` 时调用：

| 决策点 | 位置 | 登录信任 | 代理豁免 |
|---|---|---|---|
| 第 5 步基础自动封禁 | `app/engine.py:734` | 生效 | 生效 |
| 6.1 敏感端口高频 | `app/engine.py:786` | 生效 | 生效 |
| 6.2 CC 高频 | `app/engine.py:800` | 生效 | 生效 |
| 6.3 多代理探测 | `app/engine.py:813` | 生效 | **不生效**（`proxy=False`） |

- 去掉 `app/engine.py:765` 起那个函数开头的两处提前返回（修改前位于 `app/engine.py:762`、`app/engine.py:764`）。
- docstring 与注释已同步：`_proxy_exempt`（`app/engine.py:368` 起）、`app/engine.py:765` 起函数的 docstring（写明三项检测的豁免差异）、第 5 步注释（`app/engine.py:732-733`）。
- 未新增配置项。

### 6.3 为什么保留

6.3 的判据是同一 IP 在窗口内访问了多个不同代理，这本身不是在用自己那一个服务的特征。豁免单个代理名不应让整个多代理探测失效。登录信任仍跳过 6.3（信任优先）。

### 内存计数语义

计数函数 `_attack_count` / `_attack_scan` 未改，计数照常累加，窗口语义不变。命中豁免时，本次认领被消耗但不封禁，计数封顶在阈值。判定只在认领时进行，非认领连接不增加开销；`_trusted_login_ids()` 自带 3 秒缓存，决策路径不引入磁盘 IO。

## 2. 新增测试（`tests/test_ban_exempt.py:133-235`，`ExemptScopeTest` 共 7 条）

| spec 用例 | 测试 | 修复前 | 修复后 |
|---|---|---|---|
| 1 第 5 步：登录信任 IP 达阈值不封 | `test_base_trusted_login_not_banned` | FAIL | 通过 |
| 2 第 5 步：豁免代理达阈值不封 | `test_base_exempt_proxy_not_banned` | FAIL | 通过 |
| 3 6.1：豁免代理高频不封，计数照常 | `test_sensitive_exempt_not_banned_but_counted` | ERROR（`KeyError`，提前返回导致未计数） | 通过 |
| 4 6.3：多个豁免代理仍封 | `test_scan_across_exempt_proxies_banned` | FAIL | 通过 |
| 5 6.2：豁免代理不封 | `test_cc_exempt_not_banned` | 通过 | 通过 |
| 6 6.3：登录信任不封 | `test_scan_trusted_login_not_banned` | 通过 | 通过 |
| 对照：非豁免代理仍封 | `test_base_non_exempt_still_banned` | 通过 | 通过 |

- spec 预期修复前为红的 2 条（用例 2、4）已确认由红转绿。
- 用例 1、3 修复前同样为红：用例 1 是因为第 5 步未看登录信任，用例 3 是因为 `app/engine.py:762` 提前返回导致未计数。
- 用例 5、6 修复前已通过：原先开头的提前返回已覆盖这两种情况。

## 3. P2 各条

### P2-1 `trust_my_ip` 限频（`frpwaf_main.py:1829-1892`）

- 去掉实例属性 `self._last_trust_log`（宝塔每次请求新建实例，该属性不起作用）。
- 按 IP 去重：用新增的 `store.trusted_login_expiry(ip)`（`app/store.py:904`）取剩余有效期，剩余超过 TTL 一半时不重写、不记审计日志（`frpwaf_main.py:1881` 起），无需额外状态。
- 只写入公网地址：回环、链路本地、内网、未指定 / 组播 / 保留地址均跳过，返回消息说明原因（`saved=False`，`reason=non_public`）。
- 两个面板都不读该接口的返回值（`index.html:1676` 回调为空），返回结构变化不影响前端。

### P2-2 错误响应不回传堆栈

- 新增 `_fail(msg)`（`frpwaf_main.py:575`）：前端只返回简短消息 + 异常类型名，完整堆栈写入 `data/frpwaf.log` 的 `[错误]` 行。
- 改用 `_fail` 的 8 个方法：`cdn_trust_list`（`frpwaf_main.py:1798`）、`cdn_trust_del`（`:1815`）、`cdn_trust_clear`（`:1827`）、`trust_my_ip`（`:1892`）、`self_protect_info`（`:1920`）、`self_protect_save`（`:1957`）、`trust_login_del`（`:1974`）、`trust_login_clear`（`:1986`）。
- **遗留清单**（按 spec 本轮不改的老方法，共 34 个，格式为 `frpwaf_main.py` 行号：方法）：

```
484:install_waf        558:uninstall_waf      628:web_toggle         811:set_web_port
847:apply_to_frps      886:frp_info           919:frp_control        934:frp_install_start
951:frp_uninstall      961:frp_rollback       977:frp_get_config     989:frp_ensure_config
1005:frp_save_config   1080:frp_save_raw      1091:frp_verify        1226:frp_release_ports
1266:geo_query         1422:ai_save_config    1473:ai_test           1500:ai_run_now
1623:kernban_sync      1677:ban_ip            1707:unban_ip          1725:unban_all_black
1738:unban_all_temp    2065:add_ip_entry      2081:del_ip_entry      2117:batch_import_ips
2172:conn_logs         2241:purge_conn_logs   2342:save_policy       2370:upgrade_check
2422:upgrade_apply     2512:change_admin_pwd
```

  该清单按 `traceback.format_exc()` 的出现位置统计（`frpwaf_main.py:588` 是 `_fail` 自身写日志，已排除），个别位置可能只用于写日志而不回传前端，后续统一改造时需逐条复核。

### P2-3 可信网段审计文案（`app/ai.py`）

- 拆分为 `_in_config_cidrs`（`app/ai.py:173`，人工配置网段）与 `_in_learned_cidrs`（`app/ai.py:197`，AI 学习表）；原 `_in_trusted_cidr` 保留在 `app/ai.py:156`。
- `_apply_action`（`app/ai.py:462`）中：命中配置网段记 `mode=trusted`（`app/ai.py:511`），命中学习表记 `mode=learned`（`app/ai.py:516`），审计文案分别写明来源。
- 删除 patch 残留且无调用方的 `_legacy_in_trusted_cidr_unused`（消除 pi-lens 的 3 条未定义名称告警）。
- 测试口径同步：`tests/test_ai_cdn_guard.py:253`、`:269` 两条学习表用例的断言改为 `learned`；`:192` 为配置网段用例，保持 `trusted`。全仓确认面板与统计没有写死只认 `trusted` 的判断，`learned` 记录不会漏显或漏计。

### P2-4 学习表计数（`app/store.py:754`、`frpwaf_main.py:1790`）

- 新增 `store.count_trusted_cidrs()`：`SELECT COUNT(*)` 并过滤过期记录。
- `cdn_trust_list` 改用它计数，不再拉全表。

### P2-5 熔断计数口径（`app/store.py:1308` 起）

- 核实结果：`store.add_ip`（`app/store.py:625-644`）只写 `ip_list`，**不写 `ban_log`**。
- docstring 已写明：只统计 `ban_log` 中 reason 以 `ai:` 开头的临时封禁；AI 永久处置（写入 `ip_list` 黑名单）、引擎自动封禁、手工封禁均不计入。
- 影响：同一 /24 的 IP 若都被直接永久拉黑，不会推高该计数，熔断也不会因此触发。是否把永久黑名单纳入口径属于行为变更，需单独决策；本轮未改熔断逻辑。

## 4. 流程说明

- 推送：spec 纪律节写不推送，协调者最新指令要求推送，按协调者指令执行了 `git push -u origin HEAD`。
- rebase：未执行 `git rebase main`。若合并前 main 已前进，需 rebase 后重跑全量测试。
- 提交范围：按 AGENTS.md 多会话避让规则，只暂存本会话改动的文件，未用 `git add -A`；过程文件 `reports/p11-progress.md` 未提交。
- 行尾 / 空白：`git diff --check` 无告警；`-w` 对比下各文件均有实质改动，无纯格式 churn。

## 5. 遗留风险

1. **共享计数窗口**：豁免流量消耗一次认领后，同一窗口内同一 IP 再访问非豁免代理时，第 5 步、6.1、6.2 不会再次触发，需等窗口过期。
2. **内网访问不再写登录信任**：通过内网地址访问面板时 `trust_my_ip` 不再写入信任，这是 spec 要求的行为变化。
3. **堆栈仍在运行日志中**：`_fail` 把完整堆栈写入 `data/frpwaf.log`，面板的运行日志页仍可看到；接口响应已不含路径。
4. **P2-2 遗留 34 个老方法**：仍回传堆栈片段，见第 3 节清单。
5. **P2-5 口径**：永久黑名单不计入同段熔断，见第 3 节。
6. **已有代码的 pi-lens 提示（本轮未改）**：`app/store.py:161`、`:276`、`:334` 不在本轮改动范围；`frpwaf_main.py:1674`、`:2062` 的 unreachable-except 为误报（内层 `try` 被当成同级子句），外层 `ValueError` 分支可达；`_fail` 的 path-traversal 提示为误报，日志路径固定、不接收外部输入。
