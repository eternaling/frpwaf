# 验证报告：frp 配置读写去除第三方 toml 依赖（Bug F）

- 关联任务：`docs/tasks/archive/2026-09/task-20260930-134500-frp-toml-stdlib.md`
- 执行日期：2026-09-30
- 环境：本地 Windows + Python 3.12.6（`tomllib` 仅用于交叉比对；生产代码不依赖）
- 结论：**通过**

## 验证目标

证明「无第三方 `toml` 包」的环境下，frp 配置读取 / 保存 / 原文语法校验全链路可用，
且自研 `app/toml_lite.py` 的解析语义与标准库 `tomllib` 一致、生成输出可被其接受。

## 执行结果

| # | 用例 | 实际结果 | 判定 |
|---|---|---|---|
| 1 | 解析基础语法（表/数组表/点分键/引号键/多行字符串/内联表/注释） | 全部符合预期 | ✅ |
| 2 | 生成 + 往返一致（含空 dict） | 一致 | ✅ |
| 3 | frps / frpc 模板可解析；`auth.token` 点分键正确 | 通过 | ✅ |
| 4 | `load_config` / `save_config` 全链路（含 `maxPoolCount` 归位、字段合并、`httpPlugins` 保留、写前备份） | 通过 | ✅ |
| 5 | 非法输入报错且带行号（缺值/缺等号/未闭合/重复键等 5 类） | 通过 | ✅ |
| 6 | 与官方 `tomllib` 交叉比对：我方 `dumps` → 官方解析（含嵌套数组表/特殊字符） | 语义一致 | ✅ |
| 7 | 与官方交叉比对：同一文本两边解析结果一致（6 组样例，含 CRLF / Unicode 转义 / 折行） | 一致 | ✅ |
| 8 | 与官方交叉比对：frps / frpc 模板 + `[[httpPlugins]]` 注入块，读改写后官方可解析且语义不变 | 一致 | ✅ |
| 9 | 差异模糊测试：26 组 tricky 样本 + 10 组非法样本（接受/拒绝行为与官方一致） | 零差异 | ✅ |
| 10 | 表命名空间边界差异测试 52 项（重复表/点分键冲突/内联表冻结/数组表重置等） | 零差异 | ✅ |
| 11 | 随机差异测试：3000 份随机文档（接受/拒绝 + 值比对） | 零差异 | ✅ |
| 12 | 随机生成往返：2000 份随机 dict（`dumps` → 官方解析 → 语义一致） | 零差异 | ✅ |
| 13 | 私有包加载机制（`frpwaf_app`）下 `toml_lite` 子模块可导入、全链路可用 | 通过 | ✅ |
| 14 | 端到端：用户既有配置（含注释/自定义段/注入块）读取 → 表单保存 → 原文校验 → frpc 全链路 | 通过 | ✅ |
| 15 | 边界：空文件 / 仅注释 / CRLF / UTF-8 BOM | 均可解析 | ✅ |
| 16 | 静态检查：`python -m py_compile app/*.py frpwaf_main.py` | 通过 | ✅ |
| 17 | 残留扫描：生产代码 `grep "import toml"` | 已清零 | ✅ |
| 18 | `node scripts/audit-agent-migration.cjs`（含 hooks 行为 49 项） | 全部通过 | ✅ |
| 19 | 版本一致性：`app/__init__.py` = `info.json` = 1.3.9 | 一致 | ✅ |
| 20 | Shell 语法：`install.sh` / `uninstall.sh` / `build.sh` / `frpwaf.init` | 全部通过 | ✅ |

> 复现命令（临时脚本已按规范清理，不提交仓库）：
> 在无 `toml` 环境（`builtins.__import__` 拦截）下执行
> `python -X utf8 <临时脚本>`；交叉比对用 `import tomllib` 对照。

## 回归范围

- **frp 配置读写**：`load_config` / `save_config` / `ensure_config` / `check_toml`
- **插件端接口**：`frp_get_config` / `frp_save_config` / `frp_save_raw` /
  `frp_release_ports`（读端口）
- **既有安全约定**：写前备份、写后 `frps verify`、失败回滚、`httpPlugins` 保留
- **私有包加载**：`frpwaf_main._app("frp")` 路径不受影响

## 遗留问题

- `app/toml_lite.py` 不支持日期 / 时间类型（frp 配置不会出现；遇到明确报错并带行号）。
- 服务器端（宝塔真实环境）未实测，建议升级后点开「frp 管理」页做一次读取 / 保存冒烟。
