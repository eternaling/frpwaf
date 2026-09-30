# 验证报告：AI 审查分级处置（Bug G，v1.3.10）

- 关联任务：`docs/tasks/archive/2026-09/task-20260930-153603-ai审查分级封禁.md`
- 执行日期：2026-09-30
- 环境：本地 Windows + Python 3.12.6（`FRPWAF_HOME` 指向临时目录，隔离真实数据）
- 结论：**通过**

## 验证目标

证明 AI 自动 IP 审查的**分级处置**行为正确：确凿 → 永久黑名单、疑似 → 临时封禁、
SSH 相关疑似也永久（可关）、白名单优先不连坐、不重复处置，且配置/面板/版本/文档全链路一致。

## 执行结果

| # | 用例 | 实际结果 | 判定 |
|---|---|---|---|
| 1 | `malicious` → 写入 `ip_list` black（`/32`），无生效临时封禁 | 通过 | ✅ |
| 2 | `suspicious` → 仅临时封禁（`ban_log` 含 `expire_at`） | 通过 | ✅ |
| 3 | `suspicious` + SSH 相关（category=`ssh_bruteforce`）→ 永久黑名单 | 通过 | ✅ |
| 4 | SSH 兜底：无 `category` 但 reason 含 ssh → 永久黑名单 | 通过 | ✅ |
| 5 | `benign` → 无任何处置（`action=none`） | 通过 | ✅ |
| 6 | 白名单（单 IP）命中 → `skipped`，不写黑名单/不封禁 | 通过 | ✅ |
| 7 | 白名单（CIDR 覆盖）命中 → `skipped` | 通过 | ✅ |
| 8 | 已在黑名单 → `already_banned`，不重复写入 | 通过 | ✅ |
| 9 | 已在临时封禁 → `already_banned` | 通过 | ✅ |
| 10 | 临时封禁中的 IP 被判 `malicious` → 升级永久并释放同名临时记录 | 通过 | ✅ |
| 11 | 永久写入失败时**不**释放临时封禁（防御性顺序：先永久、后释放） | 通过 | ✅ |
| 12 | 二次审查同一批 IP → 不重复封禁（历史 Bug 回归） | 通过 | ✅ |
| 13 | 模型返回集合外 IP → 忽略并记录告警（防提示词注入，Bug D 回归） | 通过 | ✅ |
| 14 | 非法 IP 字符串 → 记录「IP 格式非法，跳过」，不抛异常 | 通过 | ✅ |
| 15 | `ai_suspicious_ban=false` → 疑似不处置 | 通过 | ✅ |
| 16 | `ai_ssh_strict=false` → SSH 疑似走临时封禁 | 通过 | ✅ |
| 17 | `ai_ssh_permanent_suspicious=false` → SSH 疑似走临时封禁 | 通过 | ✅ |
| 18 | `ai_auto_ban=false` → 只记录判定、不处置 | 通过 | ✅ |
| 19 | 审查摘要 `ai_last_result` 含「永久黑名单 N 个，临时封禁 M 个」 | 通过 | ✅ |
| 20 | `python -m py_compile app/*.py frpwaf_main.py` | 通过 | ✅ |
| 21 | 插件端 `index.html` 内联 JS `node --check` | 通过 | ✅ |
| 22 | `node scripts/sync-agent-skills.cjs --check`（33 技能双端一致） | 通过 | ✅ |
| 23 | `node scripts/audit-agent-migration.cjs`（含 hooks 行为 49 项） | 全部通过 | ✅ |
| 24 | 版本一致性：`app/__init__.py` = `info.json` = 1.3.10 | 一致 | ✅ |
| 25 | Shell 语法：`install.sh` / `uninstall.sh` / `build.sh` / `frpwaf.init` | 全部通过 | ✅ |
| 26 | 凭据暴露审计（`credential-exposure-audit`，141 文件） | 0 命中 | ✅ |

> 复现命令（临时脚本 `scratchpad/ai_review_test.py` 按规范不入库）：
> `python -X utf8 scratchpad/ai_review_test.py`（30+ 断言全部 PASS）。

## 发布产物校验（v1.3.10 成品包）

| # | 用例 | 实际结果 | 判定 |
|---|---|---|---|
| 27 | 成品包文件集 = build.sh 清单（18 文件 + 2 目录项） | 一致 | ✅ |
| 28 | 全部文件无 CRLF（仓库内 LF，`git archive` 导出） | 通过 | ✅ |
| 29 | 每个文件与 tag `v1.3.10` blob 逐字节一致 | 通过 | ✅ |
| 30 | 脚本权限位 `install.sh` / `uninstall.sh` / `frpwaf.init` = 755 | 通过 | ✅ |
| 31 | 解包后 `bash -n` 三个脚本 + `py_compile` 12 个 Python 文件 | 通过 | ✅ |
| 32 | 顶层含 `info.json` + `install.sh`（宝塔「上传安装」识别条件） | 满足 | ✅ |
| 33 | Release 附件上传后下载校验（90,115 字节，SHA-256 一致） | 一致 | ✅ |

- 成品包：`frpwaf-1.3.10.zip`，**90,115 字节**，
  SHA-256 `7364773d355f98ec5e95a36444e4b031c523835f5aae791c0d441dfd5668281c`
- Release：`https://gitea.nightsoil.cn/night/frpwaf/releases/tag/v1.3.10`

## 回归范围

- **AI 审查链路**：`ai.review()` / `_collect()` / `_extract_json()` / `_apply_action()`
- **存储**：`store.add_ip` / `store.add_ban` / `store.is_banned` / `store.unban_ip` / `store.remove_ip`
- **决策链不受影响**：白名单 → 黑名单 → 封禁 → 限速 → 自动封禁 → allow（未改动）
- **缓存与内核同步**：永久写入后 `engine.invalidate_cache()` + `firewall.sync_from_store()`
- **配置键放行**：`/api/config`（Web 端）与 `AI_KEYS`（插件端）
- **面板**：AI 审查页 3 个新开关回显/保存、结果表「类型」列

## 遗留问题

- 服务器端（宝塔真实环境）未实测；建议升级 v1.3.10 后在「AI 审查」页做一次
  「测试连接 + 立即审查」冒烟，确认分级处置与结果表展示符合预期。
- AI 只能看到 frp 暴露的 SSH 隧道连接（`NewUserConn` 不含本地端口），
  直连 22 端口的扫描不在送审范围内——SSH 从严依据模型的 `category` 与代理名推断。
