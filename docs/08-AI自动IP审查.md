# 08 · AI 自动 IP 审查

`app/ai.py` 周期性把**最近一段时间的高频来源 IP**（含归属地、连接数、命中代理）
汇总后交给大模型判断是否恶意，可选**自动封禁**。

仅用标准库 `urllib`，无第三方依赖。

## 1. 触发方式

- **后台自动**：`ai.loop_forever()` 线程每 20 秒醒一次，若 `ai_enabled` 且距上次
  运行超过 `ai_interval`（默认 300 秒，最短 60），执行一次 `review()`。
- **手动立即**：面板「立即审查」（`ai.review(force=True)`，忽略 `ai_enabled`）。

## 2. 采集（`_collect`）

```sql
SELECT ip, COUNT(*) AS conns,
       SUM(CASE WHEN action!='allow' THEN 1 ELSE 0 END) AS rejected,
       GROUP_CONCAT(DISTINCT proxy_name) AS proxies
FROM conn_log WHERE ts>=? GROUP BY ip HAVING conns>=?
ORDER BY conns DESC LIMIT ?
```

- 窗口 `ai_window`（默认 300 秒，最短 30）；
- 门槛 `ai_min_conns`（默认 20，低于不送审）；
- 上限 `ai_max_ips`（默认 20）。
- 每个 IP 补 `geo.lookup()` 的归属地文本。

无符合项时写一条 `ai_review`（`verdict=none, action=skip`）并返回「本次无可审查的 IP」。

## 3. 调用大模型（`call_model`）

支持两种协议（`ai_protocol`）：

### 3.1 `openai`

```
POST {base}/v1/chat/completions
Authorization: Bearer <key>
{"model":..., "messages":[{"role":"system",...},{"role":"user",...}],
 "temperature":0.1, "max_tokens":1500}
```

### 3.2 `anthropic`

```
POST {base}/v1/messages
x-api-key: <key>
anthropic-version: 2023-06-01
{"model":..., "max_tokens":1500, "temperature":0.1, "system":..., "messages":[...]}
```

### 3.3 地址智能拼接（`_endpoint`）

兼容用户不同填法，避免 `/v1/v1/...`：

| base | 结果（以 `/v1/chat/completions` 为例） |
|---|---|
| `http://host` | `http://host/v1/chat/completions` |
| `http://host/v1` | `http://host/v1/chat/completions` |
| `http://host/v1/` | `http://host/v1/chat/completions` |
| `http://host/v1/chat/completions` | 原样返回 |

### 3.4 重试策略

- 网络类 / 超时错误：**重试一次**（间隔 2 秒）；
- HTTP 层错误（4xx/5xx）：**不重试**，直接返回 `HTTP <code> <reason> <detail>`；
- 超时 `ai_timeout`（默认 120 秒，最短 15）。

### 3.5 返回解析（`_extract_json`）

容忍 markdown 代码块与多余文字：先剥 ```` ```json ... ``` ````，再取第一个 `[`
到最后一个 `]`，`json.loads`。解析失败 / 非数组 → 报错并记一条 `error`。

## 4. 提示词与输出格式

**系统提示**（`SYSTEM_PROMPT`）：设定模型为服务器安全分析师，审查反向代理入站
来源 IP，判断是否恶意（端口扫描、SSH 爆破、爬虫、异常高频、高风险地区自动化攻击等），
正常用户判 benign，**只输出 JSON**。

**要求输出**：

```json
[{"ip":"1.2.3.4","verdict":"malicious|suspicious|benign","reason":"简短中文理由"}]
```

判定规则：确凿攻击 → `malicious`；可疑不确定 → `suspicious`；正常 → `benign`。

## 5. 处理与自动封禁（`review`）

对模型返回的每个条目：

1. 取 `ip` / `verdict` / `reason`；
2. **只处理本次真正送审过的 IP**（Bug D 修复，见下）；
3. 若 `verdict == "malicious"` 且 `ai_auto_ban` 开：
   - 已在封禁中（`store.is_banned`）→ `action="already_banned"`，**不重复封禁**；
   - 否则 `store.add_ban(ip, "ai: <reason>", ai_ban_seconds)` → `action="banned"`；
4. 写一条 `ai_review` 记录；
5. 更新配置 `ai_last_run` / `ai_last_result`。

返回 `{ok, msg, results, checked, banned}`。

### 5.1 安全边界：只封「送审过的 IP」（Bug D，关键）

```python
if ip not in stat:
    continue
```

**为什么**：大模型可能因**幻觉**或**提示注入**返回集合之外的 IP（例如被审查内容里
诱导出的无关地址，甚至攻击者控制的目标 IP）。若对模型返回的任意 IP 都自动封禁，
攻击者可通过构造输入诱导模型输出某个无辜 IP，从而**借 AI 之手封禁任意地址**。
故只对「本次实际送审集合」内的 IP 生效，集合外的直接丢弃。

### 5.2 不重复封禁

已封禁的 IP 不再 `add_ban`。否则每个审查周期都会重新插入一条封禁记录，
**不断把封禁到期时间往后顺延**（历史故障：同一 IP 被连封 19 次，等于永久封禁）。

## 6. 配置项

见 [04-数据模型与配置项.md](04-数据模型与配置项.md) §3.8。要点：

| 键 | 默认 | 说明 |
|---|---|---|
| `ai_enabled` | `false` | 总开关 |
| `ai_protocol` | `openai` | `openai` / `anthropic` |
| `ai_base_url` / `ai_api_key` / `ai_model` | 空 / 空 / `claude-haiku-4.5` | 接口与模型 |
| `ai_interval` | 300 | 间隔（≥60） |
| `ai_window` | 300 | 分析窗口（≥30） |
| `ai_min_conns` | 20 | 送审门槛 |
| `ai_max_ips` | 20 | 单次上限 |
| `ai_auto_ban` | `true` | 恶意是否自动封禁 |
| `ai_ban_seconds` | 1800 | 封禁时长 |
| `ai_timeout` | 120 | 调用超时（≥15） |

## 7. 密钥保护

- `ai_api_key` 在**读取时掩码为 `******`**：
  - Web 端 `GET /api/config` 返回 `ai_api_key = "******"`（有值时）；
  - 插件端 `ai_get_config` 同样掩码。
- 保存时若传入值为 `******` 或空 → **不覆盖**已存密钥。
- 面板回显永远拿不到明文密钥。

## 8. 测试连接（`/api/ai/test`、`ai_test`）

用**当前表单值**（可临时覆盖已保存配置，仅当非空且非 `******`）对一条示例 IP
（`8.8.8.8`）调用一次模型，成功返回「连接成功，模型返回正常」，否则返回错误详情。

## 9. 审查记录（`ai_review` 表）

`action` 取值：`banned` / `already_banned` / `ban_failed` / `none` / `skip` / `error`。
`verdict` 取值：`malicious` / `suspicious` / `benign` / `error` / `none`。
面板「AI 审查」页可查看最近 200 条。

## 10. 常见问题

| 现象 | 原因 / 处置 |
|---|---|
| 「未配置 AI 接口地址或密钥」 | 先填 `ai_base_url` + `ai_api_key` |
| 「模型返回无法解析为 JSON」 | 模型未按格式输出；换更强模型或调提示词 |
| 连接失败 / 超时 | 检查网关连通性、`ai_timeout`；网络类错误会自动重试一次 |
| 审查到 IP 但不封禁 | `ai_auto_ban` 关闭，或该 IP 已在封禁中 |
| 同一 IP 反复出现 | 正常：每周期都会审查；已封禁的不重复封 |
