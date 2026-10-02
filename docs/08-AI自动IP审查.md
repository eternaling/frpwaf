# 08 · AI 自动 IP 审查

`app/ai.py` 周期性把**最近一段时间的高频来源 IP**（含归属地、连接数、命中代理）
汇总后交给大模型判断是否恶意，并按判定**分级处置**：

| 判定 | 处置 | 落点 | 时长 |
|---|---|---|---|
| `malicious`（确凿） | **永久黑名单** | `ip_list`（black） | 永久（内核 `timeout=0`），需人工解封 |
| `suspicious`（疑似） | 临时封禁 | `ban_log` | `ai_ban_seconds`（默认 1800 秒，到期自动释放） |
| `suspicious` + SSH 相关 | **永久黑名单**（从严，可关） | `ip_list`（black） | 永久 |
| `cdn_origin`（CDN 回源）/ 强特征命中 | 仅记录，**不自动封禁**（`ai_cdn_guard` 控制） | —— | —— |
| `benign` / 白名单命中 / 已处置 | 仅记录 | —— | —— |

黑名单开关关闭时，原本需要永久黑名单的判定降级为临时封禁；不释放已有临时封禁，
避免记录了永久名单却没有应用层拦截。

> **CDN 回源保护（`ai_cdn_guard`，默认开）**：源站部署在 CDN 之后时，frps 看到的
> 来源 IP 是 CDN 边缘节点，它们被大量真实用户共享。一旦按单 IP 高频将其自动封禁，
> CDN 回源被拒会导致**整站不可访问（Cloudflare 522）**。故判定为 CDN 回源的 IP
> 一律跳过自动处置（记 `skipped`），只记录不封禁。

仅用标准库 `urllib`，无第三方依赖。

## 1. 触发方式

- **后台自动**：`ai.loop_forever()` 线程每 20 秒醒一次（有待处理请求时 2 秒），
  若 `ai_enabled` 且距上次运行超过 `ai_interval`（默认 300 秒，最短 60），
  执行一次 `review()`。
- **手动立即（异步）**：面板「立即审查」按钮走插件端 `ai_run_now`——只写
  `ai_run_requested` 时间戳并**立即返回**（面板进程不执行审查，避免大批量
  送审耗时超过插件请求超时、按钮一直停在「审查中…」）；daemon 的
  `loop_forever` 快速轮询消费该请求并执行 `review(force=True)`，
  前端用 `ai_status` 轮询进度（`running` / `stale` / `last_result`）。
- **互斥**：`review()` 全程持 `_review_lock`，自动循环与手动触发并发到达时
  只跑一轮（其余返回「已有审查在进行中」）；每轮开始/结束写
  `ai_review_state`（running/清空）与 `ai_last_ok`，前端据此判断完成与成败。

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
 "temperature":0.1, "max_tokens":<动态>}
```

### 3.2 `anthropic`

```
POST {base}/v1/messages
x-api-key: <key>
anthropic-version: 2023-06-01
{"model":..., "max_tokens":<动态>, "temperature":0.1, "system":..., "messages":[...]}
```

### 3.3 地址智能拼接（`_endpoint`）

兼容用户不同填法，避免 `/v1/v1/...`：

| base | 结果（以 `/v1/chat/completions` 为例） |
|---|---|
| `http://host` | `http://host/v1/chat/completions` |
| `http://host/v1` | `http://host/v1/chat/completions` |
| `http://host/v1/` | `http://host/v1/chat/completions` |
| `http://host/v1/chat/completions` | 原样返回 |

### 3.4 分批送审、并行与动态 max_tokens（大批量关键）

送审量超过 **100 条/批**（`_BATCH_SIZE`）时自动分批调用，每批独立计算
`max_tokens = min(16384, max(1024, 条数×120 + 512))`（`_max_tokens_for`）。
批次**并行送审**（`_MAX_WORKERS = 3`，波内并行、波间串行）——「一批 IP
一起送审、一起拿回」，总耗时约为串行的 1/N；每波内的批次相互独立，
单批失败不影响其它批。

**为什么**：历史故障（1000 条一次送审）——`max_tokens` 写死 1500，模型输出
被截断成非法 JSON，整轮审查作废。分批后单批输出规模可控；条数越多，所需
输出 token 越多，动态上限随之提高，从根因上消除截断。

**失败降级**（`_call_batch`）：

- 单批解析失败（截断）或网关拒绝 `max_tokens` / 请求体过大（413）→
  **二分重试**（递归减半，共享拆分预算 16 次）；拆到 `_MIN_SPLIT = 5` 条
  仍失败即放弃该批，**不再拆到单条**（避免网关日志被碎片小请求刷屏）；
- 解析成功但缺条目（截断抢救只保住前半段、或模型漏答）→ 只对缺失 IP 补审
  一次（缺失 ≥2 条时；只缺 1 条不补，代价大于收益）；
- 鉴权 / 限流等 HTTP 错误二分无意义：记录后于**波边界**提前终止，
  不把剩余批次全部发出（同一波已发出的无法收回，最多浪费一波）；
- 全部批次失败才返回 `ok=False`；部分失败时返回已成功判定，
  **未获判定的 IP 不处置**（安全方向不受影响），摘要标注「N 个未获判定」。

### 3.5 重试策略

- 网络类 / 超时错误：**重试一次**（间隔 2 秒）；
- HTTP 层错误（4xx/5xx）：**不重试**，直接返回 `HTTP <code> <reason> <detail>`；
- 超时 `ai_timeout`（默认 120 秒，最短 15，**按批**生效）。

### 3.6 返回解析（`_extract_json`）

容忍 markdown 代码块与多余文字：先剥 ```` ```json ... ``` ````，再取第一个 `[`
到最后一个 `]`，`json.loads`。整体解析失败时（多为输出被 `max_tokens` 截断），
用 `_salvage_json` 按 `{` 起点逐对象 `raw_decode` **抢救**能完整解析的条目；
抢救条目仍与送审集合求交集后处置，缺失条目不处置（安全方向不受影响），
并由 `_call_batch` 触发漏答补齐。全失败 → 报错并记一条 `error`。

## 4. 提示词与输出格式

**系统提示**（`SYSTEM_PROMPT`）：设定模型为服务器安全分析师，审查反向代理入站
来源 IP，判断是否恶意（端口扫描、SSH 爆破、爬虫、异常高频、高风险地区自动化攻击等），
正常用户判 benign，**只输出 JSON**。提示词同时要求识别 **CDN 回源**：ISP 为 CDN 厂商
（Cloudflare / CloudFront / Fastly / Sucuri / Imperva / Incapsula / Akamai / 阿里云 CDN /
腾讯云 CDN 等）且对 http/https 代理高频、无被拒的单一来源，属共享边缘节点回源，
判 `benign` + `category=cdn_origin`，**不得判恶意**（误封会导致整站 522）。

**要求输出**：

```json
[{"ip":"1.2.3.4","verdict":"malicious|suspicious|benign",
  "category":"ssh_bruteforce|port_scan|web_scan|crawler|rate_abuse|cdn_origin|other|none",
  "reason":"简短中文理由"}]
```

- 判定规则：确凿攻击 → `malicious`；可疑不确定 → `suspicious`；正常 → `benign`；
- `category` 为攻击类型，`ssh_bruteforce` 是 SSH 从严判定依据之一，
  `cdn_origin` 是 CDN 回源保护依据（跳过自动封禁）；
  旧格式（无 `category`）不会导致误判，会退化为理由/代理名关键词兜底。

## 5. 处理与分级处置（`review`）

对模型返回的每个条目：

1. 取 `ip` / `verdict` / `category` / `reason`；
2. **只处理本次真正送审过的 IP**（Bug D 修复，见下）；非法 verdict 归为 `unknown`；
3. 交给 `_apply_action()` 分级处置：
   - `verdict == "malicious"` → **永久黑名单**：`store.add_ip(ip, "black", "ai: <reason>")`，
     并释放该 IP 的同名临时封禁（升级语义）；若黑名单开关关闭，改为临时封禁；
   - `verdict == "suspicious"` 且非 SSH 相关 → **临时封禁**：
     `store.add_ban(ip, "ai: <reason>", ai_ban_seconds)`；
   - `verdict == "suspicious"` 且 SSH 相关（`ai_ssh_strict` 开）→ 永久黑名单
     （`ai_ssh_permanent_suspicious` 控制，可关闭退回临时）；
   - `verdict` 为 `malicious` / `suspicious` 且判定为 **CDN 回源**
     （`category=cdn_origin`，或 `geo` 文本命中 CDN 厂商关键字，`ai_cdn_guard` 开）
     → `skipped`，**只记录、不写任何封禁**（防整站 522）；
   - 白名单命中的 IP → `skipped`，**不做任何自动处置**；
   - 已在黑名单 → `already_banned`（不重复写入）；
   - 已在临时封禁 → 疑似场景 `already_banned`；确凿场景直接升级为永久；
4. 写一条 `ai_review` 记录；
5. 若本轮产生了永久黑名单：立即 `engine.invalidate_cache()` 并触发
   `firewall.sync_from_store()`（内核同步），保证「封完即生效」；
   若开启了 `fw_sync_enabled`，同一时刻只跑一个同步任务（事件去重，见
   [05 §4.4](05-内核级封禁.md)），批量处置不会引发同步风暴；
6. 更新配置 `ai_last_run` / `ai_last_result` / `ai_last_ok`
   （摘要格式：`审查 N 个 IP，永久黑名单 X 个，临时封禁 Y 个`，
   CDN 回源跳过时追加 `，CDN 回源跳过 Z 个`；
   走 `config.save(patch)` 合并语义，不覆盖并发写入的其它字段）；
   本轮状态 `ai_review_state` 在 finally 中清空（任何出口都不会残留「审查中」）。

返回 `{ok, msg, results, checked, banned, temp_banned}`。

### 5.1 SSH 相关判定（从严）

`_is_ssh_related(category, reason, proxies)` 满足任一即视为 SSH 相关：

- `category` 为 `ssh_bruteforce` / `ssh_attack` / `ssh_login` 等；
- `category`、`reason`、`proxies` 任一文本包含 `ssh`（大小写不敏感）。

> 为什么用代理名兜底：frp 回调（`NewUserConnContent`）只有
> `remote_addr` / `proxy_name` / `proxy_type`，**没有目标端口**；
> 代理名如 `ssh_22` 是「经 frp 暴露 SSH 隧道」的强信号。
> 注意：AI 只能看到经过 frp 的 SSH 隧道，看不到服务器 22 端口被直连爆破。

### 5.2 白名单优先（防连坐）

自动处置前先 `_is_whitelisted(ip)`（名单含 CIDR 匹配）。即使模型判恶意，
白名单命中的 IP 也不自动处置（记 `skipped`），避免「封 IP 段连坐白名单」。

### 5.2.1 CDN 回源保护（防 522，`ai_cdn_guard`）

源站部署在 CDN（Cloudflare 等）之后时，frps 回调拿到的 `remote_addr` 是 **CDN 边缘
节点 IP**（不是真实访客）：单一 IP 承载全站访客的回源连接，天然「高频」。若不豁免，
AI 会按单 IP 高频判恶意 → 永久拉黑边缘节点 → CDN 回源被拒 → **整站 522**。

双重识别（`ai_cdn_guard` 默认开，仅对 `malicious` / `suspicious` 判定生效）：

1. 模型输出 `category=cdn_origin`；
2. 兜底：`geo` 归属地/ISP 文本命中已知 CDN 厂商关键字（`_CDN_KEYWORDS`：
   Cloudflare、CloudFront、Fastly、Sucuri、Imperva、Incapsula、Akamai、
   阿里云 CDN、腾讯云 CDN、百度云加速、网宿、ChinaCache、KeyCDN、BunnyCDN、
   StackPath、EdgeCast、Limelight、Gcore）。

命中即 `skipped`（`reason` 标注「CDN 回源，跳过自动处置」），**不写黑名单、
不写临时封禁**。关键字只含纯 CDN 厂商，不含通用云厂商名（避免把云主机上的
攻击者也一并豁免）；关闭 `ai_cdn_guard` 可恢复原分级处置。

> 局限：frp 插件回调本身拿不到真实访客 IP（只有 `remote_addr`），因此无法在
> WAF 层封禁「真实攻击者」；CDN 场景下的 IP 级自动封禁应交给 CDN 自身
> （Cloudflare WAF 等）。本保护确保误封不会造成整站不可用。

### 5.3 安全边界：只封「送审过的 IP」（Bug D，关键）

```python
if ip not in stat:
    continue
```

**为什么**：大模型可能因**幻觉**或**提示注入**返回集合之外的 IP（例如被审查内容里
诱导出的无关地址，甚至攻击者控制的目标 IP）。若对模型返回的任意 IP 都自动封禁，
攻击者可通过构造输入诱导模型输出某个无辜 IP，从而**借 AI 之手封禁任意地址**。
故只对「本次实际送审集合」内的 IP 生效，集合外的直接丢弃。

### 5.4 不重复处置

已处置的 IP 不重复写入：

- 已在黑名单 → `already_banned`（`ip_list` 有 `UNIQUE(cidr, list_type)` 约束兜底）；
- 已在临时封禁 → 疑似场景不再 `add_ban`。否则每个审查周期都会重新插入一条记录，
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
| `ai_auto_ban` | `true` | 是否自动处置（关 = 只记录不动作） |
| `ai_ban_seconds` | 1800 | **疑似**封禁时长（秒）；确凿判定走永久黑名单 |
| `ai_suspicious_ban` | `true` | 疑似（`suspicious`）是否自动临时封禁 |
| `ai_ssh_strict` | `true` | SSH 相关（SSH 爆破 / 代理名含 ssh）是否从严 |
| `ai_ssh_permanent_suspicious` | `true` | SSH 相关疑似是否也直接永久黑名单（需 `ai_ssh_strict` 开） |
| `ai_cdn_guard` | `true` | CDN 回源保护：判定为 CDN 回源（`cdn_origin` / 厂商特征）的 IP 不自动封禁（防整站 522） |
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

`action` 取值：

| action | 含义 |
|---|---|
| `permanent` | 已加入永久黑名单（确凿 / SSH 从严） |
| `banned` | 已临时封禁（疑似，`ai_ban_seconds`） |
| `already_banned` | 已在黑名单或临时封禁中，未重复写入 |
| `skipped` | 白名单命中或 CDN 回源保护命中，跳过自动处置 |
| `ban_failed` | 写入失败（记录日志，由对账/下轮修复） |
| `none` | 判定正常 / 未开启自动处置 / 已关闭开关 |
| `skip` / `error` | 无送审对象 / 调用或解析失败 |

`verdict` 取值：`malicious` / `suspicious` / `benign` / `unknown` / `error` / `none`。
面板「AI 审查」页可查看最近 200 条（含攻击类型 `category`）。

## 10. 常见问题

| 现象 | 原因 / 处置 |
|---|---|
| 「未配置 AI 接口地址或密钥」 | 先填 `ai_base_url` + `ai_api_key` |
| 「模型返回无法解析为 JSON」 | 模型未按格式输出；换更强模型或调提示词 |
| 连接失败 / 超时 | 检查网关连通性、`ai_timeout`；网络类错误会自动重试一次 |
| 审查到 IP 但不封禁 | `ai_auto_ban` 关闭，或该 IP 已在黑名单/临时封禁中（不重复处置） |
| 疑似被永久封禁 | SSH 相关从严（`ai_ssh_strict` + `ai_ssh_permanent_suspicious`）命中；可在「IP 封禁」页解封，或用「解封全部黑名单」一键恢复 |
| 同一 IP 反复出现 | 正常：每周期都会审查；已处置的不重复封 |
| 误封了正常 IP | 到「IP 封禁」页删除对应黑名单条目（永久）或解禁（临时）；也可用「解封全部黑名单」/「解封全部临时封禁」批量恢复；必要时调整提示词/阈值 |
| CDN 边缘 IP 被判恶意 | `ai_cdn_guard` 开启时不会封禁（记 `skipped`）；若曾误封导致 522，用「解封全部黑名单」恢复 |
| 站点 522（CDN 回源超时） | 多为 CDN 边缘 IP 被误封：面板「解封全部黑名单」+「解封全部临时封禁」，确认 `ai_cdn_guard` 为开 |
