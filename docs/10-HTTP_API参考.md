# 10 · HTTP API 参考

## 一、独立面板 API（守护进程 `7080`）

所有响应为 JSON。成功一般 `{"code":0,...}`，失败 `{"code":<非0>,"msg":...}`。
需登录的接口若会话无效返回 `401 {"code":401,"msg":"未登录或会话已过期"}`。

> 认证：`POST /api/login` 成功后下发 Cookie `frpwaf_sid`（`HttpOnly; SameSite=Lax`），
> 后续请求自动携带。
>
> **首登改密门禁**：`password_changed=false` 时，除 `/api/login`、`/api/password`、
> `/api/overview` 与静态页以外的 `/api/*` 一律返回
> `403 {"code":403,"msg":"需先修改默认口令","password_change_required":true}`
> （`/api/logout` 也在被拦范围内，前端已容错）。门禁在认证之后判定，
> 未登录仍只得到 `401`，不泄露「口令未改」这个状态。
>
> **并发闸门**：面板与回调各自独立（默认 96 / 32），超限的新连接被**直接断开**
> （无 503 响应体）。回调走独立监听 `127.0.0.1:7082`，只接受 `/frp/handler`。

### 1. 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 入参 `{username, password}`。成功 `{code:0,user,password_change_required}` + Set-Cookie；失败 `401`；限速 `429`（带 `Retry-After`） |
| POST | `/api/logout` | 清 Cookie，`{code:0}`（`password_changed=false` 时会被首登改密门禁拦为 `403`） |

### 2. 概览 / 版本

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/overview` | 统计 + 运行信息（version/uptime/各开关/admin_user/geo_available/engine_errors/frp_remote_denied/**invalid_addr**，以及 `http_addr`/`http_port`/`frp_handler_addr`/`frp_handler_port`/`max_concurrent`/`handler_max_concurrent`/`remote_access`/`password_change_required`/**strict_addr**/**ai_allow_private**） |
| GET | `/api/version` | `{code:0, version}` |

`invalid_addr` 是**进程内当日计数**：`remote_addr` 无法解析为 IP 的次数。它本该恒为 `0`，
持续增长说明 frps 回调格式变了、黑白名单与自动封禁正在静默失效（每次刷新还会限频记一条日志）。
配套开关 `strict_addr`（解决方式）与 `ai_allow_private` 也由本接口回传，供前端渲染开关态。

### 3. 配置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/config` | 返回配置（**剔除** `secret`/`admin_password`；`ai_api_key` 有值时为掩码 `******`、未设置为 `""`；含回显用 `http_addr`） |
| POST | `/api/config` | 保存白名单内的配置键（见下）。保存后立即同步内核封禁；改监听地址/端口/并发上限时**立即重绑并回传实际监听位**。**值等于 `******` 的机密字段被丢弃**（保留磁盘原值，不是清空） |

POST 允许的键（类型校验）：
`blacklist_enabled, whitelist_enabled, auto_ban_enabled, auto_ban_window,
auto_ban_threshold, auto_ban_seconds,
auto_ban_cc_enabled, auto_ban_cc_window, auto_ban_cc_threshold, auto_ban_cc_seconds,
auto_ban_scan_enabled, auto_ban_scan_window, auto_ban_scan_threshold, auto_ban_scan_seconds,
auto_ban_ssh_enabled, auto_ban_ssh_window, auto_ban_ssh_threshold,
rate_limit_enabled, rate_limit_per_sec,
burst_window, proxy_cool_enabled, proxy_cool_min_conns, proxy_cool_uniq_threshold,
proxy_cool_single_pct, proxy_cool_seconds,
log_max_rows, fw_sync_enabled, ai_enabled, ai_protocol, ai_base_url, ai_api_key,
ai_model, ai_interval, ai_window, ai_min_conns, ai_max_ips, ai_auto_ban,
ai_ban_seconds, ai_suspicious_ban, ai_ssh_strict, ai_ssh_permanent_suspicious,
ai_timeout`。

**本轮新增的两个开关**（不在上表里，单独用宽松布尔解析：字符串 `"false"` 不会被 `bool()` 当成 `True`）：

| 键 | 类型 | 默认 | 效果 |
|---|---|---|---|
| `strict_addr` | bool | `false` | `false` = 地址解析失败时放行（`invalid-ip-pass`）并计入 `invalid_addr`；`true` = **拒连**（`invalid-ip-strict`，fail-closed） |
| `ai_allow_private` | bool | `true` | `true` = AI 接口允许私有/回环地址（内网自建网关）；`false` = 只允许公网。link-local 与云元数据网段**不受此开关影响、永远拒绝** |

> 两键均**不需重启**（≤1 秒配置缓存过期后生效）。完整语义与「永远拒绝」的网段清单见
> [04 §3.11](04-数据模型与配置项.md) 与 [09 §4.1](09-认证与安全.md)。
> 保存时若同时改了 `ai_base_url`，会**先过 SSRF 校验**（按新提交的 `ai_allow_private` 判定），
> 不通过则整个保存被拒绝（`code:1` + 中文原因）。

**监听类键**（单独校验，不属上表布尔/整型白名单）：

| 键 | 校验 |
|---|---|
| `http_addr` | 只接受 `127.0.0.1` / `0.0.0.0` / `::1` / `::`（`localhost` 归一化为 `127.0.0.1`）；其它值明确报错**不静默回退** |
| `http_port`、`frp_handler_port` | 必须是数字且 `1~65535` |
| `max_concurrent`、`handler_max_concurrent` | 整型，钳制到 `[8, 512]` |
| 端口冲突 | 面板端口 ≠ 回调端口；回调端口 ≠ 拦截页端口（否则 `code:1` 报错） |
| `block_page_addr` | 字符串（拦截页监听地址） |

> 窗口类参数保存时强制 ≥1：`auto_ban_window`、`auto_ban_cc_window`、
> `auto_ban_scan_window`、`auto_ban_ssh_window`。
> 突发观测/冷却：`burst_window` ≥2、`proxy_cool_seconds` ≥10（与运行时一致）、
> `proxy_cool_single_pct` ≤100。
> 防呆回退：开关开启时参数为「未设置形态」（阈值/时长 0、窗口 ≤1 秒）会在
> 加载/保存时自动回退 DEFAULTS 默认值（见 [04 §3.4.1](04-数据模型与配置项.md)），
> 保证设置页无需手填参数；停用请关闭对应开关而不是把阈值填 0。

> 注意：`web_enabled`/`admin_*` **不**经此接口改（用宝塔插件端）；`http_addr`/`http_port`/
> `frp_handler_port`/`max_concurrent`/`handler_max_concurrent` **可以**经此接口改
> （网页端「设置 → 监听与安全」）。

### 4. 账号

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/password` | 入参 `{old, new, new_user, old_user}`；改用户名与/或密码。成功后写 `password_changed=true`（门禁按口令实值对齐，写错也不会误放行）；新口令不得为 `123456` |

### 5. IP 名单

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/iplist?type=black\|white&limit=N` | 名单列表（附归属地）。返回条数上限 `PANEL_LIST_CAP=5000`，`limit` 缺省或非法时取上限（防大名单全量拉取） |
| POST | `/api/iplist` | `{action:"add", cidr, list_type, remark}` |
| POST | `/api/iplist` | `{action:"del", id}` |
| POST | `/api/iplist` | `{action:"clear_black"}` **一键解封全部黑名单**（只清 black，不动白名单；刷新规则缓存 + 内核同步；返回 `已解封全部黑名单（N 条）`） |
| POST | `/api/iplist` | `{action:"batch", text, list_type}`（每行 `cidr[,备注]`，`#` 注释） |

### 6. 连接日志

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/logs?limit&offset&ip&action&proxy` | 日志 + `total`（limit ≤1000） |
| POST | `/api/logs` | `{action:"purge"}` 清空 |
| GET | `/api/logs/proxies` | 日志中出现过的代理名 |
| GET | `/api/logs/summary?window` | 按代理聚合（window 钳制 60~86400，默认 3600）：`conns/uniq_ips/single_ips/single_pct/rejected/last_ts/proxy_type` |
| GET | `/api/burst` | 突发观测快照（代理级指标 + 定性 `level` + `cool_remain`）与冷却阈值配置 `config`；插件端 `burst_status` 经守护进程每 10s 落盘的 `data/burst_snapshot.json` 读取（附 `ts`/`stale`） |

### 7. 封禁

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/bans` | `{data: 生效封禁, history: 历史}`（附归属地） |
| POST | `/api/bans` | `{action:"unban", ip}` |
| POST | `/api/bans` | `{action:"unban_all"}` **一键解封全部生效中的临时封禁**（与黑名单解封独立；返回 `已解封全部临时封禁（N 条）`） |
| POST | `/api/bans` | `{action:"ban", ip, seconds}`（无效 IP 返回 `{code:1,msg}`） |

### 8. 代理统计

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/proxies` | 每个代理的累计统计 |

### 9. 归属地

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/geo?ip=` | 单 IP 归属地 + 连接次数 |
| GET | `/api/geo/db` | 归属地库状态（available/path/size） |

### 10. 内核封禁

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/kernban` | `{available, enabled, mode, set4, set6, rule, redirect, redirect_ports}`（`mode`: `drop` / `redirect` / `off`） |
| POST | `/api/kernban/sync` | 按开关同步（DROP / nat REDIRECT / 清理）；写审计日志 |

### 11. AI

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/ai/review` | 最近 200 条审查记录（含 `verdict` / `action` / `reason`） |
| POST | `/api/ai/review` | 立即审查（force，**同步执行**）；返回 `{ok,msg,results,checked,banned,temp_banned}` |
| GET | `/api/ai/results` | 同 `/api/ai/review` GET |
| POST | `/api/ai/test` | 测试连接（可用表单覆盖 base/key/model/protocol）。**只提交后台任务并立即返回**，不再同步返回测试结果：`{code:0,msg:"已提交后台执行，正在调用模型…",data:{job_id,started:true}}`；同类任务已在跑时 `code:1` |
| GET | `/api/ai/test/status` | 轮询测试连接任务状态 `{code:0,data:{…job 状态…}}`（字段与语义见 §12.1） |

> `POST /api/ai/review` 在 daemon 进程内同步执行审查（与插件端 `ai_run_now`
> 的异步触发不同）；大批量送审可能耗时较长。独立 Web 端自 2026-10 起已在
> 「AI 审查」页提供「立即审查」入口（`aiRunNow`，二次确认 + 写审计）；
> 大批量场景仍建议从宝塔插件端操作（见 [07](07-管理面板与插件功能.md)）。

> **Web 端无专属 UI 的接口**：`/api/blockpage`（拦截页服务状态，诊断用）、
> `/api/version`、`/api/ai/results`
> （`/api/ai/review` GET 的别名）、`/api/metrics` 与 `/api/export`
> （双端都没有按钮，用 curl 直接调，见 §13）。其余 `/api/kernban`、`/api/ai/review`、
> `/api/service`、`/api/syslog`、`/api/about`、`/api/upgrade/*` 自 2026-10 起均已在
> `web/index.html` 提供入口。仍仅插件端可用的能力是 frp 管理、frps 集成注入、
> 网页端开关/改端口、静态拦截页开关（依赖宝塔面板上下文与 root 流程）。

### 12. 关于 / 运行日志 / 服务控制 / 在线升级 / 拦截页

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/about` | `{name, version, author, repo, license, runtime}` |
| GET | `/api/syslog?limit=N` | `data/frpwaf.log` 尾部（limit 1~2000，默认 200）→ `{lines, total}` |
| POST | `/api/service` | `{action:"restart"\|"stop"}`；延迟约 2s 执行（避免当前请求被自身重启打断）；写审计 |
| GET | `/api/upgrade/check` | 检查 GitHub 最新版本（取 `github_repo`；POST 时可用入参 `repo` **仅做只读对比**）→ `{ok,current,latest,has_update,tarball,url,notes,pkg,asset_names}`；`pkg` 为可校验的发布包（`{name,url,size,sha256,hash_source}`），无锤点时返回 `verify_hint`（「该发布缺少校验信息…」） |
| POST | `/api/upgrade/apply` | **提交**在线升级任务（选定带 sha256 锤点的包 → 下载校验 → 解包+结构校验 → 备份 → 覆盖程序 → 重启；失败自动回滚，**不覆盖 data/**）；写审计。**立即返回 job 状态，不再返回升级结果**：`{code:0,msg:"升级任务已提交，正在后台执行（可轮询进度）",data:{job_id,started:true}}`。**仓库只取配置 `github_repo`**，请求体的 `repo` 被忽略（不一致会写一条拒绝审计）。**发布缺校验锤点时升级会在后台失败**（任务状态 `ok:false` + 「该发布缺少校验信息…」）；升级备份只保留最近 3 份并清理包内已不存在的陈旧 `.py` |
| GET | `/api/upgrade/status` | 轮询升级任务状态 `{code:0,data:{…job 状态…}}`（字段与语义见 §12.1） |
| GET | `/api/blockpage` | 拦截页服务状态 `{enabled, running, port}` |

#### 12.1 异步任务（提交 + 轮询）与 job 状态结构

`POST /api/upgrade/apply` 与 `POST /api/ai/test` 都是**长耗时**操作（升级要下载几十 MB、
覆盖几百个文件再重启；模型调用上限 120s），同步执行必然先撞上反向代理/宝塔面板的
**60s 超时**——用户看到「失败」，后台其实已经成功。因此这两个接口改为
**提交 + 轮询**（实现见 `app/job.py`）：

1. `POST` 接口只做**入参校验**（仓库配置、AI 地址 SSRF 校验等，仍在请求线程内）
   并把任务交给后台线程，**立刻**返回 `{code:0, msg, data:{job_id, started:true}}`；
2. 调用方拿 `data.job_id` 去对应的 `status` 端点轮询，直到 `done=true`；
3. 两个 `status` 端点都是 `GET`，都**需要登录**（走统一 `/api/*` 门禁，未登录 `401`；
   `password_changed=false` 时同样被首登改密门禁拦为 `403`），无入参。

> **这是一次 API 行为变更**：老调用方若还按「一次 POST 拿最终结果」使用，拿到的只是
> 「已提交」，需要改成「提交 → 轮询 status」，见 [13 §10.6](13-变更历史与版本.md)。

状态字段（`data` 内容，`app/job.py` 的字段契约；新增字段只追加不改语义）：

| 字段 | 类型 | 含义 |
|---|---|---|
| `job_id` | string | 本次任务标识（形如 `upgrade-1793000000-1a2b`），提交时返回，用于对账 |
| `kind` | string | 任务类型：`upgrade` / `ai_test`（与状态文件名一致） |
| `running` | bool | 是否正在执行 |
| `percent` | int | 0~100 的**粗略**进度（升级只有 5/100 两个分段，其余靠前端显示「已等待 N 秒」） |
| `msg` | string | 给用户看的中文阶段说明（进行中/成功/失败都用它） |
| `done` | bool | 是否已结束（成功、失败、中断都置 `true`） |
| `ok` | bool | 结束时是否成功（**未结束时恒为 `false`**；`ok=true` 只表示任务成功结束，升级场景「已是最新版本」也是 `ok=true`） |
| `error` | string | 失败原因（成功时为空串） |
| `ts` | int | 心跳时间戳（epoch 秒），供僵死判定，前端可忽略 |
| `started` | int | 开始时间戳（epoch 秒） |
| `finished` | int | 结束时间戳（epoch 秒，未结束为 `0`） |
| `ms` | int | 总耗时（毫秒，未结束为 `0`；按秒级时间差换算，非精确计时） |

升级任务结束时还会并入 `from` / `to` / `sha256`（来自 `upgrade.apply()` 的返回值），
可用于确认「到底有没有换版本」。

**并发语义（同类任务串行）**：同一 `kind` 同一时刻只允许一个任务在跑。已有任务时
第二个提交被拒，返回 `{code:1, msg:"已有任务在进行中（<当前阶段说明>），请等待完成"}`——
`msg` 括号里就是正在跑那条任务的 `msg`（如「正在调用模型…」/「检查更新…」）。
僵死任务（见下）**不算**占用，避免一次面板重启后永久拒绝提交。

**僵死判定**：后台线程每 10 秒刷一次 `ts`（`app/job.py` 的 `HEARTBEAT`）；`running=true`
而 `ts` 超过 60 秒没更新（`STALE`），说明执行线程已随进程消失（面板重启/被 kill），
状态会被改写为 `running:false, done:true, ok:false`，`msg`/`error` 均为
「任务状态已中断（服务可能重启过），请刷新页面确认最终结果」——前端因此能收尾，
不会永远转圈。任务执行到末尾时服务会重启（升级场景自带重启），所以这条文案说的是
**「中断或已重启，请自行确认」**，而不是断言失败。

示例：

```jsonc
// POST /api/upgrade/apply（提交成功：不含升级结果）
{"code":0,"msg":"升级任务已提交，正在后台执行（可轮询进度）",
 "data":{"job_id":"upgrade-1793000000-1a2b","started":true}}
// POST /api/upgrade/apply（同类任务已在跑：拒绝提交）
{"code":1,"msg":"已有任务在进行中（检查更新…），请等待完成"}

// GET /api/upgrade/status：从未提交过（空状态）
{"code":0,"data":{"job_id":"","kind":"upgrade","running":false,"percent":0,
 "msg":"","done":false,"ok":false,"error":"","ts":0,"started":0,"finished":0,"ms":0}}
// GET /api/upgrade/status：进行中
{"code":0,"data":{"job_id":"upgrade-1793000000-1a2b","kind":"upgrade","running":true,
 "percent":5,"msg":"检查更新、下载并校验发布包…","done":false,"ok":false,"error":"",
 "ts":1793000010,"started":1793000000,"finished":0,"ms":0}}
// GET /api/upgrade/status：结束（成功）
{"code":0,"data":{"job_id":"upgrade-1793000000-1a2b","kind":"upgrade","running":false,
 "percent":100,"msg":"已升级到 1.4.3，服务即将重启","done":true,"ok":true,"error":"",
 "ts":1793000090,"started":1793000000,"finished":1793000090,"ms":90000,
 "from":"1.4.2","to":"1.4.3","sha256":"…"}}
```

> **轮询节奏**（双端前端一致，可直接照抄）：间隔 1500ms（插件端首次 800ms 起轮询），
> 最长等 10 分钟；**升级末尾会重启服务，重启窗口内的请求必然失败**，所以请求失败要
> 容忍——插件端连续 8 次（约 16s）、Web 端连续 20 次（约 30s）才判定为取不到状态。
> 提交阶段的失败（未配置仓库 / 地址非法 / 已有任务）**不会**进入轮询，直接 `code:1` 返回。

### 13. 运行指标 / 数据导出

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/metrics` | 进程内失败计数 + `uptime_s`（纯内存，重启清零） |
| GET | `/api/export` | 导出名单 / 封禁历史 / 配置（机密掩码），带 `Content-Disposition` |

#### 13.1 `GET /api/metrics`

响应把同一份计数**平铺在顶层**又**镜像进 `data`**（面板侧统一读 `data` 也不会踩空）：

```jsonc
{"code":0, "engine_errors":0, "invalid_addr":0, "db_write_fail":0, "fw_sync_fail":0,
 "fw_sync_ms":12, "ai_call_ms":0, "frp_remote_denied":0, "ai_fail":0, "db_backup_fail":0,
 "uptime_s":86400, "data":{"engine_errors":0, /* …同上…, */ "uptime_s":86400}}
```

| 字段 | 含义 |
|---|---|
| `engine_errors` | 决策引擎在回调路径抛异常的次数（**本该恒为 0**，增长说明准入判定在某条分支上崩了） |
| `invalid_addr` | `remote_addr` 无法解析为 IP 的次数（应与 `strict_addr` 配合观察，见 §2） |
| `db_write_fail` | 写库失败次数（封禁/日志未真正落库） |
| `fw_sync_fail` | 内核封禁（ipset/iptables）同步失败次数 |
| `fw_sync_ms` | **最近一次**内核同步耗时（毫秒，非累计；无数据为 0） |
| `ai_call_ms` | **最近一次** AI 调用耗时（毫秒，非累计；无数据为 0） |
| `ai_fail` | AI 调用失败次数 |
| `frp_remote_denied` | 非本机来源访问 `/frp/handler` 被拒（403）的次数 |
| `db_backup_fail` | **数据库自动快照备份失败次数**（含磁盘空间不足跳过）；持续增长意味着「删库/误清理后没有回退点」，排查见 [11 §3](11-开发运维与常见问题.md) |
| `uptime_s` | 本进程模块加载至今的秒数（≈服务运行时长） |

> 全部计数都是**进程内内存值**：重启即清零，不落库、不分天。所以「重启后指标归零」
> 是预期行为，不是接口故障。字段名属于接口契约（面板与监控脚本按名取值），不随意改名。

#### 13.2 `GET /api/export`

- **需登录**（走统一的 `/api/*` 门禁，未登录 `401`）；`password_changed=false` 时同样被
  首登改密门禁拦为 `403`（不在豁免名单里）。
- **只支持 GET**，其它方法返回 `405 {"code":1,"msg":"导出仅支持 GET"}`。
- 无入参（不接受筛选/分页参数）。
- 走 store 的**只读连接**（`export_rows()`），不占全局写锁：导出期间回调请求照常写入，
  不会因为一次导出就把准入请求堵在锁上。两次列表查询各自独立，**不是**跨表一致事务快照。
- 响应带 `Content-Disposition: attachment; filename="frpwaf-export-YYYYMMDD-HHMMSS.json"`：
  浏览器点开链接即**直接存成文件**（而不是在标签页里渲染一大坨 JSON）。文件名里的时间戳
  取导出时刻（本地时区，秒精度）。

返回体：

```jsonc
{
  "ok": true,
  "exported_at": 1793000000,          // epoch 秒
  "ip_list": [                        // 全部名单（黑 + 白，按 id 升序），无条数上限
    {"cidr":"1.2.3.4/32", "list_type":"black", "remark":"手动封禁", "created_at":1792000000}
  ],
  "bans": [                            // 封禁历史，按 id 倒序取最近 20000 条
    {"ip":"5.6.7.8", "reason":"manual", "banned_at":1792000000,
     "expire_at":1792003600, "released":0}
  ],
  "config_masked": { /* 全量配置，机密字段已掩码 */ }
}
```

| 字段 | 含义 |
|---|---|
| `ok` | 恒为 `true`（失败走 `code`/HTTP 错误，本接口不返回 `code`） |
| `exported_at` | 导出时刻，epoch **秒**（整数） |
| `ip_list` | 全量名单：`cidr`（已规范化，单个 IP 带 `/32` 或 `/128`）、`list_type`（`black`/`white`）、`remark`、`created_at`（epoch 秒）。**不含自增 `id`**（跨库迁移时 id 无意义） |
| `bans` | 封禁历史（含已释放）：`ip`、`reason`、`banned_at`/`expire_at`（epoch 秒）、`released`（`0` 生效中 / `1` 已释放）。**按 `id` 倒序取最近 20000 条**，历史更久的不在导出内 |
| `config_masked` | 全量配置（含 `admin_user`、各开关与参数），**机密字段掩码**，见下 |

**机密字段掩码**：`ai_api_key`、`admin_password`、`secret` 三个键一律输出 `******`；
**空值保持空串**（不留掩码）——否则「配了一个密钥」和「没配」在导出文件里长得一样。
掩码是单向的：导出文件不能回灌成配置（`POST /api/config` 收到 `******` 会丢弃、保留磁盘原值）。

> 为什么要掩码：导出文件通常会被丢进聊天工具/工单当附件传来传去，一次「点一下导出」
> 就把 root 级口令与 AI 密钥落进下载目录，是最容易忽略的凭据外泄路径。
> 真实值请从 `/opt/frpwaf/data/frpwaf.json` 取（`chmod 600`）。

### 14. frp 回调（非 API，但由同一进程提供）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/frp/handler?op=NewUserConn` | frps 回调；返回 `{"reject":bool,...}` |

---

## 二、宝塔插件端接口

路由：`?action=a&name=frpwaf&s=<method>`（GET 或 POST，视方法）。返回结构
由 `public.returnMsg` 或字典决定。

- **`name=frpwaf`** 是宝塔用来定位插件目录（`/www/server/panel/plugin/frpwaf`）的固定参数，
  前端由 `bt_tools.send({url:'/plugin?action=a&name=frpwaf&s=<method>', data:{...}})` 发出。
- **`action=a`** 是宝塔路由约定，恒为 `a`（见下方「参数命名坑」）。

> **参数命名坑**：宝塔路由固定带 `action=a`，会污染 `get.action`。凡「按 action 过滤」
> 一律改名：日志动作用 **`log_action`**，代理筛选用 **`log_proxy`**。

### 状态 / 安装 / 服务

`get_waf_info`、`install_waf`、`reinstall_waf`、`uninstall_waf`、`waf_admin(status)`、
`web_toggle(enabled)`、`set_web_port(port)`。

### frps 集成

`get_frps_status`、`apply_to_frps`。

### frp 管理（`kind=frps|frpc`）

`frp_info`、`frp_latest`、`frp_install_start(version)`、`frp_install_status`、
`frp_control(status)`、`frp_uninstall`、`frp_rollback`、`frp_get_config`、
`frp_ensure_config`、`frp_save_config(data)`、`frp_save_raw(content)`、
`frp_verify`、`frp_log(lines)`、`frp_release_ports`。

### 名单 / 封禁

`list_ips(type)`、`add_ip_entry(cidr,list_type,remark)`、`del_ip_entry(id)`、
`batch_import_ips(text,list_type)`、`list_bans`、`ban_ip(ip,mode,remark,seconds)`、
`unban_ip(kind,ip|id)`、`unban_all_black`（一键解封全部黑名单）、
`unban_all_temp`（一键解封全部临时封禁）、`ban_history`。

### 日志 / 统计 / 归属

`conn_logs(limit,offset,ip,log_action,log_proxy)`、`log_proxy_list`、
`logs_summary(window)`、`burst_status`、
`purge_conn_logs`、`proxy_stats`、`geo_query(ip)`、`geo_top(limit)`、
`geo_db_info`、`get_log(lines)`、`clear_log`。

### 策略 / 内核 / 账号

`waf_overview`、`get_policy`、`save_policy`、`kernban_status`、`kernban_sync`、
`get_admin`、`change_admin_pwd(old,new,new_user,old_user)`、
`about`、`upgrade_check`、`upgrade_apply`（**提交后台任务**，立即返回 `data`=job 状态）、
`upgrade_status`（轮询升级任务状态）。

> `get_policy` / `save_policy` 的布尔键含 `auto_ban_cc_enabled` / `auto_ban_scan_enabled` /
> `auto_ban_ssh_enabled` / `proxy_cool_enabled` / `block_page_enabled` / `block_page_ban_enabled` /
> `block_page_risk_enabled` / `block_page_404_enabled`，整型键含三组窗口/阈值/时长参数、
> 突发观测/冷却参数与 `block_page_port`，字符串键含 `github_repo` / `block_page_redirect_ports`
> （见 [04 §3.4.1 / §3.5.1 / §3.7.1 / §3.10](04-数据模型与配置项.md)）。

### AI

`ai_get_config`、`ai_save_config(...)`、`ai_test(...)`（**提交后台任务**，立即返回
`data`=job 状态；SSRF 校验仍在提交阶段完成）、`ai_test_status`（轮询测试连接任务状态）、
`ai_run_now`（异步提交，只写 `ai_run_requested` 并立即返回）、`ai_status`（轮询进度）、
`ai_results`。

> `upgrade_status` / `ai_test_status` 返回的是 `{status:true, data:{…job 状态…}}`，
> 字段与守护进程的 `/api/upgrade/status`、`/api/ai/test/status` **完全一致**（读的是同一个
> `data/job_<kind>.json`），见 §12.1。

---

## 三、返回约定

**Web API**：`{"code":0, ...}` 成功；`{"code":<非0>, "msg":...}` 失败。
列表类返回 `{"code":0, "data":[...]}`，分页额外带 `total`。

**插件端**：`public.returnMsg(True/False, msg)` → `{"status":true/false, "msg":...}`；
数据类方法直接返回 `{"status":true, "data":...}`。

### 完整返回示例

```jsonc
// GET /api/overview
{"code":0,"data":{
  "total_conns":1234,"today_conns":56,"today_rejected":7,"today_uniq_ip":12,
  "black_count":4,"white_count":0,"active_bans":1,
  "version":"1.4.2","uptime":3600,"http_addr":"127.0.0.1","http_port":7080,
  "frp_handler_addr":"127.0.0.1","frp_handler_port":7082,
  "max_concurrent":96,"handler_max_concurrent":32,
  "remote_access":false,"password_change_required":false,
  "blacklist_enabled":true,"whitelist_enabled":false,"auto_ban_enabled":false,
  "rate_limit_enabled":false,"admin_user":"admin","geo_available":true,
  "auto_ban_cc_enabled":true,"auto_ban_scan_enabled":true,"auto_ban_ssh_enabled":true,
  "proxy_cool_enabled":false,
  "engine_errors":0,"frp_remote_denied":0}}

// GET /api/config（机密已过滤/掩码）
{"code":0,"data":{
  "blacklist_enabled":true,"whitelist_enabled":false,"fw_sync_enabled":true,
  "auto_ban_enabled":false,"auto_ban_window":60,"auto_ban_threshold":200,
  "auto_ban_seconds":600,
  "auto_ban_cc_enabled":true,"auto_ban_cc_window":60,"auto_ban_cc_threshold":300,"auto_ban_cc_seconds":600,
  "auto_ban_scan_enabled":true,"auto_ban_scan_window":60,"auto_ban_scan_threshold":20,"auto_ban_scan_seconds":600,
  "auto_ban_ssh_enabled":true,"auto_ban_ssh_window":60,"auto_ban_ssh_threshold":20,
  "rate_limit_enabled":false,"rate_limit_per_sec":0,
  "burst_window":60,"proxy_cool_enabled":false,"proxy_cool_min_conns":300,
  "proxy_cool_uniq_threshold":200,"proxy_cool_single_pct":80,"proxy_cool_seconds":60,
  "log_max_rows":200000,"ai_enabled":false,"ai_protocol":"openai",
  "ai_base_url":"","ai_api_key":"","ai_model":"claude-haiku-4.5",
  "ai_auto_ban":true,"ai_ban_seconds":1800,"ai_suspicious_ban":true,
  "ai_ssh_strict":true,"ai_ssh_permanent_suspicious":true,"ai_cdn_guard":true,
  "ai_timeout":120, /* … */}}

// POST /api/login 成功
{"code":0,"msg":"登录成功","user":"admin","password_change_required":false}   // 同时 Set-Cookie: frpwaf_sid=…
// POST /api/login 失败 / 限速（429 带 Retry-After）
{"code":401,"msg":"用户名或密码错误"}
{"code":429,"msg":"尝试过于频繁，请 300 秒后再试"}

// 首登改密门禁（password_changed=false 时非白名单 API）
{"code":403,"msg":"需先修改默认口令","password_change_required":true}

// POST /api/config（监听类）——失败示例不回退、直接报错
{"code":1,"msg":"监听地址只能是 127.0.0.1 / 0.0.0.0 / ::1 / :: 之一（当前输入 '10.0.0.5'）；其它地址请直接修改 data/frpwaf.json 后重启服务"}
{"code":1,"msg":"面板端口与回调端口不能相同（均为 7080）"}
{"code":0,"msg":"保存成功，面板当前监听 127.0.0.1:7080（并发上限 96）","data":{…}}

// POST /api/upgrade/apply（拒绝升级）
{"code":1,"msg":"该发布缺少校验信息：Release 里没有带 digest 的发布包资产，也没有 SHA256SUMS / pkg.sha256 校验文件，无法安全升级"}

// POST /api/iplist（add / batch / 重复条目）
{"code":0,"msg":"添加成功"}
{"code":0,"msg":"导入完成：成功 3，跳过 1"}
{"code":1,"msg":"该条目已存在: 1.2.3.4/32"}

// POST /api/iplist（clear_black）/ POST /api/bans（unban_all）
{"code":0,"msg":"已解封全部黑名单（12 条）"}
{"code":0,"msg":"已解封全部临时封禁（3 条）"}

// GET /api/bans
{"code":0,"data":[{"id":1,"ip":"1.2.3.4","reason":"manual","banned_at":…,
  "expire_at":…,"released":0,"geo":"中国 广东 深圳 · 电信"}],"history":[…]}

// GET /api/metrics（纯内存计数，重启清零；顶层与 data 各一份）
{"code":0,"engine_errors":0,"invalid_addr":0,"db_write_fail":0,"fw_sync_fail":0,
 "fw_sync_ms":8,"ai_call_ms":0,"frp_remote_denied":0,"ai_fail":0,"db_backup_fail":0,
 "uptime_s":172800,"data":{…同上…}}

// GET /api/export（机密字段已掩码；响应头带 Content-Disposition: attachment）
{"ok":true,"exported_at":1793000000,
 "ip_list":[{"cidr":"1.2.3.4/32","list_type":"black","remark":"手动封禁","created_at":1792000000}],
 "bans":[{"ip":"5.6.7.8","reason":"manual","banned_at":1792000000,
          "expire_at":1792003600,"released":0}],
 "config_masked":{"admin_user":"admin","ai_enabled":false,
                  "ai_api_key":"******","admin_password":"******","secret":""}}

// 错误
{"code":404,"msg":"接口不存在"}
{"code":500,"msg":"服务器内部错误"}   // 不回显 detail（仅写入运行日志）

// POST /frp/handler
{"reject":false,"unchange":true}
{"reject":true,"reject_reason":"blacklist"}
```

## 四、示例

```bash
# 登录（保存 cookie）
curl -s -c /tmp/c.txt -X POST http://127.0.0.1:7080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"123456"}'

# 查概览
curl -s -b /tmp/c.txt http://127.0.0.1:7080/api/overview

# 运行指标（失败计数 / 备份失败次数）
curl -s -b /tmp/c.txt http://127.0.0.1:7080/api/metrics

# 导出名单+封禁+配置（-OJ 按响应头里的文件名直接存盘；机密字段为 ******）
curl -s -OJ -b /tmp/c.txt http://127.0.0.1:7080/api/export

# 加黑名单
curl -s -b /tmp/c.txt -X POST http://127.0.0.1:7080/api/iplist \
  -H 'Content-Type: application/json' \
  -d '{"action":"add","cidr":"1.2.3.4","list_type":"black","remark":"test"}'

# 模拟 frps 回调（回调专用监听，默认 7082；旧配置回退 7080）
curl -s -X POST 'http://127.0.0.1:7082/frp/handler?op=NewUserConn' \
  -H 'Content-Type: application/json' \
  -d '{"content":{"remote_addr":"1.2.3.4:5555","proxy_name":"web","proxy_type":"tcp","user":{"user":""}}}'
```
