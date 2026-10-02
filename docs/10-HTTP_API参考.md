# 10 · HTTP API 参考

## 一、独立面板 API（守护进程 `7080`）

所有响应为 JSON。成功一般 `{"code":0,...}`，失败 `{"code":<非0>,"msg":...}`。
需登录的接口若会话无效返回 `401 {"code":401,"msg":"未登录或会话已过期"}`。

> 认证：`POST /api/login` 成功后下发 Cookie `frpwaf_sid`（`HttpOnly; SameSite=Lax`），
> 后续请求自动携带。

### 1. 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 入参 `{username, password}`。成功 `{code:0,user}` + Set-Cookie；失败 `401`；限速 `429` |
| POST | `/api/logout` | 清 Cookie，`{code:0}` |

### 2. 概览 / 版本

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/overview` | 统计 + 运行信息（version/uptime/各开关/admin_user/geo_available/engine_errors/frp_remote_denied） |
| GET | `/api/version` | `{code:0, version}` |

### 3. 配置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/config` | 返回配置（过滤 `secret`/`admin_password`，`ai_api_key` 掩码 `******`） |
| POST | `/api/config` | 保存白名单内的配置键（见下）。保存后立即同步内核封禁 |

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

> 窗口类参数保存时强制 ≥1：`auto_ban_window`、`auto_ban_cc_window`、
> `auto_ban_scan_window`、`auto_ban_ssh_window`。
> 突发观测/冷却：`burst_window` ≥2、`proxy_cool_seconds` ≥10（与运行时一致）、
> `proxy_cool_single_pct` ≤100。
> 防呆回退：开关开启时参数为「未设置形态」（阈值/时长 0、窗口 ≤1 秒）会在
> 加载/保存时自动回退 DEFAULTS 默认值（见 [04 §3.4.1](04-数据模型与配置项.md)），
> 保证设置页无需手填参数；停用请关闭对应开关而不是把阈值填 0。

> 注意：`http_addr`/`http_port`/`web_enabled`/`admin_*` **不**经此接口改（用宝塔插件端）。

### 4. 账号

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/password` | 入参 `{old, new, new_user, old_user}`；改用户名与/或密码 |

### 5. IP 名单

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/iplist?type=black\|white&limit=N` | 名单列表（附归属地）。返回条数上限 `PANEL_LIST_CAP=5000`，`limit` 缺省或非法时取上限（防大名单全量拉取） |
| POST | `/api/iplist` | `{action:"add", cidr, list_type, remark}` |
| POST | `/api/iplist` | `{action:"del", id}` |
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
| GET | `/api/kernban` | `{available, enabled, set4, set6, rule}` |
| POST | `/api/kernban/sync` | 手动同步；开关关闭时清理内核残留 |

### 11. AI

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/ai/review` | 最近 200 条审查记录（含 `verdict` / `action` / `reason`） |
| POST | `/api/ai/review` | 立即审查（force，**同步执行**）；返回 `{ok,msg,results,checked,banned,temp_banned}` |
| GET | `/api/ai/results` | 同 `/api/ai/review` GET |
| POST | `/api/ai/test` | 测试连接（可用表单覆盖 base/key/model/protocol） |

> `POST /api/ai/review` 在 daemon 进程内同步执行审查（与插件端 `ai_run_now`
> 的异步触发不同）；大批量送审可能耗时较长，独立 Web 端目前未提供入口，
> 日常请从宝塔插件端操作（见 [07](07-管理面板与插件功能.md)）。

> **后端存在、但独立 Web 端无 UI 的接口**：`/api/kernban`、`/api/kernban/sync`、
> `/api/ai/*`（以上接口可用 curl 直接调用，但 `web/index.html` 未提供入口，
> 日常请从宝塔插件端操作）。Web 端实际使用的只有：登录/登出、概览、版本、配置、
> 改密、名单、日志、封禁、代理统计、归属地。

### 12. frp 回调（非 API，但由同一进程提供）

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
`unban_ip(kind,ip|id)`、`ban_history`。

### 日志 / 统计 / 归属

`conn_logs(limit,offset,ip,log_action,log_proxy)`、`log_proxy_list`、
`logs_summary(window)`、`burst_status`、
`purge_conn_logs`、`proxy_stats`、`geo_query(ip)`、`geo_top(limit)`、
`geo_db_info`、`get_log(lines)`、`clear_log`。

### 策略 / 内核 / 账号

`waf_overview`、`get_policy`、`save_policy`、`kernban_status`、`kernban_sync`、
`get_admin`、`change_admin_pwd(old,new,new_user,old_user)`。

> `get_policy` / `save_policy` 的布尔键含 `auto_ban_cc_enabled` / `auto_ban_scan_enabled` /
> `auto_ban_ssh_enabled` / `proxy_cool_enabled`，整型键含三组窗口/阈值/时长参数与
> 突发观测/冷却参数（见 [04 §3.4.1 / §3.5.1](04-数据模型与配置项.md)）。

### AI

`ai_get_config`、`ai_save_config(...)`、`ai_test(...)`、`ai_run_now`（异步提交，
只写 `ai_run_requested` 并立即返回）、`ai_status`（轮询进度）、`ai_results`。

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
  "version":"1.3.9","uptime":3600,"http_addr":"0.0.0.0","http_port":7080,
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
  "ai_ssh_strict":true,"ai_ssh_permanent_suspicious":true,"ai_timeout":120, /* … */}}

// POST /api/login 成功
{"code":0,"msg":"登录成功","user":"admin"}   // 同时 Set-Cookie: frpwaf_sid=…
// POST /api/login 失败 / 限速
{"code":401,"msg":"用户名或密码错误"}
{"code":429,"msg":"尝试过于频繁，请 300 秒后再试"}

// POST /api/iplist（add / batch / 重复条目）
{"code":0,"msg":"添加成功"}
{"code":0,"msg":"导入完成：成功 3，跳过 1"}
{"code":1,"msg":"该条目已存在: 1.2.3.4/32"}

// GET /api/bans
{"code":0,"data":[{"id":1,"ip":"1.2.3.4","reason":"manual","banned_at":…,
  "expire_at":…,"released":0,"geo":"中国 广东 深圳 · 电信"}],"history":[…]}

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

# 加黑名单
curl -s -b /tmp/c.txt -X POST http://127.0.0.1:7080/api/iplist \
  -H 'Content-Type: application/json' \
  -d '{"action":"add","cidr":"1.2.3.4","list_type":"black","remark":"test"}'

# 模拟 frps 回调
curl -s -X POST 'http://127.0.0.1:7080/frp/handler?op=NewUserConn' \
  -H 'Content-Type: application/json' \
  -d '{"content":{"remote_addr":"1.2.3.4:5555","proxy_name":"web","proxy_type":"tcp","user":{"user":""}}}'
```
