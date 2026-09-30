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
| GET | `/api/overview` | 统计 + 运行信息（version/uptime/各开关/admin_user/geo_available） |
| GET | `/api/version` | `{code:0, version}` |

### 3. 配置

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/config` | 返回配置（过滤 `secret`/`admin_password`，`ai_api_key` 掩码 `******`） |
| POST | `/api/config` | 保存白名单内的配置键（见下）。保存后立即同步内核封禁 |

POST 允许的键（类型校验）：
`blacklist_enabled, whitelist_enabled, auto_ban_enabled, auto_ban_window,
auto_ban_threshold, auto_ban_seconds, rate_limit_enabled, rate_limit_per_sec,
log_max_rows, fw_sync_enabled, ai_enabled, ai_protocol, ai_base_url, ai_api_key,
ai_model, ai_interval, ai_window, ai_min_conns, ai_max_ips, ai_auto_ban,
ai_ban_seconds, ai_timeout`。

> 注意：`http_addr`/`http_port`/`web_enabled`/`admin_*` **不**经此接口改（用宝塔插件端）。

### 4. 账号

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/password` | 入参 `{old, new, new_user, old_user}`；改用户名与/或密码 |

### 5. IP 名单

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/iplist?type=black\|white` | 名单列表（附归属地） |
| POST | `/api/iplist` | `{action:"add", cidr, list_type, remark}` |
| POST | `/api/iplist` | `{action:"del", id}` |
| POST | `/api/iplist` | `{action:"batch", text, list_type}`（每行 `cidr[,备注]`，`#` 注释） |

### 6. 连接日志

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/logs?limit&offset&ip&action&proxy` | 日志 + `total`（limit ≤1000） |
| POST | `/api/logs` | `{action:"purge"}` 清空 |
| GET | `/api/logs/proxies` | 日志中出现过的代理名 |

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
| GET | `/api/ai/review` | 最近 200 条审查记录 |
| POST | `/api/ai/review` | 立即审查（force） |
| GET | `/api/ai/results` | 同 `/api/ai/review` GET |
| POST | `/api/ai/test` | 测试连接（可用表单覆盖 base/key/model/protocol） |

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
`purge_conn_logs`、`proxy_stats`、`geo_query(ip)`、`geo_top(limit)`、
`geo_db_info`、`get_log(lines)`、`clear_log`。

### 策略 / 内核 / 账号

`waf_overview`、`get_policy`、`save_policy`、`kernban_status`、`kernban_sync`、
`get_admin`、`change_admin_pwd(old,new,new_user,old_user)`。

### AI

`ai_get_config`、`ai_save_config(...)`、`ai_test(...)`、`ai_run_now`、`ai_results`。

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
  "rate_limit_enabled":false,"admin_user":"admin","geo_available":true}}

// GET /api/config（机密已过滤/掩码）
{"code":0,"data":{
  "blacklist_enabled":true,"whitelist_enabled":false,"fw_sync_enabled":true,
  "auto_ban_enabled":false,"auto_ban_window":60,"auto_ban_threshold":200,
  "auto_ban_seconds":600,"rate_limit_enabled":false,"rate_limit_per_sec":0,
  "log_max_rows":50000,"ai_enabled":false,"ai_protocol":"openai",
  "ai_base_url":"","ai_api_key":"","ai_model":"claude-haiku-4.5", /* … */}}

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
{"code":500,"msg":"服务器内部错误","detail":"…traceback…"}

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
