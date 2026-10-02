# FRP WAF

基于 **frp `httpPlugins`** 的 IP 准入控制防火墙，以 **宝塔面板插件** 形式安装，提供独立管理面板。

对访问 frps 代理端口的来源 IP 做黑/白名单、手动封禁、自动封禁与限速，并记录连接审计日志。

---

## 目录结构

```
/opt/frpwaf/                    项目源码 & 运行目录（数据在这里）
├── app/
│   ├── __init__.py
│   ├── config.py               配置读写（data/frpwaf.json）
│   ├── store.py                SQLite 存储层
│   ├── engine.py               准入决策引擎
│   ├── firewall.py             内核级封禁同步（ipset + iptables）
│   ├── frp.py                  frp 服务端/客户端管理（合并官方 frp管理器）
│   ├── toml_lite.py            TOML 解析/生成（纯标准库，供 frp 配置读写）
│   ├── ai.py                   AI 自动 IP 审查
│   ├── geo.py                  IP 归属地查询
│   ├── auth.py                 登录/会话（HMAC 签名 Cookie）
│   └── daemon.py               守护进程（插件回调 + 管理 API + 静态页）
├── web/index.html              独立管理面板（SPA）
├── data/                       运行时数据（SQLite / 配置 / 日志 / PID）
│   ├── frpwaf.db               名单、日志、封禁、统计
│   └── frpwaf.json             配置（含管理员密码）
├── frpwaf_main.py              插件后端（public 接口）
├── index.html                  插件前端（宝塔面板内嵌页）
├── info.json                   插件元信息
├── install.sh                  插件安装/卸载脚本
├── uninstall.sh                插件卸载脚本
├── frpwaf.init                 服务启动脚本（/etc/init.d/frpwaf）
├── build.sh                    组装 & 打包 & 安装插件
└── README.md

/www/server/panel/plugin/frpwaf/   宝塔插件安装位置（由 build.sh install 生成）
```

> **插件包根目录 = 本仓库根目录**。宝塔「上传安装」会扫描压缩包，取同时含
> `info.json` + `install.sh` 的目录作为插件根，并把其下内容原样拷入
> `/www/server/panel/plugin/frpwaf/`。因此压缩包**根目录**必须直接包含
> `app/`、`web/`、`frpwaf_main.py`、`info.json` 等（不能再多套一层文件夹），
> 否则 `app/` 会缺失，点击插件即报 `FileNotFoundError: .../app/__init__.py`。
> 用 `bash build.sh zip` 生成的 `dist/frpwaf.zip` 即为可直接上传的成品。

---

## 打包 / 上传安装

```bash
cd /opt/frpwaf

# 生成可直接上传的插件 zip（结构：zip 根目录下就是 app/ web/ info.json ...）
bash build.sh zip
# -> /opt/frpwaf/dist/frpwaf.zip

# 或直接安装到本机宝塔插件目录
bash build.sh install
```

宝塔面板 → 软件商店 → 第三方插件 → **上传安装**，选择 `dist/frpwaf.zip` 即可。

---

## 访问与账号

| 项目 | 值 |
|---|---|
| 管理面板 | `http://<服务器IP>:7080/` |
| 账号 | `admin`（默认，可在面板内修改） |
| 密码 | `123456`（默认，**请安装后立即修改**） |
| 插件回调 | `http://127.0.0.1:7080/frp/handler` |

> 宝塔面板 → 软件商店 → 已安装/第三方插件 中会出现「FRP WAF 防火墙」。

---

## 工作原理

1. `frps.toml` 中注入：

   ```toml
   [[httpPlugins]]
   name = "frpwaf"
   addr = "127.0.0.1:7080"
   path = "/frp/handler"
   ops = ["NewUserConn"]
   ```

2. 每次有用户访问代理端口，frps 会 POST 请求到 `/frp/handler?op=NewUserConn`，
   body 含 `content.remote_addr`（来源 IP:端口）、`proxy_name` 等。

3. WAF 按以下顺序决策并返回 `{"reject": true/false}`：

   ```
   白名单命中 → allow
   黑名单命中 → reject
   生效封禁中 → reject
   限速超限   → reject
   自动封禁触发 → reject
   其余       → allow
   ```

4. frps 收到 `reject: true` 即拒绝该连接。

> ⚠️ **fail-closed**：若 WAF 进程不可用，frps 会拒绝**所有**用户连接（frp 官方行为）。
> 因此请勿随意停止 frpwaf 服务；需要停用时，请先在插件里移除 frps 的 httpPlugins 配置。

---

## 为什么封禁后「连接数」还在涨？（内核级封禁）

frp 的 `httpPlugins` 是**应用层**准入：被拒绝的连接，其 **TCP 连接仍会被内核接受**，
只是随后被 frps 断开。因此被禁 IP 仍能不停发起新连接，导致：

- `conn_log` / `proxy_stat` 的「连接数」持续上涨（每次重试都记一条）
- 白白消耗 frps 与 WAF 的 CPU、连接资源

> 注意：这只是**计数在涨**，被禁 IP 的每一次尝试都被拒绝了（日志中均为 `reject`），
> 并没有真正建立代理连接。

**解决办法**：把「黑名单 + 生效中的封禁」同步到 **`ipset + iptables`**，
让被禁 IP 的数据包在**内核层直接 DROP** —— 连 frps 都到不了，计数自然停止。

| 项 | 值 |
|---|---|
| ipset 集合 | `frpwaf_block`（IPv4）、`frpwaf_block6`（IPv6） |
| iptables 链 | `FRPWAF_BLOCK`（位于 `INPUT` 第 1 条，命中集合即 DROP） |
| 开关 | 插件「IP 封禁」页顶部 / 独立面板「设置」页 `fw_sync_enabled` |
| 手动同步 | 插件「IP 封禁」页「立即同步」按钮 / `POST /api/kernban/sync` |
| 状态查询 | `GET /api/kernban` |

- 后台线程每 10 秒自动对账一次（增/删/到期），无需人工维护。
- 临时封禁使用集合的 per-entry `timeout`，到期由内核自动移除；永久黑名单 `timeout=0`。
- 需要 **root + ipset + iptables**；不满足时自动降级为「不启用」，仍由 frp 应用层拦截。
- 卸载插件时会清理 `FRPWAF_BLOCK` 链与 ipset 集合。
- 本机若装有宝塔防火墙（同样使用 ipset），本模块使用独立集合名，互不影响。

---

## frp 服务端 / 客户端管理（合并官方「frp管理器」）

本插件已把宝塔官方 **「frp管理器」**（`frp` 插件，2023-11 后停更）的功能并入，
并修复其已知问题。入口：插件左侧菜单 **「frp 管理」**。

**功能**

- 服务端 / 客户端切换（`frps` / `frpc`），各自独立管理。
- **服务状态**：安装状态、当前版本、运行状态、程序/配置路径；启动 / 停止 / 重启。
- **版本管理**：动态查询 GitHub 最新版、一键安装 / 升级（可选指定版本）。
- **配置修改**：结构化表单（端口、面板账号密码、token、日志、连接池等），
  保存后自动 `verify` 校验。
- **配置文件（原文）**：直接编辑 `frps.toml` / `frpc.toml`，保存前 TOML 语法校验。
- **运行日志**：读取并展示 `frps` / `frpc` 日志。
- **一键放行端口**：探测系统防火墙（firewalld / ufw）自动放行 frps 关键端口
  （KCP/QUIC 按 UDP 放行，支持 quicBindPort）。
- **卸载**：停止服务并删除程序目录。

**相对官方插件修复的问题**

| 官方插件问题 | 本插件的处理 |
|---|---|
| `maxPoolCount` 写在顶层（frp 0.52+ 需在 `[transport]` 下） | 自动归位到 `[transport]` |
| 重装会 `rm -rf /usr/local/frps` 并**重新随机生成配置**（破坏性） | 升级只替换二进制，**保留配置**；写前自动备份 |
| 端口占用检查用 `netstat\|awk` 脆弱正则 | 改用 `ss` 解析 |
| 版本写死 0.53.2 / 0.52.3，无法升级、无 arm 支持 | 支持 amd64/arm64/arm/386，动态查最新版 |
| 写配置用 `toml.dumps` 可能丢未知字段 | 读改写整表，**保留 `[[httpPlugins]]` 等**（自带纯标准库 `toml_lite`，无第三方依赖） |
| 无配置校验、无备份 | 写前备份、写后 `frps verify`，失败自动回滚 |
| 下载源 `download.bt.cn` 已 403 | 改用 GitHub Releases（含镜像回退） |

> 提示：本机原 frps 由官方插件安装，配置目录 `/usr/local/frps` 与 WAF 的
> `[[httpPlugins]]` 注入共用同一个 `frps.toml`；本插件的配置读写会完整保留该注入。

---

## 管理面板功能

- **概览**：今日连接/拦截/独立 IP、生效封禁、名单数量、最近连接。
- **IP 名单**：黑/白名单增删、CIDR 支持、批量导入。
- **连接日志**：按 IP / 动作过滤、分页、清空。
- **封禁管理**：手动封禁/解封、当前生效封禁、历史记录。
- **代理统计**：各代理累计连接数与被拒数。
- **设置**：策略开关、自动封禁参数、限速、日志保留、修改管理员账号（用户名与密码均可改）。

---

## AI 自动 IP 审查

周期性把最近一段时间的高频来源 IP（含归属地、连接数、被拒率、命中代理）
汇总后交给大模型判断是否恶意，并按判定**分级处置**。

**在宝塔插件「AI 审查」页配置：**

| 项 | 说明 |
|---|---|
| 启用审查 | 开启后后台线程按间隔自动审查 |
| 协议 | `openai`（`/v1/chat/completions`）或 `anthropic`（`/v1/messages`） |
| 接口地址 | 填到根，如 `http://127.0.0.1:3000`；也可填 `.../v1` 或完整路径，程序会自动识别、不会重复拼接 |
| API Key | Bearer / x-api-key |
| 模型 | 如 `claude-haiku-4.5` |
| 审查间隔 | 秒，最短 60 |
| 分析窗口 | 每次分析最近多少秒的连接 |
| 最小连接数 | 窗口内低于此值的 IP 不送审（减少噪音与费用） |
| 自动处置 | 关 = 只记录不动作 |
| 疑似临时封禁 | 疑似（`suspicious`）自动临时封禁，时长可配 |
| SSH 相关从严 | SSH 爆破 / 代理名含 ssh 的 IP 从严 |
| SSH 疑似也永久 | SSH 相关疑似直接永久黑名单（最严） |
| 接口超时 | 单次模型调用超时（秒，默认 120）；网关较慢时调大，失败会自动重试一次 |

**分级处置**：

| 判定 | 处置 |
|---|---|
| `malicious`（确凿：爆破/扫描/攻击） | **永久黑名单**（需人工在「IP 封禁」页解封） |
| `suspicious`（疑似） | 临时封禁（到期自动释放） |
| `suspicious` + SSH 相关 | **永久黑名单**（从严，可关） |
| `benign` / 白名单命中 | 仅记录，不处置 |

**实现**：`app/ai.py`，仅用标准库 `urllib`，无额外依赖。
后台线程 `ai.loop_forever()` 按间隔运行，审查记录写入 `ai_review` 表。

> 提示：模型建议用便宜快速的小模型（如 haiku 级别），单次审查成本很低。
> 若不想自动处置，关闭「自动处置」即只记录不动作；误封可在「IP 封禁」页手动解封。

---

## 常用操作

```bash
# 服务控制
/etc/init.d/frpwaf start|stop|restart|status

# 重新组装并安装插件（代码改动后）
cd /opt/frpwaf && bash build.sh install

# 查看 WAF 日志
tail -f /opt/frpwaf/data/frpwaf.log

# 备份数据
cp /opt/frpwaf/data/frpwaf.db /root/frpwaf.db.bak
```

---

## 重要提示

- **自动封禁默认关闭**。frp 代理端口（尤其 HTTP/HTTPS vhost）天然有大量并发连接，
  阈值过低会误封正常用户。如需启用，建议阈值 ≥ 200/60s 并结合业务观察。
  （攻击类型自动封禁——CC / 端口扫描 / 敏感服务爆破——默认**开启**，
  参数留 0 视为未设置、保存时自动回退默认值，可在设置页按需关闭。）
- **回调来源限制**：`/frp/handler` 仅接受本机（127.0.0.1/::1）来源，其它来源一律 403；
  若 frps 与 WAF 分机部署，本机制会拒绝回调，需改回同机部署或调整校验策略。
- **CC 检测覆盖范围**：frp 对 **http 类型代理不触发 NewUserConn 回调**，
  CC 自动封禁仅对 https/tcpmux 等类型生效（纯 http 代理请用限速/名单/前置代理防护）。
- 管理面板监听 `0.0.0.0:7080`，**请确保云安全组仅对你的 IP 开放该端口**，
  或改用强密码，避免面板暴露在公网。
- 修改 `frps.toml` 中的 `httpPlugins` 后需重启 frps（会瞬断隧道）。
- 卸载插件（`bash install.sh uninstall` 或直接运行 `uninstall.sh`；无参数运行
  `install.sh` 仅提示用法、不执行卸载）会移除 init 脚本，
  但**保留** `/opt/frpwaf/data` 数据；彻底删除需手动 `rm -rf /opt/frpwaf`。
