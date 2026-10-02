# 12 · Bug 修复记录

本文记录本项目**历次发现并修复的全部功能 Bug**，含现象、根因、修复与验证。
共 12 批（Bug A–I 为历史单点修复；Bug J 为 2026-10-01 全项目审查批次；
Bug K/L 为 2026-10-02 AI 大批量审查修复批次），
均在隔离环境复现、修复、验证后应用到生产。

> 编号顺序为**发现顺序**，与修复提交顺序略有交叉（Bug B 与 A 同批提交）。

### Bug ↔ 提交 ↔ 版本 对应表

| Bug | 文件 | 修复提交 / Tag | 发布版本 | 状态 |
|---|---|---|---|---|
| A | `firewall.py` | `cedf595` / `v1.3.7` | v1.3.7 | 已提交发布 |
| B | `store.py` | `cedf595` / `v1.3.7` | v1.3.7 | 已提交发布 |
| C | `firewall.py` | `v1.3.8` | v1.3.8 | 已提交发布 |
| D | `ai.py` | `v1.3.8` | v1.3.8 | 已提交发布 |
| E | `daemon.py` | `v1.3.8` | v1.3.8 | 已提交发布 |
| F | `frp.py` / `toml_lite.py` | `v1.3.9` | v1.3.9 | 已提交发布 |
| G | `ai.py` | `a2bab91` / `v1.3.10` | v1.3.10 | 已提交发布 |
| H | `frpwaf_main.py` | `e16e6fa` / `v1.3.10`（tag 重指） | v1.3.10 | 已提交发布 |
| I | `daemon.py` | v1.3.11 | v1.3.11 | 已提交发布 |
| J | `daemon.py` / `engine.py` / `store.py` / `firewall.py` / `frp.py` / `auth.py` / `config.py` / `frpwaf_main.py` / 双端面板 / `install.sh` / `uninstall.sh` | v1.3.11 | v1.3.11 | 已提交发布 |
| K | `ai.py` / `index.html` | v1.3.11 | v1.3.11 | 已提交发布 |
| L | `frpwaf_main.py` / `index.html` / `ai.py` | v1.3.11 | v1.3.11 | 已提交发布 |

> A、B 随 `cedf595` 一起提交并打 Tag `v1.3.7`；C、D、E 随后修复，随 Tag
> `v1.3.8` 一起提交（见 [13-变更历史与版本.md](13-变更历史与版本.md) §2/§4）。
> 该 Tag 指向的提交哈希可用 `git rev-list -n1 v1.3.8` 查询。

---

## Bug A：内核封禁忽略黑/白名单开关（漏封 / 误封）

**文件**：`app/firewall.py` · `sync_from_store()`

### 现象

- **误封**：在面板关闭「黑名单」开关后，应用层已放行该 IP，但该 IP **仍连不上**——
  内核 ipset 里还留着它，包被 DROP。
- **漏封**：关闭「白名单」开关后，本应下发的黑名单条目却被当作白名单剔除，**漏封**。

### 根因

`sync_from_store()` 只按 `list_type` 取全部黑名单与白名单，**完全忽略**
`blacklist_enabled` / `whitelist_enabled` 两个开关。于是内核拦截集合
与应用层实际会拒绝的集合**不一致**：

- 黑名单开关关了 → 应用层放行，内核仍下发 → 误封；
- 白名单开关关了 → 应用层不再白名单优先，内核仍按白名单剔除 → 漏封。

### 修复

`sync_from_store()` 按开关裁剪后再同步：

```python
perms = []
if cfg.get("blacklist_enabled", True):
    perms = [永久黑名单 CIDR...]
whites = []
if cfg.get("whitelist_enabled", False):
    whites = [白名单 CIDR...]
bans = store.active_bans()   # 临时封禁不受名单开关影响，始终下发
return sync(perms, bans, whites)
```

使**内核拦截集合 ≡ 应用层实际会拒绝的集合**。

### 验证

用隔离状态构造四种组合（黑名单开/关 × 白名单开/关），断言内核 `want` 集合
与 `engine.decide()` 的预期拒绝集合一致。

---

## Bug B：`ip_list.cidr` 全局唯一，黑白名单无法共存同一 CIDR

**文件**：`app/store.py` · 表结构 + `_migrate_ip_list()`

### 现象

- 想「把某黑名单项改判为白名单」时，若该 CIDR 已在黑名单，**加入白名单失败**
  （`该条目已存在`），只能先删再加，操作繁琐且中间态无防护。
- 更严重：若黑名单已有 `1.2.3.4`，而用户想同时把 `1.2.3.4` 加入白名单放行，
  **无法做到**（白名单应优先，但插不进去）。

### 根因

旧表定义 `cidr TEXT NOT NULL UNIQUE`——**cidr 全局唯一**，与 `list_type` 无关。
同一个 CIDR 只能存在于一个名单里。

### 修复

1. 表结构改为 **`UNIQUE(cidr, list_type)`**：同一 CIDR 可分别在黑、白名单各存一条，
   判定时白名单优先（见 `engine.decide` 顺序）。
2. 新增 **`_migrate_ip_list(c)`** 自动迁移旧库：
   - 读 `sqlite_master` 判断是否旧结构（含 `cidr TEXT NOT NULL UNIQUE`）；
   - 是则 `ALTER TABLE ip_list RENAME TO ip_list_old` → 建新表 →
     `INSERT OR IGNORE ... SELECT` 搬数据 → 删旧表 → 重建索引；
   - **出错回滚**（删新表、旧表改名回来），绝不丢表。
3. `_connect()` 在建表后调用迁移（幂等：已是新结构直接跳过）。

### 验证

- 在**生产库的副本**上测试迁移：4 条旧数据**完整保留**。
- 随后在生产库**原地迁移**成功。
- 隔离实例端到端验证：同一 CIDR 可同时存在于黑、白名单。

> 踩坑记录：初次测试断言 `cidr == "1.2.3.4/32"`，但旧数据实际存的是 `1.2.3.4`
> （未规范化），导致**误判迁移失败**；修正断言后确认迁移正常。

---

## Bug C：内核白名单只删「整段在内」，CIDR 包含白名单 IP 时误封白名单地址

**文件**：`app/firewall.py` · `sync()` / `_apply_whitelist()`

### 现象

黑名单放了整段 `10.0.0.0/8`，白名单只放行其中单个 IP `10.0.0.5`。
应用层白名单优先，`10.0.0.5` **放行**；但**内核层**整段 `/8` 被下发到 ipset，
`10.0.0.5` 的数据包被 DROP → **白名单用户连不上**（应用层放行、内核拦截）。

### 根因

旧 `sync()` 的白名单剔除逻辑（`_member_in`）只判断「**成员是否完全落在白名单内**」：

```python
for m in list(bucket):
    if _member_in(m, net):   # m 完全在 net 内才删
        bucket.pop(m, None)
```

对于「成员是**大 CIDR**、白名单是其中**小 IP/子网**」的情况，成员并不「落在白名单内」，
于是整段照发，白名单地址一并被内核拦截。

### 修复

改为**CIDR 差集**：`_apply_whitelist(bucket, wnets)` 把命中白名单的成员拆成
「原段 − 白名单段」后再放入：

```python
remaining = [net]
for w in wnets:
    if w.version != net.version:
        continue
    newr = []
    for n in remaining:
        if not n.overlaps(w):            newr.append(n)          # 不相交：保留
        elif n.subnet_of(w):             pass                    # 整段在白名单内：丢弃
        else:                            newr.extend(n.address_exclude(w))  # 取差集
    remaining = newr
```

拆出的子段继承原 `timeout`（临时封禁仍会到期）。

同时把 bans 与 permanent 的成员生成统一走 `_member(net)`（`/32`、`/128` 用裸地址）。

### 验证

- **400 轮随机 fuzz 测试**（约 **12 万次**随机 IP 探测），对比「应用层决策」与
  「内核集合成员判定」，**0 处不一致**。

---

## Bug D：AI 审查可被封禁「未送审」的 IP（幻觉 / 提示注入）

**文件**：`app/ai.py` · `review()`

### 现象

AI 审查时，若模型返回的 JSON 里含**本次并未送审**的 IP（例如被审查内容中诱导出的
无关地址），系统会照常按其 `verdict` **自动封禁**该 IP。

### 根因

`review()` 遍历模型返回的条目时，只要 `ip` 非空就处理，**未校验该 IP 是否在本次
送审集合内**。大模型可能因**幻觉**或**提示注入**输出任意 IP；攻击者可通过构造
输入诱导模型输出某个无辜 IP，从而**借 AI 之手封禁任意地址**（可被滥用）。

### 修复

在遍历中加白名单校验，**只处理本次真正送审过的 IP**：

```python
if ip not in stat:      # stat = {it["ip"]: it for it in items}
    continue
```

集合外的 IP 一律丢弃（不封禁、不记录为已处理）。

### 验证

构造「送审 2 个 IP、模型返回第 3 个无关 IP」的场景，确认第 3 个 IP 被忽略。

---

## Bug E：手动封禁非法 IP 导致 500

**文件**：`app/daemon.py` · `/api/bans` 的 `action == "ban"`

### 现象

在独立面板「封禁管理」里手动封禁一个**非法 IP / CIDR**（如 `abc`、`1.2.3.4/99`）时，
接口返回 **500 服务器内部错误**，而非友好的错误提示。

### 根因

`store.add_ban()` 对非法 IP 抛 `ValueError`，但 `action == "ban"` 分支**未捕获**，
异常冒泡到 `_route` 的兜底 `except`，返回 500。

### 修复

包一层 `try/except ValueError`，返回友好提示：

```python
try:
    store.add_ban(ip, "manual", int(body.get("seconds") or 3600))
except ValueError as e:
    return self._json({"code": 1, "msg": str(e)})
```

> 对照：插件端 `ban_ip` 早已捕获 `ValueError`，两端现已一致。

### 验证

隔离实例中分别提交非法与合法 IP，确认非法返回 `{code:1,msg:"无效的 IP 或 CIDR: ..."}`、
合法返回 `{code:0,msg:"已封禁"}`。

---

## Bug F：frp 管理页报「缺少 toml 模块」（配置读写全部失效）

**文件**：`app/frp.py` · `load_config()` / `save_config()`；`frpwaf_main.py` · `frp_save_raw()`

### 现象

打开插件端「frp 管理」页时弹出「缺少 toml 模块」，且：

- 配置文件（结构化）读取失败 → 表单为空、原文区为空；
- 「保存配置」「保存原文」「预创建配置文件」全部不可用；
- 版本管理、一键放行端口（依赖 `load_config` 读端口）等连带失效。

### 根因

`load_config()` / `save_config()` / `frp_save_raw()` 直接 `import toml`（第三方包）。
该包**并非 Python 标准库**，原实现依赖「宝塔 pyenv 恰好自带 0.10.2」——
运行环境未安装该包时即报错。这违反项目红线「纯标准库、无 requirements.txt」，
属于「环境恰好可用」掩盖的依赖缺陷（同类问题：宝塔面板版本 / 系统 Python 差异都会触发）。

### 修复

新增 `app/toml_lite.py`：**纯标准库** TOML 子集解析 / 生成器，
解析语义与标准库 `tomllib` 对齐（同样的 `EXPLICIT_NEST` / `FROZEN` 命名空间状态机，
同样拒绝重复表声明、内联表冻结后再展开、点分键与表头冲突等非法文档），
生成格式与 `tomllib` 标准写法一致（先标量后子表、`[[name]]` 一行）。

- `app/frp.py`：`load_config` / `save_config` 改用 `toml_lite`；
  新增 `check_toml(text)` 供插件端复用。
- `frpwaf_main.py`：`frp_save_raw` 改调 `frp.check_toml()`，不再 `import toml`。
- 全仓 `grep "import toml"` 清零（生产代码），Python 3.6+ 兼容。

### 验证

- 与官方 `tomllib` 交叉比对：生成侧（我方 `dumps` → 官方解析）与解析侧
  （同一文本两边结果一致），含 frps/frpc 模板 + `[[httpPlugins]]` 注入块。
- 表命名空间边界差异测试 52 项（重复表、点分键/表头冲突、内联表冻结、数组表等）全一致。
- 随机差异测试：3000 份随机文档（接受/拒绝 + 值比对）零差异；
  2000 份随机 dict 生成往返零差异。
- 链路验证：模拟「无 `toml` 包」环境 + `frpwaf_app` 私有包加载机制，
  `load_config` / `save_config`（含 `maxPoolCount` 归位、备份、回滚）/ `check_toml` 全通过。

---

## Bug G：AI 审查处置过轻（确凿攻击只临时封禁）

**文件**：`app/ai.py` · `review()`（分级处置）

### 现象

AI 判定为确凿攻击/扫描/爆破（`malicious`）的 IP，此前一律按 `ai_ban_seconds`
（默认 1800 秒）**临时封禁**，到期自动释放。对持续扫描、SSH 爆破类攻击，
攻击者只需等待封禁到期即可继续，防护强度不足；`suspicious` 判定则完全不动作。

### 根因

处置逻辑只有一档（`verdict == "malicious"` → `store.add_ban(..., ai_ban_seconds)`），
未区分「确凿 / 疑似」，也没有「永久封禁」落点，与用户对暴力破解、扫描行为
「直接永久拉黑」的预期不符。

### 修复

`review()` 改为分级处置（`_apply_action()`）：

| 判定 | 处置 | 落点 |
|---|---|---|
| `malicious`（确凿） | **永久黑名单** | `ip_list` black（内核 `timeout=0`） |
| `suspicious`（疑似） | 临时封禁 | `ban_log`（`ai_ban_seconds`） |
| `suspicious` + SSH 相关 | **永久黑名单**（`ai_ssh_strict` + `ai_ssh_permanent_suspicious`） | `ip_list` black |
| 白名单命中 | `skipped`，不自动处置 | —— |

配套：

- 提示词新增 `category`（攻击类型）字段，`ssh_bruteforce` 是 SSH 从严判定依据；
  旧格式缺 `category` 时按 `reason`/`proxies` 关键词兜底（`_is_ssh_related`）。
- 白名单优先（`_is_whitelisted`，含 CIDR 匹配）：模型判恶意也不处置，防连坐。
- 不重复处置：已在黑名单 → `already_banned`；已在临时封禁 → 疑似场景不再重复
  `add_ban`（保留原「不重复封禁」语义）；确凿场景升级为永久并释放临时记录。
- 产生永久黑名单后立即 `engine.invalidate_cache()` + 内核同步，封完即生效。
- 新增配置 `ai_suspicious_ban` / `ai_ssh_strict` / `ai_ssh_permanent_suspicious`；
  面板「AI 审查」页可调，结果表新增「类型」列。

### 验证

隔离实例 + 临时集成脚本（`scratchpad/ai_review_test.py`，不入库）覆盖
首轮分级、二次审查不重复、三个开关、白名单跳过、CIDR 白名单、SSH 兜底等
30+ 断言全部通过；`python -m py_compile app/*.py frpwaf_main.py` 通过。

---

## Bug H：一键放行端口永远显示「无」（调用不存在的面板 API）

**文件**：`frpwaf_main.py` · `frp_release_ports()`

### 现象

frp 管理页点击「一键放行端口」，无论 frps 配置里有多少端口，弹窗**恒为**
「已放行端口：无」；防火墙里实际**没有添加任何规则**，也没有任何报错。

### 根因

实现调用了 `public.add_firewall_rule(p, "tcp", "accept", "0.0.0.0/0", "frp管理器")`
——该函数**在宝塔面板 `class/public.py` 公共库中并不存在**（宝塔从未提供此 API）。
每次调用抛 `AttributeError`，但被内层 `except Exception: pass` **静默吞掉**，
`done` 列表恒为空 → 恒显示「无」。属「API 想当然 + 异常静默」双重缺陷。

### 修复

不再依赖任何面板私有 API，直接调用系统防火墙命令（与宝塔面板自身放行逻辑一致），
按 frp 语义区分协议：

| 端口配置项 | 协议 | 说明 |
|---|---|---|
| `bindPort` / `vhostHTTPPort` / `vhostHTTPSPort` / `tcpmuxHTTPConnectPort` / `webServer.port` | TCP | 原实现按 TCP 放行，本轮保持不变 |
| `kcpBindPort` / `quicBindPort` | **UDP** | 原实现把 kcp 当 TCP，且完全遗漏 quic |

- **后端探测**（`_firewall_backend`）：`firewall-cmd --state` 为 running → firewalld
  （CentOS 7+）；否则 `ufw status` 为 active → ufw（Debian/Ubuntu）；
  两者皆无 → 明确提示「未检测到运行中的系统防火墙」，而非假装成功。
- **firewalld**：`firewall-cmd --zone=public --add-port=P/协议 --permanent`，
  全部成功后统一 `firewall-cmd --reload`（reload 失败会附带提示）。
- **ufw**：`ufw allow P/协议`（无需 reload）。
- **结果如实回报**：已放行（firewalld `ALREADY_ENABLED`、ufw `Skipping`）视为成功；
  成功/失败**分端口列出**；部分失败返回失败状态并列出原因（不再静默）。
- **frpc**：明确提示「客户端无需放行入站端口」（原实现静默返回「无」）。
- **参数校验**：端口须为 1–65535 的整数，非法值忽略；`webServer.port` 兼容字符串数字。
- 去重键改为 `(端口, 协议)`——同一端口可同时需要 TCP 与 UDP 放行（如 `bindPort` = `kcpBindPort`）。

### 验证

桩测试（`scratchpad/release_ports_test.py`，不入库）以假 `public` 模块 + 假 frp 配置
覆盖 12 组场景、**22 项断言全部通过**：firewalld 正常/已放行/reload 失败、ufw
正常/已存在、无防火墙、frpc、端口收集（UDP 归类/去重/非法值/布尔值）、部分失败、空配置。

---

## Bug I：客户端断连刷运行日志（ConnectionResetError 完整堆栈）

**文件**：`app/daemon.py` · 新增 `_QuietHTTPServer.handle_error()`

### 现象

`data/frpwaf.log`（面板「运行日志」页）反复出现完整 traceback：

```
----------------------------------------
Exception occurred during processing of request from ('45.79.211.97', 58032)
Traceback (most recent call last):
  ...
  File "/www/server/panel/pyenv/lib/python3.13/socket.py", line 723, in readinto
    return self._sock.recv_into(b)
ConnectionResetError: [Errno 104] Connection reset by peer
----------------------------------------
```

来源 IP 多为扫描器/爬虫，日志持续增长、干扰真实信息排查。

### 根因

`http.server` 的 `BaseServer.handle_error` 默认把**请求处理线程**中的任何异常
连同完整堆栈打印到 **stderr**；服务脚本 `frpwaf.init` 以
`nohup python -m app.daemon >>frpwaf.log 2>&1 &` 启动，stderr 被合并写入运行日志。
而扫描器连接后**不发完整请求就断开**（RST），请求线程在 `rfile.readline()`
抛 `ConnectionResetError` —— 属正常网络噪声，却因默认 `handle_error` 变成堆栈刷屏。

### 修复

`ThreadingHTTPServer` 子类 `_QuietHTTPServer`，重写 `handle_error()`：

- `ConnectionResetError` / `ConnectionAbortedError` / `BrokenPipeError` /
  `TimeoutError` / `socket.timeout`（客户端断连、慢连接超时）→ **静默**，
  按 10 分钟窗口汇总一条 `已静默 N 条客户端断连异常` 写入运行日志（防刷屏又留痕）；
- 其余异常 → 原样调用默认实现（保留完整堆栈，真实故障仍可排查）。

`main()` 改用 `_QuietHTTPServer` 启动。仅影响请求线程异常出口，
不影响路由、回调与业务日志（`_log`）。

### 验证

隔离实例回归（`scratchpad/quiet_server_test.py`，不入库）**11 项断言全部通过**：

- RST 半途断开 x5：console 无 `Exception occurred`/`Traceback`/`ConnectionResetError`，
  运行日志恰好 1 条「已静默」汇总；
- 正常 `GET /`（200）、正常回调（`reject:false`）、非法 JSON 回调均正常；
- 全部用例后 console 仍无堆栈，服务存活。

### 关联说明：frps 日志的 `no route found`

用户同时报告 frps 日志刷
`[W] [httputil/reverseproxy.go:500] ... no route found: <host> <path>`。
经查 frp 源码（`pkg/util/vhost/http.go` `CreateConnection` → `ErrNoRouteFound`），
该日志由 **frp 服务端二进制**产生：请求直连 `vhostHTTPPort` 但 Host 不匹配任何
已注册 HTTP 代理域名（扫描器扫 IP、探测未知域名），frp 返回 404 并记 Warn，
属预期防御行为。**不是本插件缺陷**，处置建议见
[11-开发运维与常见问题.md](11-开发运维与常见问题.md) Q12
（调 `log.level`、关闭无用 `vhostHTTPPort`、防火墙限制来源）。
另注：HTTP 代理不触发 `NewUserConn`，此类流量不经过 WAF 决策，需在上游拦截。

---

## Bug J：全项目审查批次（2026-10-01，P0/P1/P2/P3 全量）

**文件**：`app/daemon.py`、`app/engine.py`、`app/store.py`、`app/firewall.py`、
`app/frp.py`、`app/auth.py`、`app/config.py`、`frpwaf_main.py`、`index.html`、
`web/index.html`、`install.sh`、`uninstall.sh`

### 现象（摘选）

- 任意可达 7080 的来源可 POST `/frp/handler` 伪造 `remote_addr`，把任意 IP 写入黑名单；
- 未认证可达的 500 响应回显 traceback（泄露内部结构与路径）；
- 插件端 `get_admin` / `get_waf_info` 明文回显管理员密码；
- 基础自动封禁（第 5 步）每连接查 `conn_log`（违反决策路径禁 IO 红线），
  且并发时多线程可同时达阈值重复写 `ban_log`；
- 内核同步在批量封禁时线程/子进程风暴；`sync` 快照在锁外构建存在写覆盖竞态；
- `ban_log` 无索引/无裁剪、登录限速表无界、`banned_ips` 缓存重建在锁外；
- 插件端与 WAF 进程并发写 `frpwaf.json` 互相覆盖字段；
- Web 端概览未转义（XSS 面）、封禁历史两态、空态行缺 colspan、`api()` 不统一处理错误；
- `install.sh` 无参数默认执行**卸载**（误执行即移除 frps 回调）；
- CC 文案与实际不符（http 类型不触发 NewUserConn 回调）。

### 修复（按模块）

| 模块 | 修复内容 |
|---|---|
| daemon | 回调本机校验（非本机 403 + 计数）；500 不回显 detail；登录限速表硬上限；回调路径单事务写库（`add_log_and_bump`）；engine 异常计数与限频日志；`/api/iplist` 返回条数夹取 `PANEL_LIST_CAP` |
| engine | 第 5 步改纯内存原子认领（与第 6 步统一）；计数改为「阈值封顶 + 只认领一次」（消除并发二次触发竞态）；内核同步合并单工作线程（事件去重） |
| store | `idx_ban_log_active` / `idx_conn_log_ip_ts` 复合索引；`trim_bans(20000)`；`banned_ips` 锁内双重检查；`list_ips(limit)` + `PANEL_LIST_CAP=5000` 展示上限；删除死代码 `remove_ip` |
| firewall | 快照构建+下发全程持 `_sync_lock`；`ipset restore` 批量提交（失败退化逐条） |
| frp | 删除死代码 `install()`；下载 sha256 校验（GitHub digest）；版本号正则白名单 |
| auth | 非 ASCII 签名/异常输入返回 None（不再 500） |
| config | `save(patch)` 并发保护：线程锁 + 跨进程文件锁内「读现状→合并→原子替换」；损坏拒写 |
| frpwaf_main | 密码回显掩码；`_set_cfg` 走 patch 语义（并发合并） |
| index.html | `fwAiRun` 去全局 event；`fwFrpPoll` beforeunload 清理；CC 文案修正 |
| web/index.html | 概览全量转义；封禁三态；空态 colspan 补全；`api()` 统一错误抛出 |
| install/uninstall | 参数显式分派（无参数仅提示用法）；frps.toml 清理缺 python3 / 失败时告警 |

### 验证

- `python3 -m py_compile app/*.py frpwaf_main.py`、`bash -n install.sh uninstall.sh build.sh frpwaf.init` 通过；
- 并发与索引验证（`scratchpad/verify_fix_round1.py`，不入库）10/10 通过；
- 配置并发写验证（`scratchpad/verify_config_save.py`，不入库）11/11 通过；
- 步骤 12–15 验证（`scratchpad/verify_fix_round2.py`，不入库）18/18 通过；
- 详见 [docs/tests/reports/2026-10/](tests/reports/2026-10/) 验证报告。

---

## Bug K：AI 大批量送审输出截断，整轮审查作废（2026-10-02）

**文件**：`app/ai.py`（`call_model` / `_extract_json`）· `index.html`（审查策略保存按钮）

### 现象

用户将 `ai_min_conns` 调为 1、`ai_max_ips` 调为 1000 后执行「立即审查」，
面板报「模型返回无法解析为 JSON: [ {...}, ...」，整轮审查失败、无任何处置。

### 根因

`_call_openai` / `_call_anthropic` 的 `max_tokens` **写死 1500**。送审 N 个 IP
需要模型输出 N 条判定 JSON（每条含 ip/verdict/category/reason，约 100~150 token），
1000 条需输出约 10 万 token，远超 1500 输出上限 → 模型输出在字符串中途被截断
（用户报错信息末尾 `"reason": "10次连接命中多个codebuddy代理` 无闭合引号即特征）
→ `_extract_json` 整体解析失败 → 整轮作废。

### 修复

1. **分批送审**：`call_model` 超过 `_BATCH_SIZE` 自动分批调用
   （初始 40 条/批；Bug L 已调至 **100 条/批并并行**），单批输出规模可控；
2. **动态 max_tokens**：`_max_tokens_for(n) = min(16384, max(1024, n*120+512))`，
   按批内条数计算，小批量不浪费、大批量不截断；
3. **截断抢救**：`_extract_json` 整体解析失败时用 `_salvage_json` 逐对象
   `raw_decode` 抢救完整条目（缺失条目不处置，安全方向不变）；
4. **失败降级**：单批解析失败 / 网关拒绝 max_tokens / 413 → 二分重试
   （拆分预算 16 次）；解析成功但漏答 → 对缺失 IP 补审一次；鉴权类 HTTP
   错误直接终止不重复请求；部分批次失败时摘要标注「N 个未获判定（不处置）」；
5. **面板**：「审查策略」卡片补独立「保存策略」按钮（复用 `ai_save_config`，
   后端本就覆盖全部策略字段，此前仅缺前端入口）。

### 验证

`scratchpad/ai_truncation_fix_test.py` 10 组 27 项断言 +
`scratchpad/ai_bulk_e2e_test.py` 端到端 9 项断言全部通过（均不入库）：
- 90 条送审单批；截断只保住前 45 条 → 自动补审缺失 45 条，最终 90 条全部获得判定；
- 持续失败场景：25 条获判定、65 条不处置，黑名单恰 25 条，摘要正确标注；
- 既有 `scratchpad/ai_review_test.py`（分级处置 30+ 断言）回归全通过；
- `python -m py_compile app/*.py frpwaf_main.py`、`node scratchpad/check_html_js.cjs` 通过。

### 后续修复（同日，Bug L）

用户实测后追加报告两个问题（按钮卡「审查中…」+ 观感「一个一个 IP 送审」），
根因与修复见 Bug L。

---

## Bug L：立即审查按钮卡死 + 送审碎片化（2026-10-02）

**文件**：`frpwaf_main.py`（`ai_run_now`/`ai_status`）· `index.html`（`fwAiRun` 轮询）
· `app/ai.py`（并行批次、最小拆分、互斥与状态机）· `app/config.py`（状态键）

### 现象

用户点击「立即审查一次」后：
1. 按钮**一直停在「审查中…」**，不再恢复；
2. 观察网关日志，像是**一次只送一个 IP** 去审查（希望一批一起送、一起拿回）。

### 根因

1. **按钮卡死**：插件端 `ai_run_now` 在面板进程内**同步**执行
   `ai.review(force=True)`——大批量审查（顺序分批 × 每批最长 `ai_timeout` 秒）
   远超插件请求/网关超时，HTTP 回调永不返回，前端恢复按钮的代码永远不执行；
2. **碎片化观感**：`_call_batch` 解析失败一路二分拆到 **1 条/批**，网关日志
   出现大量单条请求；且批次串行执行，整体慢，进一步强化「一个一个」的观感。

### 修复

1. **异步立即审查**：插件端 `ai_run_now` 只写 `ai_run_requested` 时间戳并
   **立即返回**；daemon `loop_forever` 消费执行（`ai_run_consumed` 游标，
   `requested > consumed` 才执行）；前端 `fwAiRun` 提交后轮询 `ai_status`，
   按 `running`/`stale`/`last_result` 恢复按钮并提示结果——即使面板/网关超时
   也不会卡死，页面刷新后还会自动恢复「审查中…」状态继续轮询；
2. **批次放大 + 并行**：`_BATCH_SIZE` 40 → **100**（一批 IP 一起送审），
   批次波内并行（`_MAX_WORKERS=3`）、波间串行（鉴权类错误于波边界提前终止），
   总耗时约为串行的 1/N；
3. **最小拆分 5 条**：解析失败不再拆到单条；漏答补齐要求缺失 ≥2 条；
4. **互斥与状态机**：`review()` 持 `_review_lock`（并发触发只跑一轮），
   每轮写 `ai_review_state`（finally 清空，任何出口不残留）、`ai_last_ok`，
   前端轮询据此判断完成/失败；`ai_status` 对 120 秒未被消费的请求报 stale
   （WAF 服务未运行场景），不会无限转圈。

### 验证

- `scratchpad/ai_async_parallel_test.py`（临时脚本，不入库）**19 项断言全过**：
  320 条 4 批并发（峰值并发 3、耗时 < 串行理论值）、拆分止步 5 条、状态机
  （running → 清空 / last_ok 成功失败两态）、loop_forever 消费请求、review 互斥；
- `scratchpad/verify_plugin_ai_async.py`（临时脚本，不入库）**21 项断言全过**：
  未配置拒绝、提交立即返回、pending/running/finished/stale 四态、回显字段；
- 既有回归全通过：`ai_truncation_fix_test.py`、`ai_bulk_e2e_test.py`、
  `ai_review_test.py`、`ai_http_e2e_test.py`、`verify_plugin_policy.py`、
  `verify_config_save.py`、`verify_regression.py`；
- `python -m py_compile app/*.py frpwaf_main.py`、`node scratchpad/check_html_js.cjs` 通过。

---

## 附：历史遗留的其它修复（早期版本，非本轮）

这些在更早的提交中已修复，一并记录：

| 提交 | 内容 |
|---|---|
| `b401eba` / `e353cd9` | 修复新机上传安装后 `FileNotFoundError: /opt/frpwaf/app/__init__.py`（私有包加载 + 目录回退） |
| `b8628fb` | 修复 frp「安装/升级」报 `ModuleNotFoundError: app.frp`（私有包名 `frpwaf_app`）；连接日志支持按代理筛选 |
| `8a51cd0` | 插件端支持网页端开关/换端口；修复内核封禁关闭不清理等 4 个 Bug |
| `64c8728` | 网页端支持修改管理员用户名 |
| `cedf595` | 名单黑白可同 CIDR 共存（含旧库迁移）；内核封禁跟随名单开关（Bug A + Bug B） |

## 统计

| 编号 | 文件 | 类型 | 严重度 |
|---|---|---|---|
| A | `firewall.py` | 内核同步与开关不一致 | 高（误封/漏封） |
| B | `store.py` | 表结构缺陷 | 中（功能受限） |
| C | `firewall.py` | 白名单差集错误 | 高（误封白名单） |
| D | `ai.py` | 安全边界缺失 | 高（可被封任意 IP） |
| E | `daemon.py` | 未捕获异常 | 低（体验） |
| F | `frp.py` | 第三方依赖（环境缺失即崩） | 高（frp 配置管理整体不可用） |
| G | `ai.py` | 处置分级缺失（确凿未永久） | 中（持续攻击到期即恢复） |
| H | `frpwaf_main.py` | 调用不存在的面板 API + 异常静默 | 中（功能恒失败且无提示） |
| I | `daemon.py` | 客户端断连异常默认打完整堆栈（stderr 并入日志） | 低（日志噪声，干扰排查） |
| K | `ai.py` / `index.html` | max_tokens 写死致大批量输出截断、整轮作废 | 高（大批量审查不可用） |
| L | `frpwaf_main.py` / `index.html` / `ai.py` | 立即审查同步执行致按钮卡死；拆分到单条致送审碎片化 | 高（按钮不可用 + 审查慢） |
