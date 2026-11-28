# 12 · Bug 修复记录

本文记录本项目**历次发现并修复的全部功能 Bug**，含现象、根因、修复与验证。
共 18 批（Bug A–I 为历史单点修复；Bug J 为 2026-10-01 全项目审查批次；
Bug K/L 为 2026-10-02 AI 大批量审查修复批次；Bug M 为 2026-10-02 CDN 回源误封批次；
Bug N 为 2026-10-09 Windows 打包 CRLF 污染批次；
**Bug O–R 为 2026-11 安全/健壮性优化评审批次**；Bug S–Y 为 2026-11 后续评审/发布批次；
**Bug Z 为 2026-11-22 数据快照备份批次；Bug AA 为 2026-11 P2-3.5 异步任务化批次**），
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
| M | `ai.py` / `config.py` / `store.py` / `daemon.py` / `frpwaf_main.py` / 双端面板 | v1.3.12 | v1.3.12 | 待提交 |
| N | `build.sh` / `install.sh` / `frpwaf_main.py` | 待提交 | 待发布 | 待提交 |
| O | `app/upgrade.py` | `3acad49` | 待发布 | 待提交 |
| P | `frpwaf_main.py` | `45ed6be` | 待发布 | 待提交 |
| Q | `app/config.py` / `app/daemon.py` / `install.sh` / `frpwaf.init` / `app/blockpage.py` | `8409919` / `979c5c6` / `5e141cd` | 待发布 | 待提交 |
| R | `app/daemon.py` / `frpwaf.init` / `install.sh` | `8409919` | 待发布 | 待提交 |
| S | `frpwaf.init` / `frpwaf.service` / `install.sh` / `uninstall.sh` | `7746544` | 待发布 | 待提交 |
| T | `.gitattributes` / `build.sh` / `install.sh` | `ca2bf0e` | 待发布 | 待提交 |
| U | `frpwaf_main.py` | `4857d61` | 待发布 | 待提交 |
| V | `app/daemon.py` / `app/config.py` / `frpwaf_main.py` | `1245817` | 待发布 | 待提交 |
| W | `app/config.py` / `app/daemon.py` / `frpwaf_main.py` | `1245817` | 待发布 | 待提交 |
| X | `app/daemon.py` / `frpwaf_main.py` | `1245817` | 待发布 | 待提交 |
| Y | `app/daemon.py` / `app/engine.py` / `app/store.py` / `app/config.py` | `1245817` | 待发布 | 待提交 |
| Z | `app/store.py` | `034379d` | 待发布 | 待提交 |
| AA | `app/job.py` / `app/daemon.py` / `frpwaf_main.py` / 双端面板 | `74c0702` / `e56a97e` / `4f252a1` | 待发布 | 待提交 |
| AC | `index.html` | 待提交 | 待发布 | 待提交 |

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

## Bug M：AI 审查误封 CDN 回源边缘 IP，整站 522（2026-10-02）

**文件**：`app/ai.py`（提示词 / `_is_cdn_origin` / `_apply_action` / `_collect`）·
`app/config.py`（`ai_cdn_guard`）· `app/store.py`（批量解封）· `app/daemon.py` ·
`frpwaf_main.py` · `index.html` · `web/index.html`

### 现象

用户的 gitea 部署在 CDN（Cloudflare 边缘加速）之后，`ai_min_conns=3`、
`ai_max_ips=1000`。浏览器控制台大量 **522**（Cloudflare「连接超时」）：
`site-manifest.json`、`theme-gitea-auto.*.css`、`app.js`、`logo.svg` 等资源全部
加载失败，整站不可访问；部分请求返回「此网站需要 JavaScript」错误页。

### 根因

源站位于 CDN 之后时，frps 回调拿到的 `remote_addr` 是 **CDN 边缘节点 IP**
（真实访客 IP 不可见）。边缘节点为全站访客回源，天然满足「单 IP 高频」——
`ai_min_conns=3` 使其被送审，模型仅凭单 IP 高频 + 无真实用户画像，将边缘节点
判为 `malicious`（确凿）→ **永久拉黑**；随后 CDN 回源连接被 WAF 拒绝 →
Cloudflare 回源超时 → **整站 522**。

处置链路本身没有回源豁免：任何按来源 IP 的自动封禁（AI 审查等）在 CDN 场景下
都可能封掉共享的边缘节点，属于结构性缺陷，而非单次模型误判。

### 修复

1. **提示词识别 CDN 回源**：`SYSTEM_PROMPT` / `_build_user_prompt` 增加
   `category=cdn_origin` 取值与判定规则（ISP 为 CDN 厂商、对 http/https 代理
   高频且无被拒 → `benign` + `cdn_origin`，不得判恶意），并明确「误封会导致
   整站 522」；`_collect` 增加 `ptypes`（代理类型）供模型参考；
2. **本地兜底 `_is_cdn_origin`**：模型漏判时，`geo` 文本命中已知 CDN 厂商关键字
   （`_CDN_KEYWORDS`：Cloudflare / CloudFront / Fastly / Sucuri / Imperva /
   Incapsula / Akamai / 阿里云 CDN / 腾讯云 CDN 等）同样视为回源；
3. **跳过自动处置**：`_apply_action` 中 `verdict ∈ {malicious, suspicious}` 且
   判定为 CDN 回源时，写 `ai_review`（`action=skipped`，理由「CDN 回源，跳过自动
   处置」），**不写黑名单、不写临时封禁**；白名单优先逻辑保持不变；
4. **开关 `ai_cdn_guard`**（默认 `true`，双端面板 + 配置放行）：关闭后恢复原有
   分级处置；摘要追加「CDN 回源跳过 N 个」；
5. **批量恢复工具**：`store.clear_blacklist()` / `store.release_all_bans()` +
   `unban_all_black` / `unban_all_temp`（插件端）+ `clear_black` / `unban_all`
   （Web API）+ 双端按钮（二次确认，操作后刷新规则缓存并触发内核同步）。

### 验证

- `scratchpad/verify_cdn_guard_unban.py`（临时脚本，不入库）**33 项断言全过**：
  `cdn_origin` 跳过 / ISP 关键字兜底 / 关开关恢复处置 / benign 不受影响 /
  白名单优先 / 端到端假网关（摘要与记录）/ 批量解封条数与状态 /
  daemon 真实 HTTP 链路（`clear_black`、`unban_all`）；
- 既有回归全通过：`ai_review_test.py`、`ai_bulk_e2e_test.py`、
  `verify_followup.py`、`verify_plugin_policy.py`、`verify_plugin_ai_async.py`、
  `verify_e2e.py`（22/22）、`check_settings_ids.cjs`、`check_html_js.cjs`；
- `python -m py_compile app/*.py frpwaf_main.py` 通过。

---

## Bug N（2026-10-09）：Windows 打包 CRLF 污染致 init 脚本无法执行

### 现象

服务重启/启动时报：

```
/usr/bin/bash: line 1: /etc/init.d/frpwaf: cannot execute: required file not found
```

### 根因

`/etc/init.d/frpwaf` 的 shebang 变成了 `#! /bin/bash\r`（末尾多一个 CR）。
内核解析 shebang 时把解释器路径当作 `/bin/bash\r`，该文件不存在 →
`cannot execute: required file not found`。

CR 的来源：仓库**索引里是 LF（正确）**，但 Windows 工作区
（`core.autocrlf=true`）是 CRLF，而 `build.sh` 用 `cp -a` **直接拷工作区**打包，
于是 CRLF 混进成品包；安装时 `cp -f frpwaf.init /etc/init.d/frpwaf`
把 CR 一起带到了系统里。

即：**只要在 Windows 上执行打包，就会复现**（与代码逻辑无关，是打包链路缺陷）。

### 修复

三层纵深防御（根因 + 两道兜底）：

1. **`build.sh`（根因）**：组装完包后，把所有文本文件
   （`*.py`/`*.sh`/`*.init`/`*.html`/`*.css`/`*.js`/`*.json`/`*.md`/`*.txt`）
   强制归一化为 LF；随后**校验**，若仍残留 CR 则 `exit 1` 中止打包
   —— 保证任何平台产出的包都是 LF；
2. **`install.sh`（兜底）**：拷贝 init 脚本后 `sed -i 's/\r$//'`，
   旧包也能装出正确的脚本；
3. **`frpwaf_main.py` `install_waf()`（兜底）**：面板「安装 / 更新」按钮
   走同一流程，同样做行尾归一化。

附带修复：`build.sh` 中选取 python 解释器时跳过 Windows 应用商店占位符
（`python3 -c` 会失败），并加 `sed` 回退；校验不用
`find -exec grep -lU`（GNU grep 3.0 下会把所有文本文件误报为命中），改用 python 判定。

### 验证

- 完整构建通过，退出码 0，输出「行尾检查通过（全 LF）」；
- 成品包复核：`frpwaf.init` / `install.sh` / `uninstall.sh` / `frpwaf_main.py` /
  `app/*.py` / `index.html` / `info.json` 均 **CRLF=0**，shebang 为 `#! /bin/bash`；
- `python -m py_compile app/*.py frpwaf_main.py` 通过；
- `bash -n install.sh uninstall.sh build.sh frpwaf.init` 通过。

### 受影响环境的手工修复

已装旧版（init 脚本带 CR）的机器，二选一：

```bash
# 方式一：直接修系统里的脚本
sed -i 's/\r$//' /etc/init.d/frpwaf /usr/bin/frpwaf
/etc/init.d/frpwaf restart

# 方式二：面板点「安装 / 更新」（新版本已内置归一化）
```

---

## Bug O（2026-11）：在线升级零哈希校验，可被兑换为 root RCE

**文件**：`app/upgrade.py` · `apply()` / `check()` / `_pick_package()` / `_download()` / `validate_tree()`

> 发现方式：2026-11 只读安全/性能评审（P0-2 + P1-6，报告
> `frpwaf-review/docs/optimization-review.md`）。修复提交 `3acad49`（分支 `frpwaf-upgrade`）。

### 现象

在线升级链路（面板「关于 → 一键升级」/ `/api/upgrade/apply` / 插件端 `upgrade_apply`）
只校验仓库地址符合 `owner/repo` 正则，随后就：

- 下载 GitHub 自动生成的 **源码 tarball**（`app/upgrade.py:98-103`），**无大小上限、无哈希、无签名**；
- `validate_tree` 只要求 `frpwaf_main.py` / `app/daemon.py` / `info.json` **三个文件名存在**，
  不查内容；
- 以 **root** 覆盖 `/opt/frpwaf` 与插件目录并在 2 秒后重启加载；
- 升级仓库地址来自**请求体** `repo`（`repo` 不可信）；
- 备份只增不减，覆盖与回滚都不删「新包已不存在」的 `.py`。

后果：任何拿到面板会话的人（叠加 Bug Q 的默认口令 = 一条已知路径）都能指定自己的仓库，
让 root 进程写下任意 `app/*.py` 并重启——**服务器 root 权限完全失守**。
即使仓库地址不可篡改，上游仓库/账号被接管也是同一条落地路径。
事后也无法证明落地的包到底是什么：审计只记 repo 字符串。

### 根因

两件事同时成立：

1. **可信边界错了**：把「仓库地址」当成了「代码可信」的证明，而仓库地址完全由请求方决定；
2. **落地包没有完整性锤点**：整条链路没有任何 sha256 / 签名比对，
   `validate_tree` 又只查文件名，等于「同名前门」直接放行。

### 修复

**原则：fail-closed——没有锤点就不升级。**

1. **只认带 sha256 锤点的发布包资产**（`.zip` / `.tar.gz`）：
   - 优先取 GitHub asset 的 `digest`（`sha256:...`）；
   - 拿不到时要求 Release 附带 `SHA256SUMS` / `pkg.sha256`（`_SUMS_NAMES`）并逐包比对；
   - **两者都没有 → 拒绝升级**，提示「该发布缺少校验信息」（不再退化去用源码 tarball）；
   - 下载后 `hmac.compare_digest` 常量时间比对，不一致直接失败（不「换源重试」）。
2. **体积/数量上限**：单包下载 32MB、单次读 256KB、解包后 96MB / 2000 文件、
   API 响应 1MB、SHA256SUMS 64KB；下载同时做 `Content-Length` 预检与累计字节硬限（防压缩炸弹）。
3. **传输面收窄**：改用 `http.client` 直连，只允许 https，**逐跳校验重定向**仍为 https，
   拒绝 `file:` / `data:` / 带 userinfo 的地址（旧实现用 `urlopen`，默认 opener 支持这些方案）。
4. **结构校验加强**（`validate_tree`）：`info.json` 可解析且带 `versions`、
   `app/daemon.py` 含 `def main(`、`frpwaf_main.py` 含 `class frpwaf_main`、
   且**包内版本必须等于发布 tag**（`expect_version`）；主文件/daemon 过短也判为异常。
5. **仓库只取自配置**：`apply()` 要求 `repo == config.github_repo`，
   请求体的 `repo` 一律忽略（「检查更新」仍可用入参 repo 做只读对比）。
6. **审计可追溯**：记录 `from → to`、包名、sha256、锤点来源（asset digest / 校验文件）；
   拒绝升级同样写审计并带原因。
7. **备份与陈旧模块**：备份只保留最近 3 份（`data/upgrade_backup/<ts>` 按时间序清理）；
   覆盖后删除目标目录里「新包已不存在」的 `.py/.pyc/.pyo`，**回滚也同样清理**
   （陈旧模块仍可被 import，是真实隐患）；升级前磁盘可用 < 50MB 直接拒绝。
8. 升级入口加**单实例锁**（并发点击只跑一个）；失败分支自动回滚。

> **取舍**：无校验信息时**拒绝升级**（fail-closed），不静默放行。
> 代价是发布流程必须上传带锤点的资产——已写入 `public-repo-release` 技能的检查清单。

### 验证

- 4 个隔离自检脚本：锤点选择（digest 优先 / SHA256SUMS 兼底 / 都没有则拒绝）、
  解包路径穿越与 zip 炸弹、下载上限、备份清理与陈旧模块删除；
- `apply()` 端到端（含失败回滚）——digest 不匹配时拒绝且目标目录未被修改；
- 用**真实 v1.4.2 发布资产**跑完整校验链：选包 → 下载 151,598 字节 →
  sha256 与 asset digest 逐字符一致 → `validate_tree` 通过（版本故意改成 9.9.9 时被拒）；
- 版本不一致 / 缺 `versions` / 缺 `def main(` 均被拒绝并给出中文原因。

### 严重度

**高（可导致 root RCE，且事后不可证明落地内容）**。

---

## Bug P（2026-11）：`frps.toml` 非原子写 + 校验失败仍落盘，可致全站隧道中断

**文件**：`frpwaf_main.py` · `_write()` / `_backup_file()` / `frp_save_raw()` / `_set_frps_plugin_addr()` / `apply_to_frps()`

> 发现方式：2026-11 只读安全/性能评审（P1-5，报告
> `frpwaf-review/docs/optimization-review.md`）。修复提交 `45ed6be`（分支 `frpwaf-upgrade`）。

### 现象

1. 面板「frp 管理 → 配置原文」保存一段 `frps verify` 通不过的配置时，接口仍返回
   「已保存，请检查」——**坏配置留在盘上**，用户以为存好了，下次 frps 重启才炸。
2. `frps.toml` 的写入是 `open(path, "w")` **先截断再写**，写入过程中进程被杀 /
   磁盘满 / OOM 会留下**半截文件**；frps 重启即起不来 → 全部隧道中断（fail-closed）。

### 根因

- `_write()` 直接 `open(path, "w")` 截断写，非原子；
- `frp_save_raw()` 先 `_write()` 再 `frp.verify()`，失败只返回提示、不回滚；
- 与 `app/frp.py:save_config()`（写临时文件 → verify → 失败回滚）的正确实现**不一致**；
- 另有两处用 shell `cp -a ... $(date)` 做备份，失败也不阻止后续写入。

### 修复

1. **`_write()` 改原子写**：同目录临时文件（`<path>.tmp.<pid>`）→ `flush` + `fsync` →
   保留原文件 mode → `os.replace()` → 目录 `fsync`（`_fsync_dir`）；
   并 `newline=""` 关闭换行转换（不让 CRLF 混进配置）。
2. **新增 `_backup_file()`**：备份为 `<path>.bak.<ts>`，**备份失败直接抛异常**，
   调用方据此**放弃写入**——绝不出现「备份没成功就把原文件改了」。
3. **`frp_save_raw()` 改为「候选文件 + verify + replace」**：
   写同目录候选 → `frps verify -c <候选>` → 通过才 `os.replace`；
   **失败删候选、原文件全程不动**，返回「配置校验未通过，已放弃保存」。
   候选必须与正式文件同目录（frp 对配置里的相对路径按配置文件位置解析，放 `/tmp` 校验会假失败）。
4. `FRPS_TOML` 三处写入（`_set_frps_plugin_addr` / `apply_to_frps` / 端口切换）
   统一走 `backup=True`；删除两处 shell `cp -a` 备份。
5. 顺带：注入 `[[httpPlugins]]` 的 `addr` 改由 `_frp_handler_endpoint()` 决定
   （`frp_handler_addr:frp_handler_port`，旧配置回退 `http_addr:http_port`，通配地址折算
   `127.0.0.1`），并把 `_set_frps_plugin_port(port)` 改为幂等的 `_set_frps_plugin_addr()`
   （已是目标值时不重写，不再每次都产生 `.bak`）；见 Bug Q 的配套提交 `979c5c6`。

### 验证

- `_write()` 原子性：写入中不产生半截目标文件；原文件 mode 保留；内容不转 CRLF；
  临时文件在任何路径上都不残留；
- `frp_save_raw()` 四个分支：TOML 语法错 / `verify` 不过 / `verify` 通过 / 备份失败，
  均符合预期且无残留候选文件；**校验失败时原文件字节不变**；
- `bash -n` / `python -m py_compile` 通过。

### 严重度

**高（配置损坏即 frps 起不来 → 全部隧道中断）**。

---

## Bug Q（2026-11）：面板默认对公网监听 + 默认弱口令 + 无强制改密

**文件**：`app/config.py` / `app/daemon.py` / `install.sh` / `frpwaf.init` / `app/blockpage.py` / 双端面板

> 发现方式：2026-11 只读安全/性能评审（P0-1，报告
> `frpwaf-review/docs/optimization-review.md`）。修复提交 `8409919`（面板侧）/
> `979c5c6`（插件端回传 `password_changed` + 回调端点配套）/ `5e141cd`（拦截页监听独立）。

### 现象

- `DEFAULTS["http_addr"]` 为 `"0.0.0.0"`，`admin_password` 为 `"123456"`，公开 README
  直接给出安装后的默认凭据 → 「装完 + 云安全组放通 7080」这一条**默认体验路径**
  就等于把 root 级操作面摆到公网；
- 登录后**没有强制改密**；`http_addr` 又不在 `/api/config` 白名单里，
  用户即使意识到风险也只能手改 `data/frpwaf.json`；
- 登录失败限速是**按来源 IP 的进程内字典**，分布式来源可完全绕过；重启即清零。

### 根因

默认值把「开箱能用」置于「默认安全」之上；且缺少「默认口令尚未修改」这个状态，
无法在接口层拦截。

### 修复

1. **默认只绑本机**：`http_addr` 默认改为 `127.0.0.1`；`install.sh` 在配置文件**不存在**时
   显式写入可访问地址（`127.0.0.1` / `7080` / 回调 `7082` / `password_changed=false`，`chmod 600`），
   **已存在则不覆盖**（避免升级抹掉用户改过的监听/口令/名单）。
2. **面板内可改回，但只接受四值**：`/api/config` 放开 `http_addr`，仅接受
   `127.0.0.1` / `0.0.0.0` / `::1` / `::`（`localhost` 归一化），其它值**明确报错不静默回退**；
   网页端「设置 → 监听与安全」的「允许远程访问」开关即对应此项。
3. **首登强制改密**：新增 `password_changed`；为 `false` 时除 `/api/login`、
   `/api/password`、`/api/overview` 与静态页外的 `/api/*` 一律
   `403 {"msg":"需先修改默认口令"}`；`/api/password` 拒绝把新口令设为 `123456`；
   `normalize_password_flag()` 按「口令是否仍等于出厂默认值」**推导**标志
   （改回 `123456` 会重新触发门禁），不采信存储值。
4. **登录限速双维度 + 落盘**：来源 IP（10 次/300s，锁定 300s 起指数退避封顶 3600s）
   + 全局失败总数（300 次/300s，冷却 60s 起指数退避），本机来源不参与全局冷却；
   失败计数落盘 `data/login_guard.json`（2 秒节流、原子替换、`chmod 600`），重启不清零。
5. **拦截页不被连带收紧**：新增 `block_page_addr`（默认 `0.0.0.0`），`blockpage.ensure()`
   改读该项，否则面板收紧到 `127.0.0.1` 后拦截页也只在本机监听，被封 IP 会变成连接超时
   而不是看到页面；`ensure()` 同时比对地址与端口（只改地址也能真正重绑）。
6. 双端面板补引导：网页端改密门禁弹层；插件端概览页在监听地址非回环时展示安全提示。

### 验证

- 隔离实例验证四种组合（监听 本机/通配 × 口令 默认/已改）：默认配置登录后除白名单 API
  外全部 403；改密后恢复正常；把口令改回 `123456` 后门禁重新生效；
- `/api/config` 传 `10.0.0.5` / 域名 → 明确报错且配置未变；传四值 → 立即重绑并回传实际监听位；
- 重启服务后失败计数仍生效（`login_guard.json`）；
- 拦截页在面板收紧后仍可从外网访问（`block_page_addr=0.0.0.0`）。

### 严重度

**高（默认配置即可被登录；叠加 Bug O 直接到 root）**。

---

## Bug R（2026-11）：面板并发无上限，慢连接可拖死 frps 回调（fail-closed 放大）

**文件**：`app/daemon.py` / `frpwaf.init` / `install.sh`

> 发现方式：2026-11 只读安全/性能评审（P0-3，报告
> `frpwaf-review/docs/optimization-review.md`）。修复提交 `8409919`（分支 `frpwaf-p0-panel`）。

### 现象

`ThreadingHTTPServer` 每连接一个线程（= 一个 fd），**无任何并发上限**，
且面板与 frps 回调共用同一个监听与同一批 fd；`frpwaf.init` 未提升 `RLIMIT_NOFILE`
（Debian 上通常 1024）。

后果：一次几百到一千条「连上不发送」的慢连接就能把 root 进程打到 `EMFILE` →
`accept` 失败 → **frps 的 `POST /frp/handler` 回调也失败** → frps 按项目设定
fail-closed 拒绝全部连接 → **全站隧道中断**。不依赖任何口令，成本极低。

### 根因

两层缺失叠加：①进程内无并发闸门；②面板面与回调面共用同一监听/同一 fd 预算，
所以「面板被扫」能直接变成「回调失败」。

### 修复

1. **并发硬闸门**：`_QuietHTTPServer` 加 `BoundedSemaphore`，超限的连接
   **直接 `shutdown`+`close` 而不排队**（排队的连接本身也占 fd；回 503 也要占一个线程与 fd）；
   超限计数按窗口汇总记一条日志，避免扫描时刷屏。默认面板 `96` / 回调 `32`
   （`max_concurrent` / `handler_max_concurrent`，钳制 `[8,512]`，可面板调）。
2. **回调与面板分端口**：回调独立监听 `127.0.0.1:7082`（`frp_handler_addr` /
   `frp_handler_port`），专用 Handler 只接 `/frp/handler`（其它路径 404）；
   面板监听仍兼容 `/frp/handler`（旧 `frps.toml` 不必改也能工作）。
   回调监听启动失败只告警并退回面板兼任，不让服务起不来。
3. **fd 上限**：`frpwaf.init` start 前 `ulimit -n 8192`（硬上限不足时忽略，闸门仍能兜住），
   `install.sh` 同步。
4. **端口冲突校验 + 运行时重绑**：面板/回调/拦截页端口两两不得相同（保存时拒绝，
   `normalize_listen` 加载时逐级回退）；改监听后 daemon **立即重绑**（先关旧后绑新，
   失败回退旧监听并报错）。

### 验证

- 并发压测：把 `max_concurrent` 调到 8，并发 50 条慢连接时新连接被立即断开、
  面板已建立请求不受影响，且**回调监听仍能正常响应**；
- 回调专用监听非 `/frp/handler` 路径返回 404；
- 端口冲突（面板=回调 / 回调=拦截页）保存被拒绝；改 `http_addr` 后监听位变化、
  绑定失败时回退旧地址并返回错误；
- `ulimit -n` 在服务进程内生效为 8192。

### 严重度

**高（低成本触发全部隧道中断）**。

---

## Bug S（2026-11-21）：init 的 PID 误判导致重启后服务静默不启动

**文件**：`frpwaf.init` / `frpwaf.service`（新增）/ `install.sh` / `uninstall.sh`

> 发现方式：2026-11 生产实测 + 只读性能/健壮性评审（P1-2，报告
> `frpwaf-review/docs/optimization-review.md`）。修复提交 `7746544`（分支 `frpwaf-init-heal`）。

### 现象

2026-11-21 生产上执行 `systemctl restart frps` 时出现：init 脚本报 `done`，
但**旧进程并没有退出**；紧接着启动侧又因「PID 文件里的 PID 还活着」判定为
`already running` 直接返回 0。结果 frps 在一段时间内**完全没在跑**，
**所有隧道中断**，而两个脚本的返回值全是成功。

（生产上踩的是 frps 的 init 脚本；`frpwaf.init` 是同一套 `get_pid` / `is_running` 写法，
同样会踩——它挂了则 frps 回调全部落空，按 fail-closed 同样全部隧道中断。）

### 根因

两层叠加：

1. **只看存活不看身份**：`is_running` 等价于 `kill -0 $(cat pidfile)`。掉电 / OOM /
   重启后 PID 会被系统和别的进程复用，`kill -0` 成功只说明「这个号码有进程」，
   不代表「它是我们的守护进程」。
2. **停止侧只信 pidfile**：pidfile 丢失或内容被清时，真正在跑的孤儿进程没人回收，
   而启动侧看到端口被占又会判定异常，两个方向都不自洽。

### 修复

**`frpwaf.init`（PID 判定改为「身份 + 可用性」双校验）**

- `is_daemon_pid`：`kill -0` 之外再读 `/proc/<pid>/cmdline`，必须命中
  **`-m app.daemon`**（用严格子串 `-m app.daemon` 而不是宽松的 `app.daemon`，
  避免把 `python -c "import app.daemon"` 这类巧合命令行误认成服务进程）。
- `start` 四步（顺序不可换）：① pidfile 里的 PID 身份不对 → 清掉；② pidfile 缺失/失效但
  守护进程仍在 → 按 cmdline 反查（`pgrep -f -- "-m app\.daemon"`，`--` 不可省，否则
  `-m` 被当成 pgrep 选项报 `invalid option` 并静默返回空）并**回填** pidfile，避免重复拉起撞端口；
  ③ 身份对**且**回调端点可用 → 才认 `already running`；④ 身份对但端点不通 → 判定**假阳性**，
  回收后重新拉起。
- `stop` 在 pidfile 缺失/无效时按 cmdline 反查孤儿进程，统一 TERM → 20×0.5s 轮询 →
  KILL 兜底 → **再次确认真的退出**，失败才报错，避免留下孤儿。
- **可用性探针 `probe_alive`** 打的是回调端点 `/frp/handler`（GET 期望 405），**不是**
  `/api/version`——后者属于 `/api/*` 必须先登录、`web_enabled=false` 时还会整体 403，
  无法区分「服务正常」与「面板关闭」。探针另加 `curl --noproxy '*'`：机器上配了
  `http_proxy` 时代理会给 `127.0.0.1` 回 503，让「端口没监听」被误判成健康（实测复现）。
- **systemd 托管时 `start`/`stop`/`status` 全部转调 systemctl**（`systemd_managed()`），
  否则 `frpwaf stop` 杀掉的进程会被 `Restart=always` 立刻拉回，表现为「停不掉」。

**`frpwaf.service`（新增 systemd unit）**：`Type=simple` + `Restart=always` +
`RestartSec=2` 自带自愈，替代 cron 看护；`LimitNOFILE=8192` 对齐 `ulimit -n 8192`；
`KillMode=mixed` + `TimeoutStopSec=15` 保证不残留子线程。详见
[02 §3.1](02-目录结构与安装部署.md)。

**`install.sh` / `uninstall.sh`**：有 systemd 就优先装 unit 并 enable，否则回退 init.d；
切换前先 `stop` 掉现有实例（旧 nohup 进程占着回调端口会让新 unit 反复 `EADDRINUSE`）；
插件包缺 unit 时**回退 init.d 而不是报错退出**（否则一次升级就把服务置为停止）。
卸载侧的顺序与 systemd 缓存坑见 [02 §3 / §3.1](02-目录结构与安装部署.md)。

### 验证

WSL Debian + 临时 `WAF_HOME` + 假 `app.daemon`（**未触碰生产**）：

- init 逻辑 **21 项**全通过，**含「用旧脚本对照复现误判」**（先证明旧写法会误判，再证明新写法不会）；
- systemd **15 项**全通过（启动 / `Restart=always` 自愈 / init 转调 / 停止不复活）；
- install **24 项**全通过（含「缺 unit 回退 init.d」「init.d → systemd 迁移不产生双实例」）；
- uninstall **12 项**全通过；
- `shellcheck`(strict) 0 告警、`bash -n` / `dash -n` 通过、`systemd-analyze verify` 通过。

### 严重度

**高**（服务静默不启动且脚本全报成功 → 全部隧道中断，且无任何告警）。

---

## Bug T（2026-11）：`frpwaf.service` 带 CRLF 行尾导致 systemd 解析失败

**文件**：`.gitattributes` / `build.sh` / `install.sh`

> 发现方式：新增 unit 后的打包链路复核。修复提交 `ca2bf0e`（分支 `main`）。
> 与 **Bug N** 同源：Bug N 是 `frpwaf.init`（shebang 变 `#!/bin/bash\r`），
> 本 Bug 是新增的 unit 文件。

### 现象

Windows 工作区（`core.autocrlf=true`）打包出的安装包里，`frpwaf.service` 是 CRLF 行尾。
装到 `/etc/systemd/system/frpwaf.service` 后 systemd **解析失败**：`Restart=always\r`
不是合法值，unit 起不来——而 init.d 路径是好的，于是表现为「某些机器装完服务不上」。

### 根因

两条前提叠加：

1. 仓库索引是 LF，但 Windows 工作区检出是 CRLF，而 `build.sh` 是 `cp -a` **直拷工作区**；
2. `.gitattributes` 的行尾规则是**白名单式**的（`*.py` / `*.sh` / `*.init` …），
   新增 `*.service` 时没人想到要加一条，于是它不受任何规则约束。

与 `frpwaf.init` 不同的是：**systemd 不会忽略行尾的 `\r`**（内核读 shebang 时也只是找不到
解释器），两者都是「文件看起来没坏、但服务起不来」这类最难查的故障。

### 修复

1. `.gitattributes` 新增 `*.service text eol=lf`，把「unit 必须 LF」固化进仓库策略；
2. `build.sh` 的行尾归一化清单**加入 `*.service`**（与 `*.init` 同一批处理），
   并在打包末尾校验「包内不得残留 CR」，残留则**中止打包**、绝不产出 CRLF 包；
3. `install.sh` 的 `Install_systemd_unit()` 写入前用 `tr -d '\r'` 整份去 CR（兜底，
   也兼顾用户手工放进插件目录的旧包），再用 `printf` 写入临时文件后 `mv` 到目标（原子替换）。

### 验证

- `git check-attr text eol -- frpwaf.service` → `text: set`、`eol: lf`；
- `build.sh zip` 后对成品包内 `*.service` 检查 `grep -c $'\r'` 为 0；
- 故意把工作区 unit 改成 CRLF 后跑 `build.sh` → 归一化成功、校验不命中、打包通过；
- 故意让包内残留 CR → 打包**中止**并报错（负向用例）。

### 严重度

**高**（unit 解析失败 → 服务不自愈/起不来；且只影响部分平台，极易在 Linux 上自测通过）。

---

## Bug U（2026-11）：存量配置缺新键 → 回调端点回退到面板端口，分端口隔离静默失效

**文件**：`frpwaf_main.py`

> 发现方式：分端口上线后的生产复核（自检全过，但实际注入值不对）。
> 修复提交 `4857d61`（分支 `main`）。

### 现象

P0-3 的「回调与面板分端口」上线后，**新装机器正常、存量机器没有生效**：
`frps.toml` 的 `[[httpPlugins]] addr` 仍然是 `127.0.0.1:7080`（面板端口）。
后果是分端口隔离完全失效——面板被慢连接/扫描打满时，回调仍与面板抢同一份 fd 与并发额度，
Bug R 修的问题在存量机器上**一点没改善**。

最坑的地方：**所有自检都是通过的**。配置项存在（`config.load()` 里有）、
服务起来了、面板能开、回调能通——只是走错了端口。

### 根因

两个函数读配置的方式不同：

- `_cfg_effective()`：`DEFAULTS` 叠加磁盘内容，**内存里补齐新键**——新键有默认值；
- `_cfg()`：只读磁盘**原始 JSON**——新键在文件里不存在，就真的不存在。

`frp_handler_port` 这类新键只在 `load()` 的**内存结果**里补齐，**不会回写到文件**。
于是注入路径用 `_cfg()` 读时拿不到 `frp_handler_port`，`int(None or 0)` 之类回退逻辑
把它降级成 `http_port`——**没有报错、没有告警，只是静默走了旧的单端口方案**。

### 修复

注入路径统一改用 `_cfg_effective()`（具体是 `_frp_handler_endpoint()` 取配置那一行）；
`_cfg()` 保留给「必须看磁盘原值」的场景（如判断某键是否被用户显式设置过）。

> 改动只有 **1 行**（`cfg = self._cfg()` → `cfg = self._cfg_effective()`），
> 但 `_frp_handler_endpoint()` 是回调端点的唯一计算入口（注入与对账都调它，
> 见 `frpwaf_main.py:612` / `:737`），所以修一处即全军生效。

### 验证

生产实测（修复前后对比）：

| | `endpoint` | `注入` |
|---|---|---|
| 修复前 | `("127.0.0.1", 7080)` | `False` |
| 修复后 | `("127.0.0.1", 7082)` | `True`，且 `frps.toml` 的 `addr` 已为 `7082` |

### 严重度

**高**（安全隔离失效，且**完全静默**：自检、日志、面板都看不出问题，
只有对照 `frps.toml` 才能发现）。

> **教学价值**：「配置项存在」≠「生效」。凡是「默认值靠 `DEFAULTS` 叠加、而磁盘里没有该键」
> 的字段，任何走原始磁盘读取的代码路径都会静默降级。新加配置键时，**必须同时检查所有读取路径**
> 用的是 `_cfg()` 还是 `_cfg_effective()`。

---

## Bug V（2026-11）：`/api/ai/test` 可用任意 `base_url` 让 root 进程发起请求（SSRF）

**文件**：`app/daemon.py` / `app/config.py` / `frpwaf_main.py`

> 发现方式：2026-11 只读安全评审（P1-7）。修复提交 `1245817`（分支 `frpwaf-daemon-sec`） /
> `d18a604`（新增 `ai_allow_private`）/ `1899f22`（插件端同步）。

### 现象

守护进程以 **root** 运行，而 `/api/ai/test` 会把请求体里的 `ai_base_url` 直接交给 `urllib`，
**只拼接不校验 scheme/host**。于是任何**已登录用户**（默认口令即可）都能让 root：

- `file:///etc/shadow` 读本机文件；
- `http://169.254.169.254/latest/meta-data/iam/...` 读云元数据（IMDSv1 开启时可拿 STS 凭据）；
- 扫内网管理口；
- 并且错误信息里**回显了响应体前 300 字符**，等于把 SSRF 变成一条**数据外带通道**。

### 根因

AI 模块把「用户填的地址」当成可信输入；`_https_only` 这类校验当时只写在 `upgrade.py` 里，
AI 模块没有。事后看更根本的问题是：**只校验 URL 文本、不校验解析后的 IP**——
即使限定了 http/https，`http://attacker.com` 指向内网仍能绕过。

### 修复

`daemon.ai_url_guard`，四条规则顺序不可交换：

1. **只允许 `http` / `https`**，其它 scheme 一律拒绝；
2. **先 `getaddrinfo` 解析，再按 IP 判定**；一次解析出多个地址时**任一不合规即整体拒绝**；
3. **永远拒绝**（不受任何配置影响）：`169.254.0.0/16`（含 `169.254.169.254`）、
   `100.100.100.200/32`（阿里云元数据）、`fd00:ec2::254/128`（AWS IPv6 元数据）、
   IPv6 链路本地 `fe80::/10`、组播、未指定地址（`0.0.0.0` / `::`）；
4. **私有 / 回环 / 保留地址**由新增配置 `ai_allow_private` 决定（默认 `true` 允许——
   AI 网关本来就在内网；置 `false` 则只允许公网）。

配套：

- **校验点有两处**：保存 `ai_base_url` 时（不能先存恶意地址、再走 `/api/ai/test` 绕开）+ 实际调用前；
- IPv4-mapped IPv6（`::ffff:1.2.3.4`）先**摊平为 IPv4** 再比较，否则换个写法就绕过网段判定；
- 错误摘要**不回显响应体**（只回 `HTTP 4xx/5xx`）；
- 插件端 `ai_test` 走同一套校验（`1899f22`）。

### 验证

- `file:///etc/passwd` → 拒绝（只允许 http/https）；
- `http://169.254.169.254/` / `http://[fd00:ec2::254]/` / `http://[fe80::1]/` → 拒绝（硬拒，`ai_allow_private` 取任何值）；
- `http://127.0.0.1:3000` 且 `ai_allow_private=true`（默认）→ 放行；置 `false` → 拒绝；
- 公网域名 A 记录指向 `10.0.0.5` → 拒绝（解析后判定）；同一域名 A 记录一公一私 → 整体拒绝；
- 连接失败时响应只有 `HTTP 502（响应体已省略，详见运行日志）`，不含内网内容。

### 严重度

**高**（root 进程 SSRF：内网探测 + 云元数据凭据 + 数据外带，登录即可触发）。

---

## Bug W（2026-11）：「读配置 → 改一项 → 整体回写」把机密字段覆盖成掩码 `******`

**文件**：`app/config.py` / `app/daemon.py` / `frpwaf_main.py`

> 发现方式：2026-11 只读安全评审（P1-8）。修复提交 `1245817`（daemon）/ `d18a604`
> （常量下沉到 `config.py`）/ `1899f22`（插件端）。

### 现象

`GET /api/config` 回显时把 `ai_api_key` 替换成 `"******"`；而 `POST /api/config` 的
`allowed` 表里 `"ai_api_key": str` 会把这串掩码**原样写回**。于是任何「读配置 → 改一个字段 →
整体提交」的客户端（含第三方脚本、将来的前端改造）都会把真实密钥**覆盖成 6 个星号**。

后果是**静默的**：AI 审查从此每次调用都 401，`ai_last_result` 被错误信息覆盖，
界面上看起来只是「AI 审查不工作」。同样的坑对 `admin_password` / `secret` 一样成立——
把口令写成 `******` 等于把自己锁在门外。

### 根因

「回显掩码」这件事只做了一半：**读侧掩码、写侧不认识掩码**。而三条写入路径
（`daemon` 的 `/api/config`、插件端 `ai_save_config`、`config.save`）各自实现，
插件端早就有 `if v != "******"` 判断，守护进程没有——**两端行为不一致**。

### 修复

1. 常量下沉到 `app/config.py`（唯一真源，禁止各端硬编码副本）：
   `MASKED_VALUE = "******"`、`MASKED_KEYS = ("ai_api_key", "admin_password", "secret")`；
2. 三条写入路径共用同一语义：**值等于 `MASKED_VALUE` 的机密字段一律丢弃**；
   注意「丢弃」= **保留磁盘原值**，**不是清空**（要清空得传空串）；
3. 读侧行为对齐：`secret` / `admin_password` **不返回**，`ai_api_key` 有值才回掩码。

### 验证

- `GET /api/config` 拿到的 `ai_api_key` 为 `******` → 原样 `POST` 回去 → 再 `GET`，
  磁盘 `data/frpwaf.json` 里的真实密钥**未被改写**（对比 `sha256sum`）；
- 传送空串 `""` → 密钥**被清空**（证明「丢弃」与「清空」语义区分正确）；
- `secret` 在响应里完全不出现；改密后回写全量配置不会导致旧会话复活。

### 严重度

**高**（一次正常保存就可能静默破坏 AI 密钥或管理员口令，无可观测告警）。

---

## Bug X（2026-11）：日志可被 frpc 客户端注入伪造（一行变两行）

**文件**：`app/daemon.py` / `frpwaf_main.py`

> 发现方式：2026-11 只读安全评审（P1-9）。修复提交 `1245817`（daemon）/ `1899f22`（插件端）。

### 现象

`_log` / `_audit` 直接把 `msg` 写进 `data/frpwaf.log`，而调用点里含外部可控字段：
`proxy_name` / `proxy_type` / `user` 来自 frpc 客户端的 `NewUserConn` 回调。
只要其中含一个 `\n`，就能**凭空插入一整行看似可信的日志**——例如伪造一条
`[审计] 修改管理员口令`，而 `/api/syslog` 与插件端「运行日志」页会**原样展示**。

日志是安全产品的取证依据，取证链一旦可被攻击者写入，事后定性与追责就全失效。

### 根因

把「日志」当成纯输出通道，忽略了它是**结构化记录**：任何不可信字段都必须
在进入时消掉「换行 = 新记录」这个能力，而不是指望调用方自觉。

### 修复

日志入口统一净化（`daemon._log`，`_audit` 也走它；插件端 `_log_text` 同口径）：

| 处理 | 规则 |
|---|---|
| 行分隔符 | `\r` / `\n` 转义成**字面量** `\\r` / `\\n`（不再拆行） |
| 其它控制字符 | `\x00-\x08` / `\x0b` / `\x0c` / `\x0e-\x1f` / `\x7f` **丢弃** |
| 长度 | 不可信字段截断到 **64 字符**（`_LOG_FIELD_MAX`，超出补 `...`） |

插件端从 `config` 按 `getattr(..., "MASKED_VALUE", "******")` 取常量，
两端规则**必须一致**——「一端净化、一端不净化」等于把防护降到较弱的一端。

### 验证

- 构造 `proxy_name = "正常\n[审计] 已解封全部黑名单"` 的回调 → 日志里只有**一行**，
  且换行被转义为字面 `\n`，不会出现独立的 `[审计]` 行；
- 超长 `proxy_name`（200 字符）→ 日志中截断到 64 + `...`；
- 正常日志格式（时间戳前缀）不变。

### 严重度

**中高**（取证链可被污染，且可用于伪造高危操作记录；不直接影响业务可用性）。

---

## Bug Y（2026-11）：地址解析失败静默放行，且 IPv4-mapped 形态使黑名单整段失效

**文件**：`app/daemon.py` / `app/engine.py` / `app/store.py` / `app/config.py`

> 发现方式：2026-11 只读安全评审（P1-11）。修复提交 `1245817`（daemon）/
> `a0fd5c7`（engine 归一化 + `strict_addr`）/ `d18a604`（配置键）。

### 现象

两个独立但同源的缺陷：

1. **形态变了就静默放行**：`_split_addr` 用 `addr.count(":") == 1` 判断是不是 `ip:port`，
   其余整串当「纯 IPv6」返回 → `ipaddress.ip_address()` 抛错 → 决策**直接返回 allow**
   （`invalid-ip-pass`），只留一条「字段异常，已放行」日志。只要 frps 输出格式变成
   `2001:db8::1:5678`（不带方括号）或任何非 IP 字符串，**黑白名单与自动封禁全部静默失效**。
2. **IPv4-mapped 不命中**：`ipaddress.ip_address("::ffff:1.2.3.4")` 是 IPv6 对象，
   与 `ip_list` 里的 `1.2.3.4` **永不相等** → 黑名单对该形态的连接完全无效。

当前 frps（Go `net.TCPAddr.String()`）输出带方括号，所以**生产上暂时不触发**——
但这是单点：frps 升级、前置代理改动、自研回调任一变化就会踩，且**没有任何告警**。

### 根因

`_split_addr` 是「猜格式」而不是「严格解析」，失败时又选了一个**无感**的兜底（放行 + 一行日志）；
同时归一化只做在部分入口，没覆盖「名单匹配 / 封禁查询 / 写入」三处。

### 修复

1. **严格解析**：`_split_addr` 改正则 + `ipaddress.ip_address`，接受
   `'1.2.3.4:5678'` / `'[::1]:5678'` / `'[::1]'` / `'1.2.3.4'` / `'::1'`，
   解析不出就返回 `("", 0)`，由调用方决定放行还是拒连；
2. **可见化**：`_mem["invalid_addr"]` 计数（限频告警），经 `/api/overview` 暴露——
   把「静默失效」变成可观测指标；
3. **可切 fail-closed**：新增配置 `strict_addr`（默认 `false` 保持原行为）——
   `false` 放行并计数（`invalid-ip-pass`），`true` **拒连**（`invalid-ip-strict`）；
4. **v4-mapped 归一化**：`::ffff:1.2.3.4` → `1.2.3.4`，在**进决策前**完成一次
   （daemon `_split_addr` 与 engine `decide` 双保险），后续白/黑名单匹配、封禁查询、
   限速与自动封禁计数**口径一致**；决策路径写入名单/封禁前也再归一化一次
   （`_attack_ban` 把 `ip` 换成归一化形态再 `store.add_ip`/`store.add_ban`）。
   另外反向也兼容：名单里写成 `::ffff:1.2.3.0/120` 时，IPv4 连接也能命中
   （`_match_cands` 只在 `::ffff:0:0/96` 及更具体的前缀内追加映射候选，
   避免 `::/0` 这类「整个 IPv6」网段把 IPv4 连接一并拦下）。

### 验证

- `remote_addr = "2001:db8::1:5678"`（不带方括号）→ `strict_addr=false` 时放行且
  `invalid_addr` +1；`strict_addr=true` 时 reject 且 reason 为 `invalid-ip-strict`；
- 黑名单加 `1.2.3.4` 后，回调 `remote_addr = "::ffff:1.2.3.4:5678"` → **正确 reject**
  （修复前为 allow）；自动封禁写入的也是 `1.2.3.4/32` 而不是映射形态；
- 名单里写 `::ffff:1.2.3.0/120` 时，IPv4 连接 `1.2.3.4` 也能命中；
- 正常 `1.2.3.4:5678` / `[::1]:5678` 行为不变（回归）。

> **遗留（未在本轮处理）**：`store` 自身不归一化，所以经 `POST /api/iplist`
> **直接手填** `::ffff:1.2.3.4/32` 会以映射形态落库（判定仍能命中，但库里会同时存在
> `1.2.3.4/32` 与 `::ffff:1.2.3.4/32` 两条语义相同的记录）。建议后续在
> `store.add_ip` 入口统一折叠。

### 严重度

**高**（黑名单在特定形态下整段失效，且无告警；`strict_addr` 提供主动收紧手段）。

---

## Bug Z（2026-11-22）：备份保留策略在连续备份时失效（写了策略 ≠ 策略生效）

**文件**：`app/store.py`（`_backup_name` / `_claim_backup_path` / `backup_db` / `_prune_backups`）

> 发现方式：新功能自验（数据快照备份 P2-3.11）。修复提交 `034379d`，
> 回归用例 `6f78d93` + `034379d`（`tests/test_backup.py` 共 12 例）。

### 现象

`backup_db(keep=7)` 写明「只保留最近 7 份」，但在**真实时钟下连续调用**时根本攒不满：
在同一秒里连做十几次备份，`data/backup/` 里最后只剩 **2 个文件**（而不是 7 个）。

后果比「少几份备份」更隐蔽：单个文件被下一次备份**覆盖**后，那份快照就永久没了——
用户以为「过去一周每天都有快照」，实际只有最后几次。而备份机制本来就是为
`purge_logs` / `clear_blacklist` / 误删目录这类**不可逆操作**兜底的，兜底本身失效时
没有任何报错。

### 根因

备份文件名只精确到**秒**（`frpwaf-YYYYMMDD-HHMMSS.db`），而 `backup_db()` 落地用的是
`os.replace(tmp, final)`——**同秒内的第二次备份会算出同一个 `final` 并把第一份原子地覆盖掉**。
于是：

1. 同一秒内 N 次备份 → 磁盘上只有 1 个文件（秒跨过去了才多一个）；
2. `_prune_backups` 按「文件名排序取最近 keep 份」裁剪，但**手上根本没有 keep 份**，
   裁剪是空转；
3. 整条链「策略写了但没生效」，且因为每一步都成功返回 `(True, path)`，**没有任何信号**。

上游成因是验证方式：上一批的 10 个用例全都用 `mock` **按用例驱动时间戳**（每例手动给一个
不同名字），只验证了「裁剪逻辑本身选得对不对」，没验证「真实时钟下连续备份能不能攒满」。
**时间源被打桩时，撞名这个维度就从测试视野里消失了。**

### 修复

1. **文件名加微秒定宽**：`frpwaf-YYYYMMDD-HHMMSS-ffffff.db`。用**整数微秒**而不是
   「秒 + 浮点小数」——epoch 秒已到 1.7e9，float64 在该量级的最小增量约 0.24µs，
   浮点算亚秒段会抖；各字段定宽且分隔符一致，因此**字典序仍严格等于时间序**
   （裁剪靠排序，这个不变式不能破）。
2. **`O_CREAT|O_EXCL` 原子占位**（`_claim_backup_path`）：先按当前微秒算出名字，再以
   排他创建 `<name>.db.tmp` 抢占；OS 保证同一时刻只有一个进程能创建成功，因此
   **多进程（守护进程与插件端）并发备份也不会抢到同一个名字**。
3. **撞名顺延 1µs 重试**（最多 1000 次）：新名字仍大于旧名字，字典序不变；
   占不到名字就**放弃本轮**，绝不复用/覆盖既有快照。
4. **裁剪只认本程序的完整命名**（`frpwaf-<ts>[-ffffff].db`）：运维自己 `cp` 进备份
   目录的 `.db` / 其它文件永远不会被当成备份删掉；旧版秒精度命名仍被识别
   （不会变成删不掉的垃圾），且因名字最小被优先裁剪。

### 验证

- **原场景**：真实时钟下连做 10 次 `backup_db()`，修复前只剩 **2 个文件**；
  修复后达到 `keep=7`，且留下的就是**最后 7 次**（个数、身份、次序三样都比）；
- `test_consecutive_backups_reach_keep_limit`：真实时钟连做 **12 次（不 sleep）** →
  12 次产生 **12 个互不相同的名字**，裁剪后正好 7 份 = 最后 7 次，名字严格递增；
- `test_prune_spares_foreign_files`：备份目录里放 `manual-dump.db` / `frpwaf-notes.db` /
  `keep-me.txt` 与一份旧版秒精度命名，12 次备份后前者**原封不动**、旧版命名被裁掉；
- `test_retention_keeps_newest_seven`（打桩时间戳）仍通过：裁剪逻辑本身没被改坏；
- 慢快照一致性、不持全局锁、磁盘不足跳过、库不存在不抛异常等其余用例全部通过；
  全量 **133** 个用例绿。

### 严重度

**中**：不直接影响准入与在线流量，但**备份机制静默失效**——
真正需要回滚时才发现没有可用的历史快照，而那时已无法补救。

> **教学价值**：这是「**策略写了 ≠ 策略生效**」的典型样本。规则写在 `keep=7` 上是声明，
> 生效需要「名字不撞、裁剪有东西可裁、失败可见」三个条件同时成立；当时 10 个测试
> 全绿也未能发现，因为**测试把时间源打桩成了理想值**，恰好绕开了唯一的失效维度。

---

## Bug AA（2026-11）：升级/测试连接同步执行撞上 60s 代理超时（页面报失败，后台其实成功）

**文件**：`app/job.py`（新增）/ `app/daemon.py` / `frpwaf_main.py` / `index.html` / `web/index.html`

> 发现方式：P2-3.5 长耗时操作梳理。修复提交 `74c0702`（守护进程 + `app/job.py`）、
> `e56a97e`（Web 端）、`4f252a1`（插件端）。

### 现象

在面板点「在线升级」或「AI 测试连接」，页面转圈到 **60 秒左右**后提示失败
（插件端弹「提交失败」/请求超时，Web 端报网络错误）；但重新打开页面或刷新版本号，
发现**升级其实已经成功**（或模型其实已经回了），只是结果没回到浏览器。

后果是诱发重复操作：用户以为没成，反复点升级 → 同一批文件被多次覆盖；
反复点测试连接 → 多个并发请求打同一个模型（既耗额度，也看不出哪次是真实结果）。

### 根因

两个操作都是**在请求线程里同步执行**：

- 升级：`POST /api/upgrade/apply`（`app/daemon.py`）与插件端 `upgrade_apply`
  在请求内直接调 `upgrade.apply()` —— 下载发布包（最长 60s）+ 解包 + 覆盖几百个文件 + 重启；
- 测试连接：`POST /api/ai/test`（`app/daemon.py`）与插件端 `ai_test` 在请求内直接调
  `ai.call_model()`，模型超时上限 `ai_timeout` 默认 **120s**。

而宝塔面板前置的 Nginx **默认 60s 超时**：先到的是代理超时，连接被断开、浏览器拿到
失败/空响应；而后台 Python 线程**并不因此停下**，它继续把升级/调用跑完。
即「用户看到的结果」与「实际发生的结果」从这一刻起分叉，且双方都不知道。

### 修复

1. **新增 `app/job.py`**（通用后台任务状态模块）：状态原子落盘（`data/job_<kind>.json`，
   临时文件 + `os.replace`）、10 秒心跳 + 60 秒僵死判定、按 `kind` 串行，字段契约固定为
   `job_id/kind/running/percent/msg/done/ok/error/ts/started/finished/ms`。
2. **两个操作改为「提交 + 轮询」**：`POST /api/upgrade/apply`、`POST /api/ai/test`
   （以及插件端 `upgrade_apply` / `ai_test`）只做**提交前校验**（仓库配置、AI 地址 SSRF
   校验——坏地址不占任务名额），随后**立即返回** `data.job_id`；实际耗时工作需要的结果
   由 `job.status()` 提供。
3. **新增两个状态端点**：`GET /api/upgrade/status`、`GET /api/ai/test/status`
   （插件端 `upgrade_status` / `ai_test_status`），返回同一份 job 状态。
4. **双端前端改轮询**：间隔 1500ms、上限 10 分钟，并**容忍「升级重启窗口」内的请求失败**
   （插件端连续 8 次、Web 端连续 20 次才报错），避免在升级成功的瞬间报「失败」。
5. **并发保护**：同类任务已在跑时第二个提交被拒（`code:1` + 「已有任务在进行中（…），
   请等待完成」），既防两个升级同时覆盖同一批文件，也防连点按钮并发打模型。

### 验证

- **真实行为实测**（`app/job.py` 在独立 `FRPWAF_HOME` 下跑，不进仓库）：提交后立即返回
  `running=true, done=false`；同 kind 第二次提交被拒且 `msg` 带出当前阶段；任务结束后
  `done=true, ok=true, percent=100, ms` 与 worker 返回的附加字段（`from`/`to`/`sha256`）
  一并并入状态文件；`running=true` 而心跳超时后状态被改写为「已中断」且 `ok=false`。
- **前端**：升级过程中页面显示阶段说明 + 百分比 + 「已等待 N 秒」；重启窗口内的失败请求
  只换提示不打断，升级后在 6s / 20s 各静默重读一次版本号。
- **接口契约**：两个 `status` 端点需登录（未登录 `401`，首登未改密时 `403`），无入参，
  空状态返回全默认值；详见 [10 §12.1](10-HTTP_API参考.md)。

### 严重度

**中**：不影响功能正确性（升级/测试最终都真的执行了），但会**误导用户判断**并诱发重复操作
（重复覆盖文件、重复请求模型），也是「用户报『升级失败』但版本号确实变了」这类
排查困惑的根源。

> **维护者须知**：僵死判定是「`running=true` 且心跳超过 `STALE`（60s）未更新」，
> 它依赖不变式 **`HEARTBEAT`(10s) < `STALE`(60s)** —— 改小 `STALE` 到 ≤ 心跳间隔会把
> 下载大包/模型迟迟不回的正常任务误判为中断；改大则用户要多等一会儿才能收尾。
> 另外任务状态文件**不会自动删除**，排障时 `cat data/job_*.json` 能看到上次结果（见
> [11 §6.5](11-开发运维与常见问题.md)）。

---

## Bug AB（2026-12-02）：概览卡片区的口径说明被塞进 grid 容器，版面塌陷

**现象**：插件端概览页 8 张统计卡片挤成一行，而「统计口径：……」那一大段说明被压成
最右侧一条**竖直的文字列**（逐字换行、几乎不可读），并把整页高度撑得很长。

**根因**：`.fw-stats` 是 `display:grid`（`repeat(auto-fit,minmax(130px,1fr))`），而渲染
代码把说明 div 连同卡片一起拼进了同一个容器的 `innerHTML`：

```js
document.getElementById('fwStats').innerHTML = cards.map(...).join('')
  + '<div class="fw-tip" style="flex-basis:100%;margin:6px 0 0">统计口径：…</div>';
```

`flex-basis` 是 flex 属性，在 grid 容器里完全无效。于是说明 div 被当成一个普通网格
单元格参与 auto-fit 排布，落在最窄的一列里被逐字折行。

实测（Chromium，视口 1400、卡片区宽 1158px、6 列 × 183px）把说明追加进网格后：

| 指标 | 说明在网格内（旧） | 说明在网格外（新） |
|---|---|---|
| 说明宽度 | 183px（单列） | 1173px（整宽） |
| 说明高度 | 518px | 108px（两段说明合计） |
| 同行卡片高度 | 117px → **524px**（被撑高 4.5 倍） | 117px |

**修复**：说明移出网格——`index.html` 在 `#fwStats` 之后新增 `#fwStatsNote` 容器，
统计口径与攻击类型两段说明整宽渲染在那里，网格只放卡片。同时把 `minmax(130px,1fr)`
提到 `minmax(170px,1fr)`，避免 1200px 左右仍挤成一行 8 列导致文字溢出。

**顺带修掉的同类问题**：同一渲染函数里的第二段说明（「攻击类型封禁」）也是用
`flex-basis:100%` 塞进网格，一并移出。全仓库再无非网格容器里的该写法。

**顺带修掉的口径误导**：「近24h新增封禁」副行原为
`当前生效 (perm+temp)（临时 temp · 永久名单 perm）`，把**黑名单条目数**与
**生效封禁数**相加后称作「当前生效」，与同一行的「生效封禁 = 0」卡片自相矛盾。
改为 `黑名单 N 条 · 临时封禁 M 条生效`，口径说明同步注明「黑名单条数即名单规模，
不代表正在生效的封禁；生效封禁数只看「生效封禁」卡片」。两端同步。

**回归防线**：`tests/test_panel_overview_copy.py::PanelStatsLayoutTest` 用文本断言钉住
「说明容器在网格之外」「网格 innerHTML 不含 `.fw-tip`」「两端都不再有内联 flex-basis」
「副行不再出现 `当前生效` + `(perm+temp)` 拼接」。

## Bug AC（2026-12）：插件端 `FW_POLICY_STR` 声明被误删，「保存策略」全部静默失效

**现象**：插件端设置页点「保存策略」没任何反应——不报错、不提示、配置也不变。
因为没有任何报错信息，很容易被当成「网络慢了」或「本来就保存了」。

**根因**：提交 `294c07c`（加 `strict_addr` / `ai_allow_private` 开关）改动
`FW_POLICY_BOOL` / `FW_POLICY_INT` 时，把紧跟其后的

```js
var FW_POLICY_STR=['github_repo','block_page_redirect_ports'];
```

整行删掉了，但 `fwLoadPolicy` / `fwSavePolicy` 仍在调用 `FW_POLICY_STR.forEach(...)`。
于是两个函数执行到那一行就抛 `ReferenceError`：

- `fwLoadPolicy`：布尔与整数已经回填完，字符串字段（`github_repo`、拦截页重定向
  端口）永远回显为空；
- `fwSavePolicy`：**`fwSend('save_policy', …)` 在抛错之后，所以一次也没发出去**，
  整个保存链路死掉。

**修复**：恢复声明，并把新增的字符串字段一并加入（`sys_ssh_log`、`sys_protect_ips`），
同时加注释说明「新增字符串字段必须加在这里」及其失效后果。

**回归防线**：`tests/test_sysdetect_panel.py::PanelSysdetectCopyTest`
`.test_panel_policy_str_list_declared` 断言 `var FW_POLICY_STR=[` 存在且包含新增键。
（只钉声明存在——断言具体内容会随字段增长而频繁失效。）

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
| M | `ai.py` / `config.py` / `store.py` / `daemon.py` / `frpwaf_main.py` / 双端面板 | AI 误封 CDN 回源边缘 IP 致整站 522；缺回源豁免与批量恢复工具 | 高（整站不可访问） |
| N | `build.sh` / `install.sh` / `frpwaf_main.py` | Windows 工作区 CRLF 混入成品包，`/etc/init.d/frpwaf` shebang 变 `#!/bin/bash\r`，服务重启报 `cannot execute: required file not found` | 高（服务无法启动/重启） |
| O | `app/upgrade.py` | 升级链路零哈希/零签名校验、仓库取自请求体、无体积上限、陈旧模块不清理 | 高（root RCE） |
| P | `frpwaf_main.py` | `frps.toml` 非原子写；`frp_save_raw` 校验失败仍落盘 | 高（配置损坏 → 全站隧道中断） |
| Q | `app/config.py` / `app/daemon.py` / `install.sh` / `frpwaf.init` / `app/blockpage.py` / 双端面板 | 面板默认监听 `0.0.0.0` + 默认弱口令 + 无强制改密；登录限速可被分布式绕过且重启清零 | 高（默认配置即可被登录） |
| R | `app/daemon.py` / `frpwaf.init` / `install.sh` | 面板无并发上限且与回调同 fd 预算，慢连接可致回调失败 → fail-closed 全站拒连 | 高（全站隧道中断） |
| S | `frpwaf.init` / `frpwaf.service` / `install.sh` / `uninstall.sh` | PID 判定只看 `kill -0`，PID 被复用即误判「已在运行」→ 重启后服务静默不启动 | 高（全站隧道中断且无告警） |
| T | `.gitattributes` / `build.sh` / `install.sh` | `frpwaf.service` 带 CRLF，systemd 把 `always\r` 当非法值、unit 解析失败 | 高（服务不自愈/起不来） |
| U | `frpwaf_main.py` | 注入路径用 `_cfg()`（磁盘原值）而非 `_cfg_effective()`，存量配置缺新键 → 回调回退面板端口、分端口隔离静默失效 | 高（隔离失效且完全静默） |
| V | `app/daemon.py` / `app/config.py` / `frpwaf_main.py` | `/api/ai/test` 可用任意 `base_url` 让 root 进程请求（SSRF）；错误回显响应体 | 高（内网探测/云元数据/数据外带） |
| W | `app/config.py` / `app/daemon.py` / `frpwaf_main.py` | 回显掩码 `******` 被原样回写，覆盖真实密钥/口令 | 高（静默破坏密钥与口令） |
| X | `app/daemon.py` / `frpwaf_main.py` | 日志/审计可被 frpc 客户端注入伪造（`\n` 拆行） | 中高（取证链可污染） |
| Y | `app/daemon.py` / `app/engine.py` / `app/store.py` / `app/config.py` | 地址解析失败静默放行（无告警）；IPv4-mapped 未归一化致黑名单整段失效 | 高（黑名单失效且无告警） |
| Z | `app/store.py` | 备份文件名只精确到秒，同秒连续备份互相覆盖 → 「保留 7 份」策略失效 | 中（备份静默失效，需回滚时才发现） |
| AA | `app/job.py` / `app/daemon.py` / `frpwaf_main.py` / 双端面板 | 升级/测试连接在请求线程内同步执行，超 60s 代理超时 → 页面报失败而后台已成功，诱发重复操作 | 中（不影响正确性，影响用户判断） |
| AB | `index.html` / `web/index.html` | 概览把口径说明拼进 `display:grid` 容器（`flex-basis:100%` 在 grid 无效）→ 说明被压成竖排文字列并把同行卡片撑高 4.5 倍；副行把名单条目数与生效封禁数相加称「当前生效」 | 中（版面塌陷 + 口径误导） |
| AC | `index.html` | `FW_POLICY_STR` 声明被误删 → `fwLoadPolicy`/`fwSavePolicy` 抛 `ReferenceError`，「保存策略」一次也没发出去且无任何报错 | 高（配置修改完全失效且静默） |
