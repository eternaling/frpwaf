# 12 · Bug 修复记录

本文记录本项目**历次发现并修复的全部功能 Bug**，含现象、根因、修复与验证。
共 6 个（Bug A–F），均在隔离环境复现、修复、验证后应用到生产。

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
