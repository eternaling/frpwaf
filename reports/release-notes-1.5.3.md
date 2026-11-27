# FRPWAF v1.5.3 发布说明

| 项 | 值 |
|---|---|
| 版本 | `1.5.3` |
| 上一版 | `v1.5.2` |
| 版本号提交 | 待发布时回填（本文件先于 Tag 产出） |
| 提交数 | `git rev-list --count v1.5.2..HEAD` = **20**（含 5 个合并提交） |
| 发布包 | `frpwaf-1.5.3.zip`（构建产物位于 `dist/frpwaf.zip`） |
| 包大小 | **275464** 字节 |
| 成品包 SHA-256 | `743b545cdeea5209594db024d3f10cb8af463a7f420ebbbaeace7f10d39b01fd` |
| 包内文件数 | **27** |
| 包内抽查 | 9 项全过（版本号两处一致 / `_TRUST_SUBNET_MIN_IPS=3` / `_in_trusted_cidr` / `_PANEL_PAYLOAD` / `purge_legacy_trusted_cidrs` / 版本闸门两变量 / `frpwaf.init` 首行纯 LF / 顶层无多余目录） |
| 测试 | 全套 `python -m unittest discover -s tests -t .` 通过，零 `expectedFailure` |

> 状态：**材料已就绪，尚未发布**。owner 未批准前不执行 Tag、双端 Release、附件上传。

---

## 1. 为什么要发这一版

v1.5.2 之后 `main` 上又合入 20 个提交，其中包含来源识别口径、自动处置豁免、
版面（插件元数据）与在线升级行为的实质修改，但都**没有随之发版**。

结果是发布包继续落后于生产代码：换机器安装或使用「在线升级」，装回来的仍是
v1.5.2 的行为。v1.5.2 那次发版的直接起因就是同一形态的问题（见
[docs/13](../docs/13-变更历史与版本.md) §13.1），本版不再重复。

本版另有一处**必须随包下发**的修复：`info.json` 的 `checks` 字段类型错误会让
面板遍历插件列表时抛异常（详见 §2.2），这不是运行期热修能覆盖的，只能靠新包。

---

## 2. 本版包含的改动

### 2.1 来源识别与处置

**① CDN 回源判定加类型硬否决**

判定不再只看「碰过多个代理」这一类行为特征，而是先看端口/协议类型：

- 只有当来源触达的代理**全部属于 Web 类型**时，才可能被认作回源；
  纯 tcp 端口上的来源直接否决，不进后续任何一层判定。
- 行为层要求类型齐全：多站点判定（`web_multi`）需要 `ptypes` 非空且全为 Web 类型，
  仅凭「代理名个数」不再足以认定回源。
- 弱证据不再持久化：只有 `keyword`、以及 `model` 配合交叉证据才写入学习表；
  行为层单独命中与同段熔断只跳过本次，不再写入长期条目。
- 模型层要交叉证据：`category=cdn_origin` 必须配合关键字命中或
  「全 Web 类型 + 多站点」，否则不认。原实现把模型层当作最可靠来源，
  但它实际只在模型自相矛盾时才触发，属最不可靠的样本。
- 关键字收紧：删除裸 `esa`（子串匹配会误中 Empresa / Mesa / Telesat / Teresa
  这类无关文本），改为完整短语；4 字符以下 ASCII 关键字统一要求词边界。
- 提示词去掉绝对化措辞，改为可验证条件，并明确「通用云厂商不能仅凭厂商名判回源」
  「非 Web 端口不可能是回源」。
- 学习条目记录命中层与来源（`model` / `keyword` / `behavior`），面板可区分。

配套存储侧：`trusted_cidr` 增 `source` / `expires_at` / `first_reason` 三列，
幂等迁移（`PRAGMA` 查列，缺列才 `ALTER`）；按来源分级有效期
（`manual` 永久 / `keyword` 30d / `model` 14d / `behavior`+subnet 24h）；
查询过滤过期条目、命中续期（上限 `created_at+90d`）；
`purge_expired_trusted_cidrs` 挂到守护进程周期任务；条数上限淘汰。
`first_reason` 冲突时不覆盖，原始理由可追溯。

**② 四条自动处置路径接上可信回源网段豁免**

此前只有 AI 侧不处置回源来源，引擎侧的四条自动处置路径完全不查可信网段，
于是「AI 不管」形同虚设。本版让引擎侧与 AI 侧同口径：

| 路径 | 说明 |
|---|---|
| 基础阈值 | 第 5 步基础自动处置 |
| 敏感端口探测 | 永久名单判定点 |
| CC（高频请求） | 默认 300/60s，共享回源节点很容易达标 |
| 多源探测 | 回源节点访问多站点正是误判画像，也接入豁免 |

实现要点：

- 新增 `engine._in_trusted_cidr()`：人工 `ai_trusted_cidrs` + 学习表，
  与 `app/ai.py::_in_trusted_cidr` **同口径，两处必须一起改**。
- 新增 `engine._trusted_cidr_index()`：`/32` 走 `(版本, 整数)` 集合 O(1) 命中，
  宽网段（`/24` 升级）逐个比较；3 秒缓存，`invalidate_cache()` 立即失效，
  决策热路径不查库。带版本判断，避免 IPv4 `0.0.0.1` 与 IPv6 `::1` 整数相同误配。
- 读库失败按「没有可信网段」处理——宁可照常处置，也不全量放行。
- 热路径开销实测：空表 4.3us/次，满载 2020 条 8.4us/次（增量约 4us）。

**③ 启动时清理旧版本遗留的误学条目**

旧口径判回源不看 `proxy_type`，「碰过 ≥2 个代理」就写成可信回源段，
于是纯 tcp 来源也会被记进去。这类条目（`source=legacy`）会被引擎与 AI 两处
同时认账，等于给一个按现行口径根本不算回源的来源长期免处置。

- 启动迁移 `_migrate_trusted_cidr()` 全量删除 `source='legacy'`（幂等）；
- 新增 `store.purge_legacy_trusted_cidrs()`：只清 `legacy`，
  保留 `keyword` / `model` / `manual` 等强证据；
- 类型硬否决上线后不可能再产生 `legacy`，全删安全。

**④ 同段整段信任的升级门槛从 2 提到 3**

同 `/24` 的强证据 `/32` 达到门槛就把整段记为可信（24h 有效期）。门槛原为 2，
而模型层旁证允许「全 Web 类型 + ≥2 个代理名」，一个多站探测的 Web 来源就能
占一个强证据名额；同段凑两个即整段信任 24 小时，代价太低。提到 3 之后，
「一次误判 + 邻近误判」需要连续三次才成立。

不改「必须至少一条 `keyword`」的原因：v1.5.2 那次事故的根因正是回源来源的
归属地文本只写云厂商名、不含 CDN 字样，关键字层完全落空，只有模型层 + 行为旁证
能认出来；要求 `keyword` 等于让这类来源永远升不了级。

### 2.2 布局与运维

**① `info.json` 的 `checks` 改为插件目录内的字符串**

原写法是 JSON 数组，且指向 `/opt/frpwaf/app/daemon.py`，两处都不对：

- 类型：面板 `panelPlugin.checksSetup()` 第一行是 `checks.split(',')`，
  数组会抛 `AttributeError`（`'list' object has no attribute 'split'`）。
  面板缓存 `data/list.json` 里 redis / alioss 的 `checks` 都是字符串，可对照。
- 位置：探针必须落在面板管得着的插件目录内。指 `/opt` 会在「上传安装中途」
  与「运行目录被动过」两种情况下误报未安装。

改为字符串 `/www/server/panel/plugin/frpwaf/frpwaf_main.py`。

**② 属主与目录结构规范化**

- `/opt/frpwaf` 现场收缩为只有 `app/` `web/` `data/`，发布侧文件与面板载荷
  移入归档目录（可回滚）。
- 属主被污染成服务器上不存在的 uid，根因是 SFTP 直传。`docs/14` 增加硬约束：
  只允许「上传 zip 安装」或「面板内在线升级」，传完必须 `chown root:root`
  且 `find -uid <旧uid>` 为空。
- 日常检查清单补「备份在跑」「属主无污染」两项，并新增
  `ls -A /opt/frpwaf` 应只有 `app data web` 的检查项。

**③ 生产改为发布包驱动**

生产不再现场构建（`build.sh` 的 `SRC` 就是 `/opt/frpwaf`，与在线升级互斥）：

- 新增 `scripts/make_plugin_zip.py`：开发机产出成品包（包内文件为顶层、
  文本归一化 LF、排除 `__pycache__`/`*.pyc`、校验 `frpwaf.init` 首行无 CR、
  断言关键文件齐全）。Windows Git Bash 通常没有 `zip` 命令，故用标准库 `zipfile`。
- `docs/02` 新增现行发布流程小节；`docs/11` 的 `build.sh` 用法标注
  「仅在仓库检出目录可用」；`docs/14` 增加对应检查项。

**④ 新增独立数据备份脚本与定时任务**

`data/` 原来只有守护进程自己写的 24h 热备，且与主库同盘同目录，盘坏一起没；
`/opt` 也不在面板备份范围内。

- `scripts/frpwaf-databak.sh`：先用 `sqlite3 .backup` 做一致快照（热库直接 tar
  会撕裂），再过 `PRAGMA integrity_check`，不通过不产包；打包库 + 配置 +
  `MANIFEST`（写明排除了 `data/backup`、`frp_backup`，并记录各表行数便于对数）；
  `.tmp` 原子改名；保留最近 7 份。
- 部署为 `/usr/local/bin/frpwaf-databak.sh` + `/etc/cron.d/frpwaf-databak`
  （每天 03:23）。
- 实测产物 3.3M（库 14M 压缩）；恢复演练：`integrity_check=ok`，
  7 张表行数与线上逐条相等，`frpwaf.json` 83 个键可解析。

### 2.3 升级行为变化

**① 在线升级不再把面板载荷写进运行目录**

`/opt/frpwaf` 是运行目录，插件目录是面板集成层。`_targets()` 把两个目录都当
覆盖目标，`_overwrite()` 又无差别写入包内所有文件，于是 7 个面板载荷
（`frpwaf_main.py`、`index.html`、`info.json`、`install.sh`、`uninstall.sh`、
`frpwaf.init`、`frpwaf.service`）每次在线升级都被写进运行目录——而运行目录里
这些没有任何代码在读，代价是同一文件名在两处各一份，运维容易改错文件。

改动：新增 `_PANEL_PAYLOAD` 名单 + `_is_runtime_dir()` + `_drop_panel_payload()`；
运行目录跳过这 7 个文件并**清掉历史副本**，插件目录仍全量覆盖（否则面板端 UI
与安装脚本会留在旧版本）。清理顺序为先按名单删、再跑后缀级 `_prune_stale`。
`web/` 不在名单内（独立面板要读运行目录的 `web/`），`build.sh`/`docs` 也不在
名单内（保留现有工作流）。

**② `install.sh` 增加版本一致性闸门**

`install.sh` 同步 `app/` 到 `/opt` 之前，断言 `info.json` 的 `versions` 必须等于
`app/__init__.py` 的 `__version__`（脚本变量 `_pkg_ver` / `_code_ver`），
不等则**中止安装且不同步任何代码**。因为载荷目录单向覆盖运行目录，
装上拼包会在不重启的情况下静默替换正在跑的代码。任一处读不到则跳过，不阻断
自定义安装。

### 2.4 面板（插件端）

- 新增「误封保护」页：回源段表格（可删除/清空）、登录信任 IP 表格（可取消）、
  代理豁免与登录信任有效期编辑。后端新增
  `cdn_trust_list` / `cdn_trust_del` / `cdn_trust_clear` /
  `self_protect_info` / `self_protect_save` / `trust_login_del` / `trust_login_clear`。
  所有表格字段经 `fwEsc` 转义；清空类操作二次确认并写入操作审计。
- 进入「误封保护」页即把**当前访问面板的客户端 IP** 记入登录信任
  （原实现只挂在独立面板的登录接口上，而 owner 的实际工作流是直连数据库/SSH
  隧道，根本不会访问独立面板，机制对他等于失效）。直连取 `REMOTE_ADDR`，
  经反代取 `X-Forwarded-For`；回环地址不写入；`trust_login_ttl=0` 时直接返回；
  日志限频 10 分钟一条。
- 代理冷却豁免与插件错误回显一并修复：豁免流量完全排除于计数窗口
  （命中豁免即不计数、不处置），永久名单不计入同网段熔断阈值；
  `frpwaf_main.py` 旧接口不再回传堆栈，统一走 `_fail` / `_log_exc`，
  完整堆栈只写运行日志（净化为单行），前端仅见短消息。
- **回源段可溯源**：「误封保护」页的回源段表格新增「来源审查」列，显示该网段是
  由第几条 AI 审查记录学来的（`trusted_cidr` 新增 `ai_review_id` 列，只记首次来源，
  命中续期不改写）。排障时从「学过这个网段」能直接回查当时那次审查，不必靠时间与
  IP 在 `ai_review` 里猜。老库启动时自动补列，存量条目该列为 0（无关联），不影响
  既有条目与判定。

---

## 3. 升级注意

1. **新版首次在线升级会清掉 `/opt/frpwaf` 下的面板载荷副本**，
   这是**预期行为**（§2.3 ①）。升级后 `ls -A /opt/frpwaf` 应只剩
   `app data web`；若再次出现 `info.json` / `install.sh` 等文件，说明被旧流程的
   发布包覆回去了。
2. **不要用 `build.sh` 在生产构建**，改用「开发机打包 → 传服务器 → 解到插件目录 →
   `install.sh install`」。生产线上不再需要 `.git`。
3. **在线升级后确认插件目录仍是最新**：运行目录跳过载荷，插件目录照常全量覆盖，
   两者版本应一致（可对比 `ai.py` / `upgrade.py` 的 md5）。
4. **备份脚本需要部署一次**：新增脚本不会随在线升级自动生成定时任务，
   需按 `docs/02` 部署 `/usr/local/bin/frpwaf-databak.sh` 与
   `/etc/cron.d/frpwaf-databak`。
5. **本次启动会清空 `source=legacy` 的学习条目**（一次性，幂等），
   强证据条目（`keyword` / `model` / `manual`）不受影响；无需人工干预。
6. **无破坏性变更**：`trusted_cidr` 三列迁移是幂等 `ALTER`，不碰既有数据；
   无配置项删除或改名。
7. **升级后建议**：把常用的数据库/SSH 隧道名填入 `auto_ban_exempt_proxies`，
   并在「误封保护」页确认回源段与登录信任列表。

---

## 4. 验证

- 全量测试 `python -m unittest discover -s tests -t .`：**359 tests OK**，零 `expectedFailure`。
- 新增用例方向以反向用例为主：纯 tcp 不得判回源、`Mesa` 等不得误命中、
  行为层与熔断不得写入学习表、过期条目不得匹配、`first_reason` 不被覆盖、
  迁移幂等、四条自动处置路径各含对照、`/24` 覆盖同段未见 IP、
  升级两个目标的写入差异、历史副本被清、`info.json` 类型正确。
- 迁移实测（生产数据副本）：5 列扩 8 列、存量行 `source=legacy`、
  `first_reason` 回填、连跑两次不报错不丢数据。

---

## 5. 发布包

打包命令：

```sh
python scripts/make_plugin_zip.py
```

产物 `dist/frpwaf.zip`：

| 项 | 值 |
|---|---|
| 包大小 | **275464** 字节 |
| SHA-256 | `743b545cdeea5209594db024d3f10cb8af463a7f420ebbbaeace7f10d39b01fd` |
| 文件数 | **27** |

包内顶层直接是 `app/` `web/` `info.json` `install.sh` `uninstall.sh`
`frpwaf.init` `frpwaf.service` `frpwaf_main.py` `index.html`，没有多套一层目录。

包内抽查 9 条与逐条结果见发布时的回填记录（Tag / 双端 Release / 附件名
按 `docs/13` §14 的格式回填）。

---

## 6. 发布清单（owner 批准后执行）

- [ ] 回填本文 §5 的包大小 / SHA-256 / 文件数，以及表头「版本号提交」
- [ ] 提交版本号变更与本文档
- [ ] 打 Tag `v1.5.3`
- [ ] 建双端 Release（Gitea / GitHub），附件 `frpwaf-1.5.3.zip` + `SHA256SUMS`
- [ ] 按 `docs/13` §14 回填 Tag 指向、Release id、附件名与 SHA-256
- [ ] 生产机验证 `check()` 返回 `latest=1.5.3, has_update=True`
