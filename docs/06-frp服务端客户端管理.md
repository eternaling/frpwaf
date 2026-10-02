# 06 · frp 服务端 / 客户端管理

本模块（`app/frp.py` + 插件端 `frp_*` 方法）把宝塔官方「**frp管理器**」插件的
能力并入本插件，并修复其多个已知问题。

## 1. 目录与文件

| 项 | 路径 |
|---|---|
| frps 安装目录 | `/usr/local/frps` |
| frps 配置 | `/usr/local/frps/frps.toml` |
| frps 服务脚本 | `/etc/init.d/frps` |
| frpc 安装目录 | `/usr/local/frpc` |
| frpc 配置 | `/usr/local/frpc/frpc.toml` |
| frpc 服务脚本 | `/etc/init.d/frpc` |
| 升级前备份 | `data/frp_backup/<kind>-<时间戳>/` |
| 异步任务状态 | `data/frp_job.json`（进度，前端轮询） |
| 下载临时文件 | 系统临时目录 `frp_<ver>_<arch>.tar.gz`（安装后删除） |

> 备份目录与任务文件均由 `config.DATA_DIR` 推导，随 `FRPWAF_HOME` 迁移。
> 代码里还定义了 `data/frp_job.log`（`JOB_LOG`）常量，但当前**未实际写入**，属预留。

## 2. 相对官方「frp管理器」的改进

| # | 官方插件的问题 | 本模块的处理 |
|---|---|---|
| 1 | `maxPoolCount` 写在**顶层**，frp 0.52+ 要求放在 `[transport]` 下 | `save_config()` 自动把 `maxPoolCount` 归位到 `[transport]` |
| 2 | 重装会**清空** `/usr/local/frps` 并**重新随机生成配置**（破坏性） | 升级只替换二进制；`_backup()` 先备份；配置已存在则不覆盖 |
| 3 | 端口占用检查用 `netstat\|awk` 脆弱正则 | 改用 `ss -H -lntu` 解析 |
| 4 | 版本写死（0.53.2/0.52.3），无法升级、无 arm 支持 | 多架构（`arch()`）+ 动态查最新版（`latest_version()`） |
| 5 | 写配置用 `toml.dumps` 可能丢未知字段 | 读改写**整表**，保留 `httpPlugins` 等（自带 `toml_lite`） |
| 6 | 无配置校验、无备份 | 写前备份、写后 `frps verify`，失败回滚 |

## 3. 安装 / 升级（异步）

### 3.1 为什么异步

下载 frp 发布包可能几十 MB，面板 HTTP 请求不能长时间阻塞。故：

- `start_install(kind, version)`：立即返回，启动后台线程 `_install_worker`；
- 进度写入 `data/frp_job.json`（`running/percent/msg/done/ok/kind/ts`）；
- 前端轮询 `frp_install_status` → `job_status()`。

`job_status()` 带**心跳判断**：`running=true` 但 `ts` 超过 90 秒未更新
（面板重启导致线程消失）→ 判定为「安装任务已中断」，避免前端一直转圈。

> 注意：早期版本的同步安装函数 `frp.install()` 属死代码，已在全项目审查批次中删除；
> 安装实际走 `start_install` / `_install_worker`。

### 3.2 安装流程（`_install_worker`）

1. 解析版本：空或 `latest` → `latest_version()`（GitHub API，10 分钟缓存）；
   失败兜底 `0.71.0`。**版本号白名单校验**（`^\d+\.\d+\.\d+$`，`valid_version()`）——
   不合法直接拒绝，防止用户输入携带路径分隔符进入 URL / 临时文件路径。
2. 已是目标版本且二进制存在 → 仅补 `init`（如缺），直接完成。
3. 若已有安装 → `_backup(kind)` 备份整个目录。
4. **下载**：`_download()` 依次尝试镜像 `gh-proxy.com` → `ghfast.top` → GitHub 直连，
   用 `curl -fL` 流式下载，带 `--speed-limit 20480 --speed-time 20` 断速保护；
   文件 >100KB 才算成功。进度按 `5 + size/13.9MB*75` 上报（封顶 80%）。
   下载完成后按 GitHub Release API 提供的 **sha256 digest** 校验完整性
   （对全部镜像生效；旧版本/接口不可达拿不到 digest 时跳过校验但写日志留痕），
   校验失败的镜像结果会被删除并尝试下一个镜像。
5. **解压**：`_extract_binaries()` 解出 `frps`/`frpc` 二进制。
   - **关键**：目标二进制可能正在运行，直接覆盖会 `ETXTBSY`（Text file busy）。
     故先复制到同目录 `*.new.<pid>`，`os.replace()` **原子改名**顶替
     （改名不影响正在运行的旧 inode）。
6. 若无配置文件 → `generate_config()` 生成。
7. `_install_init()` 安装服务脚本 + `/usr/bin/<kind>` 软链 + 开机自启。
8. **配置迁移**：`_migrate_config()`（见 §6）。
9. 若升级前服务在运行 → `restart` 并校验是否真的起来；**起不来则自动回滚**。

### 3.3 失败自动回滚

- 迁移后仍校验不过（`mig_note` 且未改变）→ 回滚二进制。
- 重启后服务未运行 → `rollback(kind)` 还原最近备份并重启。

## 4. 下载源（镜像）

```python
MIRRORS = ["https://gh-proxy.com/", "https://ghfast.top/", ""]
```

GitHub 直连在国内多数服务器极慢或不可达，故优先用加速镜像，`""`（直连）兜底。

## 5. 配置读写（安全）

- `load_config(kind)`：`toml_lite.load` 返回结构化字典（自带解析器，见 §5.1）。
- `ensure_config(kind)`：文件缺失时**预创建**（不覆盖已有）。
- `save_config(kind, patch)`：
  1. `maxPoolCount` 归位到 `[transport]`；
  2. 深度合并 `patch`（字典递归 `update`）；
  3. `toml_lite.dumps` 输出整表（保留未提及字段如 `httpPlugins`）；
  4. 写前 `cp` 备份 → 写 → `verify()`；
  5. **校验失败自动回滚**并返回错误。
- `check_toml(text)`：语法校验，返回错误串（合法为空）；供插件端「保存原文」复用。
- `verify(kind)`：`<bin> verify -c <toml>`，合法返回空串。
- `tail_log(kind)`：优先用配置里 `log.to`，否则 `/var/log/frps.log`。

### 5.1 自带 TOML 解析器（`app/toml_lite.py`）

**为什么**：原先 `import toml`（第三方包）依赖宝塔 pyenv 恰好自带；环境缺失即报
「缺少 toml 模块」，且违反项目「纯标准库、无 requirements.txt」红线。

**实现**：纯标准库的 TOML 子集解析 / 生成，解析语义与标准库 `tomllib` 对齐
（同样的命名空间状态机 `EXPLICIT_NEST` / `FROZEN`，同样拒绝重复表声明、
内联表冻结后再展开、点分键与表头冲突等非法文档），生成格式与 `tomllib`
标准写法一致（先标量后子表、`[[name]]` 一行）。支持：表 / 数组表 / 点分键 /
引号键、基本 / 字面量 / 多行字符串、整数（含 `0x`/`0o`/`0b`）、浮点、布尔、
数组、内联表、注释、CRLF、BOM。不支持日期 / 时间（frp 配置不会出现，遇到明确报错）。

**兼容**：Python 3.6+（无 `tomllib` 也可用）；验证方式见
`docs/tests/`（与 `tomllib` 交叉比对 + 随机差异测试）。

## 6. 配置迁移（新版严格 schema）

新版 frp 对配置**严格解析**，遇到旧版遗留字段会报 `json: unknown field` 拒绝启动
（这是升级后服务起不来的主因）。`_migrate_config()` 处理（字段/段落清单见
`app/frp.py` 的 `_LEGACY_DROP_FIELDS` / `_LEGACY_DROP_SECTIONS`）：

- 删除遗留**段落**（仅当为空）：`[transport.kcp]`、`[kcp]`；
- 删除遗留**字段**：`tcpKeepalive`、`keepAliveSeconds`、`dashboardPwd`、
  `heartbeatInterval`、`protocol`（顶层 + `[transport]` 内）；
- 写临时文件用**新二进制 `verify` 把关**；不过则保留原配置并返回提示
  （`(changed=False, note=...)`，调用方据此回滚二进制）；
- 通过则备份原文件（`*.premigrate.<时间戳>`）后落盘。

> 只有**真正发生改动**（`changed=True`）才算迁移成功；若 `note` 非空但 `changed=False`，
> 说明「迁移后仍校验不过」，`_install_worker` 会**回滚二进制**以免留下起不来的新版。

## 7. 回滚（`rollback`）

- 找最近一次（非当前）备份目录 `data/frp_backup/<kind>-<时间戳>`；
- 逐文件**原子还原**（二进制用 `os.replace` 避免 ETXTBSY）；
- 若原服务在运行则 `restart`；
- 返回回滚到的版本。

## 8. 状态 / 控制

- `is_running(kind)`：跑 `init status`，看输出含 `is running`。
- `control(kind, action)`：`start/stop/restart`。
- `status_info(kind)`：`{installed, version, running, config_path, bin}`。
- `uninstall(kind)`：停服务、去自启、删 init/软链、删目录。

## 9. 默认模板与端口

`generate_config("frps")` 用 `_free_port()` 从起始端口找空闲端口（并避开已占用）：

| 项 | 起始端口 | 说明 |
|---|---|---|
| `bindPort` | 15443 | 主监听端口 |
| `kcpBindPort` | = bindPort | KCP |
| `quicBindPort` | bindPort+2 | QUIC |
| `vhostHTTPPort` | 18080 | HTTP 虚拟主机 |
| `vhostHTTPSPort` | 18443 | HTTPS 虚拟主机 |
| `tcpmuxHTTPConnectPort` | 16337 | TCPMUX |
| `webServer.port` | 7001 | frps 仪表盘 |

- 模板含 `[transport] maxPoolCount=50`、`[log] to=/var/log/frps.log`、`[auth] token`。
- `webServer` 密码、`auth.token` 由 `_random(16)` 生成。
- frpc 模板含一个 `ssh` 代理示例（`remotePort`）。

## 10. 插件端接口（`frpwaf_main.py`）

| 方法（`s=`） | 作用 |
|---|---|
| `frp_info` | frps/frpc 状态（版本/运行/架构/配置路径） |
| `frp_latest` | 查 GitHub 最新版（带缓存） |
| `frp_install_start` | 启动后台安装任务 |
| `frp_install_status` | 查询安装进度 |
| `frp_control` | 启动/停止/重启 |
| `frp_uninstall` | 卸载 |
| `frp_rollback` | 回滚到升级前备份 |
| `frp_get_config` | 读配置（结构化 + 原文 + 路径） |
| `frp_ensure_config` | 预创建配置文件 |
| `frp_save_config` | 结构化保存（保留未知字段、写前备份、写后校验） |
| `frp_save_raw` | 原文保存（TOML 语法校验 + 写前备份 + verify） |
| `frp_verify` | 配置校验 |
| `frp_log` | 读 frps/frpc 日志（tail N 行） |
| `frp_release_ports` | 一键放行 frps 关键端口（调宝塔防火墙） |

> `kind` 参数默认 `frps`，可传 `frpc`。`frp_release_ports` **仅对 frps 生效**
> （`frpc` 会提示无需放行——客户端没有入站端口）。实现方式：探测系统防火墙后端
> （CentOS 7+ 的 `firewalld`、Debian/Ubuntu 的 `ufw`，与宝塔面板自身一致），
> 按 frp 语义区分协议后逐个放行：
> **TCP**：`bindPort`、`vhostHTTPPort`、`vhostHTTPSPort`、`tcpmuxHTTPConnectPort`、`webServer.port`；
> **UDP**：`kcpBindPort`、`quicBindPort`（KCP/QUIC 为 UDP 传输）。
> `firewalld` 用 `firewall-cmd --zone=public --add-port=P/协议 --permanent` 并统一 `--reload`；
> `ufw` 用 `ufw allow P/协议`。已放行（`ALREADY_ENABLED` / `Skipping`）视为成功，
> 结果按「成功/失败」分端口回报；未检测到运行中的防火墙时给出明确提示。
> `frp_save_raw` 仅做 **TOML 语法校验**，`verify`
> 失败时返回提示但**内容已写入**（结构化保存 `frp_save_config` 才是失败即回滚）。

## 11. 约束提醒

- **不要改动 frps 的日志配置**（`[log]`），按项目约定保持原样。
- **不要擅自升级 frps 版本**——升级动作须经明确同意后再执行。
- 升级/改配置前 `frp.py` 已自动备份到 `data/frp_backup/`，出问题可 `frp_rollback`。
