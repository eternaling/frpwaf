# 交付报告：在线升级不再把面板载荷写进运行目录

范围：只改仓库代码 + 测试 + 文档。**未提交、未 push、未 tag**，未触碰任何服务器。

## 1. 问题与结论

在线升级 `_overwrite()` 原本把包内所有文件覆盖到**每个**目标
（`_targets()` = 运行目录 + 插件目录），于是 7 个面板载荷每次升级都被写进 `/opt/frpwaf`，
而 `/opt` 里那 7 个没有任何代码在读（插件入口由面板从插件目录加载，安装脚本读
`${PLUGIN_DIR}/...`，守护进程只 `import app.*`）。

改动后：**运行目录只落 `app/` 与 `web/`**，7 个面板载荷只写插件目录，
并顺带清掉运行目录里历史升级遗留的同名副本。

## 2. 代码改动（`app/upgrade.py`）

| 位置 | 内容 | 为什么 |
|---|---|---|
| `app/upgrade.py:92` | 新增 `_PANEL_PAYLOAD` 常量（7 个文件名） | 把「只在插件目录有意义」的文件集中成一份名单，注释写明为何不需要副本、以及 `web/` 为何不在此列 |
| `app/upgrade.py:636` | 新增 `_is_runtime_dir(target)` | 用 `abspath` 归一后与 `config.BASE` 比较，避免尾斜杠导致排除失效 |
| `app/upgrade.py:644` | 新增 `_drop_panel_payload(target)` | 只按固定名单删这 7 个具体文件（不遍历目录、不碰 `data/`），升级一次即收干净 |
| `app/upgrade.py:683-711` | 改 `_overwrite()`：运行目录跳过载荷 + 清理残留 | 修复「升级一次也不变干净」；顺序上先清名单再跑 `_prune_stale`，否则 `frpwaf_main.py` 会先被当作「包内已不存在的 .py」删掉、从被清清单里消失 |

关键约束（已逐条确认）：

- **`app/`、`web/` 两个目标都继续覆盖**：`daemon.py:35` 的 `WEB_DIR` 指向运行目录下的
  `web/`，`_static()`（`daemon.py:1260`）只在 `WEB_DIR` 内取文件，缺了独立 Web 端直接 404。
- **`_prune_stale()` 未退化**：跳过载荷后 `pkg_rel` 里没有这 7 个，但它们是白名单式删除，
  不会误删；陈旧 `.py` 清理仍生效（有专门用例守）。
- **`_backup()` 未改**，仍走 `_iter_files()` 全量备份 —— 回滚不缺文件（有用例守）。
- **回滚语义保持**：`_restore()` 会把备份里的载荷文件原样还原（= 恢复升级前状态），这是正确的回滚行为，下一个成功升级会再清一次。
- **`install_waf()`（面板「安装/更新网页端」）本就只 `cp -a app/. web/.`**，不写载荷进 `/opt` —— `_overwrite()` 是唯一的越界写入方，改完不存在第二个写入方把副本写回来。

## 3. 测试（`tests/test_upgrade.py`，新增 11 个）

`class OverwriteTargetTest`（`tests/test_upgrade.py:191`）

| 用例 | 断言什么 |
|---|---|
| `test_payload_set_is_the_documented_seven` | `_PANEL_PAYLOAD` 恰好是这 7 个，不多不少（多了坏插件端，少了留副本） |
| `test_plugin_target_receives_payload` | 目标是插件目录时，7 个载荷照常写入（不能把面板端弄坏） |
| `test_plugin_target_writes_payload` | 哨兵 `shutil.copy2`，确认这 7 个**确实**被写入插件目录 |
| `test_runtime_target_skips_payload` | 哨兵 `shutil.copy2`：运行目录下这 7 个**从未被写入**（不是「写了又删」），且最终不存在 |
| `test_runtime_target_purges_existing_payload` | 运行目录预置 7 个旧副本 → 升级后全部消失，且都出现在 `removed` 返回值里 |
| `test_app_and_web_written_to_both_targets` | `app/daemon.py`、`app/engine.py`、`web/index.html` 在两个目标都落地 |
| `test_non_payload_root_files_still_reach_runtime` | 排除的是固定 7 个，不是「所有根目录文件」——`build.sh`、`README.md` 仍照常覆盖 |
| `test_runtime_data_dir_untouched` | 运行目录 `data/frpwaf.json` 内容不被覆盖 |
| `test_runtime_stale_module_still_pruned` | 跳过后 `app/legacy_module.py` 这类陈旧 `.py` 仍被删除并登记 |
| `test_backup_still_captures_payload` | `_backup()` 仍把目标里 7 个载荷 + `app/daemon.py` 全备到（8 个），`data/` 不计入 |
| `test_runtime_dir_detected_regardless_of_trailing_separator` | `base` 与 `base + os.sep` 都认作运行目录；插件目录不认 |

**变异验证**（证明用例真有回归价值，不只是跑绿）：

| 变异 | 结果 |
|---|---|
| 删掉 `if runtime and rel in _PANEL_PAYLOAD: continue` | 失败 1 项 |
| 关掉 `_drop_panel_payload()` 清理 | 失败 1 项 |
| `runtime = False`（等价修复前行为） | 失败 2 项 |

> 备注：最初的「运行目录不写入」断言只查最终文件是否存在，变异测试发现它**抓不到**
> 「先写再删」（两者终态相同）。因此改用 `mock.patch.object(upgrade.shutil, "copy2", spy)`
> 哨兵落盘目标，并校验「写入计数 == 实际落盘次数」。

## 4. 文档同步

| 文件 | 改动 |
|---|---|
| `docs/02-目录结构与安装部署.md` §1 | 明确装好之后是**两段式布局**（面板集成层 / 运行层），并声明 7 个面板载荷只在插件目录存在 |
| `docs/02` §4 | 新增「在线升级同样只写运行层」说明，含理由与 `web/` 例外 |
| `docs/04-数据模型与配置项.md` §3.10 | 升级流程行改为「覆盖程序 + 清理陈旧 `.py`」，并列出两种目标目录的覆盖范围差异 |
| `docs/10-HTTP_API参考.md` §12 | `/api/upgrade/apply` 行补上按目标目录分开的覆盖范围 |
| `docs/11-开发运维与常见问题.md` §4 | 补「运行层只留 `app/`、`web/`、`data/`」，说明排查「哪份代码在跑」不需要两处对比 |
| `docs/14-运维注意事项与约束.md` §四 | 新增检查项：`ls /opt/frpwaf` 不应出现这 7 个 |
| `docs/14` §一 #11 | **修正**：原文让运维「需要版本对照时看 `info.json`」，而该文件正是本次从 `/opt` 移除的；改为看插件目录的 `info.json`（包版本）+ `/opt/frpwaf/app/__init__.py` 的 `__version__`（运行代码版本） |
| `tests/README.md` | `test_upgrade.py` 一行补上新增覆盖点 |

## 5. 验证结果

```
python -m unittest discover -s tests -t .
Ran 355 tests in 24.322s
OK
```

344（基线）+ 11（新增）= 355，全绿。

附带校验：

- `node scripts/sync-agent-skills.cjs --check` → 34 skills / 6 command mirrors / 6 pi prompts / 8 hook wrappers / 2 codex agents 全部同步
- `node scripts/audit-agent-migration.cjs` → 审计通过（hooks 行为 60/60）

## 6. 一个值得记录的判断：`info.json`

7 个里唯一需要额外论证的是 `info.json`——`docs/14` #11 原先让运维「版本对照时看 `info.json`」，
那句话在 `/opt/frpwaf` 语境下指向的正是本次要移除的文件。

结论：**仍然排除**，理由是运行期没有任何代码读它（`grep info.json` 只命中
`upgrade.py` 校验**入包**副本）；`install.sh:66` 读的是 `${PLUGIN_DIR}/info.json`；
运行代码版本的权威来源是 `app/__init__.py` 的 `__version__`，而 `app/` 始终覆盖到运行目录。
既然版本真源就在 `/opt/frpwaf/app/__init__.py`，在 `/opt` 再留一份 `info.json` 只会重新制造
「同一信息两处、哪份是准的」问题。因此改的是**文档口径**（指向权威位置），不是排除名单。

另外 `build.sh`、`docs/`、`README.md` **本就不在**排除名单，这是对的：
`docs/11` §5 记录的开发流程是 `cd /opt/frpwaf && bash build.sh`，而 `build.sh` 用自身位置
推导包根——把它排除会直接打断这条已文档化的工作流。

## 7. 未做（留给合并与部署）

- 未提交 / 未 push / 未 tag。
- 未改 `app/__init__.py` 的 `__version__`，未动 `docs/13-变更历史与版本.md`（版本与发布由用户决定）。
- 未碰服务器：生产上 `/opt/frpwaf` 里现存的 7 个旧副本，需要**首次用新版本在线升级一次**
  才会被自动清掉（或按 `docs/14` §四 新增检查项手工 `rm` 那 7 个，别删 `app/`、`web/`、`data/`）。
