# 验证报告：一键放行端口修复（Bug H，v1.3.10 并入）

- 关联任务：`docs/tasks/active/task-20260930-163800-一键放行端口修复.md`
- 执行日期：2026-09-30
- 环境：本地 Windows + Python 3.12.6（桩注入假 `public` 模块与假 frp 配置，隔离真实环境）
- 结论：**通过**

## 验证目标

证明「一键放行端口」修复正确：不再调用不存在的面板 API；按系统防火墙后端
（firewalld/ufw）真实执行放行命令；kcp/quic 按 UDP、补上 quicBindPort；
结果如实回报（成功/失败分端口）；frpc/无防火墙/空配置有明确提示。

## 执行结果

| # | 用例 | 实际结果 | 判定 |
|---|---|---|---|
| 1 | firewalld 正常路径：`--add-port=15444/tcp`、`15444/udp`、`15446/udp` 等全部执行且带 `--permanent` | 通过 | ✅ |
| 2 | 去重：`bindPort=kcpBindPort=15444` 时 TCP/UDP 各放行一次 | 通过 | ✅ |
| 3 | `firewall-cmd --reload` 在全部加端口后执行一次 | 通过 | ✅ |
| 4 | 已放行（`ALREADY_ENABLED`）视为成功 | 通过 | ✅ |
| 5 | ufw 路径：`ufw allow 7002/tcp` + `7002/udp`，不做 reload | 通过 | ✅ |
| 6 | ufw 已存在规则（`Skipping adding existing rule`）视为成功 | 通过 | ✅ |
| 7 | 无防火墙：明确失败提示，且不执行任何放行命令 | 通过 | ✅ |
| 8 | frpc：提示「无需放行入站端口」，不执行任何命令 | 通过 | ✅ |
| 9 | 部分失败：状态为 False，成功与失败分端口列出 | 通过 | ✅ |
| 10 | 空端口配置：提示「未从配置中读到可放行的端口」 | 通过 | ✅ |
| 11 | 非法值忽略：`0` / `99999` / `"abc"` 不放行；`webServer.port="7002"` 兼容字符串数字 | 通过 | ✅ |
| 12 | 布尔值忽略（`True` 是 `int` 子类，不得被当作端口 1） | 通过 | ✅ |
| 13 | firewalld `--reload` 失败：附「注意：reload 失败」提示 | 通过 | ✅ |
| 14 | firewalld 存在但未运行：回退 ufw（active 时） | 通过 | ✅ |
| 15 | `python -m py_compile frpwaf_main.py` | 通过 | ✅ |
| 16 | 桩测试 12 组场景共 **22 项断言** | 22 通过 / 0 失败 | ✅ |

> 复现命令（临时脚本 `scratchpad/release_ports_test.py` 按规范不入库）：
> `python -X utf8 scratchpad/release_ports_test.py`

## 发布产物校验（v1.3.10 重指后重建）

| # | 用例 | 实际结果 | 判定 |
|---|---|---|---|
| 17 | 成品包文件集 = build.sh 清单（18 文件 + 2 目录项） | 一致 | ✅ |
| 18 | 全部文件无 CRLF（`git archive` 自新 tag 导出） | 通过 | ✅ |
| 19 | 每个文件与新 tag `v1.3.10` blob 逐字节一致 | 通过 | ✅ |
| 20 | 解包后 `bash -n` 三个脚本 + `py_compile` 12 个 Python 文件 | 通过 | ✅ |
| 21 | Release 附件替换后鉴权下载校验（字节数与 SHA-256 一致） | 一致 | ✅ |

- 成品包：`frpwaf-1.3.10.zip`（重建后字节数与 SHA-256 见下）
- Release：`https://gitea.nightsoil.cn/night/frpwaf/releases/tag/v1.3.10`

## 回归范围

- **frp 管理链路**：`frp_release_ports` 仅改动自身；`load_config` / `save_config` /
  `frp_save_raw` / `frp_control` 等未触碰。
- **决策链与内核封禁**：不受影响（未改动）。
- **面板**：`index.html` 未改动（`fwFrpReleasePorts()` 仅展示 `r.msg`，新消息兼容）。
- **配置读取**：`webServer.port` 兼容字符串/整数两种来源。

## 遗留问题

- 服务器端（宝塔真实环境）未实测；建议更新插件后在「frp 管理」页点击
  「一键放行端口」冒烟，并用 `firewall-cmd --list-port` / `ufw status` 核对。
- 云服务商安全组需另行放行（面板防火墙与安全组相互独立，属已知边界）。
