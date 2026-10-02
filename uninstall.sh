#!/bin/bash
set -e
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 插件目录由脚本自身位置推导，不写死路径（宝塔可能装到其它目录 / 改目录名）。
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_HOME="${FRPWAF_HOME:-/opt/frpwaf}"
INIT=/etc/init.d/frpwaf
FRPS_TOML=/usr/local/frps/frps.toml

# 宝塔在卸载插件时会调用本脚本；此处做「无残留」清理：
#   1) 移除 frps.toml 中的 [[httpPlugins]] frpwaf 配置并重启 frps
#      （否则 frps 仍会回调已停止的 WAF，fail-closed 会导致连接被拒）
#   2) 停服务、移除内核封禁、取消开机自启、删除 init 脚本
# 运行数据保留在 /opt/frpwaf，如需彻底删除请手动: rm -rf /opt/frpwaf

echo '正在卸载 frpwaf ...'

backup=""
frps_running=0
# 移除 frps.toml 中的 frpwaf 插件配置块
if [ -f "${FRPS_TOML}" ] && grep -q "frpwaf" "${FRPS_TOML}"; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo '⚠️  卸载中止：未找到 python3，frps.toml 清理失败，WAF 保持运行。'
        exit 1
    fi
    if [ ! -x /etc/init.d/frps ] || [ ! -x /usr/local/frps/frps ]; then
        echo '卸载中止：无法校验或重启 frps，WAF 保持运行。'
        exit 1
    fi
    if frps_status=$(/etc/init.d/frps status 2>&1); then
        :
    else
        frps_status="${frps_status:-}"
    fi
    case "${frps_status}" in
        *"is running"*) frps_running=1 ;;
        *"is stopped"*) frps_running=0 ;;
        *) echo '卸载中止：无法确认 frps 状态，WAF 保持运行。'; exit 1 ;;
    esac
    backup="${FRPS_TOML}.bak.$(date +%Y%m%d-%H%M%S).$$"
    if ! cp -a "${FRPS_TOML}" "${backup}"; then
        echo '卸载中止：frps 配置备份失败，WAF 保持运行。'
        exit 1
    fi
    if ! python3 "${PLUGIN_DIR}/app/frp_uninstall.py" "${FRPS_TOML}"; then
        cp -a "${backup}" "${FRPS_TOML}"
        echo '⚠️  卸载中止：frps 回调配置清理失败，WAF 保持运行。'
        exit 1
    fi
    if ! /usr/local/frps/frps verify -c "${FRPS_TOML}" >/dev/null 2>&1; then
        cp -a "${backup}" "${FRPS_TOML}"
        echo '卸载中止：frps 配置校验失败，WAF 保持运行。'
        exit 1
    fi
    if [ "${frps_running}" -eq 1 ]; then
        if ! /etc/init.d/frps restart >/dev/null 2>&1 ||
           ! /etc/init.d/frps status 2>&1 | grep -q 'is running'; then
            cp -a "${backup}" "${FRPS_TOML}"
            /etc/init.d/frps restart >/dev/null 2>&1 || true
            echo '卸载中止：frps 重启失败，已恢复原配置，WAF 保持运行。'
            exit 1
        fi
    fi
fi

if [ -x "${INIT}" ] && ! "${INIT}" stop >/dev/null 2>&1; then
    if [ -n "${backup}" ]; then
        cp -a "${backup}" "${FRPS_TOML}"
        if [ "${frps_running}" -eq 1 ]; then
            /etc/init.d/frps restart >/dev/null 2>&1 || true
        fi
    fi
    echo '卸载中止：WAF 停止失败，已尝试恢复 frps 回调。'
    exit 1
fi

# 内核封禁清理
if command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -j FRPWAF_BLOCK 2>/dev/null || true
    iptables -F FRPWAF_BLOCK 2>/dev/null || true
    iptables -X FRPWAF_BLOCK 2>/dev/null || true
fi
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -D INPUT -j FRPWAF_BLOCK 2>/dev/null || true
    ip6tables -F FRPWAF_BLOCK 2>/dev/null || true
    ip6tables -X FRPWAF_BLOCK 2>/dev/null || true
fi
if command -v ipset >/dev/null 2>&1; then
    ipset destroy frpwaf_block 2>/dev/null || true
    ipset destroy frpwaf_block6 2>/dev/null || true
fi

# 取消开机自启 + 删除 init
if command -v chkconfig >/dev/null 2>&1; then
    chkconfig --del frpwaf >/dev/null 2>&1 || true
fi
if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d -f frpwaf remove >/dev/null 2>&1 || true
fi
rm -f "${INIT}" /usr/bin/frpwaf

echo '卸载完成（运行数据保留在 /opt/frpwaf）'
