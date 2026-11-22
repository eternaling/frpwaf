#!/bin/bash
set -e
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 插件目录由脚本自身位置推导，不写死路径（宝塔可能装到其它目录 / 改目录名）。
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_HOME="${FRPWAF_HOME:-/opt/frpwaf}"
INIT=/etc/init.d/frpwaf
UNIT=/etc/systemd/system/frpwaf.service
FRPS_TOML=/usr/local/frps/frps.toml

# 宝塔在卸载插件时会调用本脚本；此处做「无残留」清理：
#   1) 移除 frps.toml 中的 [[httpPlugins]] frpwaf 配置并重启 frps
#      （否则 frps 仍会回调已停止的 WAF，fail-closed 会导致连接被拒）
#   2) 停服务、移除内核封禁、取消开机自启、删除 init 脚本
# 运行数据保留在 ${WAF_HOME}（默认 /opt/frpwaf），如需彻底删除请手动: rm -rf ${WAF_HOME}

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

# systemd 清理：必须在 `${INIT} stop` 之前做。
# 否则 unit 文件还在且已 enable 时，init 脚本会转调 systemctl（见 frpwaf.init
# 的 systemd_managed），而我们这里要的是彻底移除。
# 先 `disable --now`（显式 stop 不触发 Restart=always），再删 unit 并 daemon-reload。
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    if [ -f "${UNIT}" ]; then
        systemctl disable --now frpwaf >/dev/null 2>&1 || true
    fi
    systemctl stop frpwaf >/dev/null 2>&1 || true
    rm -f "${UNIT}"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed frpwaf >/dev/null 2>&1 || true
else
    rm -f "${UNIT}"
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

# ---------------- 内核封禁清理 ----------------
# 这里是 filter 表 FRPWAF_BLOCK（DROP 链）、nat 表 FRPWAF_REDIRECT（拦截页改道链）
# 与 ipset frpwaf_block / frpwaf_block6 的全部残留。
# 为什么优先调用 app/firewall.py 的 teardown()：插件内卸载路径（frpwaf_main.py）
# 走的正是它，两边共用一份清理逻辑才不会再次漂移；此前只清 filter 表的后果是
# nat 里留下指向已删链的跳转，ipset 集合因仍被引用而 destroy 失败，且失败被
# 2>/dev/null 吞掉，用户以为卸干净了。
# 清理失败一律不中断卸载，但结果必须可判别——见下方 frpwaf_kernel_residue()。

# 优先路径：用解释器 import teardown()。返回非 0 只表示「没能调用成功」
# （无解释器 / 插件目录残缺 / 导入异常），不代表内核已清干净。
frpwaf_kernel_teardown() {
    _py=""
    if [ -x /www/server/panel/pyenv/bin/python ]; then
        _py=/www/server/panel/pyenv/bin/python
    elif command -v python3 >/dev/null 2>&1; then
        _py=python3
    fi
    [ -n "${_py}" ] || return 1
    [ -f "${PLUGIN_DIR}/app/firewall.py" ] || return 1
    "${_py}" -c 'import sys
sys.path.insert(0, sys.argv[1])
from app.firewall import teardown
teardown()' "${PLUGIN_DIR}"
}

# 兜底路径：解释器不可用或插件目录已被清空时直接清内核。
# 顺序必须与 teardown() 一致：先摘 INPUT/PREROUTING 的跳转，再清链内规则，
# 再删链，最后 destroy 集合——集合仍被任何规则引用时 destroy 必然失败。
# 这里的 2>/dev/null 只用于吞掉「本来就不存在」的噪音，真正的结果由下面的
# 残留校验给出，不再靠「一条命令都没报错」来假装清干净。
frpwaf_kernel_teardown_manual() {
    for _ipt in iptables ip6tables; do
        command -v "${_ipt}" >/dev/null 2>&1 || continue
        "${_ipt}" -t nat -D PREROUTING -j FRPWAF_REDIRECT 2>/dev/null || true
        "${_ipt}" -t nat -F FRPWAF_REDIRECT 2>/dev/null || true
        "${_ipt}" -t nat -X FRPWAF_REDIRECT 2>/dev/null || true
        "${_ipt}" -D INPUT -j FRPWAF_BLOCK 2>/dev/null || true
        "${_ipt}" -F FRPWAF_BLOCK 2>/dev/null || true
        "${_ipt}" -X FRPWAF_BLOCK 2>/dev/null || true
    done
    if command -v ipset >/dev/null 2>&1; then
        ipset destroy frpwaf_block 2>/dev/null || true
        ipset destroy frpwaf_block6 2>/dev/null || true
    fi
    return 0
}

# 探针：命令存在不等于能查到东西（非 root、iptables 后端异常都会让 -S 直接失败），
# 而失败会被误读成「链不存在 = 已清干净」，所以先探一次可读性。
frpwaf_kernel_probe() {
    if command -v iptables >/dev/null 2>&1 && iptables -S INPUT >/dev/null 2>&1; then
        return 0
    fi
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -S INPUT >/dev/null 2>&1; then
        return 0
    fi
    if command -v ipset >/dev/null 2>&1 && ipset list -n >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 残留校验：链/集合还在就输出名字，清干净就输出空串。
# 链不存在时 -S/-C 一律非 0（错误已丢弃），因此「本来就没有」被判为干净。
frpwaf_kernel_residue() {
    _left=""
    for _ipt in iptables ip6tables; do
        command -v "${_ipt}" >/dev/null 2>&1 || continue
        "${_ipt}" -S FRPWAF_BLOCK >/dev/null 2>&1 && _left="${_left} ${_ipt}:filter/FRPWAF_BLOCK"
        "${_ipt}" -C INPUT -j FRPWAF_BLOCK >/dev/null 2>&1 && _left="${_left} ${_ipt}:INPUT->FRPWAF_BLOCK"
        "${_ipt}" -t nat -S FRPWAF_REDIRECT >/dev/null 2>&1 && _left="${_left} ${_ipt}:nat/FRPWAF_REDIRECT"
        "${_ipt}" -t nat -C PREROUTING -j FRPWAF_REDIRECT >/dev/null 2>&1 && _left="${_left} ${_ipt}:nat/PREROUTING->FRPWAF_REDIRECT"
    done
    if command -v ipset >/dev/null 2>&1; then
        ipset list -n frpwaf_block >/dev/null 2>&1 && _left="${_left} ipset:frpwaf_block"
        ipset list -n frpwaf_block6 >/dev/null 2>&1 && _left="${_left} ipset:frpwaf_block6"
    fi
    printf '%s' "${_left}"
}

if command -v iptables >/dev/null 2>&1 || command -v ip6tables >/dev/null 2>&1 || command -v ipset >/dev/null 2>&1; then
    if frpwaf_kernel_teardown; then
        :
    else
        echo '提示：未能调用 app/firewall.py 的 teardown()（缺少解释器或插件目录不完整），改用内置内核清理。'
        frpwaf_kernel_teardown_manual
    fi
    if [ "$(id -u 2>/dev/null || echo 0)" != "0" ]; then
        echo '⚠️  非 root 运行：无法确认内核规则是否已清除，请用 root 复跑一次本脚本。'
    elif ! frpwaf_kernel_probe; then
        echo '⚠️  无法校验内核残留（iptables/ipset 不可用或无权限），请手动核对链与集合。'
    else
        kernel_left="$(frpwaf_kernel_residue)"
        if [ -n "${kernel_left}" ]; then
            echo "⚠️  未能清理内核残留：${kernel_left}"
            echo '    可手动执行：iptables -t nat -D PREROUTING -j FRPWAF_REDIRECT; iptables -t nat -F FRPWAF_REDIRECT; iptables -t nat -X FRPWAF_REDIRECT'
            echo '                ipset destroy frpwaf_block; ipset destroy frpwaf_block6  （IPv6 用 ip6tables 重复一遍）'
        else
            echo '内核封禁已清理：filter/nat 链与 ipset 集合均无残留。'
        fi
    fi
else
    echo '跳过内核封禁清理：系统未安装 iptables/ipset。'
fi

# 取消开机自启 + 删除 init
if command -v chkconfig >/dev/null 2>&1; then
    chkconfig --del frpwaf >/dev/null 2>&1 || true
fi
if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d -f frpwaf remove >/dev/null 2>&1 || true
fi
rm -f "${INIT}" /usr/bin/frpwaf

# 删掉 init.d 脚本后再 reload 一次：否则 systemd 的 sysv 生成器会把旧 init 脚本
# 残留成内存里的 `frpwaf.service`（`systemctl is-enabled frpwaf` 会报 generated/rc=0，
# 看起来像没卸干净），下一次 reload/重启才消失。
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed frpwaf >/dev/null 2>&1 || true
fi

echo "卸载完成（运行数据保留在 ${WAF_HOME}）"
