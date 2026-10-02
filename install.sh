#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 插件目录由脚本自身位置推导，不写死 /www/server/panel/plugin/frpwaf，
# 以便宝塔把插件装到其它路径（或改目录名）时仍能正确定位 app/ 与 web/。
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_HOME="${FRPWAF_HOME:-/opt/frpwaf}"
INIT=/etc/init.d/frpwaf

checkos(){
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then OS=CentOS
    elif grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then OS=Debian
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then OS=Ubuntu
    else echo "Not support OS"; exit 1; fi
}

Install_frpwaf()
{
    checkos
    # 运行代码包必须在插件目录内，否则说明压缩包结构不对（缺少 app/）。
    if [ ! -f "${PLUGIN_DIR}/app/daemon.py" ]; then
        echo "安装失败：未找到 ${PLUGIN_DIR}/app/daemon.py"
        echo "请确认上传的插件包根目录下包含 app/ 目录（不要多套一层文件夹）。"
        exit 1
    fi
    mkdir -p ${WAF_HOME}/data

    # 首次安装时把运行文件从插件目录同步到 /opt/frpwaf
    if [ ! -f ${WAF_HOME}/app/daemon.py ]; then
        cp -a ${PLUGIN_DIR}/app ${WAF_HOME}/ 2>/dev/null
        cp -a ${PLUGIN_DIR}/web ${WAF_HOME}/ 2>/dev/null
    else
        # 已存在则更新代码（保留 data）
        cp -a ${PLUGIN_DIR}/app/. ${WAF_HOME}/app/ 2>/dev/null
        cp -a ${PLUGIN_DIR}/web/. ${WAF_HOME}/web/ 2>/dev/null
    fi
    # 同步后必须存在 __init__.py，否则守护进程无法以包形式启动
    if [ ! -f ${WAF_HOME}/app/__init__.py ]; then
        echo "安装失败：${WAF_HOME}/app/__init__.py 缺失，请检查插件包是否完整。"
        exit 1
    fi

    # init 脚本
    cp -f ${PLUGIN_DIR}/frpwaf.init ${INIT}
    chmod +x ${INIT}
    cp -f ${INIT} /usr/bin/frpwaf
    chmod +x /usr/bin/frpwaf

    # 开机自启
    if [ "${OS}" == "CentOS" ]; then
        chkconfig --add frpwaf
        chkconfig --level 2345 frpwaf on
    else
        update-rc.d frpwaf defaults >/dev/null 2>&1
    fi

    ${INIT} restart
    echo '安装完成'
    echo '管理面板端口: 7080（默认账号 admin / 123456，请及时修改）'
}

Uninstall_frpwaf()
{
    checkos
    # 唯一卸载入口负责先解除 frps 回调；失败时不得停 WAF 或删除插件。
    if ! bash "${PLUGIN_DIR}/uninstall.sh"; then
        echo '卸载中止：frps 回调尚未安全解除，WAF 保持运行。'
        return 1
    fi
    rm -rf "${PLUGIN_DIR}"
    # 运行数据保留在 /opt/frpwaf，如需彻底删除请手动执行: rm -rf /opt/frpwaf
    echo '卸载完成（运行数据保留在 /opt/frpwaf）'
}

usage()
{
    echo "用法: $0 install    安装 / 更新 frpwaf"
    echo "      $0 uninstall  卸载 frpwaf"
    echo "无参数时不执行任何操作（避免误卸载）。"
}

case "${1}" in
    install)
        Install_frpwaf
        ;;
    uninstall)
        Uninstall_frpwaf
        ;;
    *)
        usage
        exit 1
        ;;
esac
