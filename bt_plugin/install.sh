#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

PLUGIN_DIR=/www/server/panel/plugin/frpwaf
WAF_HOME=/opt/frpwaf
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
    ${INIT} stop >/dev/null 2>&1
    # 移除内核级封禁（ipset + iptables）
    if command -v iptables >/dev/null 2>&1; then
        iptables -D INPUT -j FRPWAF_BLOCK 2>/dev/null
        iptables -F FRPWAF_BLOCK 2>/dev/null
        iptables -X FRPWAF_BLOCK 2>/dev/null
    fi
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -D INPUT -j FRPWAF_BLOCK 2>/dev/null
        ip6tables -F FRPWAF_BLOCK 2>/dev/null
        ip6tables -X FRPWAF_BLOCK 2>/dev/null
    fi
    if command -v ipset >/dev/null 2>&1; then
        ipset destroy frpwaf_block 2>/dev/null
        ipset destroy frpwaf_block6 2>/dev/null
    fi
    # 移除 frps.toml 中的 frpwaf 插件配置并重启 frps（避免 fail-closed 残留）
    if [ -f /usr/local/frps/frps.toml ] && grep -q "frpwaf" /usr/local/frps/frps.toml; then
        ${PLUGIN_DIR}/uninstall.sh >/dev/null 2>&1 || true
    fi
    if [ "${OS}" == "CentOS" ]; then
        chkconfig --del frpwaf
    else
        update-rc.d -f frpwaf remove >/dev/null 2>&1
    fi
    rm -f ${INIT} /usr/bin/frpwaf
    rm -rf ${PLUGIN_DIR}
    # 运行数据保留在 /opt/frpwaf，如需彻底删除请手动执行: rm -rf /opt/frpwaf
    echo '卸载完成（运行数据保留在 /opt/frpwaf）'
}

if [ "${1}" == 'install' ]; then
    Install_frpwaf
else
    Uninstall_frpwaf
fi
