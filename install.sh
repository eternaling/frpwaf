#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 插件目录由脚本自身位置推导，不写死 /www/server/panel/plugin/frpwaf，
# 以便宝塔把插件装到其它路径（或改目录名）时仍能正确定位 app/ 与 web/。
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_HOME="${FRPWAF_HOME:-/opt/frpwaf}"
INIT=/etc/init.d/frpwaf
UNIT=/etc/systemd/system/frpwaf.service

checkos(){
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then OS=CentOS
    elif grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then OS=Debian
    elif grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then OS=Ubuntu
    else echo "Not support OS"; exit 1; fi
}

Systemd_available()
{
    [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

# 安装 systemd unit。unit 里的路径默认写 /opt/frpwaf，WAF_HOME 被改写时同步替换。
Install_systemd_unit()
{
    local src="${PLUGIN_DIR}/frpwaf.service"
    local content
    if [ ! -f "${src}" ]; then
        echo "⚠️  未找到 ${src}（插件包缺少 frpwaf.service）"
        echo "   打包时需要一并带上 frpwaf.service（见 build.sh）。"
        return 1
    fi
    # 行尾兜底：Windows 工作区打包可能带入 CRLF。systemd 不会忽略行尾的 \r，
    # 会把 "always\r" 当成非法值导致 unit 解析失败，故先整份去掉 CR。
    content=$(tr -d '\r' < "${src}") || return 1
    # 用 bash 变量替换而不是 sed，避免 WAF_HOME 里的特殊字符破坏 sed 表达式。
    if [ "${WAF_HOME}" != "/opt/frpwaf" ]; then
        content=${content//\/opt\/frpwaf/${WAF_HOME}}
    fi
    printf '%s\n' "${content}" > "${UNIT}.new" || return 1
    chmod 0644 "${UNIT}.new" || true
    mv -f "${UNIT}.new" "${UNIT}" || return 1
    echo "[*] 已安装 systemd unit: ${UNIT}"
}

Install_frpwaf()
{
    checkos
    # 提升当前 shell 的 fd 上限（与服务脚本一致）：首次安装会直接启动服务，
    # 继承本 shell 的限制；Debian 默认 1024 不够 daemon 的并发闸门使用。
    ulimit -n 8192 2>/dev/null || true
    # 运行代码包必须在插件目录内，否则说明压缩包结构不对（缺少 app/）。
    if [ ! -f "${PLUGIN_DIR}/app/daemon.py" ]; then
        echo "安装失败：未找到 ${PLUGIN_DIR}/app/daemon.py"
        echo "请确认上传的插件包根目录下包含 app/ 目录（不要多套一层文件夹）。"
        exit 1
    fi
    mkdir -p "${WAF_HOME}/data"

    # 首次安装时把运行文件从插件目录同步到 /opt/frpwaf
    if [ ! -f "${WAF_HOME}/app/daemon.py" ]; then
        cp -a "${PLUGIN_DIR}/app" "${WAF_HOME}/" 2>/dev/null
        cp -a "${PLUGIN_DIR}/web" "${WAF_HOME}/" 2>/dev/null
    else
        # 已存在则更新代码（保留 data）
        cp -a "${PLUGIN_DIR}/app/." "${WAF_HOME}/app/" 2>/dev/null
        cp -a "${PLUGIN_DIR}/web/." "${WAF_HOME}/web/" 2>/dev/null
    fi
    # 同步后必须存在 __init__.py，否则守护进程无法以包形式启动
    if [ ! -f "${WAF_HOME}/app/__init__.py" ]; then
        echo "安装失败：${WAF_HOME}/app/__init__.py 缺失，请检查插件包是否完整。"
        exit 1
    fi

    # 首次安装：写入面板监听配置（仅当配置文件不存在时）。
    # 默认只绑本机：旧默认 0.0.0.0 等于把默认口令面板直接摆到公网。
    # 首次写入保证「装完就能在本机打开面板」，需要远程访问时再到面板里打开
    # 「允许远程访问」开关（或手改本文件的 http_addr）。已存在则不覆盖，
    # 避免升级时抹掉用户改过的监听地址 / 口令 / 名单。
    if [ ! -f "${WAF_HOME}/data/frpwaf.json" ]; then
        cat > "${WAF_HOME}/data/frpwaf.json" <<'JSON'
{
  "http_addr": "127.0.0.1",
  "http_port": 7080,
  "frp_handler_addr": "127.0.0.1",
  "frp_handler_port": 7082,
  "password_changed": false
}
JSON
        chmod 600 "${WAF_HOME}/data/frpwaf.json"
    fi

    # init 脚本
    # 行尾归一化：若插件包带 CRLF（Windows 工作区打包），装到 /etc/init.d/frpwaf 后
    # shebang 会变成 "#!/bin/bash\r"，内核找不到解释器，服务启动/重启报
    # `cannot execute: required file not found`。此处兜底再转一次 LF。
    cp -f "${PLUGIN_DIR}/frpwaf.init" "${INIT}"
    sed -i 's/\r$//' "${INIT}"
    chmod +x "${INIT}"
    cp -f "${INIT}" /usr/bin/frpwaf
    sed -i 's/\r$//' /usr/bin/frpwaf
    chmod +x /usr/bin/frpwaf

    # 先停掉现有实例：从旧 init.d/nohup 迁移到 systemd 时，旧进程会占着回调端口，
    # 不清掉会让新 unit 反复 EADDRINUSE 启动失败（Restart=always 会一直重试）。
    if [ -x "${INIT}" ]; then
        "${INIT}" stop >/dev/null 2>&1 || true
    fi

    # 服务托管：有 systemd 就装 unit（Restart=always 自带自愈），否则回退 init.d。
    # 注意：插件包里可能没有 frpwaf.service（旧版 build.sh 不拷它）。
    # 这种情况下必须回退 init.d 而不是直接报错，否则升级会把服务直接置为停止。
    unit_ok=0
    if Systemd_available; then
        if Install_systemd_unit; then
            unit_ok=1
        else
            echo "⚠️  未能安装 systemd unit，回退到 init.d 方式启动（此时无自动重启，崩溃后需人工/外部看护拉起）。"
        fi
    fi

    if [ "${unit_ok}" -eq 1 ]; then
        systemctl daemon-reload
        systemctl enable frpwaf >/dev/null 2>&1 || true
        # init 脚本检测到 unit 已启用会转调 systemctl start（避免双管理互相打架）
        if ! "${INIT}" start; then
            echo "启动失败：frpwaf 未能运行，请查看 journalctl -u frpwaf 与 ${WAF_HOME}/data/frpwaf.log"
            exit 1
        fi
    else
        # 无 systemd / 无 unit 文件：沿用 init.d + chkconfig
        if [ "${OS}" == "CentOS" ]; then
            chkconfig --add frpwaf
            chkconfig --level 2345 frpwaf on
        else
            update-rc.d frpwaf defaults >/dev/null 2>&1
        fi
        if ! "${INIT}" restart; then
            echo "启动失败：frpwaf 未能运行，请查看 ${WAF_HOME}/data/frpwaf.log"
            exit 1
        fi
    fi

    echo '安装完成'
    echo '管理面板: http://127.0.0.1:7080/（仅本机监听，默认账号 admin / 123456）'
    echo '首次登录会强制修改默认口令；需要远程访问请登录面板后在「设置 → 监听与安全」里打开「允许远程访问」'
    echo '（或手改 /opt/frpwaf/data/frpwaf.json 的 http_addr 并重启服务）'
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
