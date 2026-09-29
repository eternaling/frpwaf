#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 插件目录由脚本自身位置推导，不写死路径（宝塔可能装到其它目录 / 改目录名）。
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_HOME="${FRPWAF_HOME:-/opt/frpwaf}"
INIT=/etc/init.d/frpwaf
FRPS_TOML=/usr/local/frps/frps.toml

# 宝塔在卸载插件时会调用本脚本；此处做「无残留」清理：
#   1) 停服务、取消开机自启、删除 init 脚本
#   2) 移除内核级封禁（ipset + iptables）
#   3) 移除 frps.toml 中的 [[httpPlugins]] frpwaf 配置并重启 frps
#      （否则 frps 仍会回调已停止的 WAF，fail-closed 会导致连接被拒）
# 运行数据保留在 /opt/frpwaf，如需彻底删除请手动: rm -rf /opt/frpwaf

echo '正在卸载 frpwaf ...'

${INIT} stop >/dev/null 2>&1

# 内核封禁清理
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

# 移除 frps.toml 中的 frpwaf 插件配置块
if [ -f "${FRPS_TOML}" ] && grep -q "frpwaf" "${FRPS_TOML}"; then
    cp -a "${FRPS_TOML}" "${FRPS_TOML}.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null
    python3 - "${FRPS_TOML}" <<'PYEOF'
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    lines = f.read().splitlines()

segments, cur, cur_is_header = [], [], None
for ln in lines:
    s = ln.strip()
    if s.startswith("["):
        segments.append((cur_is_header, cur))
        cur, cur_is_header = [ln], s
    else:
        cur.append(ln)
segments.append((cur_is_header, cur))

out = []
for header, body in segments:
    if header and header.startswith("[[httpPlugins]]") and any("frpwaf" in l for l in body):
        continue
    out.extend(body)

text = "\n".join(out)
if "frpwaf" in text:
    text = "\n".join(l for l in text.splitlines() if "frpwaf" not in l)

with open(path, "w", encoding="utf-8") as f:
    f.write(text.strip() + "\n")
PYEOF
    /etc/init.d/frps restart >/dev/null 2>&1
fi

# 取消开机自启 + 删除 init
if command -v chkconfig >/dev/null 2>&1; then
    chkconfig --del frpwaf >/dev/null 2>&1
fi
update-rc.d -f frpwaf remove >/dev/null 2>&1
rm -f ${INIT} /usr/bin/frpwaf

echo '卸载完成（运行数据保留在 /opt/frpwaf）'
