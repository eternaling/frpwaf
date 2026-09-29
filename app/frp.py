#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - frp 服务端/客户端管理

把宝塔官方「frp管理器」插件的功能并入本插件，并修复其已知问题：

  官方插件问题 -> 本模块的处理
  1. maxPoolCount 写在顶层（frp 0.52+ 需在 [transport] 下）-> 自动归位
  2. 重装会清空 /usr/local/frps 并重新随机生成配置（破坏性）-> 升级只换二进制，保留配置
  3. 端口占用检查用 netstat|awk 脆弱正则 -> 改用 ss 解析
  4. 版本写死 0.53.2/0.52.3，无法升级、无 arm 支持 -> 支持多架构 + 动态查最新版
  5. 写配置用 toml.dumps 但可能丢未知字段 -> 读改写整表，保留 httpPlugins 等
  6. 无配置校验、无备份 -> 写前备份、写后 `frps verify`

仅标准库；外部命令 curl/wget/tar/ss。
"""
import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request

FRPS_DIR = "/usr/local/frps"
FRPC_DIR = "/usr/local/frpc"
FRPS_TOML = FRPS_DIR + "/frps.toml"
FRPC_TOML = FRPC_DIR + "/frpc.toml"
FRPS_INIT = "/etc/init.d/frps"
FRPC_INIT = "/etc/init.d/frpc"
BACKUP_DIR = "/opt/frpwaf/data/frp_backup"

GH_RELEASE = "https://github.com/fatedier/frp/releases/download/v{ver}/frp_{ver}_linux_{arch}.tar.gz"
GH_API_LATEST = "https://api.github.com/repos/fatedier/frp/releases/latest"
# 下载源前缀（按速度排序，留空=GitHub 直连，放最后兜底）
# 说明：GitHub 直连在国内多数服务器上极慢或不可达，优先使用加速镜像。
MIRRORS = [
    "https://gh-proxy.com/",
    "https://ghfast.top/",
    "",
]

# 异步安装任务状态文件（供前端轮询）
JOB_FILE = "/opt/frpwaf/data/frp_job.json"
JOB_LOG = "/opt/frpwaf/data/frp_job.log"


def _dir(kind):
    return FRPS_DIR if kind == "frps" else FRPC_DIR


def _toml_path(kind):
    return FRPS_TOML if kind == "frps" else FRPC_TOML


def _init_path(kind):
    return FRPS_INIT if kind == "frps" else FRPC_INIT


def _bin(kind):
    return os.path.join(_dir(kind), kind)


def arch():
    """返回 frp 发布包使用的架构名。"""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    if m.startswith("armv7") or m.startswith("armv6"):
        return "arm"
    if m.startswith("arm"):
        return "arm"
    if m in ("i386", "i686", "x86"):
        return "386"
    return "amd64"


def _run(args, timeout=60, shell=False):
    try:
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, shell=shell)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception as e:
        return 1, "", str(e)


# ---------------- 版本 ----------------
def installed_version(kind):
    b = _bin(kind)
    if not os.path.exists(b):
        return ""
    rc, out, err = _run([b, "--version"], timeout=10)
    text = (out or err or "").strip()
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else text


_latest_cache = {"ver": "", "ts": 0}


def latest_version(timeout=15, use_cache=True):
    """查询 GitHub 最新版本号；失败返回空串。带 10 分钟缓存。"""
    now = time.time()
    if use_cache and _latest_cache["ver"] and now - _latest_cache["ts"] < 600:
        return _latest_cache["ver"]
    try:
        req = urllib.request.Request(GH_API_LATEST,
                                     headers={"User-Agent": "frpwaf/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        tag = (data.get("tag_name") or "").lstrip("v")
        if tag:
            _latest_cache["ver"] = tag
            _latest_cache["ts"] = now
        return tag
    except Exception:
        return _latest_cache["ver"]


# ---------------- 安装 / 升级 ----------------
def _download(ver, arch_name, dest, progress=None):
    """下载 frp 发布包到 dest（流式，可上报进度），成功返回 True。"""
    for m in MIRRORS:
        url = (m + GH_RELEASE.format(ver=ver, arch=arch_name)) if m else GH_RELEASE.format(ver=ver, arch=arch_name)
        try:
            p = subprocess.Popen(["curl", "-fL", "--connect-timeout", "8",
                                  "--max-time", "300",
                                  "--speed-limit", "20480", "--speed-time", "20",
                                  "-o", dest, url],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            continue
        last = -1
        while True:
            if p.poll() is not None:
                break
            if os.path.exists(dest):
                sz = os.path.getsize(dest)
                if progress:
                    progress(sz)
                last = sz
            time.sleep(0.5)
        if p.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 100000:
            return True
        try:
            if os.path.exists(dest):
                os.remove(dest)
        except OSError:
            pass
    return False


def _extract_binaries(tar_path, kind, dest_dir):
    """从发布包中解出 frps/frpc 二进制，返回是否成功。"""
    tmp = tempfile.mkdtemp(prefix="frp_ext_")
    try:
        rc, _, err = _run(["tar", "-zxf", tar_path, "-C", tmp], timeout=120)
        if rc != 0:
            return False, err
        # 找到解出的顶层目录
        entries = [os.path.join(tmp, e) for e in os.listdir(tmp)]
        base = entries[0] if len(entries) == 1 and os.path.isdir(entries[0]) else tmp
        src = os.path.join(base, kind)
        if not os.path.exists(src):
            return False, "压缩包内未找到 %s" % kind
        os.makedirs(dest_dir, exist_ok=True)
        dst = os.path.join(dest_dir, kind)
        # 关键：目标二进制可能正在运行，直接覆盖写会触发 ETXTBSY("Text file busy")。
        # 先复制到同目录临时文件，再用 os.replace() 原子改名顶替（改名不影响正在运行的旧 inode）。
        tmp_dst = dst + ".new.%d" % os.getpid()
        try:
            shutil.copy2(src, tmp_dst)
            os.chmod(tmp_dst, 0o755)
            os.replace(tmp_dst, dst)
        except Exception:
            try:
                if os.path.exists(tmp_dst):
                    os.remove(tmp_dst)
            except OSError:
                pass
            raise
        return True, ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------- 异步安装任务（供前端轮询） ----------------
_job_lock = __import__("threading").Lock()


def _job_write(**kw):
    try:
        os.makedirs(os.path.dirname(JOB_FILE), exist_ok=True)
        # 每次写入都刷新心跳时间，供前端判断任务是否已僵死
        kw.setdefault("ts", int(time.time()))
        with open(JOB_FILE, "w", encoding="utf-8") as f:
            json.dump(kw, f, ensure_ascii=False)
    except Exception:
        pass


def job_status():
    try:
        with open(JOB_FILE, "r", encoding="utf-8") as f:
            st = json.load(f)
    except Exception:
        return {"running": False, "percent": 0, "msg": "", "done": False, "ok": False}
    # 心跳超过 90 秒未更新：说明后台线程已随面板重启而消失，判定为失败
    if st.get("running") and int(time.time()) - int(st.get("ts", 0)) > 90:
        st = {"running": False, "percent": 0, "done": True, "ok": False, "kind": st.get("kind", ""),
              "msg": "安装任务已中断（面板可能重启过），请重新点击安装"}
        _job_write(**st)
    return st


def start_install(kind, version=""):
    """启动后台安装任务；若已有任务在跑则拒绝。"""
    with _job_lock:
        st = job_status()
        if st.get("running"):
            return False, "已有安装任务在进行中"
        _job_write(running=True, percent=0, msg="准备中…", done=False, ok=False,
                   kind=kind, ts=int(time.time()))
    import threading
    threading.Thread(target=_install_worker, args=(kind, version), daemon=True).start()
    return True, "已开始"


def _install_worker(kind, version):
    try:
        _job_write(running=True, percent=1, msg="解析版本…", done=False, ok=False, kind=kind)
        ver = (version or "").strip().lstrip("v")
        if not ver or ver == "latest":
            ver = latest_version() or "0.71.0"
        a = arch()
        cur = installed_version(kind)
        have = os.path.exists(_bin(kind))
        if have and cur == ver:
            if not os.path.exists(_init_path(kind)):
                _install_init(kind)
            _job_write(running=False, percent=100, msg="%s 已是 %s，无需升级" % (kind, ver),
                       done=True, ok=True, kind=kind)
            return

        if have:
            _job_write(running=True, percent=3, msg="备份现有配置…", done=False, ok=False, kind=kind)
            _backup(kind)

        total = {"n": 0}

        def _prog(sz):
            total["n"] = sz
            pct = min(80, 5 + int(sz / 13900000.0 * 75))
            _job_write(running=True, percent=pct,
                       msg="下载中… %.1f MB" % (sz / 1048576.0), done=False, ok=False, kind=kind)

        _job_write(running=True, percent=5, msg="下载中…", done=False, ok=False, kind=kind)
        tmp_tar = os.path.join(tempfile.gettempdir(), "frp_%s_%s.tar.gz" % (ver, a))
        if not _download(ver, a, tmp_tar, progress=_prog):
            _job_write(running=False, percent=0, msg="下载失败（请检查网络/镜像）",
                       done=True, ok=False, kind=kind)
            return

        _job_write(running=True, percent=85, msg="解压并安装…", done=False, ok=False, kind=kind)
        was_running = is_running(kind)
        ok, err = _extract_binaries(tmp_tar, kind, _dir(kind))
        try:
            os.remove(tmp_tar)
        except OSError:
            pass
        if not ok:
            _job_write(running=False, percent=0, msg="解压失败：%s" % err,
                       done=True, ok=False, kind=kind)
            return

        if not os.path.exists(_toml_path(kind)):
            with open(_toml_path(kind), "w", encoding="utf-8") as f:
                f.write(generate_config(kind))
        _install_init(kind)
        new_ver = installed_version(kind)
        if not new_ver:
            _job_write(running=False, percent=0, msg="安装后无法执行二进制（架构 %s）" % a,
                       done=True, ok=False, kind=kind)
            return

        # 新版 frp 对配置采用严格解析：迁移旧版遗留字段，否则会因
        # `json: unknown field` 拒绝启动（这是升级后服务起不来的主因）
        mig_changed, mig_note = _migrate_config(kind)
        if mig_note and not mig_changed:
            # 迁移后仍校验不过：回滚二进制，避免留下无法启动的新版
            if have:
                rollback(kind)
            _job_write(running=False, percent=0, msg="升级中止：%s；已回滚" % mig_note,
                       done=True, ok=False, kind=kind)
            return

        # 若升级前服务在运行，则重启以让新二进制生效，并校验服务是否真的起来了
        restarted = ""
        if was_running:
            _job_write(running=True, percent=95, msg="重启服务以应用新版本…", done=False, ok=False, kind=kind)
            _run([_init_path(kind), "restart"], timeout=30)
            time.sleep(1)
            if not is_running(kind):
                # 重启失败：自动回滚到升级前版本，保证业务不中断
                _job_write(running=True, percent=97, msg="服务重启失败，正在自动回滚…",
                           done=False, ok=False, kind=kind)
                rb_ok, rb_msg = rollback(kind) if have else (False, "无可回滚备份")
                _job_write(running=False, percent=0,
                           msg="升级失败：新版本无法启动，已自动回滚（%s）" % rb_msg,
                           done=True, ok=False, kind=kind)
                return
            restarted = "，服务已重启" + ("，" + mig_note if mig_note else "")

        final_msg = "%s 安装完成：%s%s" % (kind, new_ver, restarted)
        if mig_note and not was_running:
            final_msg += "，" + mig_note
        _job_write(running=False, percent=100, msg=final_msg, done=True, ok=True, kind=kind)
    except Exception as e:
        _job_write(running=False, percent=0, msg="安装异常：%s" % str(e)[:200],
                   done=True, ok=False, kind=kind)



FRPS_TEMPLATE = """bindAddr = "0.0.0.0"
bindPort = {bind_port}
kcpBindPort = {bind_port}
quicBindPort = {quic_port}
vhostHTTPPort = {vhost_http}
vhostHTTPSPort = {vhost_https}
tcpmuxHTTPConnectPort = {tcpmux}

[transport]
maxPoolCount = 50
tcpMux = true
heartbeatTimeout = 90

[webServer]
addr = "0.0.0.0"
port = {web_port}
user = "{user}"
password = "{pwd}"

[log]
to = "/var/log/frps.log"
level = "info"
maxDays = 30

[auth]
token = "{token}"
"""

FRPC_TEMPLATE = """serverAddr = "{server_addr}"
serverPort = {server_port}
auth.token = "{token}"

[transport]
tcpMux = true

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = {remote_port}
"""


def _random(n):
    import secrets
    import string
    alpha = string.ascii_letters + string.digits
    return "".join(secrets.choice(alpha) for _ in range(n))


def _free_port(start, used):
    p = start
    while p in used or port_in_use(p):
        p += 1
    used.add(p)
    return p


def port_in_use(port, proto="tcp"):
    """端口是否已被监听。"""
    rc, out, _ = _run(["ss", "-H", "-lntu"], timeout=10)
    if rc != 0:
        rc, out, _ = _run(["ss", "-lntu"], timeout=10)
    pat = re.compile(r"[:.]%d\s" % int(port))
    for line in out.splitlines():
        if pat.search(line + " "):
            return True
    return False


def generate_config(kind, server_addr="", server_port=0, token=""):
    if kind == "frps":
        used = set()
        bind = _free_port(15443, used)
        http = _free_port(18080, used)
        https = _free_port(18443, used)
        tcpmux = _free_port(16337, used)
        web = _free_port(7001, used)
        pwd = _random(16)
        return FRPS_TEMPLATE.format(
            bind_port=bind, quic_port=bind + 2, vhost_http=http, vhost_https=https,
            tcpmux=tcpmux, web_port=web, user="admin", pwd=pwd,
            token=token or _random(16))
    return FRPC_TEMPLATE.format(
        server_addr=server_addr or "0.0.0.0", server_port=server_port or 15443,
        token=token or _random(16), remote_port=22)


def init_script(kind):
    """生成 init 脚本内容（与现有 frps 风格一致）。"""
    prog = "Frps" if kind == "frps" else "Frpc"
    d = _dir(kind)
    toml = _toml_path(kind)
    return """#! /bin/bash
# chkconfig: 2345 55 25
# Description: Startup script for {kind}
### BEGIN INIT INFO
# Provides:          {kind}
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts the {kind}
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
ProgramName="{prog}"
ProgramPath="{d}"
NAME={kind}
BIN=${{ProgramPath}}/${{NAME}}
CONFIGFILE={toml}
RET_VAL=0

[ -x ${{BIN}} ] || exit 0
program_version=`${{BIN}} --version`

fun_check_run(){{
    PID=`ps -ef | grep -v grep | grep -i "${{BIN}}" | awk '{{print $2}}'`
    [ ! -z $PID ] && return 0 || return 1
}}

fun_start(){{
    if fun_check_run; then
        echo "${{ProgramName}} (pid $PID) already running."
        return 0
    fi
    if [ ! -r ${{CONFIGFILE}} ]; then
        echo "config file ${{CONFIGFILE}} not found"
        return 1
    fi
    echo -n "Starting ${{ProgramName}}(${{program_version}})..."
    ${{BIN}} -c ${{CONFIGFILE}} >/dev/null 2>&1 &
    sleep 1
    fun_check_run || {{ echo "start failed"; return 1; }}
    echo " done"
    return 0
}}

fun_stop(){{
    if fun_check_run; then
        echo -n "Stoping ${{ProgramName}} (pid $PID)... "
        kill $PID && echo " done" || {{ echo " failed"; return 1; }}
    else
        echo "${{ProgramName}} is not running."
    fi
    return 0
}}

fun_restart(){{ fun_stop; fun_start; }}

fun_status(){{
    if fun_check_run; then
        echo "${{ProgramName}} (pid $PID) is running..."
    else
        echo "${{ProgramName}} is stopped"
        exit 0
    fi
}}

fun_config(){{
    [ -s ${{CONFIGFILE}} ] && vi ${{CONFIGFILE}} || {{ echo "config not found"; return 1; }}
}}

fun_version(){{
    echo "${{ProgramName}} version ${{program_version}}"
    return 0
}}

case "$1" in
    start|stop|restart|status|config|version)
        fun_$1
        RET_VAL=$?
    ;;
    *)
        echo "Usage: {{start|stop|restart|status|config|version}}"
        RET_VAL=1
    ;;
esac
exit ${{RET_VAL}}
""".format(kind=kind, prog=prog, d=d, toml=toml)


def _enable_autostart(kind):
    os_name = ""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            os_name = f.read().lower()
    except Exception:
        pass
    if "centos" in os_name or "red hat" in os_name or "rhel" in os_name:
        _run(["chkconfig", "--add", kind])
        _run(["chkconfig", "--level", "2345", kind, "on"])
    else:
        _run(["update-rc.d", kind, "defaults"])


def _install_init(kind):
    path = _init_path(kind)
    with open(path, "w", encoding="utf-8") as f:
        f.write(init_script(kind))
    os.chmod(path, 0o755)
    # /usr/bin 软链
    link = "/usr/bin/" + kind
    try:
        if os.path.islink(link) or os.path.exists(link):
            os.remove(link)
        os.symlink(path, link)
    except Exception:
        pass
    _enable_autostart(kind)


def install(kind, version="", keep_config=True):
    """安装/升级。返回 (ok, msg)。"""
    if kind not in ("frps", "frpc"):
        return False, "参数错误"
    ver = (version or "").strip().lstrip("v")
    if not ver or ver == "latest":
        ver = latest_version() or "0.71.0"
    a = arch()

    cur = installed_version(kind)
    have = os.path.exists(_bin(kind))
    if have and cur == ver:
        # 已是指定版本：仅在缺失时补齐 init / 配置，不覆盖现有文件
        if not os.path.exists(_init_path(kind)):
            _install_init(kind)
        if not os.path.exists(_toml_path(kind)):
            with open(_toml_path(kind), "w", encoding="utf-8") as f:
                f.write(generate_config(kind))
        return True, "%s 已是 %s，无需升级" % (kind, ver)

    # 备份现有
    if have:
        _backup(kind)

    tmp_tar = os.path.join(tempfile.gettempdir(), "frp_%s_%s_%s.tar.gz" % (ver, a, kind))
    if not _download(ver, a, tmp_tar):
        return False, "下载失败（请检查网络/镜像）：%s" % GH_RELEASE.format(ver=ver, arch=a)

    ok, err = _extract_binaries(tmp_tar, kind, _dir(kind))
    try:
        os.remove(tmp_tar)
    except OSError:
        pass
    if not ok:
        return False, "解压失败：%s" % err

    # 首次安装：若无配置文件则生成
    if not os.path.exists(_toml_path(kind)):
        if kind == "frps":
            with open(_toml_path(kind), "w", encoding="utf-8") as f:
                f.write(generate_config("frps"))
        else:
            # frpc 需要服务端地址，交给用户填写
            with open(_toml_path(kind), "w", encoding="utf-8") as f:
                f.write(generate_config("frpc"))

    _install_init(kind)
    new_ver = installed_version(kind)
    if not new_ver:
        return False, "安装后无法执行二进制，请检查系统架构(%s)" % a
    return True, "%s 已安装：%s" % (kind, new_ver)


def uninstall(kind):
    _run(["%s" % _init_path(kind), "stop"], shell=False)
    if "centos" in _os_name():
        _run(["chkconfig", "--del", kind])
    else:
        _run(["update-rc.d", "-f", kind, "remove"])
    for p in (_init_path(kind), "/usr/bin/" + kind):
        try:
            if os.path.exists(p) or os.path.islink(p):
                os.remove(p)
        except Exception:
            pass
    shutil.rmtree(_dir(kind), ignore_errors=True)
    return True, "%s 已卸载" % kind


def _os_name():
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            return f.read().lower()
    except Exception:
        return ""


def _backup(kind):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    src = _dir(kind)
    dst = os.path.join(BACKUP_DIR, "%s-%s" % (kind, ts))
    try:
        shutil.copytree(src, dst)
        return dst
    except Exception:
        return ""


def _latest_backup(kind, exclude=""):
    """返回该 kind 最近一次（且非 exclude 指定的）备份目录，找不到返回 ''。"""
    try:
        names = [d for d in os.listdir(BACKUP_DIR) if d.startswith(kind + "-")]
    except Exception:
        return ""
    names = [d for d in names if d != exclude]
    if not names:
        return ""
    names.sort()  # 名称含时间戳，字典序即时间序
    return os.path.join(BACKUP_DIR, names[-1])


# 旧版本（<=0.53）存在、但新版 frp 严格解析会拒绝的字段/段落。
# 升级时若不动它们，新版二进制会因 `json: unknown field` 拒绝启动。
_LEGACY_DROP_FIELDS = ("tcpKeepalive", "keepAliveSeconds", "dashboardPwd",
                       "heartbeatInterval", "protocol")
_LEGACY_DROP_SECTIONS = ("transport.kcp", "kcp")


def _migrate_config(kind):
    """把旧版配置迁移到当前二进制的严格 schema，返回 (changed, note)。

    - 剥离新版不认的遗留字段（顶层 + [transport]）
    - 删除空的 [transport.kcp] 等段落
    - 用新二进制的 `verify` 做最终把关；仍不通过则原样保留并返回提示
    """
    path = _toml_path(kind)
    if not os.path.exists(path):
        return False, ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            orig = f.read()
    except Exception:
        return False, ""
    text = orig
    dropped = []

    def _drop_section(name):
        nonlocal text
        # 匹配 [name] 段落头及其直到下一个段落头/文件尾的内容（仅当该段为空时删除）
        pat = re.compile(r'(?ms)^[ \t]*\[%s\][ \t]*\n(.*?)(?=^[ \t]*\[|\Z)' % re.escape(name))
        m = pat.search(text)
        if m and m.group(1).strip() == "":
            text = text[:m.start()] + text[m.end():]
            dropped.append("[" + name + "]")

    for sec in _LEGACY_DROP_SECTIONS:
        _drop_section(sec)

    for fld in _LEGACY_DROP_FIELDS:
        # 顶层字段行
        new = re.sub(r'(?m)^[ \t]*%s[ \t]*=.*\n?' % re.escape(fld), '', text)
        # [transport] 段内的字段行（如 heartbeatInterval / protocol）
        if new != text:
            dropped.append(fld)
        text = new
    # 再清一次 [transport] 段内遗留字段
    for fld in ("heartbeatInterval", "protocol"):
        new = re.sub(r'(?m)^[ \t]*%s[ \t]*=.*\n?' % re.escape(fld), '', text)
        if new != text and fld not in dropped:
            dropped.append(fld)
        text = new

    if text == orig:
        return False, ""
    # 写临时文件用新二进制 verify 把关
    try:
        tmp = path + ".migrate"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
        rc, out, err = _run([_bin(kind), "verify", "-c", tmp], timeout=20)
        if rc != 0:
            os.remove(tmp)
            return False, "迁移后校验未通过（%s），已保留原配置" % ((err or out).strip()[:120])
        os.remove(tmp)
    except Exception as e:
        return False, "迁移校验异常：%s" % str(e)[:120]
    # 备份后落盘
    try:
        shutil.copy2(path, path + ".premigrate.%s" % time.strftime("%Y%m%d-%H%M%S"))
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception as e:
        return False, "迁移写入失败：%s" % str(e)[:120]
    return True, "已迁移旧配置（移除：%s）" % "、".join(dropped)


def rollback(kind):
    """把最近一次备份还原到安装目录（含二进制与配置），并重启服务。"""
    bak = _latest_backup(kind)
    if not bak or not os.path.isdir(bak):
        return False, "没有可用的备份"
    was_running = is_running(kind)
    try:
        # 逐文件原子还原（二进制可能正在运行，用 os.replace 避免 ETXTBSY）
        for name in os.listdir(bak):
            src = os.path.join(bak, name)
            dst = os.path.join(_dir(kind), name)
            if os.path.isdir(src):
                if os.path.isdir(dst):
                    shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
                continue
            tmp = dst + ".rb.%d" % os.getpid()
            shutil.copy2(src, tmp)
            os.chmod(tmp, os.stat(src).st_mode & 0o777)
            os.replace(tmp, dst)
    except Exception as e:
        return False, "还原失败：%s" % str(e)[:150]
    if was_running:
        _run([_init_path(kind), "restart"], timeout=30)
    ver = installed_version(kind)
    return True, "已回滚到 %s%s" % (ver or "备份版本", "（服务已重启）" if was_running else "")


# ---------------- 状态 / 控制 ----------------
def is_running(kind):
    rc, out, _ = _run([_init_path(kind), "status"], timeout=10)
    return "is running" in (out or "")


def control(kind, action):
    if action not in ("start", "stop", "restart"):
        return False, "参数错误"
    rc, out, err = _run([_init_path(kind), action], timeout=30)
    if err.strip():
        return False, err.strip()
    low = (out or "").lower()
    if "failed" in low:
        return False, "操作失败，请检查配置或日志"
    return True, "操作成功"


# ---------------- 配置读写 ----------------
def load_config(kind):
    """返回 (ok, dict_or_msg)。"""
    try:
        import toml
    except ImportError:
        return False, "缺少 toml 模块"
    path = _toml_path(kind)
    if not os.path.exists(path):
        return False, "配置文件不存在"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return True, toml.load(f)
    except Exception as e:
        return False, "解析失败：%s" % e


def ensure_config(kind, server_addr="", server_port=0, token=""):
    """确保配置文件存在：缺失时预创建（frps / frpc 通用）。

    返回 (created: bool, path: str, msg: str)。
    已存在则原样保留，不覆盖。
    """
    if kind not in ("frps", "frpc"):
        return False, "", "参数错误"
    path = _toml_path(kind)
    if os.path.exists(path):
        return False, path, "配置文件已存在"
    d = _dir(kind)
    try:
        os.makedirs(d, exist_ok=True)
    except OSError as e:
        return False, path, "目录创建失败：%s" % e
    try:
        text = generate_config(kind, server_addr=server_addr,
                               server_port=server_port, token=token)
    except Exception as e:
        return False, path, "生成配置失败：%s" % e
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, 0o600)
    except OSError as e:
        return False, path, "写入失败：%s" % e
    return True, path, "已预创建配置文件"


def save_config(kind, patch):
    """合并 patch 到现有配置并写回（保留 httpPlugins 等未提及字段）。

    写前备份，写后做语法/合法性校验；校验失败则回滚。
    """
    try:
        import toml
    except ImportError:
        return False, "缺少 toml 模块"
    path = _toml_path(kind)
    ok, cfg = load_config(kind)
    if not ok:
        return False, cfg

    # 规整 patch：maxPoolCount 归位到 [transport]
    patch = dict(patch or {})
    if "maxPoolCount" in patch:
        try:
            cfg.setdefault("transport", {})["maxPoolCount"] = int(patch.pop("maxPoolCount"))
        except (TypeError, ValueError):
            patch.pop("maxPoolCount", None)

    for k, v in patch.items():
        if v is None:
            continue
        if isinstance(v, dict):
            cfg.setdefault(k, {})
            if isinstance(cfg[k], dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
        else:
            cfg[k] = v

    new_text = toml.dumps(cfg)
    # 校验
    bak = path + ".bak.%s" % time.strftime("%Y%m%d-%H%M%S")
    try:
        shutil.copy2(path, bak)
    except Exception:
        bak = ""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_text)
    except Exception as e:
        return False, "写入失败：%s" % e

    verr = verify(kind)
    if verr:
        # 回滚
        if bak:
            try:
                shutil.copy2(bak, path)
            except Exception:
                pass
        return False, "配置校验未通过，已回滚：%s" % verr
    return True, "修改成功"


def verify(kind):
    """返回错误字符串；合法则返回空串。"""
    b = _bin(kind)
    if not os.path.exists(b):
        return ""
    rc, out, err = _run([b, "verify", "-c", _toml_path(kind)], timeout=15)
    if rc == 0:
        return ""
    return (err or out or "verify failed").strip()[:300]


# ---------------- 日志 ----------------
def tail_log(kind, lines=300):
    path = "/var/log/frps.log" if kind == "frps" else "/var/log/frpc.log"
    # 优先使用配置里的 log.to
    ok, cfg = load_config(kind)
    if ok:
        log = cfg.get("log") or {}
        if isinstance(log, dict) and log.get("to"):
            path = log["to"]
        elif isinstance(cfg.get("log_file"), str):
            path = cfg["log_file"]
    if not os.path.exists(path):
        return ""
    rc, out, err = _run(["tail", "-n", str(int(lines)), path], timeout=10)
    return out or err or ""


def status_info(kind):
    ver = installed_version(kind)
    return {
        "installed": bool(ver),
        "version": ver,
        "running": is_running(kind),
        "config_path": _toml_path(kind),
        "bin": _bin(kind),
    }
