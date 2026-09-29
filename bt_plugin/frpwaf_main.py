#!/usr/bin/python
# coding: utf-8
# +------------------------------------------------------------------
# | FRP WAF  -  宝塔面板插件
# +------------------------------------------------------------------
# | 基于 frp httpPlugins 的 NewUserConn 钩子，对访问 frps 代理端口的
# | 来源 IP 做黑/白名单与自动封禁，并提供独立管理面板。
# +------------------------------------------------------------------
import hmac
import json
import os
import re
import sys
import threading
import subprocess
import traceback

BASE_PATH = "/www/server/panel"
os.chdir(BASE_PATH)
sys.path.insert(0, "class/")
sys.path.insert(0, "/www/server/panel/plugin/frpwaf")
import public

WAF_HOME = "/opt/frpwaf"
WAF_PORT = 7080

WAF_INIT = "/etc/init.d/frpwaf"
PLUGIN_DIR = "/www/server/panel/plugin/frpwaf"
FRPS_TOML = "/usr/local/frps/frps.toml"
PYTHON = "/www/server/panel/pyenv/bin/python"
if not os.path.exists(PYTHON):
    PYTHON = "python3"


# 宝塔面板为常驻进程，会缓存已导入的 app 包；插件更新后需自动重载，
# 否则会继续执行内存中的旧代码（例如旧 store 缺少新方法）。
#
# 注意：运行代码的目录名虽然是 app/，但**绝不能用通用包名 "app" 导入**。
# 面板进程里已有面板自身 / 其它插件的 "app" 包，一旦冲突就会报
#   ModuleNotFoundError: No module named 'app.frp'
# 因此统一用私有包名 frpwaf_app 加载，与外部彻底隔离。
_APP_PKG = "frpwaf_app"
_APP_SIG = None
_APP_LOCK = threading.Lock()


def _app_pkg_dir():
    """运行代码包目录：优先 /opt/frpwaf/app，未部署时回退插件自带 app/。

    首次安装时 WAF 尚未部署到 /opt/frpwaf，此时直接用插件目录里的代码，
    保证「点击插件」等操作在部署前也能正常工作（与旧版 sys.path 回退一致）。
    """
    cands = [os.path.join(WAF_HOME, "app"), os.path.join(PLUGIN_DIR, "app")]
    for d in cands:
        if os.path.isfile(os.path.join(d, "__init__.py")):
            return d
    return cands[0]


def _load_app_pkg():
    """把运行代码包目录以私有包名 frpwaf_app 注册到 sys.modules。

    若同名包已存在但 __path__ 不是当前选定目录（被顶替），则重建修复。
    """
    import importlib.util
    pkg_dir = _app_pkg_dir()
    cur = sys.modules.get(_APP_PKG)
    if cur is not None and list(getattr(cur, "__path__", []) or []) == [pkg_dir]:
        return cur
    # 清除可能残留的旧包与子模块
    for m in [m for m in list(sys.modules)
              if m == _APP_PKG or m.startswith(_APP_PKG + ".")]:
        sys.modules.pop(m, None)
    spec = importlib.util.spec_from_file_location(
        _APP_PKG, os.path.join(pkg_dir, "__init__.py"),
        submodule_search_locations=[pkg_dir])
    pkg = importlib.util.module_from_spec(spec)
    sys.modules[_APP_PKG] = pkg
    try:
        spec.loader.exec_module(pkg)
    except Exception:
        sys.modules.pop(_APP_PKG, None)
        raise
    return pkg


def _app(modname):
    """导入运行代码子模块，源码有变更时自动重载。

    使用私有包名 frpwaf_app，避免与宝塔面板/其它插件的通用 "app" 包冲突；
    包目录优先 /opt/frpwaf/app，未部署时回退插件目录 app/。
    """
    global _APP_SIG
    with _APP_LOCK:
        if WAF_HOME not in sys.path:
            sys.path.insert(0, WAF_HOME)
        import importlib
        pkg_dir = _app_pkg_dir()
        sig = []
        try:
            for fn in sorted(os.listdir(pkg_dir)):
                if fn.endswith(".py"):
                    sig.append((pkg_dir, fn,
                                int(os.path.getmtime(os.path.join(pkg_dir, fn)))))
        except OSError:
            pass
        sig = tuple(sig)
        if sig != _APP_SIG:
            # 源码有变更：丢弃旧的私有包（含子模块），下次重新导入新代码
            for m in [m for m in list(sys.modules)
                      if m == _APP_PKG or m.startswith(_APP_PKG + ".")]:
                sys.modules.pop(m, None)
            _APP_SIG = sig
        _load_app_pkg()   # 确保私有包存在且指向当前选定目录（防被顶替）
        return importlib.import_module(_APP_PKG + "." + modname)


class frpwaf_main:

    # ---------------- 内部工具 ----------------
    def _server_ip(self):
        try:
            ip = public.get_server_ip()
            if ip:
                return ip
        except Exception:
            pass
        return "127.0.0.1"

    def _panel_url(self):
        return "http://%s:%d/" % (self._server_ip(), WAF_PORT)

    def _read(self, path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""

    def _write(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)

    def _waf_running(self):
        res = public.ExecShell("%s status" % WAF_INIT)
        return "is running" in (res[0] or "")

    def _cfg_raw(self):
        """读取原始配置：文件不存在返回 {}，存在但损坏/读取失败则抛异常。"""
        p = os.path.join(WAF_HOME, "data", "frpwaf.json")
        if not os.path.exists(p):
            return {}
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)

    def _cfg(self):
        """读取 WAF 配置（失败时回退空字典，仅供展示类调用）。"""
        try:
            return self._cfg_raw()
        except Exception:
            return {}

    def _set_cfg(self, patch):
        """合并写入配置。

        注意：读取失败（文件损坏 / 被并发写坏）时**拒绝保存**，绝不覆盖，
        避免把 secret / admin_password / ai_api_key 一并抹除。
        """
        p = os.path.join(WAF_HOME, "data", "frpwaf.json")
        try:
            cfg = self._cfg_raw()
        except Exception:
            raise ValueError("配置文件损坏或不可读，已阻止保存以防数据丢失：%s" % p)
        if not cfg.get("secret"):
            # 文件缺失 / 缺密钥：用应用默认值补齐（会生成新 secret）
            try:
                cfg = dict(_app("config").load())
            except Exception:
                pass
        cfg.update(patch)
        if not cfg.get("secret"):
            raise ValueError("无法获取 secret，已阻止保存")
        self._write(p, json.dumps(cfg, ensure_ascii=False, indent=2))
        try:
            os.chmod(p, 0o600)
        except Exception:
            pass
        return True

    # ---------------- 状态 / 安装 ----------------
    def get_waf_info(self, get=None):
        running = self._waf_running()
        cfg = self._cfg()
        return {
            "status": running,
            "install_status": 1 if os.path.exists(WAF_INIT) else 0,
            "url": self._panel_url(),
            "port": cfg.get("http_port", WAF_PORT),
            "frps_toml": FRPS_TOML,
            "plugin_configured": "frpwaf" in self._read(FRPS_TOML),
            "admin_user": cfg.get("admin_user", "admin"),
            "admin_password": cfg.get("admin_password", ""),
        }

    def install_waf(self, get=None):
        try:
            # 1. 把运行文件同步到 /opt/frpwaf（首次安装 + 后续更新都要覆盖，
            #    否则「安装 / 更新」按钮只会重启服务、不会更新代码）。
            #    用 "app/." 形式避免嵌套成 app/app；data/ 不受影响。
            os.makedirs(os.path.join(WAF_HOME, "app"), exist_ok=True)
            os.makedirs(os.path.join(WAF_HOME, "web"), exist_ok=True)
            public.ExecShell("cp -a %s/app/. %s/app/ 2>/dev/null" % (PLUGIN_DIR, WAF_HOME))
            public.ExecShell("cp -a %s/web/. %s/web/ 2>/dev/null" % (PLUGIN_DIR, WAF_HOME))
            os.makedirs(os.path.join(WAF_HOME, "data"), exist_ok=True)
            # 2. 安装 init 脚本
            public.ExecShell("cp -f %s/frpwaf.init %s" % (PLUGIN_DIR, WAF_INIT))
            public.ExecShell("chmod +x %s" % WAF_INIT)
            public.ExecShell("cp -f %s %s" % (WAF_INIT, "/usr/bin/frpwaf"))
            public.ExecShell("chmod +x /usr/bin/frpwaf")
            # 3. 开机自启
            if "CentOS" in public.get_os_version() or "Red" in public.get_os_version():
                public.ExecShell("chkconfig --add frpwaf")
                public.ExecShell("chkconfig --level 2345 frpwaf on")
            else:
                public.ExecShell("update-rc.d frpwaf defaults")
            # 4. 启动
            public.ExecShell("%s start" % WAF_INIT)
            # 5. 同步内核封禁
            self._fw_sync()
            return public.returnMsg(True, "安装成功！管理面板：%s（默认账号 admin / 123456，请及时修改）" % self._panel_url())
        except Exception:
            return public.returnMsg(False, "安装失败：" + traceback.format_exc())

    def reinstall_waf(self, get=None):
        """重装：卸载后重新安装。注意 uninstall 会移除 frps.toml 中的插件块，
        故重装后需重新注入，否则 frps 集成会丢失（回调不再生效）。"""
        self.uninstall_waf()
        res = self.install_waf()
        try:
            if os.path.exists(FRPS_TOML):
                self.apply_to_frps()
        except Exception:
            pass
        return res

    def uninstall_waf(self, get=None):
        try:
            public.ExecShell("%s stop" % WAF_INIT)
            # 移除内核级封禁规则（ipset + iptables）
            try:
                _app("firewall").teardown()
            except Exception:
                pass
            # 移除 frps.toml 中的 httpPlugins 配置并（仅当 frps 在运行时）重启 frps
            # （否则 frps 仍会回调已停止的 WAF，fail-closed 会导致连接被拒）
            had_plugin = "frpwaf" in self._read(FRPS_TOML)
            self._remove_frps_plugin()
            if had_plugin:
                res = public.ExecShell("/etc/init.d/frps status")
                if "is running" in (res[0] or ""):
                    public.ExecShell("/etc/init.d/frps restart")
            if "CentOS" in public.get_os_version() or "Red" in public.get_os_version():
                public.ExecShell("chkconfig --del frpwaf")
            else:
                public.ExecShell("update-rc.d -f frpwaf remove")
            public.ExecShell("rm -f %s /usr/bin/frpwaf" % WAF_INIT)
            return public.returnMsg(True, "已卸载（数据保留在 %s/data）" % WAF_HOME)
        except Exception:
            return public.returnMsg(False, "卸载失败：" + traceback.format_exc())

    # ---------------- 服务控制 ----------------
    def waf_admin(self, get):
        if not hasattr(get, "status") or not get.status:
            return public.returnMsg(False, "参数错误")
        act = get["status"]
        if act not in ("start", "stop", "restart"):
            return public.returnMsg(False, "参数错误")
        res = public.ExecShell("%s %s" % (WAF_INIT, act))
        if res[1]:
            return public.returnMsg(False, res[1])
        if "failed" in (res[0] or ""):
            return public.returnMsg(False, "操作失败，请检查日志")
        return public.returnMsg(True, "操作成功")

    # ---------------- frps 集成 ----------------
    def get_frps_status(self, get=None):
        res = public.ExecShell("/etc/init.d/frps status")
        running = "is running" in (res[0] or "")
        return {
            "status": running,
            "toml": self._read(FRPS_TOML),
            "has_plugin": "frpwaf" in self._read(FRPS_TOML),
        }

    def apply_to_frps(self, get=None):
        """向 frps.toml 注入 [[httpPlugins]] 并重启 frps。"""
        try:
            content = self._read(FRPS_TOML)
            if not content.strip():
                return public.returnMsg(False, "未找到 frps.toml")
            if "frpwaf" in content:
                return public.returnMsg(True, "已配置，无需重复注入")
            # 备份
            public.ExecShell("cp -a %s %s.bak.$(date +%%Y%%m%%d-%%H%%M%%S)" % (FRPS_TOML, FRPS_TOML))
            block = (
                "\n[[httpPlugins]]\n"
                'name = "frpwaf"\n'
                'addr = "127.0.0.1:%d"\n'
                'path = "/frp/handler"\n'
                'ops = ["NewUserConn"]\n'
            ) % int(self._cfg().get("http_port", WAF_PORT))
            self._write(FRPS_TOML, content.rstrip() + "\n" + block)
            public.ExecShell("/etc/init.d/frps restart")
            return public.returnMsg(True, "已注入 frp 插件配置并重启 frps")
        except Exception:
            return public.returnMsg(False, "注入失败：" + traceback.format_exc())

    def _remove_frps_plugin(self):
        """按块移除 name="frpwaf" 的 [[httpPlugins]] 配置，保留其余内容。

        仅当 frps 正在运行时才重启（未运行时重启会失败，但不影响下次启动）。
        """
        content = self._read(FRPS_TOML)
        if "frpwaf" not in content:
            return
        lines = content.splitlines()
        # 切分为：前导段 + 各 section 块
        segments, cur, cur_is_header = [], [], None
        for ln in lines:
            s = ln.strip()
            is_header = s.startswith("[")
            if is_header:
                segments.append((cur_is_header, cur))
                cur, cur_is_header = [ln], s
            else:
                cur.append(ln)
        segments.append((cur_is_header, cur))

        out = []
        for header, body in segments:
            if header and header.startswith("[[httpPlugins]]") and any("frpwaf" in l for l in body):
                continue  # 丢弃 frpwaf 插件块
            out.extend(body)

        text = "\n".join(out)
        if "frpwaf" in text:
            # 兜底：逐行过滤残留
            text = "\n".join(l for l in text.splitlines() if "frpwaf" not in l)
        self._write(FRPS_TOML, text.strip() + "\n")
        return True

    # ---------------- frp 服务端 / 客户端管理 ----------------
    # 合并自宝塔官方「frp管理器」插件，并修复其已知问题。
    def frp_info(self, get=None):
        """frps / frpc 状态信息（含版本、安装、运行、最新版）。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            info = frp.status_info(kind)
            # 配置文件缺失时自动预创建（frps / frpc 通用）
            if not os.path.exists(frp._toml_path(kind)):
                try:
                    frp.ensure_config(kind)
                except Exception:
                    pass
            info["config_exists"] = os.path.exists(frp._toml_path(kind))
            info["arch"] = frp.arch()
            info["latest"] = ""   # 默认不联网；点「检查最新版」时再查（见 frp_latest）
            info["log_path"] = ("/var/log/frps.log" if kind == "frps" else "/var/log/frpc.log")
            return {"status": True, "data": info}
        except Exception:
            return {"status": False, "msg": "获取失败：" + traceback.format_exc()[-200:]}

    def frp_latest(self, get=None):
        """查询 GitHub 最新版本（带缓存，按需调用）。"""
        try:
            frp = _app("frp")
            return {"status": True, "latest": frp.latest_version()}
        except Exception:
            return {"status": True, "latest": ""}

    def _kind(self, get):
        k = "frps"
        try:
            k = (get.kind or "frps").strip()
        except Exception:
            pass
        return "frpc" if k == "frpc" else "frps"

    def frp_control(self, get=None):
        """启动 / 停止 / 重启 frps 或 frpc。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            action = ""
            try:
                action = (get.status or "").strip()
            except Exception:
                pass
            if action not in ("start", "stop", "restart"):
                return public.returnMsg(False, "参数错误")
            ok, msg = frp.control(kind, action)
            return public.returnMsg(ok, msg)
        except Exception:
            return public.returnMsg(False, "操作失败：" + traceback.format_exc()[-200:])

    def frp_install_start(self, get=None):
        """启动后台安装任务（立即返回，前端轮询进度）。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            ver = ""
            try:
                ver = (get.version or "").strip()
            except Exception:
                pass
            ok, msg = frp.start_install(kind, ver)
            return public.returnMsg(ok, msg)
        except Exception:
            return public.returnMsg(False, "启动失败：" + traceback.format_exc()[-300:])

    def frp_install_status(self, get=None):
        """查询后台安装任务进度。"""
        try:
            frp = _app("frp")
            return {"status": True, "data": frp.job_status()}
        except Exception:
            return {"status": True, "data": {"running": False, "percent": 0, "msg": "", "done": False}}

    def frp_uninstall(self, get=None):
        try:
            frp = _app("frp")
            kind = self._kind(get)
            ok, msg = frp.uninstall(kind)
            return public.returnMsg(ok, msg)
        except Exception:
            return public.returnMsg(False, "卸载失败：" + traceback.format_exc()[-200:])

    def frp_rollback(self, get=None):
        """回滚到最近一次升级前备份（含二进制与配置），并重启服务。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            ok, msg = frp.rollback(kind)
            return public.returnMsg(ok, msg)
        except Exception:
            return public.returnMsg(False, "回滚失败：" + traceback.format_exc()[-200:])

    def frp_get_config(self, get=None):
        """读取配置（结构化 + 原文）。配置不存在时自动预创建。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            if not os.path.exists(frp._toml_path(kind)):
                frp.ensure_config(kind)
            ok, cfg = frp.load_config(kind)
            if not ok:
                return {"status": False, "msg": cfg}
            return {"status": True, "data": cfg,
                    "raw": self._read(frp._toml_path(kind)),
                    "path": frp._toml_path(kind)}
        except Exception:
            return {"status": False, "msg": traceback.format_exc()[-200:]}

    def frp_ensure_config(self, get=None):
        """确保 frps / frpc 配置文件存在，缺失则预创建。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            created, path, msg = frp.ensure_config(kind)
            if created:
                return public.returnMsg(True, "已预创建配置文件：%s" % path)
            return public.returnMsg(True, "配置文件已存在：%s" % path)
        except Exception:
            return public.returnMsg(False, "操作失败：" + traceback.format_exc()[-200:])

    def frp_save_config(self, get=None):
        """结构化保存配置（保留未知字段、写前备份、写后校验）。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            patch = {}
            try:
                raw = get.data or "{}"
                patch = json.loads(raw) if isinstance(raw, str) else dict(raw)
            except Exception:
                return public.returnMsg(False, "参数格式错误")
            ok, msg = frp.save_config(kind, patch)
            return public.returnMsg(ok, msg)
        except Exception:
            return public.returnMsg(False, "保存失败：" + traceback.format_exc()[-300:])

    def frp_save_raw(self, get=None):
        """按原文保存配置（编辑配置文件）。写前备份、写后校验。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            text = ""
            try:
                text = get.content or ""
            except Exception:
                pass
            if not text.strip():
                return public.returnMsg(False, "内容为空")
            path = frp._toml_path(kind)
            try:
                import toml
                toml.loads(text)  # 语法校验
            except Exception as e:
                return public.returnMsg(False, "TOML 语法错误：%s" % str(e)[:200])
            public.ExecShell("cp -a %s %s.bak.$(date +%%Y%%m%%d-%%H%%M%%S)" % (path, path))
            self._write(path, text)
            verr = frp.verify(kind)
            if verr:
                return public.returnMsg(False, "配置校验未通过（已保存，请检查）：%s" % verr)
            return public.returnMsg(True, "已保存")
        except Exception:
            return public.returnMsg(False, "保存失败：" + traceback.format_exc()[-200:])

    def frp_verify(self, get=None):
        try:
            frp = _app("frp")
            kind = self._kind(get)
            err = frp.verify(kind)
            if err:
                return public.returnMsg(False, "校验失败：" + err)
            return public.returnMsg(True, "配置校验通过")
        except Exception:
            return public.returnMsg(False, traceback.format_exc()[-200:])

    def frp_log(self, get=None):
        """读取 frps / frpc 运行日志。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            n = 300
            try:
                n = max(10, min(5000, int(get.lines or 300)))
            except Exception:
                pass
            return {"status": True, "log": frp.tail_log(kind, n)}
        except Exception:
            return {"status": True, "log": ""}

    def frp_release_ports(self, get=None):
        """一键放行 frps 关键端口（调用宝塔防火墙）。"""
        try:
            frp = _app("frp")
            kind = self._kind(get)
            ok, cfg = frp.load_config(kind)
            if not ok:
                return public.returnMsg(False, cfg)
            ports = []
            if kind == "frps":
                for key in ("bindPort", "vhostHTTPPort", "vhostHTTPSPort",
                            "kcpBindPort", "tcpmuxHTTPConnectPort"):
                    if isinstance(cfg.get(key), int):
                        ports.append(cfg[key])
                ws = cfg.get("webServer") or {}
                if isinstance(ws, dict) and ws.get("port"):
                    ports.append(int(ws["port"]))
            done = []
            for p in sorted(set(ports)):
                try:
                    public.add_firewall_rule(p, "tcp", "accept", "0.0.0.0/0", "frp管理器")
                    done.append(str(p))
                except Exception:
                    pass
            return public.returnMsg(True, "已放行端口：%s" % (", ".join(done) or "无"))
        except Exception:
            return public.returnMsg(False, "放行失败：" + traceback.format_exc()[-200:])

    def get_log(self, get=None):
        n = 200
        try:
            if hasattr(get, "lines") and get.lines:
                n = max(10, min(2000, int(get.lines)))
        except Exception:
            pass
        p = os.path.join(WAF_HOME, "data", "frpwaf.log")
        data = self._read(p)
        return {"status": True, "log": "\n".join(data.splitlines()[-n:])}

    def clear_log(self, get=None):
        try:
            self._write(os.path.join(WAF_HOME, "data", "frpwaf.log"), "")
            return public.returnMsg(True, "已清空")
        except Exception:
            return public.returnMsg(False, "清空失败")

    # ---------------- IP 归属地查询 ----------------
    def geo_query(self, get=None):
        """查询单个 IP 的归属地。"""
        ip = ""
        try:
            ip = (get.ip or "").strip()
        except Exception:
            pass
        if not ip:
            return public.returnMsg(False, "请输入 IP")
        try:
            geo = _app("geo")
            g = geo.lookup(ip)
            return {"status": True, "data": {
                "ip": ip, "geo": g.get("text", ""),
                "country": g.get("country", ""), "province": g.get("province", ""),
                "city": g.get("city", ""), "isp": g.get("isp", ""),
                "lat": g.get("lat"), "lon": g.get("lon"),
            }}
        except Exception:
            return public.returnMsg(False, "查询失败：" + traceback.format_exc()[-200:])

    def geo_top(self, get=None):
        """高频来源 IP（含归属地），按连接数排序。"""
        limit = 30
        try:
            if hasattr(get, "limit") and get.limit:
                limit = max(5, min(200, int(get.limit)))
        except Exception:
            pass
        try:
            store = _app("store")
            geo = _app("geo")
            rows = store._query(
                "SELECT ip, COUNT(*) AS n FROM conn_log GROUP BY ip ORDER BY n DESC LIMIT ?",
                (limit,),
            )
            out = []
            for r in rows:
                g = geo.lookup(r["ip"])
                out.append({"ip": r["ip"], "conns": r["n"], "geo": g.get("text", "")})
            return {"status": True, "data": out}
        except Exception:
            return {"status": True, "data": []}

    def geo_db_info(self, get=None):
        try:
            geo = _app("geo")
            info = geo.db_info()
            return {"status": True, "data": info}
        except Exception:
            return {"status": True, "data": {"available": False}}

    # ---------------- AI 自动审查 ----------------
    AI_KEYS = ["ai_enabled", "ai_protocol", "ai_base_url", "ai_api_key", "ai_model",
               "ai_interval", "ai_window", "ai_min_conns", "ai_max_ips",
               "ai_auto_ban", "ai_ban_seconds", "ai_timeout"]

    def ai_get_config(self, get=None):
        cfg = self._cfg()
        data = {}
        for k in self.AI_KEYS:
            v = cfg.get(k)
            if k == "ai_api_key" and v:
                v = "******"  # 不回显密钥
            data[k] = v
        data["ai_last_run"] = cfg.get("ai_last_run", 0)
        data["ai_last_result"] = cfg.get("ai_last_result", "")
        return {"status": True, "data": data}

    def ai_save_config(self, get=None):
        try:
            patch = {}
            for k in self.AI_KEYS:
                if not hasattr(get, k):
                    continue
                v = getattr(get, k)
                if k in ("ai_enabled", "ai_auto_ban"):
                    patch[k] = str(v).lower() in ("1", "true", "on", "yes")
                elif k in ("ai_interval", "ai_window", "ai_min_conns", "ai_max_ips",
                           "ai_ban_seconds", "ai_timeout"):
                    try:
                        patch[k] = int(v)
                    except (TypeError, ValueError):
                        pass
                elif k == "ai_api_key":
                    if v and v != "******":   # 未修改则不覆盖
                        patch[k] = str(v).strip()
                else:
                    patch[k] = str(v).strip()
            # 约束
            if patch.get("ai_interval", 300) < 60:
                patch["ai_interval"] = 60
            if patch.get("ai_window", 300) < 30:
                patch["ai_window"] = 30
            if patch.get("ai_protocol") not in ("openai", "anthropic"):
                patch["ai_protocol"] = "openai"
            self._set_cfg(patch)
            return public.returnMsg(True, "AI 配置已保存")
        except Exception:
            return public.returnMsg(False, "保存失败：" + traceback.format_exc()[-200:])

    def ai_test(self, get=None):
        """测试 AI 连接（可用表单值覆盖已保存配置）。"""
        try:
            ai = _app("ai")
            cfg = self._cfg()
            tmp = {k: cfg.get(k) for k in self.AI_KEYS}
            for k in ("ai_protocol", "ai_base_url", "ai_api_key", "ai_model"):
                v = getattr(get, k, None)
                if v and str(v).strip() and str(v) != "******":
                    tmp[k] = str(v).strip()
            if not tmp.get("ai_base_url") or not tmp.get("ai_api_key"):
                return public.returnMsg(False, "请先填写接口地址与密钥")
            ok, res = ai.call_model(tmp, [{"ip": "8.8.8.8", "geo": "美国", "conns": 1,
                                           "rejected": 0, "proxies": "test"}])
            if ok:
                return public.returnMsg(True, "连接成功，模型返回正常")
            return public.returnMsg(False, "连接失败：" + str(res)[:300])
        except Exception:
            return public.returnMsg(False, "测试失败：" + traceback.format_exc()[-200:])

    def ai_run_now(self, get=None):
        """立即执行一次审查。"""
        try:
            ai = _app("ai")
            res = ai.review(force=True)
            if res.get("ok"):
                return public.returnMsg(True, res.get("msg", "完成"))
            return public.returnMsg(False, res.get("msg", "失败"))
        except Exception:
            return public.returnMsg(False, "审查失败：" + traceback.format_exc()[-300:])

    def ai_results(self, get=None):
        try:
            store = _app("store")
            rows = store.list_ai_review(100)
            return {"status": True, "data": rows}
        except Exception:
            return {"status": True, "data": []}

    # ---------------- IP 封禁 / 解禁 ----------------
    def _store(self):
        return _app("store")

    def _geo_text(self, ip):
        try:
            return _app("geo").lookup(ip).get("text", "")
        except Exception:
            return ""

    def _fw_sync(self):
        """把黑名单/封禁同步到内核防火墙（失败静默）。"""
        try:
            if self._cfg().get("fw_sync_enabled", True):
                _app("firewall").sync_from_store()
        except Exception:
            pass

    def kernban_status(self, get=None):
        """内核级封禁（ipset+iptables）状态。"""
        try:
            fw = _app("firewall")
            st = fw.status()
            st["enabled"] = bool(self._cfg().get("fw_sync_enabled", True))
            return {"status": True, "data": st}
        except Exception:
            return {"status": True, "data": {"available": False, "enabled": False}}

    def kernban_sync(self, get=None):
        """手动触发一次内核封禁同步。"""
        try:
            ok = _app("firewall").sync_from_store()
            if ok:
                return public.returnMsg(True, "已同步到内核防火墙")
            return public.returnMsg(False, "当前环境不支持（需 root + ipset/iptables）或未启用")
        except Exception:
            return public.returnMsg(False, "同步失败：" + traceback.format_exc()[-200:])

    def list_bans(self, get=None):
        """返回：黑名单永久封禁 + 临时封禁（生效中）。"""
        try:
            store = self._store()
            ips = store.list_ips("black")
            for r in ips:
                r["geo"] = self._geo_text((r.get("cidr") or "").split("/")[0])
                r["mode"] = "permanent"
            bans = store.active_bans()
            for r in bans:
                r["geo"] = self._geo_text(r.get("ip", ""))
                r["mode"] = "temp"
            return {"status": True, "data": ips, "bans": bans}
        except Exception:
            return {"status": True, "data": [], "bans": []}

    def ban_ip(self, get=None):
        """封禁 IP：mode=perm 加入黑名单；mode=temp 临时封禁。"""
        try:
            ip = (get.ip or "").strip()
            mode = (get.mode or "perm").strip()
            remark = ""
            seconds = 3600
            try:
                remark = get.remark or ""
            except Exception:
                pass
            try:
                seconds = max(60, int(get.seconds or 3600))
            except Exception:
                pass
            if not ip:
                return public.returnMsg(False, "请输入 IP 或 CIDR")
            store = self._store()
            if mode == "temp":
                # 临时封禁使用 ban_log（支持自动到期）；单 IP 或 CIDR 均可
                store.add_ban(ip, remark or "manual(bt)", seconds)
                self._fw_sync()
                return public.returnMsg(True, "已临时封禁 %s（%d 秒）" % (ip, seconds))
            else:
                store.add_ip(ip, "black", remark or "manual(bt)")
                # 同步使决策缓存失效
                try:
                    _app("engine").invalidate_cache()
                except Exception:
                    pass
                self._fw_sync()
                return public.returnMsg(True, "已加入黑名单：%s" % ip)
        except ValueError as e:
            return public.returnMsg(False, str(e))
        except Exception:
            return public.returnMsg(False, "封禁失败：" + traceback.format_exc()[-200:])

    def unban_ip(self, get=None):
        """解禁：kind=perm 删除黑名单条目；kind=temp 释放临时封禁。"""
        try:
            kind = (get.kind or "perm").strip()
            store = self._store()
            if kind == "temp":
                ip = (get.ip or "").strip()
                if not ip:
                    return public.returnMsg(False, "参数错误")
                store.unban_ip(ip)
                try:
                    _app("firewall").remove(ip)
                except Exception:
                    pass
                self._fw_sync()
                return public.returnMsg(True, "已解除临时封禁：%s" % ip)
            else:
                entry_id = get.id
                if entry_id is None or entry_id == "":
                    return public.returnMsg(False, "参数错误")
                store.del_ip(int(entry_id))
                try:
                    _app("engine").invalidate_cache()
                except Exception:
                    pass
                self._fw_sync()
                return public.returnMsg(True, "已从黑名单移除")
        except Exception:
            return public.returnMsg(False, "解禁失败：" + traceback.format_exc()[-200:])

    # ---------------- 概览统计 ----------------
    def waf_overview(self, get=None):
        """概览：今日连接/拦截/独立IP/生效封禁/黑白名单数 + 运行信息。"""
        try:
            store = _app("store")
            cfg = self._cfg()
            st = store.stats()
            st.update({
                "http_addr": cfg.get("http_addr", "0.0.0.0"),
                "http_port": cfg.get("http_port", WAF_PORT),
                "blacklist_enabled": bool(cfg.get("blacklist_enabled", True)),
                "whitelist_enabled": bool(cfg.get("whitelist_enabled", False)),
                "auto_ban_enabled": bool(cfg.get("auto_ban_enabled", False)),
                "rate_limit_enabled": bool(cfg.get("rate_limit_enabled", False)),
                "ai_enabled": bool(cfg.get("ai_enabled", False)),
            })
            return {"status": True, "data": st}
        except Exception:
            return {"status": True, "data": {}}

    # ---------------- IP 名单（黑/白） ----------------
    def list_ips(self, get=None):
        """名单列表：type=black/white，留空=全部。附归属地。"""
        lt = None
        try:
            lt = (get.type or "").strip() or None
        except Exception:
            pass
        try:
            store = _app("store")
            rows = store.list_ips(lt)
            for r in rows:
                base = (r.get("cidr") or "").split("/")[0]
                r["geo"] = self._geo_text(base)
            return {"status": True, "data": rows}
        except Exception:
            return {"status": True, "data": []}

    def add_ip_entry(self, get=None):
        """添加名单条目：cidr + list_type(black/white) + remark。"""
        try:
            cidr = (get.cidr or "").strip()
            lt = (get.list_type or "black").strip()
            remark = ""
            try:
                remark = get.remark or ""
            except Exception:
                pass
            if not cidr:
                return public.returnMsg(False, "请输入 IP 或 CIDR")
            store = _app("store")
            store.add_ip(cidr, lt, remark)
            try:
                _app("engine").invalidate_cache()
            except Exception:
                pass
            self._fw_sync()
            return public.returnMsg(True, "已添加到%s" % ("黑名单" if lt == "black" else "白名单"))
        except ValueError as e:
            return public.returnMsg(False, str(e))
        except Exception:
            return public.returnMsg(False, "添加失败：" + traceback.format_exc()[-200:])

    def del_ip_entry(self, get=None):
        """删除名单条目（按 id）。"""
        try:
            entry_id = get.id
            if entry_id is None or entry_id == "":
                return public.returnMsg(False, "参数错误")
            _app("store").del_ip(int(entry_id))
            try:
                _app("engine").invalidate_cache()
            except Exception:
                pass
            self._fw_sync()
            return public.returnMsg(True, "已删除")
        except Exception:
            return public.returnMsg(False, "删除失败：" + traceback.format_exc()[-200:])

    def batch_import_ips(self, get=None):
        """批量导入：text 每行  cidr[,备注]；list_type=black/white。"""
        try:
            text = ""
            lt = "black"
            try:
                text = get.text or ""
            except Exception:
                pass
            try:
                lt = (get.list_type or "black").strip()
            except Exception:
                pass
            store = _app("store")
            ok = fail = 0
            for line in str(text).splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                cidr = parts[0].strip()
                remark = parts[1].strip() if len(parts) > 1 else ""
                try:
                    store.add_ip(cidr, lt, remark)
                    ok += 1
                except ValueError:
                    fail += 1
            try:
                _app("engine").invalidate_cache()
            except Exception:
                pass
            self._fw_sync()
            return public.returnMsg(True, "导入完成：成功 %d，跳过 %d" % (ok, fail))
        except Exception:
            return public.returnMsg(False, "导入失败：" + traceback.format_exc()[-200:])

    # ---------------- 连接日志 ----------------
    def conn_logs(self, get=None):
        """连接审计日志（支持 ip/action/proxy 过滤 + 分页）。"""
        try:
            limit = 50
            offset = 0
            ip = None
            action = None
            proxy = None
            try:
                limit = max(1, min(500, int(get.limit or 50)))
            except Exception:
                pass
            try:
                offset = max(0, int(get.offset or 0))
            except Exception:
                pass
            try:
                ip = (get.ip or "").strip() or None
            except Exception:
                pass
            try:
                # 代理名筛选：精确匹配（下拉框值来自 log_proxy_names）
                proxy = (getattr(get, "log_proxy", "") or "").strip() or None
            except Exception:
                pass
            try:
                # 注意：不能用 get.action —— 宝塔插件路由的 URL 固定带 action=a，
                # 会污染该字段，导致按动作过滤时永远查不到数据。故用 log_action。
                action = (getattr(get, "log_action", "") or "").strip() or None
                if action is None:
                    # 兼容旧前端：仅当 action 是合法日志动作时才采用
                    legacy = (getattr(get, "action", "") or "").strip()
                    if legacy in ("allow", "reject", "rate_limit", "error", "auto_ban", "banned"):
                        action = legacy
            except Exception:
                pass
            store = _app("store")
            rows = store.list_logs(limit, offset, ip, action, proxy)
            try:
                total = store.count_logs(ip, action, proxy)
            except Exception:
                total = len(rows)
            # 归属地查询失败不应导致整表为空：逐条兜底
            try:
                _app("geo").enrich(rows)
            except Exception:
                for r in rows:
                    r.setdefault("geo", "")
            return {"status": True, "data": rows, "total": total,
                    "limit": limit, "offset": offset}
        except Exception:
            return {"status": True, "data": [], "total": 0,
                    "error": traceback.format_exc()[-200:]}

    def log_proxy_list(self, get=None):
        """连接日志中出现过的代理名（供筛选下拉框）。"""
        try:
            return {"status": True, "data": _app("store").log_proxy_names()}
        except Exception:
            return {"status": True, "data": []}

    def purge_conn_logs(self, get=None):
        try:
            _app("store").purge_logs()
            return public.returnMsg(True, "连接日志已清空")
        except Exception:
            return public.returnMsg(False, "清空失败：" + traceback.format_exc()[-200:])

    # ---------------- 封禁历史 ----------------
    def ban_history(self, get=None):
        try:
            store = _app("store")
            geo = _app("geo")
            his = store.ban_history(100)
            geo.enrich(his)
            return {"status": True, "data": his}
        except Exception:
            return {"status": True, "data": []}

    # ---------------- 代理统计 ----------------
    def proxy_stats(self, get=None):
        try:
            return {"status": True, "data": _app("store").list_proxy_stat()}
        except Exception:
            return {"status": True, "data": []}

    # ---------------- 准入策略 ----------------
    POLICY_BOOL = ["blacklist_enabled", "whitelist_enabled", "auto_ban_enabled",
                   "rate_limit_enabled", "fw_sync_enabled", "ai_enabled"]
    POLICY_INT = ["auto_ban_window", "auto_ban_threshold", "auto_ban_seconds",
                  "rate_limit_per_sec", "log_max_rows"]

    def get_policy(self, get=None):
        cfg = self._cfg()
        data = {}
        for k in self.POLICY_BOOL:
            data[k] = bool(cfg.get(k, False))
        for k in self.POLICY_INT:
            data[k] = cfg.get(k, 0)
        return {"status": True, "data": data}

    def save_policy(self, get=None):
        try:
            patch = {}
            for k in self.POLICY_BOOL:
                if hasattr(get, k):
                    patch[k] = str(getattr(get, k)).lower() in ("1", "true", "on", "yes")
            for k in self.POLICY_INT:
                if hasattr(get, k):
                    try:
                        patch[k] = max(0, int(getattr(get, k)))
                    except (TypeError, ValueError):
                        pass
            if "auto_ban_window" in patch and patch["auto_ban_window"] < 1:
                patch["auto_ban_window"] = 1
            self._set_cfg(patch)
            try:
                _app("engine").invalidate_cache()
            except Exception:
                pass
            self._fw_sync()
            return public.returnMsg(True, "策略已保存")
        except Exception:
            return public.returnMsg(False, "保存失败：" + traceback.format_exc()[-200:])

    # ---------------- 管理员账号 ----------------
    def get_admin(self, get=None):
        """读取当前管理面板账号（用户名 + 密码），供设置页回显。"""
        cfg = self._cfg()
        return {"status": True, "data": {
            "user": cfg.get("admin_user", "admin"),
            "password": cfg.get("admin_password", ""),
        }}

    def change_admin_pwd(self, get=None):
        """修改 WAF 管理面板账号：用户名与/或密码。

        参数：old（原密码，必填校验）、new（新密码，可空=不改）、
              new_user（新用户名，可空=不改）、old_user（原用户名，可选二次校验）。
        """
        try:
            old = new = new_user = old_user = ""
            try:
                old = get.old or ""
            except Exception:
                pass
            try:
                new = get.new or ""
            except Exception:
                pass
            try:
                new_user = (get.new_user or "").strip()
            except Exception:
                pass
            try:
                old_user = (get.old_user or "").strip()
            except Exception:
                pass

            cfg = self._cfg()
            if not hmac.compare_digest(str(old), str(cfg.get("admin_password", ""))):
                return public.returnMsg(False, "原密码错误")
            # 若前端填写了原用户名，则一并校验（可选，增强安全性）
            if old_user and not hmac.compare_digest(old_user, str(cfg.get("admin_user", ""))):
                return public.returnMsg(False, "原用户名错误")
            patch = {}
            if new_user:
                if len(new_user) < 2:
                    return public.returnMsg(False, "用户名至少 2 位")
                if not re.match(r"^[A-Za-z0-9_.@-]+$", new_user):
                    return public.returnMsg(False, "用户名只能包含字母、数字、_ . @ -")
                patch["admin_user"] = new_user
            if new:
                if len(str(new)) < 4:
                    return public.returnMsg(False, "新密码至少 4 位")
                patch["admin_password"] = str(new)
            if not patch:
                return public.returnMsg(False, "未修改任何内容")
            self._set_cfg(patch)
            return public.returnMsg(True, "账号已更新")
        except Exception:
            return public.returnMsg(False, "修改失败：" + traceback.format_exc()[-200:])
