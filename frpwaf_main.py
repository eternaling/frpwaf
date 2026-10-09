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
import secrets
import shutil
import sys
import threading
import subprocess
import time
import traceback

BASE_PATH = "/www/server/panel"
os.chdir(BASE_PATH)

# 插件自身所在目录：不写死 /www/server/panel/plugin/frpwaf，而是由本文件位置推导，
# 这样无论宝塔把插件装到哪个目录（改名 / 迁移 / 其它面板版本）都能正确定位 app/。
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PLUGIN_DIR)
sys.path.insert(0, "class/")
import public

WAF_HOME = "/opt/frpwaf"
WAF_PORT = 7080

WAF_INIT = "/etc/init.d/frpwaf"
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
    插件目录由本文件位置推导，宝塔把插件装到其它路径也能找到。
    """
    cands = [
        os.path.join(WAF_HOME, "app"),
        os.path.join(PLUGIN_DIR, "app"),
        os.path.join(os.path.dirname(PLUGIN_DIR), "frpwaf", "app"),
    ]
    for d in cands:
        if os.path.isfile(os.path.join(d, "__init__.py")):
            return d
    # 都找不到：明确报错（而不是抛出难懂的 FileNotFoundError），
    # 通常说明上传的插件包结构不对（缺少 app/ 目录）或未完成安装。
    raise FileNotFoundError(
        "未找到 FRP WAF 运行代码包 app/（已尝试：%s）。"
        "请确认上传的插件包根目录下包含 app/ 目录，或在宝塔插件页重新执行安装。"
        % "，".join(cands))


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
        try:
            port = int(self._cfg().get("http_port", WAF_PORT) or WAF_PORT)
        except Exception:
            port = WAF_PORT
        return "http://%s:%d/" % (self._server_ip(), port)

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

    def _cfg_effective(self):
        """读取「实际生效」配置：DEFAULTS 打底 + 旧版哨兵迁移 + 参数防呆。

        仅用于展示/回显（设置页、概览）：旧配置缺新键时展示的默认值与
        运行时（config.load()）完全一致，避免设置页把 0/False 显示出来，
        用户一保存就把坏值写回配置（历史 bug 的根因）。
        """
        try:
            cfg = dict(_app("config").DEFAULTS)
        except Exception:
            cfg = {}
        cfg.update(self._cfg())
        try:
            _app("config").migrate_legacy_attack(cfg)
        except Exception:
            pass
        try:
            _app("config").normalize_auto_ban(cfg)
        except Exception:
            pass
        try:
            _app("config").normalize_burst_cool(cfg)
        except Exception:
            pass
        return cfg

    def _set_cfg(self, patch):
        """合并写入配置（patch 语义）。

        注意：读取失败（文件损坏 / 被并发写坏）时**拒绝保存**，绝不覆盖，
        避免把 secret / admin_password / ai_api_key 一并抹除。

        并发保护：优先走 app.config.save(patch)——它在「进程内线程锁 + 跨进程
        文件锁」内读磁盘现状并合并本次修改，与 WAF 守护进程（面板保存 / AI 审查）
        并发写不同字段时互不覆盖。仅当环境变量异常导致两边配置路径不一致时，
        才回退为本地读改写（保持旧行为）。

        防呆顺序很重要：先在**磁盘现状**上做一次性哨兵迁移（见
        config.migrate_legacy_attack），再合并本次 patch——否则用户本次
        显式关闭的开关会被迁移逻辑重新打开。
        """
        p = os.path.join(WAF_HOME, "data", "frpwaf.json")
        cfg_mod = None
        try:
            cfg_mod = _app("config")
        except Exception:
            cfg_mod = None
        same_path = (cfg_mod is not None
                     and os.path.abspath(cfg_mod.CONF_PATH) == os.path.abspath(p))
        if same_path:
            try:
                raw = cfg_mod._read_disk()
            except Exception:
                raise ValueError("配置文件损坏或不可读，已阻止保存以防数据丢失：%s" % p)
            if not raw.get("secret"):
                # 文件缺失 / 缺密钥：按默认值补齐（会生成新 secret 并落盘）
                try:
                    cfg_mod.load()
                except Exception:
                    raise ValueError("无法获取 secret，已阻止保存")
            cfg_mod.save(patch)   # 锁内：读磁盘现状 -> 迁移 -> 合并 patch -> 原子替换
            return True
        # ---- 回退路径：配置路径不一致（异常环境），保持本地读改写 ----
        try:
            cfg = self._cfg_raw()
        except Exception:
            raise ValueError("配置文件损坏或不可读，已阻止保存以防数据丢失：%s" % p)
        if not cfg.get("secret"):
            try:
                cfg = dict(_app("config").load())
            except Exception:
                pass
        else:
            try:
                _app("config").migrate_legacy_attack(cfg)
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
            "web_enabled": bool(cfg.get("web_enabled", True)),
            "frps_toml": FRPS_TOML,
            "plugin_configured": "frpwaf" in self._read(FRPS_TOML),
            "admin_user": cfg.get("admin_user", "admin"),
            # 密码不回显明文：仅返回掩码，展示端据此提示「已设置」；
            # 修改密码走 change_admin_pwd（需校验原密码）。
            "admin_password": "******" if cfg.get("admin_password") else "",
        }

    def install_waf(self, get=None):
        try:
            self._audit("插件端安装/更新 WAF 网页端")
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
            # 4) 重启以加载新代码：用 restart 而非 start——服务已在运行时 start 会
            #    直接返回「already running」而不重启，导致「更新」不生效。
            public.ExecShell("%s restart" % WAF_INIT)
            # 5. 同步内核封禁
            self._fw_sync()
            return public.returnMsg(True, "WAF 网页端安装成功（仅安装网页端，非安装 frp）！管理面板：%s（默认账号 admin / 123456，请及时修改）" % self._panel_url())
        except Exception:
            return public.returnMsg(False, "安装失败：" + traceback.format_exc())

    def reinstall_waf(self, get=None):
        """重装：卸载后重新安装。注意 uninstall 会移除 frps.toml 中的插件块，
        故重装后需重新注入，否则 frps 集成会丢失（回调不再生效）。"""
        removed = self.uninstall_waf()
        if not removed.get("status"):
            return removed
        res = self.install_waf()
        try:
            if os.path.exists(FRPS_TOML):
                self.apply_to_frps()
        except Exception:
            pass
        return res

    def uninstall_waf(self, get=None):
        try:
            self._audit("插件端卸载 FRP WAF")
            # frps 持有回调时必须先摘除并成功重启，才能停止 WAF。
            frp = _app("frp")
            frps_running = False
            backup = self._remove_frps_plugin()
            if backup:
                try:
                    if not os.access(frp._bin("frps"), os.X_OK):
                        raise RuntimeError("frps 二进制不可用")
                    err = frp.verify("frps")
                    if err:
                        raise RuntimeError("frps 配置校验失败：" + err)
                    if os.path.exists(frp._init_path("frps")):
                        status = public.ExecShell("/etc/init.d/frps status")[0] or ""
                        if "is running" in status:
                            frps_running = True
                            ok, msg = frp.control("frps", "restart")
                            if not ok or not frp.is_running("frps"):
                                raise RuntimeError("frps 重启失败：" + msg)
                        elif "is stopped" not in status:
                            raise RuntimeError("无法确认 frps 状态")
                    else:
                        raise RuntimeError("frps 服务脚本不可用")
                except Exception:
                    shutil.copy2(backup, FRPS_TOML)
                    if frps_running:
                        frp.control("frps", "restart")
                    raise
            public.ExecShell("%s stop" % WAF_INIT)
            if self._waf_running():
                if backup:
                    shutil.copy2(backup, FRPS_TOML)
                    if frps_running:
                        frp.control("frps", "restart")
                raise RuntimeError("WAF 停止失败")
            # 移除内核级封禁规则（ipset + iptables）
            try:
                _app("firewall").teardown()
            except Exception:
                pass
            if "CentOS" in public.get_os_version() or "Red" in public.get_os_version():
                public.ExecShell("chkconfig --del frpwaf")
            else:
                public.ExecShell("update-rc.d -f frpwaf remove")
            public.ExecShell("rm -f %s /usr/bin/frpwaf" % WAF_INIT)
            # 清理突发观测运行时快照（daemon 内存状态，重启/重装后自动重建；
            # 避免卸载后残留过期数据被插件端误读）
            try:
                os.remove(os.path.join(WAF_HOME, "data", "burst_snapshot.json"))
            except OSError:
                pass
            return public.returnMsg(True, "已卸载（数据保留在 %s/data）" % WAF_HOME)
        except Exception:
            return public.returnMsg(False, "卸载失败：" + traceback.format_exc())

    # ---------------- 服务控制 ----------------
    def _audit(self, msg):
        """操作审计：向 data/frpwaf.log 追加 [审计] 行（与 daemon 同一文件，供「运行日志」页查看）。"""
        try:
            p = os.path.join(WAF_HOME, "data", "frpwaf.log")
            with open(p, "a", encoding="utf-8") as f:
                f.write("[%s] [审计] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
        except Exception:
            pass

    def waf_admin(self, get):
        if not hasattr(get, "status") or not get.status:
            return public.returnMsg(False, "参数错误")
        act = get.status
        if act not in ("start", "stop", "restart"):
            return public.returnMsg(False, "参数错误")
        self._audit("插件端服务控制：%s" % act)
        res = public.ExecShell("%s %s" % (WAF_INIT, act))
        if res[1]:
            return public.returnMsg(False, res[1])
        if "failed" in (res[0] or ""):
            return public.returnMsg(False, "操作失败，请检查日志")
        return public.returnMsg(True, "操作成功")

    # ---------------- 网页端（WAF 管理面板）开关 / 换端口 ----------------
    def web_toggle(self, get=None):
        """开启 / 关闭网页端（WAF 管理面板）。

        仅控制网页访问（/ 与 /api/*）。frps 回调（/frp/handler）与 WAF 防护
        始终运行，关闭后仍可从宝塔插件端随时重新开启。
        """
        try:
            try:
                raw = get.enabled
            except Exception:
                raw = None
            if raw is None:
                return public.returnMsg(False, "参数错误")
            enabled = str(raw).lower() in ("1", "true", "on", "yes")
            self._set_cfg({"web_enabled": enabled})
            return public.returnMsg(
                True,
                "网页端已开启" if enabled
                else "网页端已关闭（WAF 防护与 frps 回调不受影响，可随时重新开启）")
        except Exception:
            return public.returnMsg(False, "操作失败：" + traceback.format_exc()[-200:])

    def _port_listening(self, port, host="127.0.0.1"):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            return s.connect_ex((host, int(port))) == 0
        except Exception:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _port_free(self, port):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", int(port)))
            return True
        except OSError:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _set_frps_plugin_port(self, port):
        """把 frps.toml 中 name="frpwaf" 的 [[httpPlugins]] 块 addr 改为 127.0.0.1:port。"""
        content = self._read(FRPS_TOML)
        if "frpwaf" not in content:
            return False
        segments, cur, cur_is_header = [], [], None
        for ln in content.splitlines():
            s = ln.strip()
            if s.startswith("["):
                segments.append((cur_is_header, cur))
                cur, cur_is_header = [ln], s
            else:
                cur.append(ln)
        segments.append((cur_is_header, cur))
        changed = False
        for i, (header, body) in enumerate(segments):
            if header and header.startswith("[[httpPlugins]]") and any("frpwaf" in l for l in body):
                nb = []
                for l in body:
                    if re.match(r"\s*addr\s*=", l):
                        nb.append('addr = "127.0.0.1:%d"' % int(port))
                        changed = True
                    else:
                        nb.append(l)
                segments[i] = (header, nb)
        if changed:
            out = []
            for _, body in segments:
                out.extend(body)
            self._write(FRPS_TOML, "\n".join(out).strip() + "\n")
        return changed

    def set_web_port(self, get=None):
        """修改网页端监听端口：同步更新配置与 frps.toml 回调地址并重启 WAF / frps。"""
        try:
            import time
            try:
                raw = get.port
            except Exception:
                raw = None
            if raw is None or str(raw).strip() == "":
                return public.returnMsg(False, "参数错误：缺少端口")
            try:
                port = int(str(raw).strip())
            except (TypeError, ValueError):
                return public.returnMsg(False, "端口必须是数字")
            if port < 1 or port > 65535:
                return public.returnMsg(False, "端口范围 1-65535")

            cfg = self._cfg()
            old = int(cfg.get("http_port", WAF_PORT) or WAF_PORT)
            if port == old:
                return public.returnMsg(True, "端口未变化（仍为 %d）" % old)

            if not self._port_free(port):
                return public.returnMsg(False, "端口 %d 已被占用，请更换" % port)

            had_plugin = "frpwaf" in self._read(FRPS_TOML)

            # 1) 写配置（守护进程重启后绑定新端口）
            self._set_cfg({"http_port": port})
            # 2) 同步 frps.toml 回调地址
            if had_plugin:
                try:
                    public.ExecShell("cp -a %s %s.bak.$(date +%%Y%%m%%d-%%H%%M%%S)"
                                     % (FRPS_TOML, FRPS_TOML))
                except Exception:
                    pass
                self._set_frps_plugin_port(port)
            # 3) 重启 WAF 以绑定新端口
            public.ExecShell("%s restart" % WAF_INIT)
            host = (cfg.get("http_addr") or "127.0.0.1")
            if host in ("0.0.0.0", "::", ""):
                host = "127.0.0.1"
            ok = False
            for _ in range(12):
                time.sleep(0.5)
                if self._port_listening(port, host):
                    ok = True
                    break
            if not ok:
                # 回滚到原端口，尽量恢复服务
                self._set_cfg({"http_port": old})
                if had_plugin:
                    self._set_frps_plugin_port(old)
                public.ExecShell("%s restart" % WAF_INIT)
                if had_plugin:
                    public.ExecShell("/etc/init.d/frps restart")
                return public.returnMsg(False, "端口 %d 未能监听，已回滚为 %d（请检查端口占用 / 日志）" % (port, old))
            # 4) 重启 frps 以重新加载回调地址
            if had_plugin:
                fr = public.ExecShell("/etc/init.d/frps status")
                if "is running" in (fr[0] or ""):
                    public.ExecShell("/etc/init.d/frps restart")
            return public.returnMsg(True, "网页端端口已改为 %d，管理面板：%s" % (port, self._panel_url()))
        except Exception:
            return public.returnMsg(False, "修改失败：" + traceback.format_exc()[-200:])

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
            self._audit("插件端注入 frps 回调（httpPlugins）")
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
        if not os.path.exists(FRPS_TOML):
            return None
        with open(FRPS_TOML, "r", encoding="utf-8") as f:
            content = f.read()
        if "frpwaf" not in content:
            return None
        backup = "%s.bak.%s.%d" % (
            FRPS_TOML, time.strftime("%Y%m%d-%H%M%S"), os.getpid())
        shutil.copy2(FRPS_TOML, backup)
        _app("frp_uninstall").remove_plugin_block(FRPS_TOML)
        return backup

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
            terr = frp.check_toml(text)   # 语法校验（纯标准库，不依赖第三方 toml）
            if terr:
                return public.returnMsg(False, "TOML 语法错误：%s" % terr)
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

    # ---------------- 系统防火墙放行 ----------------
    @staticmethod
    def _port_num(v):
        """配置值规范为合法端口号（1–65535）；非法值（含布尔）返回 0。"""
        if isinstance(v, bool):
            return 0
        try:
            n = int(v)
        except (TypeError, ValueError):
            return 0
        return n if 0 < n < 65536 else 0

    def _firewall_backend(self):
        """探测系统防火墙后端：firewalld / ufw / 未检测到。

        宝塔面板自身按系统选择防火墙：CentOS 7+ 为 firewalld（面板可读到
        命令行添加的规则），Debian/Ubuntu 为 ufw（规则同步至系统）。
        返回 (后端名, 未检测到时的原因)。
        """
        out, _ = public.ExecShell("command -v firewall-cmd 2>/dev/null")
        if (out or "").strip():
            st, _ = public.ExecShell("firewall-cmd --state 2>&1")
            if (st or "").strip().lower() == "running":
                return "firewalld", ""
        out, _ = public.ExecShell("command -v ufw 2>/dev/null")
        if (out or "").strip():
            st, _ = public.ExecShell("ufw status 2>&1")
            first = ((st or "").strip().splitlines() or [""])[0].strip().lower()
            if first.startswith("status: active"):
                return "ufw", ""
        return "", ("未检测到运行中的系统防火墙（firewalld/ufw）。"
                    "若防火墙本就未启用则无需放行；启用后请重试。")

    def _fw_add_port(self, backend, port, proto):
        """放行单个端口（backend 为 firewalld / ufw），已放行视为成功。

        返回 (是否成功, 失败说明)；成功后说明为空字符串。
        """
        spec = "%d/%s" % (port, proto)
        if backend == "firewalld":
            out, err = public.ExecShell(
                "firewall-cmd --zone=public --add-port=%s --permanent" % spec)
            msg = ((out or "") + " " + (err or "")).strip()
            low = msg.lower()
            if "success" in low or "already_enabled" in low:
                return True, ""
            return False, msg[-160:] or "未知错误"
        out, err = public.ExecShell("ufw allow %s" % spec)
        msg = ((out or "") + " " + (err or "")).strip()
        low = msg.lower()
        if "rule added" in low or "skipping" in low or "rules updated" in low:
            return True, ""
        return False, msg[-160:] or "未知错误"

    def frp_release_ports(self, get=None):
        """一键放行 frps 关键端口（firewalld / ufw）。

        端口协议按 frp 语义区分：kcp/quic 为 UDP，其余为 TCP。
        """
        try:
            frp = _app("frp")
            kind = self._kind(get)
            if kind != "frps":
                return public.returnMsg(
                    True, "frpc 为客户端，无需放行入站端口；"
                          "请在 frps 服务器放行对应 remotePort。")
            ok, cfg = frp.load_config(kind)
            if not ok:
                return public.returnMsg(False, cfg)

            # 汇总待放行端口（按 端口/协议 去重；kcp/quic 走 UDP）
            wanted = set()
            for key in ("bindPort", "vhostHTTPPort", "vhostHTTPSPort",
                        "tcpmuxHTTPConnectPort"):
                p = self._port_num(cfg.get(key))
                if p:
                    wanted.add((p, "tcp"))
            for key in ("kcpBindPort", "quicBindPort"):
                p = self._port_num(cfg.get(key))
                if p:
                    wanted.add((p, "udp"))
            ws = cfg.get("webServer") or {}
            if isinstance(ws, dict):
                p = self._port_num(ws.get("port"))
                if p:
                    wanted.add((p, "tcp"))
            if not wanted:
                return public.returnMsg(False, "未从配置中读到可放行的端口，请先保存 frps 配置。")

            backend, why = self._firewall_backend()
            if not backend:
                return public.returnMsg(False, why)

            done, failed = [], []
            for port, proto in sorted(wanted):
                good, detail = self._fw_add_port(backend, port, proto)
                if good:
                    done.append("%d/%s" % (port, proto))
                else:
                    failed.append("%d/%s（%s）" % (port, proto, detail))

            warn = ""
            if backend == "firewalld" and done:
                out, err = public.ExecShell("firewall-cmd --reload 2>&1")
                rmsg = ((out or "") + " " + (err or "")).strip()
                if rmsg and "success" not in rmsg.lower():
                    warn = ("；注意：reload 失败，请手动执行 firewall-cmd --reload"
                            "（%s）" % rmsg[-120:])

            if not failed:
                return public.returnMsg(
                    True, "已放行端口（%s）：%s%s" % (backend, ", ".join(done), warn))
            if done:
                return public.returnMsg(
                    False, "部分放行（%s）：成功 %s；失败 %s%s"
                    % (backend, ", ".join(done), "，".join(failed), warn))
            return public.returnMsg(
                False, "放行失败（%s）：%s%s" % (backend, "，".join(failed), warn))
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
               "ai_auto_ban", "ai_cdn_guard", "ai_ban_seconds", "ai_suspicious_ban",
               "ai_ssh_strict", "ai_ssh_permanent_suspicious", "ai_timeout"]

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
        # 异步审查状态：供面板按钮在页面刷新后仍能正确显示「审查中…」并恢复轮询
        data["ai_last_ok"] = cfg.get("ai_last_ok", True)
        data["ai_review_state"] = cfg.get("ai_review_state", "")
        data["ai_run_requested"] = cfg.get("ai_run_requested", 0)
        data["ai_run_consumed"] = cfg.get("ai_run_consumed", 0)
        return {"status": True, "data": data}

    def ai_save_config(self, get=None):
        try:
            patch = {}
            for k in self.AI_KEYS:
                if not hasattr(get, k):
                    continue
                v = getattr(get, k)
                if k in ("ai_enabled", "ai_auto_ban", "ai_cdn_guard", "ai_suspicious_ban",
                         "ai_ssh_strict", "ai_ssh_permanent_suspicious"):
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
        """立即执行一次审查（异步触发，立即返回）。

        面板进程**不**直接执行审查：大批量送审可能耗时数分钟，会把插件请求
        拖到超时（历史故障：按钮一直停在「审查中…」）。这里只写
        `ai_run_requested` 时间戳，由 daemon 的 AI 循环消费执行；
        前端拿 ai_status 轮询进度。
        """
        try:
            cfg = self._cfg()
            if not cfg.get("ai_base_url") or not cfg.get("ai_api_key"):
                return public.returnMsg(False, "未配置 AI 接口地址或密钥")
            # 严格递增：同一秒内重复点击也必须产生新请求（消费游标按 > 比较）
            now = int(time.time())
            req = max(int(cfg.get("ai_run_requested") or 0) + 1, now)
            self._set_cfg({"ai_run_requested": req})
            return public.returnMsg(True, "已提交，正在后台审查（完成后自动显示结果）")
        except Exception:
            return public.returnMsg(False, "提交失败：" + traceback.format_exc()[-300:])

    def ai_status(self, get=None):
        """查询异步审查状态（前端轮询用）。

        running：daemon 正在执行本轮审查（ai_review_state=running 且心跳新鲜）；
        pending：请求已提交但 daemon 尚未开始（AI 循环快速轮询，正常几秒内开始）；
        请求超过 120 秒仍未被消费 → stale（WAF 服务未运行/已停止），
        前端据此恢复按钮并给出提示，不会无限转圈。
        """
        try:
            cfg = self._cfg()
            now = time.time()
            state = str(cfg.get("ai_review_state") or "")
            started = int(cfg.get("ai_review_started") or 0)
            last = int(cfg.get("ai_last_run") or 0)
            req = int(cfg.get("ai_run_requested") or 0)
            consumed = int(cfg.get("ai_run_consumed") or 0)
            running = (state == "running" and 0 <= now - started < 900)
            pending = (req > consumed and 0 <= now - req < 120)
            stale = (req > consumed and now - req >= 120)
            msg = str(cfg.get("ai_last_result") or "")
            if stale:
                msg = "审查请求长时间未被处理（WAF 服务可能未运行），请检查服务状态"
            return {"status": True, "data": {
                "running": bool(running or pending),
                "pending": bool(pending),
                "stale": bool(stale),
                "last_run": last,
                "last_ok": bool(cfg.get("ai_last_ok", True)),
                "last_result": msg,
                "requested": req,
            }}
        except Exception:
            return {"status": True, "data": {"running": False, "last_run": 0,
                                             "last_ok": True, "last_result": ""}}

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
        """把黑名单/封禁同步到内核（失败静默）。

        sync_from_store() 内部按 fw_sync_enabled / block_page_enabled 决定
        DROP（静默丢包）、REDIRECT（展示拦截页）或清理，故统一调用它。
        """
        try:
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
        """手动触发一次内核同步（按开关决定 DROP / REDIRECT / 清理）。"""
        try:
            self._audit("插件端手动同步内核封禁")
            fw = _app("firewall")
            ok = fw.sync_from_store()
            st = fw.status()
            if ok:
                return public.returnMsg(True, "已同步到内核防火墙")
            if st.get("mode") == "off":
                return public.returnMsg(True, "内核封禁与拦截页均已关闭，已清理内核规则")
            return public.returnMsg(False, "当前环境不支持（需 root + ipset/iptables）")
        except Exception:
            return public.returnMsg(False, "同步失败：" + traceback.format_exc()[-200:])

    def list_bans(self, get=None):
        """返回：黑名单永久封禁 + 临时封禁（生效中）。"""
        try:
            store = self._store()
            # 面板展示接口：限制返回条数（store.PANEL_LIST_CAP，防大名单全量拉取）
            ips = store.list_ips("black", limit=store.PANEL_LIST_CAP)
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

    def unban_all_black(self, get=None):
        """一键解封：清空黑名单全部条目（永久封禁），并同步内核。

        误封恢复手段（如 AI 误封 CDN 边缘 IP 导致 522）。仅清空黑名单，
        不影响白名单；临时封禁请在「临时封禁」卡片单独使用「解封全部」。
        """
        try:
            store = self._store()
            n = store.clear_blacklist()
            try:
                _app("engine").invalidate_cache()
            except Exception:
                pass
            self._fw_sync()
            return public.returnMsg(True, "已解封全部黑名单（%d 条）" % n)
        except Exception:
            return public.returnMsg(False, "解封失败：" + traceback.format_exc()[-200:])

    def unban_all_temp(self, get=None):
        """一键解封：释放全部生效中的临时封禁，并同步内核。

        与「解封全部黑名单」独立操作；误封恢复时可按需分别执行。
        """
        try:
            store = self._store()
            n = store.release_all_bans()
            self._fw_sync()
            return public.returnMsg(True, "已解封全部临时封禁（%d 条）" % n)
        except Exception:
            return public.returnMsg(False, "解封失败：" + traceback.format_exc()[-200:])

    # ---------------- 概览统计 ----------------
    def waf_overview(self, get=None):
        """概览：今日连接/拦截/独立IP/生效封禁/黑白名单数 + 运行信息。"""
        try:
            store = _app("store")
            # 实际生效值（DEFAULTS 打底 + 防呆）：升级场景下旧配置缺新键时，
            # 概览展示的开关状态与实际生效值一致（否则会误显示为关闭）。
            cfg = self._cfg_effective()
            st = store.stats()
            st.update({
                "http_addr": cfg.get("http_addr", "0.0.0.0"),
                "http_port": cfg.get("http_port", WAF_PORT),
                "blacklist_enabled": bool(cfg.get("blacklist_enabled", True)),
                "whitelist_enabled": bool(cfg.get("whitelist_enabled", False)),
                "auto_ban_enabled": bool(cfg.get("auto_ban_enabled", False)),
                "auto_ban_cc_enabled": bool(cfg.get("auto_ban_cc_enabled", False)),
                "auto_ban_scan_enabled": bool(cfg.get("auto_ban_scan_enabled", False)),
                "auto_ban_ssh_enabled": bool(cfg.get("auto_ban_ssh_enabled", False)),
                "rate_limit_enabled": bool(cfg.get("rate_limit_enabled", False)),
                "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
                "ai_enabled": bool(cfg.get("ai_enabled", False)),
            })
            return {"status": True, "data": st}
        except Exception:
            return {"status": True, "data": {}}

    # ---------------- IP 名单（黑/白） ----------------
    def list_ips(self, get=None):
        """名单列表：type=black/white，留空=全部。附归属地。

        面板展示接口，返回条数上限 store.PANEL_LIST_CAP（5000）：防大名单
        场景全量返回 + 逐条归属地查询拖垮面板；内部逻辑（AI/内核同步）
        直接查库，不受该上限影响。
        """
        lt = None
        try:
            lt = (get.type or "").strip() or None
        except Exception:
            pass
        try:
            store = _app("store")
            rows = store.list_ips(lt, limit=store.PANEL_LIST_CAP)
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

    def logs_summary(self, get=None):
        """按代理聚合最近窗口的连接日志（面板「聚合」视图）。

        window：秒（默认 3600，钳制 60 ~ 86400）。
        """
        try:
            window = 3600
            try:
                if hasattr(get, "window") and get.window:
                    window = max(60, min(86400, int(get.window)))
            except Exception:
                pass
            res = _app("store").summary_by_proxy(window)
            return {"status": True, "data": res["rows"], "window": window,
                    "total_proxies": res["total_proxies"]}
        except Exception:
            return {"status": True, "data": [], "window": 3600}

    def burst_status(self, get=None):
        """代理级突发观测快照 + 冷却状态（供面板展示）。

        观测与冷却状态在 WAF 守护进程内存中，插件端是另一个进程，无法直接
        访问 engine 内存；读取 daemon 后台周期落盘的 data/burst_snapshot.json。
        文件缺失（守护进程未运行/尚未写入）时返回空数据并带 stale 标记。
        """
        try:
            cfg = self._cfg_effective()
            conf = {
                "burst_window": int(cfg.get("burst_window") or 60),
                "proxy_cool_enabled": bool(cfg.get("proxy_cool_enabled", False)),
                "proxy_cool_min_conns": int(cfg.get("proxy_cool_min_conns") or 300),
                "proxy_cool_uniq_threshold": int(cfg.get("proxy_cool_uniq_threshold") or 200),
                "proxy_cool_single_pct": int(cfg.get("proxy_cool_single_pct") or 80),
                "proxy_cool_seconds": int(cfg.get("proxy_cool_seconds") or 60),
            }
            try:
                with open(os.path.join(WAF_HOME, "data", "burst_snapshot.json"),
                          "r", encoding="utf-8") as f:
                    snap = json.load(f)
            except Exception:
                snap = {}
            data = snap.get("data") or []
            ts = int(snap.get("ts") or 0)
            if snap.get("config"):
                # 以快照内配置为准（daemon 运行时生效值），避免两进程缓存不一致
                conf.update(snap["config"])
            # 过期判定：>30s 未更新视为陈旧；额外检查守护进程状态——
            # 进程未运行（或刚启动尚未写快照）时即使 ts 较新也应提示（如卸载后残留）。
            running = self._waf_running()
            stale = (not running) or (not ts) or (time.time() - ts) > 30
            return {"status": True, "data": data, "config": conf,
                    "ts": ts, "stale": stale}
        except Exception:
            return {"status": True, "data": [], "config": {}, "ts": 0, "stale": True}

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
                   "rate_limit_enabled", "fw_sync_enabled", "ai_enabled",
                   "auto_ban_cc_enabled", "auto_ban_scan_enabled", "auto_ban_ssh_enabled",
                   "proxy_cool_enabled",
                   "block_page_enabled", "block_page_404_enabled",
                   "block_page_ban_enabled", "block_page_risk_enabled"]
    POLICY_INT = ["auto_ban_window", "auto_ban_threshold", "auto_ban_seconds",
                  "rate_limit_per_sec", "log_max_rows",
                  "auto_ban_cc_window", "auto_ban_cc_threshold", "auto_ban_cc_seconds",
                  "auto_ban_scan_window", "auto_ban_scan_threshold", "auto_ban_scan_seconds",
                  "auto_ban_ssh_window", "auto_ban_ssh_threshold",
                  "burst_window", "proxy_cool_min_conns", "proxy_cool_uniq_threshold",
                  "proxy_cool_single_pct", "proxy_cool_seconds",
                  "block_page_port"]
    POLICY_STR = ["github_repo", "block_page_redirect_ports"]

    def get_policy(self, get=None):
        """读取准入策略（实际生效值，供设置页回显）。"""
        cfg = self._cfg_effective()
        data = {}
        for k in self.POLICY_BOOL:
            data[k] = bool(cfg.get(k, False))
        for k in self.POLICY_INT:
            data[k] = cfg.get(k, 0)
        for k in self.POLICY_STR:
            data[k] = str(cfg.get(k, "") or "")
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
            for k in self.POLICY_STR:
                if hasattr(get, k):
                    patch[k] = str(getattr(get, k) or "").strip()
            if "auto_ban_window" in patch and patch["auto_ban_window"] < 1:
                patch["auto_ban_window"] = 1
            # 攻击类型封禁：窗口参数同样强制 ≥1 秒；
            # 开关开启时参数为「未设置形态」（阈值/时长 0、窗口 ≤1）的回退默认值，
            # 由 _app("config").save() 内统一的 normalize_auto_ban() 完成。
            for _w in ("auto_ban_cc_window", "auto_ban_scan_window", "auto_ban_ssh_window"):
                if _w in patch and patch[_w] < 1:
                    patch[_w] = 1
            # 突发观测/冷却：窗口 ≥2s、时长 ≥10s（与引擎运行时 max(10,...) 一致）、
            # 占比 ≤100；开关开启时「未设置形态」参数的回退默认由 config.save()
            # 内的 normalize_burst_cool() 统一完成（与攻击类型封禁同一机制）。
            if "burst_window" in patch and patch["burst_window"] < 2:
                patch["burst_window"] = 2
            if "proxy_cool_seconds" in patch and patch["proxy_cool_seconds"] < 10:
                patch["proxy_cool_seconds"] = 10
            if "proxy_cool_single_pct" in patch and patch["proxy_cool_single_pct"] > 100:
                patch["proxy_cool_single_pct"] = 100
            self._set_cfg(patch)
            try:
                _app("engine").invalidate_cache()
            except Exception:
                pass
            self._fw_sync()
            try:
                _app("blockpage").ensure()   # 拦截页端口/开关变更后立即生效
            except Exception:
                pass
            return public.returnMsg(True, "策略已保存")
        except Exception:
            return public.returnMsg(False, "保存失败：" + traceback.format_exc()[-200:])

    # ---------------- 静态拦截页 / GitHub 在线升级 / 关于 ----------------
    def _upgrade_repo(self, get=None):
        """升级仓库：请求参数 repo 优先，否则取配置 github_repo。"""
        repo = ""
        try:
            repo = (get.repo or "").strip()
        except Exception:
            pass
        if not repo:
            repo = str(self._cfg().get("github_repo") or "").strip()
        return repo

    def upgrade_check(self, get=None):
        """检查 GitHub 更新（无网/无仓库返回中文错误，不抛异常）。"""
        try:
            res = _app("upgrade").check(self._upgrade_repo(get))
            return {"status": bool(res.get("ok")), "data": res,
                    "msg": res.get("error") or res.get("msg") or "检查完成"}
        except Exception:
            return {"status": False, "msg": "检查更新失败：" + traceback.format_exc()[-200:]}

    def upgrade_apply(self, get=None):
        """执行 GitHub 在线升级（检查→下载→备份→覆盖→重启→失败回滚）。"""
        try:
            self._audit("插件端触发 GitHub 在线升级")
            res = _app("upgrade").apply(self._upgrade_repo(get))
            return {"status": bool(res.get("ok")), "data": res,
                    "msg": res.get("error") or res.get("msg") or "升级完成"}
        except Exception:
            return {"status": False, "msg": "升级失败：" + traceback.format_exc()[-200:]}

    def about(self, get=None):
        """关于页信息：版本、署名、仓库、许可、运行时说明。"""
        try:
            cfg = self._cfg_effective()
            return {"status": True, "data": {
                "name": "FRP WAF",
                "version": _app("__init__").__version__,
                "author": _app("__init__").__author__,
                "repo": str(cfg.get("github_repo") or ""),
                "license": "MIT",
                "runtime": "Python 3 标准库 + SQLite + 原生 JS（零第三方依赖）",
            }}
        except Exception:
            return {"status": False, "msg": "读取失败"}

    # ---------------- 管理员账号 ----------------
    def get_admin(self, get=None):
        """读取当前管理面板账号（用户名 + 密码掩码），供设置页回显。

        不回显明文密码：避免插件请求日志 / 浏览器网络面板 / 截图泄露；
        修改密码走 change_admin_pwd（需校验原密码）。
        """
        cfg = self._cfg()
        return {"status": True, "data": {
            "user": cfg.get("admin_user", "admin"),
            "password": "******" if cfg.get("admin_password") else "",
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
            patch["secret"] = secrets.token_hex(32)
            self._set_cfg(patch)
            return public.returnMsg(True, "账号已更新")
        except Exception:
            return public.returnMsg(False, "修改失败：" + traceback.format_exc()[-200:])
