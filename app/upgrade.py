#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - GitHub 在线升级

仓库地址由配置 github_repo（owner/repo）提供，**不写死**。流程：
  检查最新版本（GitHub API）→ 下载 tar.gz → 安全解包并校验 → 备份 → 覆盖程序
  → 重启服务 → 任一步失败自动回滚。

只覆盖「程序文件」，**绝不触碰 data/**（数据库、配置、日志、备份）。
仅使用标准库（urllib / tarfile / shutil / subprocess）。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

from . import __version__, config

# 不参与覆盖/备份的目录与文件（数据、开发资产、构建产物、运行时产物）
_EXCLUDE_DIRS = {".git", ".claude", ".agents", ".codex", "scripts", "scratchpad",
                 "dist", "data", "__pycache__", ".ruff_cache", ".pytest_cache",
                 "node_modules", "vendor"}
_EXCLUDE_EXT = {".pyc", ".pyo", ".db", ".log", ".pid", ".wal", ".shm"}
_EXCLUDE_FILES = {"frpwaf.json", "frpwaf.db"}

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# 宝塔插件安装目录候选（升级时一并覆盖，保证插件端 UI 也更新）
_PLUGIN_DIRS = ("/www/server/panel/plugin/frpwaf",)
_INIT = "/etc/init.d/frpwaf"

_lock = threading.Lock()


def valid_repo(repo):
    """owner/repo 格式校验。"""
    return bool(repo) and bool(_REPO_RE.match(repo))


def ver_tuple(v):
    """版本号 -> 可比较元组；非数字段按 0 处理。"""
    parts = []
    for p in str(v or "").lstrip("vV").split("."):
        m = re.match(r"^(\d+)", p.strip())
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts) or (0,)


def _https_only(url):
    """仅允许 https:// 地址，阻断 file:// 等本地读取面（urllib 支持 file 方案）。"""
    if not str(url).lower().startswith("https://"):
        raise ValueError("仅允许 https 地址：%s" % str(url)[:80])
    return url


def _get_json(url, timeout=15):
    req = urllib.request.Request(_https_only(url), headers={
        "User-Agent": "frpwaf-updater",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def check(repo, timeout=15):
    """检查最新版本。

    返回 {ok, error?, current, latest, has_update, tarball, url, notes}。
    无网/无仓库/无 Release 时返回中文错误，不抛异常。
    """
    repo = (repo or "").strip()
    if not valid_repo(repo):
        return {"ok": False, "error": "请先在设置中填写 GitHub 仓库（格式 owner/repo）"}
    try:
        data = _get_json("https://api.github.com/repos/%s/releases/latest" % repo, timeout)
    except Exception as e:
        return {"ok": False, "error": "检查更新失败（网络或仓库不可达）：" + str(e)[:200]}
    if not isinstance(data, dict) or not data.get("tag_name"):
        return {"ok": False, "error": "该仓库暂无 Release，请先在 GitHub 发布版本"}
    latest = str(data.get("tag_name")).lstrip("vV")
    return {
        "ok": True,
        "current": __version__,
        "latest": latest,
        "has_update": ver_tuple(latest) > ver_tuple(__version__),
        "tarball": data.get("tarball_url") or "",
        "url": data.get("html_url") or "",
        "notes": (data.get("body") or "")[:2000],
    }


def _download(url, dest, timeout=60):
    req = urllib.request.Request(_https_only(url), headers={"User-Agent": "frpwaf-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f, 64 * 1024)
    return os.path.getsize(dest)


def _safe_extract(tar_path, dest):
    """安全解包：拒绝绝对路径、`..` 逃逸与链接条目（防路径穿越）。

    逐成员写出（不用 extractall），显式校验每个路径都在 dest 内。
    """
    with tarfile.open(tar_path, "r:gz") as tf:
        base = os.path.abspath(dest)
        for m in tf.getmembers():
            p = os.path.abspath(os.path.join(dest, m.name))
            if p != base and not p.startswith(base + os.sep):
                raise ValueError("压缩包包含非法路径：%s" % m.name)
            if m.issym() or m.islnk():
                raise ValueError("压缩包包含链接条目（拒绝）：%s" % m.name)
        for m in tf.getmembers():
            if not m.isfile():
                continue
            dst = os.path.join(dest, m.name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(dst, "wb") as out:
                shutil.copyfileobj(src, out)
    return dest


def _find_root(extract_dir):
    """GitHub tarball 顶层为 <repo>-<ref>/：解包后定位真正的项目根。"""
    entries = [e for e in os.listdir(extract_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(extract_dir, entries[0])):
        return os.path.join(extract_dir, entries[0])
    return extract_dir


def _iter_files(root):
    """遍历程序文件（排除数据/开发资产/运行时产物），产出 (绝对路径, 相对路径)。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in _EXCLUDE_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in _EXCLUDE_FILES or os.path.splitext(fn)[1].lower() in _EXCLUDE_EXT:
                continue
            full = os.path.join(dirpath, fn)
            yield full, os.path.relpath(full, root)


def validate_tree(root):
    """确认解包内容确为本项目（关键文件齐全）。返回 (ok, 缺失列表)。"""
    need = ("frpwaf_main.py", os.path.join("app", "daemon.py"), "info.json")
    missing = [n for n in need if not os.path.exists(os.path.join(root, n))]
    return (not missing), missing


def _targets():
    """升级目标：运行目录 + 可写的宝塔插件目录（去重）。"""
    out = [config.BASE]
    for d in _PLUGIN_DIRS:
        if (os.path.isdir(d) and os.access(d, os.W_OK)
                and os.path.abspath(d) != os.path.abspath(config.BASE)):
            out.append(d)
    return out


def _backup(target, backup_dir):
    """备份目标目录下的程序文件（保持相对结构）。"""
    n = 0
    for full, rel in _iter_files(target):
        dst = os.path.join(backup_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(full, dst)
        n += 1
    return n


def _overwrite(root, target):
    """把解包内容覆盖到目标目录（保持相对结构）。"""
    n = 0
    for full, rel in _iter_files(root):
        dst = os.path.join(target, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(full, dst)
        n += 1
    return n


def _restore(targets, backup_root):
    """从备份回滚目标目录。"""
    for i, t in enumerate(targets):
        b = os.path.join(backup_root, str(i))
        if not os.path.isdir(b):
            continue
        for full, rel in _iter_files(b):
            dst = os.path.join(t, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(full, dst)


def restart_service():
    """同步重启 WAF（调用 init 脚本）。"""
    if not os.path.exists(_INIT):
        return False
    subprocess.run([_INIT, "restart"], timeout=30,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def schedule_init(action, delay=2):
    """延迟执行 init 脚本动作（start/stop/restart），避免当前 HTTP 请求被自身打断。

    用 list 参数启动独立 python 子进程，不经 shell，无注入面。
    """
    if action not in ("start", "stop", "restart"):
        return False
    if not os.path.exists(_INIT):
        return False
    code = ("import time, subprocess; time.sleep(%d); "
            "subprocess.run([%r, %r], stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL)" % (delay, _INIT, action))
    try:
        subprocess.Popen([sys.executable, "-c", code],
                         start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return False
    return True


def schedule_restart(delay=2):
    """延迟重启（避免当前 HTTP 请求被自身重启打断）。"""
    return schedule_init("restart", delay)


def apply(repo, restart=None):
    """执行升级：检查 → 下载 → 解包校验 → 备份 → 覆盖 → 重启 → 失败回滚。

    restart: 可选回调（默认延迟重启 WAF 服务）。返回 {ok, error?/msg, from, to}。
    """
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "已有升级任务在进行中，请稍后"}
    try:
        repo = (repo or "").strip()
        info = check(repo)
        if not info.get("ok"):
            return {"ok": False, "error": info.get("error", "检查更新失败")}
        if not info.get("has_update"):
            return {"ok": True, "msg": "已是最新版本（%s）" % info["current"],
                    "from": info["current"], "to": info["current"]}
        tarball = info.get("tarball")
        if not tarball:
            return {"ok": False, "error": "未获取到下载地址"}
        tmp = tempfile.mkdtemp(prefix="frpwaf_upgrade_")
        try:
            tar_path = os.path.join(tmp, "pkg.tar.gz")
            _download(tarball, tar_path)
            ext = os.path.join(tmp, "src")
            os.makedirs(ext, exist_ok=True)
            _safe_extract(tar_path, ext)
            root = _find_root(ext)
            ok, missing = validate_tree(root)
            if not ok:
                return {"ok": False, "error": "压缩包内容不完整（缺少 %s）" % ", ".join(missing)}
            targets = _targets()
            backup_root = os.path.join(config.DATA_DIR, "upgrade_backup",
                                       time.strftime("%Y%m%d-%H%M%S"))
            for i, t in enumerate(targets):
                _backup(t, os.path.join(backup_root, str(i)))
            try:
                for t in targets:
                    _overwrite(root, t)
            except Exception as e:
                _restore(targets, backup_root)
                return {"ok": False, "error": "覆盖失败，已回滚：" + str(e)[:200]}
            try:
                (restart or schedule_restart)()
            except Exception as e:
                _restore(targets, backup_root)
                try:
                    (restart or schedule_restart)()
                except Exception:
                    pass
                return {"ok": False, "error": "重启失败，已回滚：" + str(e)[:200]}
            return {"ok": True, "msg": "已升级到 %s，服务即将重启" % info["latest"],
                    "from": info["current"], "to": info["latest"]}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    except Exception as e:
        return {"ok": False, "error": "升级失败：" + str(e)[:200]}
    finally:
        _lock.release()
