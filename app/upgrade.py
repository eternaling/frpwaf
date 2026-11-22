#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - GitHub 在线升级

仓库地址由配置 github_repo（owner/repo）提供，**不写死**。流程：
  检查最新版本（GitHub API）→ 校验发布包哈希 → 下载 → 安全解包并校验 → 备份
  → 覆盖程序 → 重启服务 → 任一步失败自动回滚。

校验策略（fail-closed，默认拒绝）：
  - 只升级 Release 里**带 sha256 锚点**的发布包资产（.zip / .tar.gz）。
  - 锚点优先取 GitHub asset `digest`（形如 `sha256:...`）；
    拿不到时要求 Release 附带 `SHA256SUMS` / `pkg.sha256` 资产并逐包比对。
  - 两者都没有时**直接拒绝升级**并提示「该发布缺少校验信息」，绝不静默放行。
    取舍理由：这条链路以 root 覆盖 /opt/frpwaf 并重启服务，没有校验锚点就等于
    把「上游账号被接管」直接兑换成本机 root RCE；宁可升级失败也不能无校验落地。
    发布方只需在 Release 上多传一个 SHA256SUMS 即可恢复升级能力。

只覆盖「程序文件」，**绝不触碰 data/**（数据库、配置、日志、备份）。
仅使用标准库（urllib / tarfile / zipfile / shutil / subprocess）。
"""
import contextlib
import hashlib
import hmac
import http.client
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
import urllib.parse
import urllib.request
import zipfile

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

# ---- 体积/数量上限（防超大包与 gzip/zip 炸弹）----
_MAX_PKG_BYTES = 32 * 1024 * 1024        # 单包下载上限 32MB
_MAX_READ_CHUNK = 256 * 1024             # 单次读取上限
# 响应没有 Content-Length 时，进度文案（「已下载 N」）的刷新步长。
# 没有总长度算不出百分比，只能报绝对量；步长取 1MB 是为了让几十 MB 的包
# 最多产生几十次回调（job 状态是整份 JSON 原子重写，逐 chunk 回调会写爆磁盘）。
_DL_TEXT_STEP = 1024 * 1024
# 下载重试：实测同一链路上 248KB 的包耗时在 4.3s–28.2s 之间波动，
# 单次超时再大也可能撞上更差的时段，重试（新连接）比死等更有效。
_DL_ATTEMPTS = 3          # 总尝试次数（含首次）
_DL_TIMEOUT = 120         # 单次 socket 超时（秒）；原来 60s 余量不够
_MAX_EXTRACT_BYTES = 96 * 1024 * 1024    # 解包后总字节上限
_MAX_EXTRACT_FILES = 2000                # 解包后文件数上限
_MAX_SUMS_BYTES = 64 * 1024              # SHA256SUMS 资产体积上限
_MAX_API_BYTES = 1024 * 1024             # GitHub API 响应体积上限

# ---- 发布包识别 ----
# Release 里的包资产后缀（按优先级）
_PKG_EXTS = (".tar.gz", ".tgz", ".zip")
# 校验文件资产名（小写比较）
_SUMS_NAMES = {"sha256sums", "sha256sums.txt", "sha256sum", "sha256sum.txt",
               "checksums.txt", "checksums.sha256", "pkg.sha256"}

# 备份保留份数（只留最近几份，避免 data/ 被升级备份吃满盘）
_BACKUP_KEEP = 3
# 升级前最低可用空间（备份 + 解包都需要空间）
_MIN_FREE_BYTES = 50 * 1024 * 1024
# 覆盖后要清理的陈旧文件后缀（陈旧模块仍可能被 import，是真实隐患）
_STALE_EXT = {".py", ".pyc", ".pyo"}

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
    """仅允许 https 地址，阻断 file:// 等本地读取面（urllib 支持 file / data 方案）。

    用 urlsplit 解析出 scheme 再做白名单判断，避免 `https://` 前缀之外的
    `file:`、`data:`、`ftp:` 以及带 userinfo 的混淆地址混进来。
    """
    raw = str(url or "")
    try:
        parts = urllib.parse.urlsplit(raw)
    except Exception:
        raise ValueError("非法下载地址：%s" % raw[:80])
    if parts.scheme.lower() != "https" or not parts.netloc or "@" in parts.netloc:
        raise ValueError("仅允许 https 地址：%s" % raw[:80])
    return raw


def _audit(msg):
    """写一条审计行到 data/frpwaf.log（与 daemon / 插件端同一文件，供运行日志页查看）。

    升级链路是 root 覆盖代码的高危动作，审计必须能回答「从哪个版本到哪个版本、
    落地包的 sha256 是什么」。写失败不影响升级本身。
    """
    try:
        p = os.path.join(config.DATA_DIR, "frpwaf.log")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a", encoding="utf-8") as f:
            f.write("[%s] [审计] %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg))
    except Exception:
        pass


def _configured_repo():
    """读取配置里的升级仓库（apply 的唯一可信来源）。"""
    try:
        return str(config.get().get("github_repo") or "").strip()
    except Exception:
        return ""


# 只允许 https 下载：不用 urllib.request.urlopen / OpenerDirector.open，
# 它们的默认 opener 支持 file:/ftp:/data: 方案，且会跟随任意 scheme 的重定向。
# 这条链路下载的包会被 root 落地并重启加载，方案面与重定向链都比通用客户端更窄。


def _open_url(url, headers=None, timeout=15, max_redirects=5):
    """以 https GET 打开地址，返回 (conn, resp)；逐跳校验重定向目标仍为 https。"""
    cur = _https_only(url)
    hdrs = {"User-Agent": "frpwaf-updater"}
    hdrs.update(headers or {})
    for _ in range(max_redirects + 1):
        parts = urllib.parse.urlsplit(cur)
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                           timeout=timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request("GET", path, headers=hdrs)
        resp = conn.getresponse()
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.getheader("Location") or ""
            try:
                resp.read(4096)
            except Exception:
                pass
            conn.close()
            if not loc:
                raise ValueError("重定向缺少 Location：%s" % cur[:80])
            cur = _https_only(urllib.parse.urljoin(cur, loc))
            continue
        if resp.status != 200:
            try:
                body = resp.read(512).decode("utf-8", "replace")
            except Exception:
                body = ""
            conn.close()
            raise ValueError("下载失败（HTTP %d）：%s" % (resp.status, body[:120]))
        return conn, resp
    raise ValueError("重定向次数过多：%s" % str(url)[:80])


@contextlib.contextmanager
def _https_response(url, headers=None, timeout=15):
    """上下文管理的 https 响应（退出时关闭响应与连接）。"""
    conn, resp = _open_url(url, headers=headers, timeout=timeout)
    try:
        yield resp
    finally:
        for obj in (resp, conn):
            try:
                obj.close()
            except Exception:
                pass


def _get_json(url, timeout=15):
    with _https_response(url, headers={"Accept": "application/vnd.github+json"},
                        timeout=timeout) as r:
        raw = r.read(_MAX_API_BYTES + 1)
    if len(raw) > _MAX_API_BYTES:
        raise ValueError("接口响应体积超限（>%d 字节）" % _MAX_API_BYTES)
    return json.loads(raw.decode("utf-8", "replace"))


def _fetch_text(url, max_bytes=_MAX_SUMS_BYTES, timeout=15):
    """读取小体积文本资产（SHA256SUMS 之类），带硬上限。"""
    with _https_response(url, timeout=timeout) as r:
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("校验文件体积超限（>%d 字节）" % max_bytes)
    return data.decode("utf-8", "replace")


def _sha256_from_digest(digest):
    """解析 GitHub asset digest（`sha256:<hex>`）为裸 hex；不是 sha256 则返回空串。"""
    d = str(digest or "").strip().lower()
    if not d.startswith("sha256:"):
        return ""
    h = d.split(":", 1)[1].strip()
    return h if re.fullmatch(r"[0-9a-f]{64}", h) else ""


def _parse_sums(text):
    """解析 SHA256SUMS 文本 -> {文件名: sha256}（兼容 `hex  name` / `hex *name`）。"""
    out = {}
    for ln in str(text or "").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) < 2:
            continue
        h = parts[0].strip().lower().lstrip("*")
        name = os.path.basename(parts[-1].strip().lstrip("*").lstrip("./"))
        if re.fullmatch(r"[0-9a-f]{64}", h) and name:
            out[name] = h
    return out


def _asset_list(data):
    """归一化 Release assets 列表。"""
    out = []
    for a in (data or {}).get("assets") or []:
        if not isinstance(a, dict):
            continue
        name = str(a.get("name") or "")
        url = str(a.get("browser_download_url") or "")
        if not name or not url:
            continue
        try:
            size = int(a.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        out.append({"name": name, "url": url, "size": size,
                    "digest": str(a.get("digest") or "")})
    return out


def _pick_package(data, timeout=15):
    """从 Release 资产中挑出「带 sha256 锚点」的发布包；没有则返回 None。

    锚点来源优先级：asset digest > SHA256SUMS / pkg.sha256 资产。
    返回 {name, url, size, sha256, hash_source} 或 None。
    """
    assets = _asset_list(data)
    cands = [a for a in assets if a["name"].lower().endswith(_PKG_EXTS)]
    # 优先 frpwaf 命名的包，其次按名称稳定排序
    cands.sort(key=lambda a: (0 if "frpwaf" in a["name"].lower() else 1, a["name"]))
    if not cands:
        return None

    # 只有存在「无 digest」的候选时才去取校验文件（省一次网络请求）
    sums_table, sums_from = {}, ""
    if any(not _sha256_from_digest(a["digest"]) for a in cands):
        for a in assets:
            if a["name"].lower() not in _SUMS_NAMES:
                continue
            try:
                table = _parse_sums(_fetch_text(a["url"], timeout=timeout))
            except Exception:
                table = {}
            if table:
                sums_table, sums_from = table, a["name"]
                break

    for a in cands:
        if a["size"] and a["size"] > _MAX_PKG_BYTES:
            continue
        sha = _sha256_from_digest(a["digest"])
        source = "GitHub Release asset digest"
        if not sha:
            sha = sums_table.get(a["name"], "")
            source = "Release 校验文件 %s" % sums_from
        if not sha:
            continue
        return {"name": a["name"], "url": a["url"], "size": a["size"],
                "sha256": sha, "hash_source": source}
    return None


def check(repo, timeout=15):
    """检查最新版本。

    返回 {ok, error?, current, latest, has_update, url, notes, pkg, asset_names}。
    无网/无仓库/无 Release 时返回中文错误，不抛异常。
    `pkg` 为可校验的发布包（None 表示该发布没有校验信息，apply 会拒绝）。
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
    try:
        pkg = _pick_package(data, timeout=timeout)
    except Exception:
        pkg = None
    out = {
        "ok": True,
        "current": __version__,
        "latest": latest,
        "has_update": ver_tuple(latest) > ver_tuple(__version__),
        # tarball 仅作展示/排障保留，**升级绝不使用**（GitHub 自动源码包没有哈希锚点）
        "tarball": data.get("tarball_url") or "",
        "url": data.get("html_url") or "",
        "notes": (data.get("body") or "")[:2000],
        "pkg": pkg,
        "asset_names": [a["name"] for a in _asset_list(data)],
    }
    if not pkg:
        out["verify_hint"] = ("该发布缺少校验信息：Release 里没有带 digest 的发布包资产，"
                              "也没有 SHA256SUMS / pkg.sha256 校验文件，无法安全升级")
    return out


def _fmt_size(n):
    """把字节数格式化成给用户看的短文案（KB / MB）。"""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "-"
    if n >= 1024 * 1024:
        return "%.1f MB" % (n / float(1024 * 1024))
    return "%d KB" % max(1, n // 1024)


def _download(url, dest, expect_sha256="", max_bytes=_MAX_PKG_BYTES,
              timeout=60, progress=None):
    """流式下载到 dest，返回 (字节数, sha256 hex)。

    体积双保险：Content-Length 预检 + 累计字节上限（防无长度响应 / 压缩炸弹），
    单次读取不超过 _MAX_READ_CHUNK。expect_sha256 非空时做常量时间比对，
    不一致抛 ValueError（调用方据此拒绝升级，不做「换源重试」）。

    progress: 可选回调 progress(percent, msg)；不传则行为完全不变。
      percent 是**下载本身**的进度 0-100：
        - 响应带 Content-Length 时，按 total / Content-Length 算真实百分比；
        - 响应没有 Content-Length（chunked）时 percent 传 None，只用 msg 里的
          「已下载 N」报绝对量。没有总长度就没有真实百分比，这里不接受
          「按已下载字节假装推进」——那会让用户误判剩余时间，比不动更糟。
      两种分支都做了节流，避免逐 chunk 回调把状态文件写爆：
        - 有总长度：percent 变化才回调（旧值相同直接跳过）；
        - 无总长度：累计字节跨过 _DL_TEXT_STEP 才更新一次文案。
      回调自身抛异常不影响下载（进度上报不能拖垮升级）。
    """
    h = hashlib.sha256()
    total = 0
    last_pct = -1
    last_step = -1
    with _https_response(url, timeout=timeout) as r:
        try:
            clen = int(r.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            clen = 0
        if clen > max_bytes:
            raise ValueError("发布包体积超限（%d 字节 > 上限 %d 字节）" % (clen, max_bytes))
        with open(dest, "wb") as f:
            while True:
                chunk = r.read(min(_MAX_READ_CHUNK, max_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("下载体积超限（>%d 字节），已中止" % max_bytes)
                h.update(chunk)
                f.write(chunk)
                if progress is None:
                    continue
                if clen > 0:
                    pct = min(100, (total * 100) // clen)
                    if pct == last_pct:
                        continue
                    last_pct = pct
                    msg = "正在下载发布包… %d%%（%s / %s）" % (
                        pct, _fmt_size(total), _fmt_size(clen))
                else:
                    step = total // _DL_TEXT_STEP
                    if step == last_step:
                        continue
                    last_step = step
                    pct = None
                    msg = "正在下载发布包… 已下载 %s" % _fmt_size(total)
                try:
                    progress(pct, msg)
                except Exception:
                    pass
    if total <= 0:
        raise ValueError("发布包内容为空")
    digest = h.hexdigest()
    if expect_sha256 and not hmac.compare_digest(digest, str(expect_sha256).lower()):
        raise ValueError("发布包 sha256 校验失败（期望 %s，实际 %s）"
                         % (expect_sha256, digest))
    return total, digest


def _safe_extract_tar(tar_path, dest):
    """安全解包 tar.gz：拒绝绝对路径、`..` 逃逸与链接条目，并限制总字节/文件数。"""
    base = os.path.abspath(dest)
    total = 0
    count = 0
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        # 先用声明的 size 做一次快速预判（谎报大小的条目还会被下面累计计数拦住）
        declared = sum(m.size for m in members if m.isfile())
        if declared > _MAX_EXTRACT_BYTES:
            raise ValueError("压缩包解包后体积超限（声明 %d 字节）" % declared)
        for m in members:
            p = os.path.abspath(os.path.join(dest, m.name))
            if p != base and not p.startswith(base + os.sep):
                raise ValueError("压缩包包含非法路径：%s" % m.name)
            if m.issym() or m.islnk():
                raise ValueError("压缩包包含链接条目（拒绝）：%s" % m.name)
        for m in members:
            if not m.isfile():
                continue
            count += 1
            if count > _MAX_EXTRACT_FILES:
                raise ValueError("压缩包文件数超限（>%d）" % _MAX_EXTRACT_FILES)
            dst = os.path.join(dest, m.name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(dst, "wb") as out:
                while True:
                    buf = src.read(_MAX_READ_CHUNK)
                    if not buf:
                        break
                    total += len(buf)
                    if total > _MAX_EXTRACT_BYTES:
                        raise ValueError("解包后总字节超限（>%d）" % _MAX_EXTRACT_BYTES)
                    out.write(buf)
    return dest


def _safe_extract_zip(zip_path, dest):
    """安全解包 zip：同 tar 口径（拒绝穿越/符号链接 + 总字节与文件数上限）。"""
    base = os.path.abspath(dest)
    total = 0
    count = 0
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        declared = sum(i.file_size for i in infos if not i.is_dir())
        if declared > _MAX_EXTRACT_BYTES:
            raise ValueError("压缩包解包后体积超限（声明 %d 字节）" % declared)
        for i in infos:
            if i.is_dir():
                continue
            name = str(i.filename or "").replace("\\", "/")
            p = os.path.abspath(os.path.join(dest, name))
            if p != base and not p.startswith(base + os.sep):
                raise ValueError("压缩包包含非法路径：%s" % name)
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("压缩包包含符号链接条目（拒绝）：%s" % name)
        for i in infos:
            if i.is_dir():
                continue
            count += 1
            if count > _MAX_EXTRACT_FILES:
                raise ValueError("压缩包文件数超限（>%d）" % _MAX_EXTRACT_FILES)
            name = str(i.filename or "").replace("\\", "/")
            dst = os.path.join(dest, name)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with zf.open(i) as src, open(dst, "wb") as out:
                while True:
                    buf = src.read(_MAX_READ_CHUNK)
                    if not buf:
                        break
                    total += len(buf)
                    if total > _MAX_EXTRACT_BYTES:
                        raise ValueError("解包后总字节超限（>%d）" % _MAX_EXTRACT_BYTES)
                    out.write(buf)
    return dest


def _safe_extract(pkg_path, dest):
    """按后缀分派安全解包（tar.gz / tgz / zip）。"""
    if str(pkg_path).lower().endswith(".zip"):
        return _safe_extract_zip(pkg_path, dest)
    return _safe_extract_tar(pkg_path, dest)


def _pkg_ext(name):
    """发布包资产名 -> 本地文件名后缀（决定解包方式）。

    _PKG_EXTS 已按「先长后短」排序（.tar.gz 必须先于 .tgz/.zip 判断），
    故意复用同一个元组，避免两处顺序不一致。
    """
    n = str(name or "").lower()
    for ext in _PKG_EXTS:
        if n.endswith(ext):
            return ext
    return ".tar.gz"


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


def _read_head(path, limit=262144):
    """读取文件前 limit 字节文本（用于结构断言，避免读整份大文件）。"""
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


def validate_tree(root, expect_version=""):
    """确认解包内容确为本项目：关键文件齐全 + 最小结构断言。

    只查文件名挡不住「同名前门」——这里进一步校验 info.json 可解析且带 versions、
    daemon 有 def main、主文件有插件类定义，并把包内版本与发布 tag 对齐。
    返回 (ok, problems)，problems 为中文描述列表。
    """
    problems = []

    main_py = os.path.join(root, "frpwaf_main.py")
    if not os.path.isfile(main_py):
        problems.append("缺少 frpwaf_main.py")
    else:
        txt = _read_head(main_py)
        if len(txt.strip()) < 2000:
            problems.append("frpwaf_main.py 内容异常（过短）")
        elif "class frpwaf_main" not in txt:
            problems.append("frpwaf_main.py 缺少 class frpwaf_main 定义")

    daemon = os.path.join(root, "app", "daemon.py")
    if not os.path.isfile(daemon):
        problems.append("缺少 app/daemon.py")
    else:
        txt = _read_head(daemon)
        if len(txt.strip()) < 1000:
            problems.append("app/daemon.py 内容异常（过短）")
        elif "def main(" not in txt:
            problems.append("app/daemon.py 缺少 def main( 入口")

    info = os.path.join(root, "info.json")
    if not os.path.isfile(info):
        problems.append("缺少 info.json")
    else:
        try:
            with open(info, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception as e:
            meta = None
            problems.append("info.json 无法解析为 JSON：%s" % str(e)[:100])
        if isinstance(meta, dict):
            ver = str(meta.get("versions") or "").strip()
            if not ver:
                problems.append("info.json 缺少 versions 字段")
            elif expect_version and ver_tuple(ver) != ver_tuple(expect_version):
                problems.append("包内版本 %s 与发布版本 %s 不一致" % (ver, expect_version))

    return (not problems), problems


def _targets():
    """升级目标：运行目录 + 可写的宝塔插件目录（去重）。"""
    out = [config.BASE]
    for d in _PLUGIN_DIRS:
        if (os.path.isdir(d) and os.access(d, os.W_OK)
                and os.path.abspath(d) != os.path.abspath(config.BASE)):
            out.append(d)
    return out


def _backup(target, backup_dir):
    """备份目标目录下的程序文件（保持相对结构）。失败抛异常（不得在无备份时覆盖）。"""
    n = 0
    for full, rel in _iter_files(target):
        dst = os.path.join(backup_dir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(full, dst)
        n += 1
    return n


def _prune_stale(target, keep_rel):
    """删除目标目录里「新包里已不存在」的 .py/.pyc/.pyo（防陈旧模块被 import）。

    只在 _iter_files 口径内操作（data/、.git、__pycache__ 等永不触碰），
    且只动 Python 模块后缀，避免误删运行时文件。
    """
    removed = []
    for full, rel in list(_iter_files(target)):
        if rel in keep_rel:
            continue
        if os.path.splitext(rel)[1].lower() not in _STALE_EXT:
            continue
        try:
            os.remove(full)
            removed.append(rel)
        except OSError:
            pass
    return removed


def _overwrite(root, target):
    """把解包内容覆盖到目标目录（保持相对结构），并清理新包中已不存在的旧模块。

    返回 (写入数, 被清理的相对路径列表)。
    """
    pkg_rel = set()
    n = 0
    for full, rel in _iter_files(root):
        pkg_rel.add(rel)
        dst = os.path.join(target, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(full, dst)
        n += 1
    return n, _prune_stale(target, pkg_rel)


def _restore(targets, backup_root):
    """从备份回滚目标目录，并清理「备份里没有」的模块（让回滚后的状态干净）。"""
    for i, t in enumerate(targets):
        b = os.path.join(backup_root, str(i))
        if not os.path.isdir(b):
            continue
        keep = set()
        for full, rel in _iter_files(b):
            dst = os.path.join(t, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(full, dst)
            keep.add(rel)
        _prune_stale(t, keep)


def _backup_root_dir():
    return os.path.join(config.DATA_DIR, "upgrade_backup")


def _prune_backups(keep=_BACKUP_KEEP):
    """只保留最近 keep 份升级备份（目录名即时间戳），返回被删除的目录名列表。"""
    root = _backup_root_dir()
    try:
        names = [d for d in os.listdir(root)
                 if re.match(r"^\d{8}-\d{6}$", d)
                 and os.path.isdir(os.path.join(root, d))]
    except OSError:
        return []
    names.sort()
    stale = names[:-keep] if keep > 0 else names
    removed = []
    for name in stale:
        shutil.rmtree(os.path.join(root, name), ignore_errors=True)
        removed.append(name)
    return removed


def _free_bytes():
    """data/ 所在磁盘可用字节数；无法获取返回 -1。"""
    try:
        return shutil.disk_usage(config.DATA_DIR).free
    except OSError:
        return -1


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


# 各阶段进度（0-100）。阶段边界上报，不在文件循环里逐个回调：
# 状态文件是整份 JSON 重写，覆盖几百个文件时逐文件上报会把磁盘写爆，
# 而且前端轮询间隔远大于单文件耗时，逐文件数字跳变也看不出信息。
_P_CHECK = 10        # 配置/仓库复核 + 检查更新
_P_FOUND = 20        # 已确认有新版本
_P_DOWNLOAD = 30     # 下载发布包
_P_VERIFIED = 45     # 发布包 sha256 校验通过
_P_EXTRACT = 60      # 解包
_P_VALIDATE = 70     # 包内容结构校验
_P_BACKUP = 80       # 备份现有文件
_P_OVERWRITE = 90    # 覆盖文件
_P_RESTART = 100     # 调度服务重启


def _progress_cb(progress):
    """把调用方传进来的 progress 包成 _emit(percent, msg)。

    三件事，都是为了「进度上报出问题也绝不影响升级本身」：
      1. 钳制到 0-100 且**单调不减**：阶段是顺序执行的，回退的百分比只会
         让前端进度条倒退，看起来像重试；
      2. progress 为 None 时返回空实现，apply() 里不必到处判空；
      3. 回调自身抛任何异常都被吞掉 —— 状态文件写失败、前端回调里的 bug
         都不该让升级中断在半覆盖状态（那比没有进度条严重得多）。
    """
    last = [0]

    def _emit(percent, msg):
        if progress is None:
            return
        try:
            p = int(percent)
        except (TypeError, ValueError):
            return
        p = max(0, min(100, p))
        if p < last[0]:
            p = last[0]
        last[0] = p
        try:
            progress(p, msg)
        except Exception:
            pass

    return _emit


def _download_with_retry(url, dest, expect_sha256="", max_bytes=_MAX_PKG_BYTES,
                         progress=None, attempts=_DL_ATTEMPTS, timeout=_DL_TIMEOUT):
    """带重试的 _download。网络抖动是常态，一次失败不该让升级失败。

    为什么不再加长超时：实测同一条链路上 248KB 的包耗时波动很大
    （4.3s / 11.0s / 28.2s），单次 socket 超时无论调到多大都可能撞上
    更差的时段；而重试能让第二次从新的连接开始，比单纯等待更有效。

    - 每个 attempt 重新建连、重新写文件（上一次的半成品被覆盖）
    - 只对网络/超时类异常重试；**哈希不匹配、体积超限等确定性错误不重试**
      （重试也不会变好，反而拖长时间，且可能是被投毒）
    - 每次重试前用 progress 报一句，用户能看到“在重试”而不是卡住
    返回与 _download 相同：(字节数, sha256)。
    """
    last_exc = None
    for i in range(max(1, int(attempts))):
        try:
            return _download(url, dest, expect_sha256=expect_sha256,
                             max_bytes=max_bytes, timeout=timeout,
                             progress=progress)
        except (ValueError,) as exc:
            # 体积超限 / 哈希不匹配 / 解包前校验失败：确定性错误，不重试
            raise
        except Exception as exc:                      # noqa: BLE001
            last_exc = exc
            if i + 1 >= max(1, int(attempts)):
                break
            if progress is not None:
                try:
                    progress(None, "下载中断（%s），正在重试（第 %d/%d 次）…"
                             % (type(exc).__name__, i + 2, int(attempts)))
                except Exception:
                    pass
            time.sleep(1.5 * (i + 1))
    raise last_exc if last_exc else RuntimeError("下载失败")


def _download_progress(emit):
    """把 _download 的 0-100 下载进度映射到 _P_DOWNLOAD.._P_VERIFIED（30→45）。

    下载是整条升级流程里唯一能按字节算出百分比的阶段，几十 MB 的包停在 30%
    几十秒会被当成卡死，所以这一段用真实进度替掉阶段边界。
    节流在映射里做：区间只有 15 个百分点，同一数值只报一次（百分比变化才
    emit），一次下载最多 16 次回调；percent 传 None（无 Content-Length）时只
    刷新文案、数值停在 _P_DOWNLOAD。
    下载跑到 100% 时封顶到 _P_VERIFIED - 1（44），_P_VERIFIED（45）专属
    「sha256 校验通过」那一格：否则下载刚结束就报 45，随后校验完成再报一次
    45，同一百分点被两个阶段各报一次，也提前宣布了尚未发生的校验。
    """
    span = _P_VERIFIED - _P_DOWNLOAD
    state = [_P_DOWNLOAD]     # 起点已由调用方上报过，不重复报 30

    def _on_progress(percent, msg):
        if percent is None:
            # 没有总长度：百分比不动，只更新已下载量文案
            emit(_P_DOWNLOAD, msg)
            return
        try:
            ratio = float(percent) / 100.0
        except (TypeError, ValueError):
            return
        ratio = max(0.0, min(1.0, ratio))
        p = _P_DOWNLOAD + int(round(span * ratio))
        if p >= _P_VERIFIED:
            p = _P_VERIFIED - 1
        if p <= state[0]:
            return
        state[0] = p
        emit(p, msg)

    return _on_progress


def apply(repo, restart=None, progress=None):
    """执行升级：仓库复核 → 检查 → 校验哈希 → 下载 → 解包校验 → 备份 → 覆盖 → 重启。

    restart: 可选回调（默认延迟重启 WAF 服务）。
    progress: 可选回调 progress(percent, msg)；不传则行为完全不变。
              percent 为 0-100 的单调不减阶段值，msg 是给用户看的中文短语。

    纵深防御（即使上层把请求体里的 repo 传下来也不会变成 root RCE）：
      - repo 必须与配置 `github_repo` 一致，否则直接拒绝；
      - 发布包必须有 sha256 锚点，且下载后比对一致，否则拒绝；
      - 备份失败绝不覆盖，覆盖失败/重启失败自动回滚。

    返回 {ok, error?/msg, from, to, sha256?, pkg?, removed?}。
    """
    # 先建好进度回调：后续阶段边界只需 _emit(percent, msg)，不传 progress 时是空操作
    _emit = _progress_cb(progress)
    if not _lock.acquire(blocking=False):
        return {"ok": False, "error": "已有升级任务在进行中，请稍后"}
    try:
        _emit(_P_CHECK, "正在检查更新…")
        cfg_repo = _configured_repo()
        if not valid_repo(cfg_repo):
            msg = "未配置可用的升级仓库（github_repo），已拒绝升级"
            _audit("拒绝升级：" + msg)
            return {"ok": False, "error": msg}
        repo = (repo or "").strip()
        if repo and repo.lower() != cfg_repo.lower():
            msg = ("升级仓库必须与配置 github_repo（%s）一致，请求的 %s 已拒绝升级"
                   % (cfg_repo, repo))
            _audit("拒绝升级：" + msg)
            return {"ok": False, "error": msg}
        repo = cfg_repo

        free = _free_bytes()
        if 0 <= free < _MIN_FREE_BYTES:
            msg = ("磁盘剩余空间不足（%d MB < %d MB），已拒绝升级，请先清理 data/ 或旧备份"
                   % (free // (1024 * 1024), _MIN_FREE_BYTES // (1024 * 1024)))
            _audit("拒绝升级：" + msg)
            return {"ok": False, "error": msg}

        info = check(repo)
        if not info.get("ok"):
            return {"ok": False, "error": info.get("error", "检查更新失败")}
        if not info.get("has_update"):
            return {"ok": True, "msg": "已是最新版本（%s）" % info["current"],
                    "from": info["current"], "to": info["current"]}
        _emit(_P_FOUND, "发现新版本 %s，准备下载…" % info["latest"])

        pkg = info.get("pkg") or {}
        if not pkg.get("sha256"):
            msg = info.get("verify_hint") or "该发布缺少校验信息，已拒绝升级"
            _audit("拒绝升级：%s（仓库 %s，版本 %s）" % (msg, repo, info["latest"]))
            return {"ok": False, "error": msg, "from": info["current"], "to": info["latest"]}

        tmp = tempfile.mkdtemp(prefix="frpwaf_upgrade_")
        try:
            pkg_name = pkg.get("name") or "pkg.tar.gz"
            pkg_path = os.path.join(tmp, "pkg" + _pkg_ext(pkg_name))
            _emit(_P_DOWNLOAD, "正在下载发布包…")
            size, sha = _download_with_retry(pkg["url"], pkg_path,
                                             expect_sha256=pkg["sha256"],
                                             progress=_download_progress(_emit))
            # 哈希比对在 _download 内部完成（不一致会抛异常），走到这里即已通过
            _emit(_P_VERIFIED, "发布包完整性校验通过…")
            _audit("升级包校验通过：%s（%d 字节，sha256 %s，锚点：%s）"
                   % (pkg_name, size, sha, pkg.get("hash_source") or "-"))

            ext_dir = os.path.join(tmp, "src")
            os.makedirs(ext_dir, exist_ok=True)
            _emit(_P_EXTRACT, "正在解包发布包…")
            _safe_extract(pkg_path, ext_dir)
            root = _find_root(ext_dir)
            _emit(_P_VALIDATE, "正在校验包内容…")
            ok, problems = validate_tree(root, expect_version=info["latest"])
            if not ok:
                msg = "升级包内容校验未通过：%s" % "；".join(problems)
                _audit("拒绝升级：" + msg)
                return {"ok": False, "error": msg, "sha256": sha,
                        "from": info["current"], "to": info["latest"]}

            targets = _targets()
            if not targets:
                return {"ok": False, "error": "未找到可写入的升级目标目录"}

            backup_root = os.path.join(_backup_root_dir(),
                                       time.strftime("%Y%m%d-%H%M%S"))
            _emit(_P_BACKUP, "正在备份现有文件…")
            try:
                for i, t in enumerate(targets):
                    _backup(t, os.path.join(backup_root, str(i)))
            except Exception as e:
                return {"ok": False, "error": "备份失败，未做任何覆盖：%s" % str(e)[:200]}

            removed = []
            _emit(_P_OVERWRITE, "正在覆盖文件…")
            try:
                for t in targets:
                    _n, rm = _overwrite(root, t)
                    removed.extend(rm)
            except Exception as e:
                _restore(targets, backup_root)
                _audit("升级覆盖失败已回滚：%s" % str(e)[:200])
                return {"ok": False, "error": "覆盖失败，已回滚：" + str(e)[:200],
                        "sha256": sha}

            _emit(_P_RESTART, "正在调度服务重启…")
            try:
                (restart or schedule_restart)()
            except Exception as e:
                _restore(targets, backup_root)
                try:
                    (restart or schedule_restart)()
                except Exception:
                    pass
                _audit("升级重启失败已回滚：%s" % str(e)[:200])
                return {"ok": False, "error": "重启失败，已回滚：" + str(e)[:200],
                        "sha256": sha}

            pruned = _prune_backups()
            _audit("在线升级成功：%s → %s，包 %s（sha256 %s），清理陈旧模块 %s，"
                   "清理旧备份 %s"
                   % (info["current"], info["latest"], pkg_name, sha,
                      ",".join(removed) or "无", ",".join(pruned) or "无"))
            return {"ok": True, "msg": "已升级到 %s，服务即将重启" % info["latest"],
                    "from": info["current"], "to": info["latest"],
                    "sha256": sha, "pkg": pkg_name,
                    "hash_source": pkg.get("hash_source") or "",
                    "removed": removed}
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    except Exception as e:
        _audit("在线升级失败：%s" % str(e)[:200])
        return {"ok": False, "error": "升级失败：" + str(e)[:200]}
    finally:
        _lock.release()
