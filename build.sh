#!/bin/bash
# 组装 / 打包 / 安装 FRP WAF 宝塔插件
#
# 用法:
#   bash build.sh            # 仅组装插件包 -> dist/frpwaf
#   bash build.sh zip        # 组装并打成可上传的 zip -> dist/frpwaf.zip
#   bash build.sh install    # 组装并直接安装到本机宝塔插件目录
#
# 目录约定（重要）：
#   宝塔「上传安装」会扫描压缩包，找到同时含 info.json + install.sh 的目录
#   作为插件根目录，并把该目录下的全部内容原样拷进 /www/server/panel/plugin/<name>。
#   因此插件包根目录必须同时包含 info.json / install.sh / app/ / web/ ...
#   本仓库根目录即为插件包根目录，dist/frpwaf 是从仓库根目录拷贝出的成品。
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
PKG="$SRC/dist/frpwaf"
ZIP="$SRC/dist/frpwaf.zip"
PLUGIN=/www/server/panel/plugin/frpwaf

echo "[*] 组装插件包 -> $PKG"
rm -rf "$PKG" "$ZIP"; mkdir -p "$PKG"
# 运行代码包与网页资源
cp -a "$SRC/app" "$PKG/"
cp -a "$SRC/web" "$PKG/"
# 插件封装（后端 / 前端 / 元信息 / 安装卸载脚本 / 服务脚本）
cp -a "$SRC/frpwaf_main.py" "$PKG/"
cp -a "$SRC/index.html"     "$PKG/"
cp -a "$SRC/info.json"      "$PKG/"
cp -a "$SRC/install.sh"     "$PKG/"
cp -a "$SRC/uninstall.sh"   "$PKG/"
cp -a "$SRC/frpwaf.init"    "$PKG/"
chmod +x "$PKG/install.sh" "$PKG/uninstall.sh" "$PKG/frpwaf.init"
# 清理字节码缓存 / 编辑器垃圾，避免打进发布包
find "$PKG" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$PKG" -name '*.py[co]' -delete 2>/dev/null || true
find "$PKG" -name '.DS_Store' -delete 2>/dev/null || true

# ---- 行尾归一化（关键）----
# 背景：仓库索引是 LF，但 Windows 工作区（core.autocrlf=true）是 CRLF，而上面是
# `cp -a` 直接拷工作区。若不归一化，成品包里的 `frpwaf.init` 首行会变成
# `#! /bin/bash\r`，装到 /etc/init.d/frpwaf 后内核找不到解释器 `/bin/bash\r`，
# 服务启动/重启报：`cannot execute: required file not found`。
# 这里强制转成 LF，保证在任意平台（Linux / Windows Git Bash）打包产物都一致。
echo "[*] 行尾归一化为 LF"
# 选一个真正可用的 python：Windows 上的 python3 可能是应用商店占位符（`-c` 会失败）
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys' >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -n "$PY" ]; then
  echo "[*] 使用 $PY 归一化"
  find "$PKG" -type f \( -name '*.py' -o -name '*.sh' -o -name '*.init' -o -name '*.html' \
    -o -name '*.css' -o -name '*.js' -o -name '*.json' -o -name '*.md' -o -name '*.txt' \) \
    -exec "$PY" -c 'import sys
for p in sys.argv[1:]:
    d = open(p, "rb").read()
    if b"\r" in d:
        open(p, "wb").write(d.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))' {} +
else
  echo "[!] 未找到可用 python，改用 sed"
  find "$PKG" -type f \( -name '*.py' -o -name '*.sh' -o -name '*.init' -o -name '*.html' \
    -o -name '*.css' -o -name '*.js' -o -name '*.json' -o -name '*.md' -o -name '*.txt' \) \
    -exec sed -i 's/\r$//' {} +
fi

# 校验：包内文本文件不得残留 CR（残留则构建失败，绝不产出 CRLF 包）
# 校验：包内文本文件不得残留 CR（残留则构建失败，绝不产出 CRLF 包）
# 注：不用 `find -exec grep -lU`——GNU grep 3.0 下该组合会把所有文本文件误报为命中。
if [ -n "$PY" ]; then
  CRLF_HIT=$(find "$PKG" -type f \( -name '*.py' -o -name '*.sh' -o -name '*.init' -o -name '*.html' \
    -o -name '*.css' -o -name '*.js' -o -name '*.json' -o -name '*.md' -o -name '*.txt' \) \
    -exec "$PY" -c 'import sys
for p in sys.argv[1:]:
    if b"\r" in open(p, "rb").read():
        print(p)' {} + 2>/dev/null || true)
else
  CRLF_HIT=$(grep -rlU $'\r' "$PKG" 2>/dev/null || true)
fi
if [ -n "$CRLF_HIT" ]; then
  echo "[!] 错误：包内仍有 CRLF 文件，已中止打包（避免服务报 cannot execute）"
  echo "$CRLF_HIT" | head -10
  exit 1
fi
echo "[*] 行尾检查通过（全 LF）"

echo "[*] 包内容:"; ls -la "$PKG"

if [ "$1" == "zip" ]; then
  echo "[*] 打包可上传 zip -> $ZIP"
  # 以包内文件为顶层（不含 frpwaf/ 外壳），宝塔上传即可直接识别
  (cd "$PKG" && zip -rq "$ZIP" .)
  echo "[*] 生成完成：$ZIP"
  exit 0
fi

if [ "$1" == "install" ]; then
  echo "[*] 安装到宝塔插件目录 -> $PLUGIN"
  mkdir -p "$PLUGIN"
  cp -a "$PKG/." "$PLUGIN/"
  chmod 600 "$PLUGIN"/*.py "$PLUGIN"/*.json "$PLUGIN"/index.html 2>/dev/null || true
  chmod +x "$PLUGIN/install.sh" "$PLUGIN/uninstall.sh" "$PLUGIN/frpwaf.init"
  # 清理字节码缓存并刷新 mtime，促使面板 PluginLoader 重新加载插件主模块
  find "$PLUGIN" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  touch "$PLUGIN/frpwaf_main.py"
  # 宝塔面板重载标记：安装/更新插件时由面板写入，直接拷贝文件时手动补上
  if [ -d /www/server/panel/data ]; then
    touch /www/server/panel/data/frpwaf.pl
  fi
  echo "[*] 执行 install.sh"
  bash "$PLUGIN/install.sh" install
fi
echo "[*] 完成"
