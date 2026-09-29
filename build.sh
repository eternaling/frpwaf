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
