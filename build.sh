#!/bin/bash
# 组装并安装 FRP WAF 宝塔插件
# 用法: bash build.sh [install]
set -e
SRC=/opt/frpwaf
PKG=/opt/frpwaf/dist/frpwaf
PLUGIN=/www/server/panel/plugin/frpwaf

echo "[*] 组装插件包 -> $PKG"
rm -rf "$PKG"; mkdir -p "$PKG"
cp -a "$SRC/app"            "$PKG/"
cp -a "$SRC/web"            "$PKG/"
cp -a "$SRC/bt_plugin/frpwaf_main.py" "$PKG/"
cp -a "$SRC/bt_plugin/install.sh"     "$PKG/"
cp -a "$SRC/bt_plugin/uninstall.sh"   "$PKG/"
cp -a "$SRC/bt_plugin/index.html"     "$PKG/"
cp -a "$SRC/bt_plugin/info.json"      "$PKG/"
cp -a "$SRC/frpwaf.init"              "$PKG/"
chmod +x "$PKG/install.sh" "$PKG/uninstall.sh" "$PKG/frpwaf.init"
echo "[*] 包内容:"; ls -la "$PKG"

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
