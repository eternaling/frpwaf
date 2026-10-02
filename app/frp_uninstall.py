#!/usr/bin/env python3
# coding: utf-8
"""精确移除 frps TOML 中的 frpwaf 回调块；调用方负责备份、校验和重启。"""
import os
import re
import sys


def remove_plugin_block(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    segments, cur, header = [], [], None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            segments.append((header, cur))
            header, cur = stripped, [line]
        else:
            cur.append(line)
    segments.append((header, cur))

    result, removed = [], False
    for header, body in segments:
        if header and header.startswith("[[httpPlugins]]") and any(
                re.match(r"""^\s*name\s*=\s*["']frpwaf["']\s*(?:#.*)?$""", line)
                for line in body):
            removed = True
            continue
        result.extend(body)
    if not removed:
        raise ValueError("未找到可安全移除的 frpwaf 插件块")

    temp = path + ".frpwaf-remove.%d" % os.getpid()
    try:
        with open(temp, "w", encoding="utf-8") as f:
            f.write("\n".join(result).strip() + "\n")
        os.chmod(temp, os.stat(path).st_mode & 0o777)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.remove(temp)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("用法：frp_uninstall.py <frps.toml>")
    remove_plugin_block(sys.argv[1])
