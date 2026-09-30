#!/usr/bin/env python3
# coding: utf-8
"""FRP WAF - 轻量 TOML 解析 / 生成（纯标准库）

背景：frp 配置读写原先 `import toml`（第三方包，宝塔 pyenv 恰好自带才未暴露问题），
违反本项目「纯标准库、无 requirements.txt」红线——运行环境缺该包时，
frp 管理页会直接报「缺少 toml 模块」。故内置覆盖 frp 配置所需子集的解析器。

支持范围（frp 配置实际用到的 TOML 子集）：
  - 键值对、点分键、引号键；[table] 与 [[array of tables]]
  - 基本 / 字面量 / 多行字符串；整数（含 0x/0o/0b）、浮点、布尔
  - 数组（可跨行、可嵌套）、内联表 { k = v }
  - 注释 #、空行、CRLF、UTF-8 BOM

不支持（frp 配置不会出现，遇到会明确报错）：日期 / 时间类型。

解析语义与标准库 tomllib 对齐（同样的命名空间状态机：EXPLICIT_NEST / FROZEN），
生成格式与 tomllib 标准 dump 写法一致（先标量后子表、`[[name]]` 一行）。

接口：
  loads(s) -> dict     load(fp) -> dict
  dumps(obj) -> str    dump(obj, fp)

兼容 Python 3.6+（不使用海量运算符 / match 等新语法）。
"""
import re

__all__ = ["TomlError", "loads", "load", "dumps", "dump"]


class TomlError(ValueError):
    """TOML 语法错误（消息带行号）。"""


_BARE_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_KEY_INITIAL_CHARS = _BARE_KEY_CHARS | frozenset("\"'")
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")
_WS = frozenset(" \t")
_WS_NL = _WS | frozenset("\n")
_ILLEGAL_STR_CHARS = frozenset(chr(i) for i in range(32)) | frozenset(chr(127))
_ILLEGAL_BASIC = _ILLEGAL_STR_CHARS - frozenset("\t")
_ILLEGAL_MULTILINE = _ILLEGAL_STR_CHARS - frozenset("\t\n")
_ESCAPES = {
    "\\b": "\b", "\\t": "\t", "\\n": "\n", "\\f": "\f",
    "\\r": "\r", '\\"': '"', "\\\\": "\\",
}
_NUM_RE = re.compile(
    r"(?:"
    r"0(?:x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*|b[01](?:_?[01])*|o[0-7](?:_?[0-7])*)"
    r"|[+-]?(?:0|[1-9](?:_?[0-9])*)(?P<floatpart>"
    r"(?:\.[0-9](?:_?[0-9])*)?(?:[eE][+-]?[0-9](?:_?[0-9])*)?)"
    r")"
)

_FROZEN = 0        # 内联表 / 数组：不可再被表头或点分键展开
_EXPLICIT_NEST = 1  # 已被 [table] / 点分键 / [[array]] 显式声明的命名空间


class _Flags(object):
    """命名空间状态：EXPLICIT_NEST / FROZEN（对齐 tomllib.Flags）。"""

    def __init__(self):
        self._flags = {}
        self._pending = set()

    def add_pending(self, key, flag):
        self._pending.add((key, flag))

    def finalize_pending(self):
        for key, flag in self._pending:
            self.set(key, flag, recursive=False)
        self._pending.clear()

    def unset_all(self, key):
        cont = self._flags
        for k in key[:-1]:
            if k not in cont:
                return
            cont = cont[k]["nested"]
        cont.pop(key[-1], None)

    def set(self, key, flag, recursive):
        cont = self._flags
        for k in key[:-1]:
            if k not in cont:
                cont[k] = {"flags": set(), "recursive_flags": set(), "nested": {}}
            cont = cont[k]["nested"]
        if key[-1] not in cont:
            cont[key[-1]] = {"flags": set(), "recursive_flags": set(), "nested": {}}
        cont[key[-1]]["recursive_flags" if recursive else "flags"].add(flag)

    def is_(self, key, flag):
        if not key:
            return False
        cont = self._flags
        for k in key[:-1]:
            if k not in cont:
                return False
            inner = cont[k]
            if flag in inner["recursive_flags"]:
                return True
            cont = inner["nested"]
        stem = key[-1]
        if stem in cont:
            inner = cont[stem]
            return flag in inner["flags"] or flag in inner["recursive_flags"]
        return False


class _Parser(object):
    def __init__(self, text):
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        if text.startswith("﻿"):
            text = text[1:]   # 容忍 BOM（用户手工编辑过的配置可能带）
        # 与 tomllib 一致：\r\n 归一化，简化行尾判断
        self.s = text.replace("\r\n", "\n")
        self.n = len(self.s)
        self.i = 0
        self.root = {}
        self.flags = _Flags()
        self.header = ()

    # ---------------- 报错与空白 ----------------
    def _err(self, msg):
        line = self.s.count("\n", 0, self.i) + 1
        col = self.i - (self.s.rfind("\n", 0, self.i) + 1) + 1
        raise TomlError("第 %d 行第 %d 列：%s" % (line, col, msg))

    def _skip_ws(self):
        s, n = self.s, self.n
        while self.i < n and s[self.i] in _WS:
            self.i += 1

    def _skip_ws_nl(self):
        s, n = self.s, self.n
        while self.i < n and s[self.i] in _WS_NL:
            self.i += 1

    def _skip_comment(self):
        """# 之后到行尾；注释中不允许控制字符（对齐 tomllib）。"""
        if self.i < self.n and self.s[self.i] == "#":
            s, n = self.s, self.n
            j = self.i + 1
            while j < n and s[j] != "\n":
                if s[j] in _ILLEGAL_BASIC:
                    self.i = j
                    self._err("注释中包含非法控制字符")
                j += 1
            self.i = j

    def _skip_comment_nl(self):
        """语句之间：跳过空白 / 换行 / 注释（数组内部同样适用）。"""
        while True:
            before = self.i
            self._skip_ws_nl()
            self._skip_comment()
            if self.i == before:
                return

    def _end_statement(self):
        self._skip_ws()
        self._skip_comment()
        if self.i < self.n and self.s[self.i] != "\n":
            self._err("语句后缺少换行")
        if self.i < self.n:
            self.i += 1   # 吃掉换行

    # ---------------- 主循环 ----------------
    def parse(self):
        while True:
            self._skip_ws()
            if self.i >= self.n:
                break
            c = self.s[self.i]
            if c == "\n":
                self.i += 1
                continue
            if c in _KEY_INITIAL_CHARS:
                self._keyval_rule()
                self._skip_ws()
            elif c == "[":
                self.flags.finalize_pending()
                if self.i + 1 < self.n and self.s[self.i + 1] == "[":
                    self._array_header_rule()
                else:
                    self._table_header_rule()
                self._skip_ws()
            elif c == "#":
                pass
            else:
                self._err("非法语句")
            self._end_statement()
        return self.root

    # ---------------- 表头 ----------------
    def _parse_key(self):
        parts = [self._parse_key_part()]
        self._skip_ws()
        while self.i < self.n and self.s[self.i] == ".":
            self.i += 1
            self._skip_ws()
            parts.append(self._parse_key_part())
            self._skip_ws()
        return tuple(parts)

    def _parse_key_part(self):
        if self.i >= self.n:
            self._err("缺少键名")
        c = self.s[self.i]
        if c in _BARE_KEY_CHARS:
            start = self.i
            while self.i < self.n and self.s[self.i] in _BARE_KEY_CHARS:
                self.i += 1
            return self.s[start:self.i]
        if c == "'":
            return self._parse_literal_str()
        if c == '"':
            self.i += 1   # 跳过开引号，_parse_basic_str 从内容起点开始
            return self._parse_basic_str(False)
        self._err("键名起始字符非法")

    def _table_header_rule(self):
        self.i += 1   # 吃掉 '['
        self._skip_ws()
        key = self._parse_key()
        if self.flags.is_(key, _EXPLICIT_NEST) or self.flags.is_(key, _FROZEN):
            self._err("表 %s 重复声明" % ".".join(key))
        self.flags.set(key, _EXPLICIT_NEST, recursive=False)
        node = self._get_or_create_nest(key, access_lists=True)
        if node is None:
            self._err("不能覆盖已有值")
        if self.i >= self.n or self.s[self.i] != "]":
            self._err("表头缺少 ']'")
        self.i += 1
        self.header = key
        self.current = node

    def _array_header_rule(self):
        self.i += 2   # 吃掉 '[['
        self._skip_ws()
        key = self._parse_key()
        if self.flags.is_(key, _FROZEN):
            self._err("不能修改内联表 / 数组")
        self.flags.unset_all(key)   # 新元素命名空间重置
        self.flags.set(key, _EXPLICIT_NEST, recursive=False)
        parent = self._get_or_create_nest(key[:-1], access_lists=True)
        if parent is None:
            self._err("不能覆盖已有值")
        last = key[-1]
        if last in parent:
            arr = parent[last]
            if not isinstance(arr, list):
                self._err("不能覆盖已有值")
            arr.append({})
        else:
            parent[last] = [{}]
        if not self.s.startswith("]]", self.i):
            self._err("数组表头缺少 ']]'")
        self.i += 2
        self.header = key
        self.current = parent[last][-1]

    def _get_or_create_nest(self, key, access_lists=True):
        """按路径定位 / 创建表；路径中遇到数组表进入其最后一个元素。

        途中撞到非表值（标量 / 内联表）时返回 None，由调用方报错。
        """
        node = self.root
        for k in key:
            if k not in node:
                node[k] = {}
            node = node[k]
            if access_lists and isinstance(node, list):
                node = node[-1] if node else None
            if not isinstance(node, dict):
                return None
        return node

    # ---------------- 键值对 ----------------
    def _keyval_rule(self):
        key, value = self._parse_key_value_pair()
        parent_key = key[:-1]
        abs_parent = self.header + parent_key

        for i in range(1, len(key)):
            cont_key = self.header + key[:i]
            if self.flags.is_(cont_key, _EXPLICIT_NEST):
                self._err("点分键不能重定义已有命名空间 %s" % ".".join(cont_key))
            self.flags.add_pending(cont_key, _EXPLICIT_NEST)

        if self.flags.is_(abs_parent, _FROZEN):
            self._err("不能修改内联表 / 数组")

        node = self._get_or_create_nest(abs_parent, access_lists=True)
        if node is None:
            self._err("不能覆盖已有值")
        if key[-1] in node:
            self._err("键 '%s' 重复定义" % key[-1])
        node[key[-1]] = value
        if isinstance(value, (dict, list)):
            self.flags.set(self.header + key, _FROZEN, recursive=True)

    def _parse_key_value_pair(self):
        key = self._parse_key()
        if self.i >= self.n or self.s[self.i] != "=":
            self._err("键后缺少 '='")
        self.i += 1
        self._skip_ws()
        value = self._parse_value()
        return key, value

    # ---------------- 值 ----------------
    def _parse_value(self):
        if self.i >= self.n:
            self._err("缺少值")
        c = self.s[self.i]
        if c == "\n":
            self._err("缺少值（值必须与键在同一行）")
        if c == '"':
            if self.s.startswith('"""', self.i):
                return self._parse_multiline_str(literal=False)
            self.i += 1   # 跳过开引号，_parse_basic_str 从内容起点开始
            return self._parse_basic_str(False)
        if c == "'":
            if self.s.startswith("'''", self.i):
                return self._parse_multiline_str(literal=True)
            return self._parse_literal_str()
        if self.s.startswith("true", self.i):
            self.i += 4
            return True
        if self.s.startswith("false", self.i):
            self.i += 5
            return False
        if c == "[":
            return self._parse_array()
        if c == "{":
            return self._parse_inline_table()
        m = _NUM_RE.match(self.s, self.i)
        if m:
            self.i = m.end()
            if m.group("floatpart"):
                return float(m.group(0).replace("_", ""))
            return int(m.group(0).replace("_", ""), 0)
        first3 = self.s[self.i:self.i + 3]
        if first3 in ("inf", "nan"):
            self.i += 3
            return float(first3)
        first4 = self.s[self.i:self.i + 4]
        if first4 in ("-inf", "+inf", "-nan", "+nan"):
            self.i += 4
            return float(first4)
        self._err("非法值（不支持日期 / 时间等类型）")

    def _parse_array(self):
        self.i += 1   # 吃掉 '['
        out = []
        self._skip_comment_nl()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self._parse_value())
            self._skip_comment_nl()
            if self.i < self.n and self.s[self.i] == "]":
                self.i += 1
                return out
            if self.i >= self.n or self.s[self.i] != ",":
                self._err("数组未闭合")
            self.i += 1
            self._skip_comment_nl()
            if self.i < self.n and self.s[self.i] == "]":
                self.i += 1
                return out

    def _parse_inline_table(self):
        self.i += 1   # 吃掉 '{'
        out = {}
        flags = _Flags()
        self._skip_ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return out
        while True:
            key, value = self._parse_key_value_pair()
            if flags.is_(key, _FROZEN):
                self._err("不能修改内联表 / 数组")
            parent = key[:-1]
            node = out
            for k in parent:
                if k not in node:
                    node[k] = {}
                node = node[k]
                if not isinstance(node, dict):
                    self._err("不能覆盖已有值")
            if key[-1] in node:
                self._err("键 '%s' 重复定义" % key[-1])
            node[key[-1]] = value
            self._skip_ws()
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                return out
            if self.i >= self.n or self.s[self.i] != ",":
                self._err("内联表未闭合")
            if isinstance(value, (dict, list)):
                flags.set(key, _FROZEN, recursive=True)
            self.i += 1
            self._skip_ws()

    # ---------------- 字符串 ----------------
    def _parse_basic_str(self, multiline):
        if multiline:
            error_on = _ILLEGAL_MULTILINE
        else:
            error_on = _ILLEGAL_BASIC
        out = []
        start = self.i
        while True:
            if self.i >= self.n:
                self._err("字符串未闭合")
            c = self.s[self.i]
            if c == '"':
                if not multiline:
                    out.append(self.s[start:self.i])
                    self.i += 1
                    return "".join(out)
                if self.s.startswith('"""', self.i):
                    out.append(self.s[start:self.i])
                    self.i += 3
                    return "".join(out)
                self.i += 1
                continue
            if c == "\\":
                out.append(self.s[start:self.i])
                self.i += 1
                out.append(self._parse_escape(multiline))
                start = self.i
                continue
            if c in error_on:
                self._err("字符串中包含非法控制字符")
            self.i += 1

    def _parse_escape(self, multiline):
        """self.i 已指向 '\\' 之后第一个字符。"""
        if self.i >= self.n:
            self._err("转义符不完整")
        c = self.s[self.i]
        if multiline and c in " \t\n":
            # 行尾反斜杠：吞掉后续空白与换行（含空行）；反斜杠后若为空白，
            # 空白之后必须是换行（对齐 tomllib 的 multiline 折行规则）
            if c == "\n":
                self.i += 1
            else:
                while self.i < self.n and self.s[self.i] in _WS:
                    self.i += 1
                if self.i >= self.n or self.s[self.i] != "\n":
                    self._err("字符串中出现未转义的反斜杠")
                self.i += 1
            while self.i < self.n and self.s[self.i] in _WS_NL:
                self.i += 1
            return ""
        two = self.s[self.i - 1:self.i + 1]
        if two == "\\u":
            self.i += 1
            return self._parse_hex_char(4)
        if two == "\\U":
            self.i += 1
            return self._parse_hex_char(8)
        if two in _ESCAPES:
            self.i += 1
            return _ESCAPES[two]
        self._err("无效的转义 '\\%s'" % c)

    def _parse_hex_char(self, width):
        """self.i 指向十六进制数字起点。"""
        h = self.s[self.i:self.i + width]
        if len(h) != width or not _HEXDIGITS.issuperset(h):
            self._err("无效的 Unicode 转义")
        cp = int(h, 16)
        if not (0 <= cp <= 55295 or 57344 <= cp <= 1114111):
            self._err("转义字符不是合法的 Unicode 码位")
        self.i += width
        return chr(cp)

    def _parse_literal_str(self):
        self.i += 1   # 吃掉开头的 '
        start = self.i
        while True:
            if self.i >= self.n:
                self._err("字符串未闭合")
            c = self.s[self.i]
            if c == "'":
                out = self.s[start:self.i]
                self.i += 1
                return out
            if c in _ILLEGAL_BASIC:
                self._err("字符串中包含非法控制字符")
            self.i += 1

    def _parse_multiline_str(self, literal):
        self.i += 3
        if self.i < self.n and self.s[self.i] == "\n":
            self.i += 1
        if literal:
            end = self.s.find("'''", self.i)
            if end < 0:
                self._err("多行字符串未闭合")
            out = self.s[self.i:end]
            for j in range(self.i, end):
                if self.s[j] in _ILLEGAL_MULTILINE:
                    self.i = j
                    self._err("字符串中包含非法控制字符")
            self.i = end + 3
            delim = "'"
        else:
            out = self._parse_basic_str(True)
            delim = '"'
        # 结尾处 4 / 5 个引号：多出的 1-2 个属于字符串内容
        if self.i < self.n and self.s[self.i] == delim:
            self.i += 1
            if self.i < self.n and self.s[self.i] == delim:
                self.i += 1
                return out + delim * 2
            return out + delim
        return out


# ==================== 生成（dict -> TOML 文本） ====================
def _quote(s):
    """按 TOML 基本字符串规则转义输出。"""
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _fmt_key(k):
    k = str(k)
    if k and _BARE_KEY_CHARS.issuperset(k):
        return k
    return _quote(k)


def _fmt_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, str):
        return _quote(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v:
            return "nan"
        if v == float("inf"):
            return "inf"
        if v == float("-inf"):
            return "-inf"
        r = repr(v)
        if "." not in r and "e" not in r and "E" not in r:
            r += ".0"
        return r
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_fmt_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join("%s = %s" % (_fmt_key(k), _fmt_value(x))
                               for k, x in v.items()) + "}"
    # 兜底：其余类型按字符串输出（TOML 无 null；None 由 _dump_table 跳过）
    return _quote(str(v))


def _dump_table(data, path, lines):
    keys = [k for k in data.keys() if data[k] is not None]
    scalars, tables, arrays = [], [], []
    for k in keys:
        v = data[k]
        if isinstance(v, dict):
            tables.append((k, v))
        elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            arrays.append((k, v))
        else:
            scalars.append((k, v))

    for k, v in scalars:
        lines.append("%s = %s" % (_fmt_key(k), _fmt_value(v)))
    for k, v in tables:
        child = path + [k]
        if lines:
            lines.append("")
        lines.append("[%s]" % ".".join(_fmt_key(x) for x in child))
        _dump_table(v, child, lines)
    for k, v in arrays:
        child = path + [k]
        for elem in v:
            if lines:
                lines.append("")
            lines.append("[[%s]]" % ".".join(_fmt_key(x) for x in child))
            _dump_table(elem, child, lines)


def dumps(data):
    """把 dict 序列化为 TOML 文本（保持键顺序；值为 None 的键跳过）。"""
    if not isinstance(data, dict):
        raise TomlError("dumps 仅支持 dict 根对象")
    lines = []
    _dump_table(data, [], lines)
    if not lines:
        return ""
    return "\n".join(lines).rstrip() + "\n"


# ==================== 对外接口 ====================
def loads(s):
    """解析 TOML 文本，返回 dict；失败抛 TomlError。"""
    return _Parser(s).parse()


def load(fp):
    """从文件对象读取并解析（文本模式；bytes 亦可）。"""
    return loads(fp.read())


def dump(obj, fp):
    """把 dict 写入文件对象。"""
    fp.write(dumps(obj))
