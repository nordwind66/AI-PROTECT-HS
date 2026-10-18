"""miniyaml -- a small, strict, *safe* YAML-subset loader (stdlib only).

Why this exists: the build machine must not need PyYAML, and `yaml.load` on untrusted input is
unsafe. This loader NEVER constructs arbitrary objects. It supports exactly what the upstream rule
repositories use and fails loudly (YamlError) on anything it does not understand instead of
silently mis-parsing:

  supported   block mappings / block sequences (indentation based, incl. "- key: value" items and
              sequences at the same indent as their parent key), plain / 'single' / "double" quoted
              scalars (multi-line folding, all YAML escapes), literal (|) and folded (>) block
              scalars with chomping and indentation indicators, flow [..] and {..} collections,
              comments, a single leading '---'.
  scalars     null/bool/int/float are resolved like PyYAML's YAML-1.1 safe resolver, EXCEPT that
              ISO timestamps and sexagesimal numbers stay strings, and mapping KEYS are always kept
              as strings.
  rejected    anchors/aliases (&a *a), tags (!!x), complex keys (?), multiple documents, tab
              indentation, merge keys.

`load(text)` -> python object; `load_with_locs(text)` additionally returns {path_tuple: line_no}
so importers can record the source line of every key / list item (provenance).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["YamlError", "load", "load_with_locs", "load_full"]


class YamlError(ValueError):
    def __init__(self, message: str, line: Optional[int] = None):
        self.line = line
        super().__init__(f"line {line}: {message}" if line else message)


# ---------------------------------------------------------------------------------------------
# scalar resolution (mirrors PyYAML's safe resolver for the types we care about)
# ---------------------------------------------------------------------------------------------
_NULLS = {"~", "null", "Null", "NULL", ""}
_TRUES = {"true", "True", "TRUE", "yes", "Yes", "YES", "on", "On", "ON"}
_FALSES = {"false", "False", "FALSE", "no", "No", "NO", "off", "Off", "OFF"}
_INT_RE = re.compile(r"^[-+]?(0|[1-9][0-9_]*)$")
_HEX_RE = re.compile(r"^[-+]?0x[0-9a-fA-F_]+$")
_BIN_RE = re.compile(r"^[-+]?0b[01_]+$")
_OCT_RE = re.compile(r"^[-+]?0[0-7_]+$")
_FLOAT_RE = re.compile(r"^[-+]?([0-9][0-9_]*)\.[0-9_]*([eE][-+][0-9]+)?$|^[-+]?\.[0-9][0-9_]*([eE][-+][0-9]+)?$")
_INF_RE = re.compile(r"^[-+]?\.(inf|Inf|INF)$")
_NAN_RE = re.compile(r"^\.(nan|NaN|NAN)$")


def _resolve_plain(s: str) -> Any:
    if s in _NULLS:
        return None
    if s in _TRUES:
        return True
    if s in _FALSES:
        return False
    if _INT_RE.match(s):
        return int(s.replace("_", ""))
    if _HEX_RE.match(s):
        return int(s.replace("_", ""), 16)
    if _BIN_RE.match(s):
        return int(s.replace("_", ""), 2)
    if _OCT_RE.match(s):
        return int(s.replace("_", ""), 8)
    if _FLOAT_RE.match(s):
        return float(s.replace("_", ""))
    if _INF_RE.match(s):
        return float("-inf") if s.startswith("-") else float("inf")
    if _NAN_RE.match(s):
        return float("nan")
    return s


# ---------------------------------------------------------------------------------------------
# quoted scalars
# ---------------------------------------------------------------------------------------------
_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
    "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85",
    "_": "\xa0", "L": " ", "P": " ",
}


def _find_double_end(buf: str, start: int) -> int:
    """index of the closing '"' for a double-quoted scalar whose opening quote is at start."""
    i = start + 1
    n = len(buf)
    while i < n:
        c = buf[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i
        i += 1
    return -1


def _find_single_end(buf: str, start: int) -> int:
    i = start + 1
    n = len(buf)
    while i < n:
        if buf[i] == "'":
            if i + 1 < n and buf[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _fold_break(out: List[str], raw: str, i: int, protect: int) -> int:
    """Handle a physical line break at raw[i] == '\\n' inside a quoted scalar. Returns new i."""
    n = len(raw)
    while len(out) > protect and out[-1] in " \t":
        out.pop()
    blank = 0
    i += 1  # consume the first newline
    while True:
        j = i
        while j < n and raw[j] in " \t":
            j += 1
        if j < n and raw[j] == "\n":
            blank += 1
            i = j + 1
            continue
        i = j
        break
    out.append(" " if blank == 0 else "\n" * blank)
    return i


def _decode_double(raw: str, line: int) -> str:
    out: List[str] = []
    protect = 0
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 1
            if i >= n:
                raise YamlError("dangling backslash in double-quoted scalar", line)
            e = raw[i]
            if e == "\n":
                i += 1
                while i < n and raw[i] in " \t":
                    i += 1
                continue
            if e in ("x", "u", "U"):
                width = {"x": 2, "u": 4, "U": 8}[e]
                digits = raw[i + 1:i + 1 + width]
                if len(digits) != width or not re.match(r"^[0-9a-fA-F]+$", digits):
                    raise YamlError(f"bad \\{e} escape in double-quoted scalar", line)
                cp = int(digits, 16)
                if cp > 0x10FFFF:
                    raise YamlError("escape beyond U+10FFFF", line)
                out.append(chr(cp))
                i += 1 + width
                protect = len(out)
                continue
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                i += 1
                protect = len(out)
                continue
            raise YamlError(f"unknown escape \\{e} in double-quoted scalar", line)
        if c == "\n":
            i = _fold_break(out, raw, i, protect)
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _decode_single(raw: str, line: int) -> str:
    out: List[str] = []
    protect = 0
    i = 0
    n = len(raw)
    while i < n:
        c = raw[i]
        if c == "'" and i + 1 < n and raw[i + 1] == "'":
            out.append("'")
            i += 2
            protect = len(out)
            continue
        if c == "\n":
            i = _fold_break(out, raw, i, protect)
            continue
        out.append(c)
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------------------------
# lines
# ---------------------------------------------------------------------------------------------
class _Line:
    __slots__ = ("no", "indent", "text", "raw")

    def __init__(self, no: int, indent: int, text: str, raw: str):
        self.no = no
        self.indent = indent
        self.text = text
        self.raw = raw

    def blank(self) -> bool:
        return self.text == "" or self.text.startswith("#")


def _strip_comment(s: str) -> str:
    """Remove a trailing ' #...' comment from an unquoted fragment."""
    if s.startswith("#"):
        return ""
    idx = s.find(" #")
    if idx != -1:
        return s[:idx].rstrip()
    return s.rstrip()


_BAD_PLAIN_START = set("@`")


class _Parser:
    def __init__(self, text: str):
        if text.startswith("﻿"):
            text = text[1:]
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        self.lines: List[_Line] = []
        for no, raw in enumerate(text.split("\n"), start=1):
            stripped = raw.lstrip(" ")
            indent = len(raw) - len(stripped)
            self.lines.append(_Line(no, indent, stripped.rstrip(), raw))
        self.pos = 0
        self.locs: Dict[Tuple, int] = {}
        self.warnings: List[Tuple[int, str]] = []

    # ---- navigation ------------------------------------------------------------------------
    def _skip_blank(self) -> None:
        while self.pos < len(self.lines) and self.lines[self.pos].blank():
            self.pos += 1

    def _peek(self) -> Optional[_Line]:
        self._skip_blank()
        if self.pos >= len(self.lines):
            return None
        ln = self.lines[self.pos]
        if ln.text.startswith("\t"):
            # tabs are legal inside content but never as block indentation
            raise YamlError("tab character used for indentation", ln.no)
        return ln

    # ---- document ---------------------------------------------------------------------------
    def parse_document(self) -> Any:
        # directives / document start
        self._skip_blank()
        while self.pos < len(self.lines) and self.lines[self.pos].text.startswith("%"):
            self.pos += 1
            self._skip_blank()
        if self.pos < len(self.lines) and self.lines[self.pos].text.startswith("---"):
            first = self.lines[self.pos].text
            if first == "---" or first.startswith("--- "):
                rest = first[3:].strip()
                if rest and not rest.startswith("#"):
                    # content on the marker line: turn it into a normal top-level line
                    ln = self.lines[self.pos]
                    self.lines[self.pos] = _Line(ln.no, 0, rest, rest)
                else:
                    self.pos += 1
        node = self._parse_block(0, ())
        self._skip_blank()
        if self.pos < len(self.lines):
            ln = self.lines[self.pos]
            if ln.text == "..." or ln.text.startswith("... "):
                return node
            if ln.text == "---" or ln.text.startswith("--- "):
                raise YamlError("multiple YAML documents are not supported", ln.no)
            raise YamlError(f"unexpected content (bad indentation?): {ln.text[:60]!r}", ln.no)
        return node

    # ---- block nodes ---------------------------------------------------------------------
    def _parse_block(self, min_indent: int, path: Tuple) -> Any:
        ln = self._peek()
        if ln is None or ln.indent < min_indent:
            return None
        if ln.text == "..." or ln.text.startswith("--- ") or ln.text == "---":
            return None
        self.locs.setdefault(path, ln.no)
        if ln.text == "-" or ln.text.startswith("- "):
            return self._parse_sequence(ln.indent, path)
        if self._split_key(ln.text) is not None:
            return self._parse_mapping(ln.indent, path)
        # a bare scalar / flow / quoted node
        self.pos += 1
        return self._parse_value_text(ln.text, ln, ln.indent - 1, path, in_seq_item=False)

    def _parse_sequence(self, indent: int, path: Tuple) -> List[Any]:
        result: List[Any] = []
        while True:
            ln = self._peek()
            if ln is None or ln.indent != indent or not (ln.text == "-" or ln.text.startswith("- ")):
                if ln is not None and ln.indent > indent:
                    raise YamlError(f"bad indentation inside sequence: {ln.text[:60]!r}", ln.no)
                break
            idx = len(result)
            item_path = path + (idx,)
            self.locs[item_path] = ln.no
            after = ln.text[1:]
            stripped = after.lstrip(" ")
            virt = indent + 1 + (len(after) - len(stripped))
            rest = stripped
            if rest == "" or rest.startswith("#"):
                self.pos += 1
                nxt = self._peek()
                if nxt is not None and nxt.indent > indent:
                    result.append(self._parse_block(indent + 1, item_path))
                else:
                    result.append(None)
                continue
            if rest == "-" or rest.startswith("- "):
                self.lines[self.pos] = _Line(ln.no, virt, rest, " " * virt + rest)
                result.append(self._parse_sequence(virt, item_path))
                continue
            if self._split_key(rest) is not None:
                self.lines[self.pos] = _Line(ln.no, virt, rest, " " * virt + rest)
                result.append(self._parse_mapping(virt, item_path))
                continue
            self.pos += 1
            result.append(self._parse_value_text(rest, ln, indent, item_path, in_seq_item=True))
        return result

    def _parse_mapping(self, indent: int, path: Tuple) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        while True:
            ln = self._peek()
            if ln is None or ln.indent != indent:
                if ln is not None and ln.indent > indent:
                    raise YamlError(f"bad indentation inside mapping: {ln.text[:60]!r}", ln.no)
                break
            if ln.text == "-" or ln.text.startswith("- "):
                break
            split = self._split_key(ln.text)
            if split is None:
                if ln.text.startswith(("---", "...")):
                    break
                raise YamlError(f"expected 'key: value', got {ln.text[:60]!r}", ln.no)
            key, rest = split
            if key == "<<":
                raise YamlError("merge keys ('<<') are not supported", ln.no)
            if key in result:
                self.warnings.append((ln.no, f"duplicate mapping key {key!r} (last value wins, like PyYAML)"))
            value_path = path + (key,)
            self.locs[value_path] = ln.no
            self.pos += 1
            if rest == "" or rest.startswith("#"):
                nxt = self._peek()
                if nxt is not None and nxt.indent > indent:
                    result[key] = self._parse_block(indent + 1, value_path)
                elif nxt is not None and nxt.indent == indent and (nxt.text == "-" or nxt.text.startswith("- ")):
                    result[key] = self._parse_sequence(indent, value_path)
                else:
                    result[key] = None
            else:
                result[key] = self._parse_value_text(rest, ln, indent, value_path, in_seq_item=False)
        return result

    # ---- keys ----------------------------------------------------------------------------
    def _split_key(self, text: str, strict: bool = True) -> Optional[Tuple[str, str]]:
        """If `text` starts with a mapping key return (key, rest_after_colon) else None.

        strict=False is used for continuation lines of multi-line plain scalars, where any
        character (including '!', '&', '*') may legally start the line."""
        if not text or text[0] in "[{!&*|>%@`#?" or text[0] in _BAD_PLAIN_START:
            if strict and text and text[0] == "?" and (len(text) == 1 or text[1] == " "):
                raise YamlError("complex mapping keys ('? ') are not supported")
            if strict and text and text[0] in "&*!":
                # an anchor/alias/tag in key position
                raise YamlError(f"anchors, aliases and tags are not supported: {text[:30]!r}")
            return None
        if text[0] == '"' or text[0] == "'":
            end = _find_double_end(text, 0) if text[0] == '"' else _find_single_end(text, 0)
            if end == -1:
                return None
            after = text[end + 1:].lstrip(" ")
            if after.startswith(":") and (len(after) == 1 or after[1] == " "):
                inner = text[1:end]
                key = _decode_double(inner, 0) if text[0] == '"' else _decode_single(inner, 0)
                return key, after[1:].lstrip(" ")
            return None
        if ":" not in text:
            return None
        n = len(text)
        i = 0
        while i < n:
            c = text[i]
            if c == ":" and (i + 1 == n or text[i + 1] == " "):
                key = text[:i].rstrip()
                if key == "":
                    return None
                return key, text[i + 1:].lstrip(" ")
            if c == "#" and i > 0 and text[i - 1] == " ":
                return None
            i += 1
        return None

    # ---- values --------------------------------------------------------------------------
    def _parse_value_text(self, rest: str, ln: _Line, parent_indent: int, path: Tuple,
                          in_seq_item: bool) -> Any:
        """Parse the value that begins with `rest` on line `ln` (already consumed)."""
        c = rest[0]
        if c in "|>":
            return self._parse_block_scalar(rest, ln, parent_indent)
        if c == '"' or c == "'":
            return self._parse_quoted(rest, ln)
        if c in "[{":
            return self._parse_flow_start(rest, ln)
        if c in "&*!":
            raise YamlError(f"anchors, aliases and tags are not supported: {rest[:30]!r}", ln.no)
        if c in _BAD_PLAIN_START:
            raise YamlError(f"reserved indicator {c!r} at start of plain scalar", ln.no)
        if c == "%":
            raise YamlError("'%' cannot start a plain scalar", ln.no)
        if c == "-" and (len(rest) == 1 or rest[1] == " "):
            raise YamlError("unexpected sequence entry", ln.no)
        return self._parse_plain(rest, ln, parent_indent)

    def _parse_plain(self, rest: str, ln: _Line, parent_indent: int) -> Any:
        first = _strip_comment(rest)
        if self._split_key(first, strict=False) is not None:
            raise YamlError(f"mapping values are not allowed here: {first[:60]!r}", ln.no)
        parts = [first]
        trailing_comment = first != rest.rstrip()
        if not trailing_comment:
            blanks = 0
            while self.pos < len(self.lines):
                nxt = self.lines[self.pos]
                if nxt.text == "":
                    blanks += 1
                    self.pos += 1
                    continue
                if nxt.text.startswith("#") or nxt.indent <= parent_indent:
                    break
                if nxt.text in ("---", "...") and nxt.indent == 0:
                    break
                piece = _strip_comment(nxt.text)
                if self._split_key(piece, strict=False) is not None:
                    raise YamlError(f"mapping values are not allowed here: {piece[:60]!r}", nxt.no)
                if blanks:
                    parts.append("\n" * blanks)
                parts.append(piece)
                blanks = 0
                self.pos += 1
                if piece != nxt.text.rstrip():
                    break
            # rewind over trailing blank lines is unnecessary: blanks carry no content
        if len(parts) == 1:
            return _resolve_plain(first)
        text = ""
        for p in parts:
            if p.startswith("\n"):
                text += p
            elif text == "" or text.endswith("\n"):
                text += p
            else:
                text += " " + p
        return text

    def _gather_until(self, rest: str, ln: _Line, finder) -> Tuple[str, int, str]:
        """Collect physical lines until finder(buf) returns the end index of the quoted scalar.

        Returns (raw_inner, end_line_no, tail)."""
        buf = rest
        end = finder(buf, 0)
        last_no = ln.no
        while end == -1:
            if self.pos >= len(self.lines):
                raise YamlError("unterminated quoted scalar", ln.no)
            nxt = self.lines[self.pos]
            self.pos += 1
            buf += "\n" + nxt.raw
            last_no = nxt.no
            end = finder(buf, 0)
        inner = buf[1:end]
        tail = buf[end + 1:]
        return inner, last_no, tail

    def _parse_quoted(self, rest: str, ln: _Line) -> str:
        if rest[0] == '"':
            inner, last_no, tail = self._gather_until(rest, ln, _find_double_end)
            value = _decode_double(inner, ln.no)
        else:
            inner, last_no, tail = self._gather_until(rest, ln, _find_single_end)
            value = _decode_single(inner, ln.no)
        tail = tail.strip()
        if tail and not tail.startswith("#"):
            raise YamlError(f"unexpected text after quoted scalar: {tail[:40]!r}", last_no)
        return value

    # ---- block scalars ---------------------------------------------------------------------
    def _parse_block_scalar(self, header: str, ln: _Line, parent_indent: int) -> str:
        style = header[0]
        m = re.match(r"^[|>]([-+]?)([1-9]?)([-+]?)\s*(#.*)?$", header)
        if not m:
            raise YamlError(f"bad block scalar header {header[:30]!r}", ln.no)
        chomp = m.group(1) or m.group(3) or ""
        explicit = int(m.group(2)) if m.group(2) else None
        base = max(parent_indent, 0) if parent_indent >= 0 else 0
        block_indent: Optional[int] = None
        if explicit is not None:
            block_indent = base + explicit
        body: List[str] = []  # content lines (already de-indented); None marker for blank
        start_pos = self.pos
        while self.pos < len(self.lines):
            cur = self.lines[self.pos]
            raw = cur.raw
            if raw.strip(" ") == "":
                body.append("")
                self.pos += 1
                continue
            if block_indent is None:
                if cur.indent <= parent_indent:
                    break
                block_indent = cur.indent
            if cur.indent < block_indent:
                break
            body.append(raw[block_indent:])
            self.pos += 1
        # trailing blank lines belong to the chomping decision, not to the content
        trailing = 0
        while body and body[-1] == "":
            body.pop()
            trailing += 1
        # give back blank lines to the stream (they carry no information for the parser)
        if not body:
            text = ""
            if chomp == "+":
                text = "\n" * trailing
            return text
        if style == "|":
            text = "\n".join(body)
        else:
            text = self._fold(body)
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * (1 + trailing)
        return text + "\n"

    @staticmethod
    def _fold(body: List[str]) -> str:
        out: List[str] = []
        prev_more = False
        i = 0
        n = len(body)
        pending_breaks = 0
        first = True
        while i < n:
            line = body[i]
            if line == "":
                pending_breaks += 1
                i += 1
                continue
            more = line[0] in " \t"
            if first:
                out.append(line)
                first = False
            else:
                if pending_breaks == 0:
                    out.append("\n" if (more or prev_more) else " ")
                else:
                    out.append("\n" * (pending_breaks + (1 if (more or prev_more) else 0)))
                out.append(line)
            pending_breaks = 0
            prev_more = more
            i += 1
        return "".join(out)

    # ---- flow collections -----------------------------------------------------------------
    def _parse_flow_start(self, rest: str, ln: _Line) -> Any:
        buf = rest
        while True:
            depth, complete = self._flow_state(buf)
            if complete:
                break
            if self.pos >= len(self.lines):
                raise YamlError("unterminated flow collection", ln.no)
            nxt = self.lines[self.pos]
            self.pos += 1
            buf += "\n" + nxt.text
        fp = _FlowParser(buf, ln.no)
        value = fp.parse()
        return value

    @staticmethod
    def _flow_state(buf: str) -> Tuple[int, bool]:
        depth = 0
        i = 0
        n = len(buf)
        seen = False
        while i < n:
            c = buf[i]
            if c == '"':
                e = _find_double_end(buf, i)
                if e == -1:
                    return depth, False
                i = e + 1
                continue
            if c == "'":
                e = _find_single_end(buf, i)
                if e == -1:
                    return depth, False
                i = e + 1
                continue
            if c == "#" and i > 0 and buf[i - 1] in " \n":
                while i < n and buf[i] != "\n":
                    i += 1
                continue
            if c in "[{":
                depth += 1
                seen = True
            elif c in "]}":
                depth -= 1
            i += 1
        return depth, seen and depth <= 0


class _FlowParser:
    def __init__(self, text: str, line: int):
        self.s = text
        self.i = 0
        self.line = line

    def _ws(self) -> None:
        s = self.s
        n = len(s)
        while self.i < n:
            if s[self.i] in " \t\n":
                self.i += 1
            elif s[self.i] == "#" and (self.i == 0 or s[self.i - 1] in " \t\n"):
                while self.i < n and s[self.i] != "\n":
                    self.i += 1
            else:
                break

    def parse(self) -> Any:
        node = self._node()
        self._ws()
        if self.i != len(self.s):
            raise YamlError(f"unexpected text after flow collection: {self.s[self.i:self.i + 30]!r}", self.line)
        return node

    def _node(self, in_map_key: bool = False) -> Any:
        self._ws()
        if self.i >= len(self.s):
            raise YamlError("unexpected end of flow collection", self.line)
        c = self.s[self.i]
        if c == "[":
            return self._seq()
        if c == "{":
            return self._map()
        if c == '"':
            e = _find_double_end(self.s, self.i)
            if e == -1:
                raise YamlError("unterminated double-quoted scalar in flow collection", self.line)
            val = _decode_double(self.s[self.i + 1:e], self.line)
            self.i = e + 1
            return val
        if c == "'":
            e = _find_single_end(self.s, self.i)
            if e == -1:
                raise YamlError("unterminated single-quoted scalar in flow collection", self.line)
            val = _decode_single(self.s[self.i + 1:e], self.line)
            self.i = e + 1
            return val
        if c in "&*!":
            raise YamlError("anchors, aliases and tags are not supported", self.line)
        start = self.i
        n = len(self.s)
        while self.i < n:
            ch = self.s[self.i]
            if ch in ",]}":
                break
            if ch == ":" and (self.i + 1 >= n or self.s[self.i + 1] in " ,]}\n"):
                break
            if ch == "#" and self.i > start and self.s[self.i - 1] in " \t":
                break
            self.i += 1
        token = self.s[start:self.i].strip()
        return _resolve_plain(token) if not in_map_key else token

    def _seq(self) -> List[Any]:
        self.i += 1
        out: List[Any] = []
        while True:
            self._ws()
            if self.i >= len(self.s):
                raise YamlError("unterminated flow sequence", self.line)
            if self.s[self.i] == "]":
                self.i += 1
                return out
            item = self._node()
            self._ws()
            if self.i < len(self.s) and self.s[self.i] == ":":
                raise YamlError("single-pair mappings inside flow sequences are not supported", self.line)
            out.append(item)
            self._ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1

    def _map(self) -> Dict[str, Any]:
        self.i += 1
        out: Dict[str, Any] = {}
        while True:
            self._ws()
            if self.i >= len(self.s):
                raise YamlError("unterminated flow mapping", self.line)
            if self.s[self.i] == "}":
                self.i += 1
                return out
            key = self._node(in_map_key=True)
            self._ws()
            if self.i < len(self.s) and self.s[self.i] == ":":
                self.i += 1
                val = self._node()
            else:
                val = None
            if not isinstance(key, str):
                key = str(key)
            if key in out:
                raise YamlError(f"duplicate mapping key {key!r}", self.line)
            out[key] = val
            self._ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1


def load(text: str) -> Any:
    """Parse `text` and return the python object (dict/list/str/int/float/bool/None)."""
    return _Parser(text).parse_document()


def load_with_locs(text: str) -> Tuple[Any, Dict[Tuple, int]]:
    """Like load() but also return {key-path tuple: 1-based line number}."""
    p = _Parser(text)
    node = p.parse_document()
    return node, p.locs


def load_full(text: str) -> Tuple[Any, Dict[Tuple, int], List[Tuple[int, str]]]:
    """Return (object, locations, warnings). Warnings are non-fatal oddities (duplicate keys)."""
    p = _Parser(text)
    node = p.parse_document()
    return node, p.locs, p.warnings
