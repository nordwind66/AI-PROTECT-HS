"""regexkit -- parse, analyse, translate and canonicalise regular expressions.

Upstream rules are written for different engines:
  * "es"  -- ECMAScript RegExp (Agent Threat Rules; normative per ATR SPEC 6.4)
  * "py"  -- Python `re` (trans-prompt-injection-detector, prompt-injection-detection-rules)
  * "pcre"-- PCRE/Hyperscan syntax (rules added manually; no translation applied)

The engine that finally executes them is Hyperscan (HS_FLAG_UTF8) with PCRE2 as exact verifier,
whose syntax is PCRE-like. This module therefore
  1. parses the source expression into an AST (RegexError on anything it cannot represent),
  2. applies *semantics-preserving* dialect fixes (ES `.` / `$` / `\\s`, \\uXXXX escapes ...),
  3. extracts feature flags (lookaround, backreference, atomic group ...) that decide whether a
     pattern can be compiled natively by Hyperscan or needs prefilter + PCRE2 verification,
  4. optionally prunes alternatives that belong to non-target languages,
  5. emits a canonical PCRE-compatible string (the thing that is stored, hashed, de-duplicated and
     compiled).
Nothing here executes upstream code; `re` is used only by tests as a sanity oracle.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

__all__ = [
    "RegexError", "parse", "emit", "analyse", "es_fidelity", "prune_alternatives", "script_of",
    "literal_words", "literal_runs", "literal_scripts", "ParsedRegex", "Features",
    "split_scoped_alternatives", "has_scoped_flags", "to_python_re", "iter_nodes", "width_range",
    "variable_width_lookbehind", "py_fidelity", "fix_surrogates", "distribute_lookbehinds",
]


class RegexError(ValueError):
    pass


# =============================================================================================
# AST
# =============================================================================================
class Node:
    pass


@dataclass
class Lit(Node):
    cp: int


@dataclass
class Dot(Node):
    pass


@dataclass
class Esc(Node):
    kind: str            # d D w W s S


@dataclass
class Prop(Node):
    name: str
    negated: bool = False


@dataclass
class Anchor(Node):
    kind: str            # ^ $ b B A z Z


@dataclass
class Cls(Node):
    negated: bool
    items: List[tuple]   # ("r", lo, hi) | ("e", letter) | ("p", name, negated)


@dataclass
class Group(Node):
    kind: str            # cap nocap named la nla lb nlb atomic flags
    body: Node
    name: Optional[str] = None
    on: str = ""
    off: str = ""


@dataclass
class Backref(Node):
    ref: Union[int, str]


@dataclass
class Quant(Node):
    body: Node
    lo: int
    hi: Optional[int]    # None = unbounded
    mode: str = "greedy"  # greedy lazy possessive


@dataclass
class Seq(Node):
    items: List[Node]


@dataclass
class Alt(Node):
    branches: List[Node]


@dataclass
class ParsedRegex:
    node: Node
    dialect: str
    flags: str                       # effective global flags subset of "imsu" (sorted)
    ncap: int
    notes: List[str] = field(default_factory=list)


# =============================================================================================
# Unicode helpers
# =============================================================================================
def script_of(cp: int) -> str:
    """Coarse script classification (enough to tell target languages from the others)."""
    if cp < 0x80:
        return "latin" if (0x41 <= cp <= 0x5A or 0x61 <= cp <= 0x7A) else "common"
    if 0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF or 0xF900 <= cp <= 0xFAFF \
            or 0x20000 <= cp <= 0x2FA1F or 0x2E80 <= cp <= 0x2FDF or 0x3007 == cp:
        return "han"
    if 0x3040 <= cp <= 0x30FF or 0x31F0 <= cp <= 0x31FF or 0xFF66 <= cp <= 0xFF9F:
        return "kana"
    if 0xAC00 <= cp <= 0xD7AF or 0x1100 <= cp <= 0x11FF or 0x3130 <= cp <= 0x318F:
        return "hangul"
    if 0x0400 <= cp <= 0x052F or 0x1C80 <= cp <= 0x1C8F or 0x2DE0 <= cp <= 0x2DFF or 0xA640 <= cp <= 0xA69F:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF or 0x1F00 <= cp <= 0x1FFF:
        return "greek"
    if 0x0600 <= cp <= 0x06FF or 0x0750 <= cp <= 0x077F or 0xFB50 <= cp <= 0xFDFF or 0xFE70 <= cp <= 0xFEFE:
        return "arabic"            # (U+FEFF, the BOM / zero-width no-break space, is NOT Arabic)
    if 0x0590 <= cp <= 0x05FF:
        return "hebrew"
    if 0x0900 <= cp <= 0x097F:
        return "devanagari"
    if 0x0E00 <= cp <= 0x0E7F:
        return "thai"
    ch = chr(cp)
    cat = unicodedata.category(ch)
    if cat.startswith("L"):
        return "latin"      # accented Latin letters, Latin extended ...
    return "common"


_ES_SPACE_EXTRA = [0x00A0, 0x1680, (0x2000, 0x200A), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF]
_ES_LINE_TERMINATORS = [0x0A, 0x0D, 0x2028, 0x2029]


# =============================================================================================
# Parser
# =============================================================================================
_HEX = "0123456789abcdefABCDEF"


class _Parser:
    def __init__(self, src: str, dialect: str):
        self.s = src
        self.i = 0
        self.n = len(src)
        self.dialect = dialect
        self.ncap = 0
        self.names: Dict[str, int] = {}
        self.notes: List[str] = []
        self.max_backref = 0
        self.named_backrefs: List[str] = []

    # ---- helpers ------------------------------------------------------------------------
    def err(self, msg: str) -> RegexError:
        return RegexError(f"{msg} (at offset {self.i} of {self.n})")

    def peek(self) -> str:
        return self.s[self.i] if self.i < self.n else ""

    def take(self) -> str:
        ch = self.s[self.i]
        self.i += 1
        return ch

    def starts(self, text: str) -> bool:
        return self.s.startswith(text, self.i)

    # ---- grammar -------------------------------------------------------------------------
    def parse(self) -> Node:
        node = self.alt()
        if self.i < self.n:
            raise self.err("unmatched ')'")
        if self.max_backref > self.ncap:
            raise self.err(f"backreference \\{self.max_backref} to a group that does not exist")
        for nm in self.named_backrefs:
            if nm not in self.names:
                raise self.err(f"backreference to unknown group name {nm!r}")
        return node

    def alt(self) -> Node:
        branches = [self.seq()]
        while self.peek() == "|":
            self.i += 1
            branches.append(self.seq())
        return branches[0] if len(branches) == 1 else Alt(branches)

    def seq(self) -> Node:
        items: List[Node] = []
        while self.i < self.n and self.peek() not in "|)":
            items.append(self.quantified())
        return Seq(items) if len(items) != 1 else items[0]

    def _braces(self) -> Optional[Tuple[int, Optional[int], int]]:
        """Parse {n} {n,} {n,m} {,m} at self.i. Returns (lo, hi, new_index) or None."""
        j = self.i + 1
        n = self.n
        s = self.s
        start = j
        while j < n and s[j].isdigit() and s[j].isascii():
            j += 1
        lo_txt = s[start:j]
        if j < n and s[j] == "}":
            if not lo_txt:
                return None
            return int(lo_txt), int(lo_txt), j + 1
        if j < n and s[j] == ",":
            j += 1
            start2 = j
            while j < n and s[j].isdigit() and s[j].isascii():
                j += 1
            hi_txt = s[start2:j]
            if j < n and s[j] == "}":
                if not lo_txt and not hi_txt:
                    return None
                if not lo_txt and self.dialect == "es":
                    return None          # {,n} is a literal in ECMAScript
                lo = int(lo_txt) if lo_txt else 0
                hi = int(hi_txt) if hi_txt else None
                return lo, hi, j + 1
        return None

    def quantified(self) -> Node:
        atom = self.atom()
        while True:
            ch = self.peek()
            if ch == "*":
                lo, hi = 0, None
                self.i += 1
            elif ch == "+":
                lo, hi = 1, None
                self.i += 1
            elif ch == "?":
                lo, hi = 0, 1
                self.i += 1
            elif ch == "{":
                br = self._braces()
                if br is None:
                    return atom           # literal '{' handled by the next atom() call
                lo, hi, self.i = br
                if hi is not None and hi < lo:
                    raise self.err("quantifier range out of order")
            else:
                return atom
            if isinstance(atom, Anchor) and atom.kind in "^$" and self.dialect == "es":
                raise self.err("nothing to repeat (quantified anchor)")
            mode = "greedy"
            nxt = self.peek()
            if nxt == "?":
                mode = "lazy"
                self.i += 1
            elif nxt == "+" and self.dialect != "es":
                mode = "possessive"
                self.i += 1
            atom = Quant(atom, lo, hi, mode)
            # Python/PCRE reject a quantifier directly after a quantifier ("a**"); ES too.
            if self.peek() in ("*", "+", "?") or (self.peek() == "{" and self._braces() is not None):
                raise self.err("multiple repeat")

    def atom(self) -> Node:
        ch = self.take()
        if ch == "(":
            return self.group()
        if ch == "[":
            return self.charclass()
        if ch == ".":
            return Dot()
        if ch == "^":
            return Anchor("^")
        if ch == "$":
            return Anchor("$")
        if ch == "\\":
            return self.escape_outside()
        if ch in "*+?":
            self.i -= 1
            raise self.err("nothing to repeat")
        # '{' that is not a valid quantifier, '}' and ']' are literals
        return Lit(ord(ch))

    # ---- groups --------------------------------------------------------------------------
    def group(self) -> Node:
        kind = "cap"
        name: Optional[str] = None
        on = off = ""
        if self.peek() == "?":
            self.i += 1
            c = self.peek()
            if c == ":":
                self.i += 1
                kind = "nocap"
            elif c == "=":
                self.i += 1
                kind = "la"
            elif c == "!":
                self.i += 1
                kind = "nla"
            elif c == ">":
                self.i += 1
                kind = "atomic"
            elif c == "#":
                end = self.s.find(")", self.i)
                if end == -1:
                    raise self.err("unterminated comment group")
                self.i = end + 1
                self.notes.append("comment group removed")
                return Seq([])
            elif c == "<":
                self.i += 1
                c2 = self.peek()
                if c2 == "=":
                    self.i += 1
                    kind = "lb"
                elif c2 == "!":
                    self.i += 1
                    kind = "nlb"
                else:
                    kind = "named"
                    name = self._group_name(">")
            elif c == "P":
                self.i += 1
                c2 = self.peek()
                if c2 == "<":
                    self.i += 1
                    kind = "named"
                    name = self._group_name(">")
                elif c2 == "=":
                    self.i += 1
                    nm = self._group_name(")", consume_end=False)
                    if self.peek() != ")":
                        raise self.err("unterminated (?P=name)")
                    self.i += 1
                    self.named_backrefs.append(nm)
                    return Backref(nm)
                else:
                    raise self.err("unsupported (?P construct")
            elif c == "'":
                self.i += 1
                kind = "named"
                name = self._group_name("'")
            elif c and c in "imsx-":
                kind, on, off = "flags", "", ""
                neg = False
                while self.peek() and self.peek() in "imsx-":
                    f = self.take()
                    if f == "-":
                        neg = True
                    elif neg:
                        off += f
                    else:
                        on += f
                if self.peek() == ")":
                    self.i += 1
                    return Group("flags", Seq([]), None, on, off)        # global inline flags
                if self.peek() != ":":
                    raise self.err("unsupported inline flag syntax")
                self.i += 1
            else:
                raise self.err(f"unsupported group construct (?{c}")
        if kind == "cap":
            self.ncap += 1
        elif kind == "named":
            self.ncap += 1
            if name in self.names:
                raise self.err(f"duplicate group name {name!r}")
            self.names[name or ""] = self.ncap
        body = self.alt()
        if self.peek() != ")":
            raise self.err("missing ')'")
        self.i += 1
        return Group(kind, body, name, on, off)

    def _group_name(self, end: str, consume_end: bool = True) -> str:
        j = self.i
        while j < self.n and self.s[j] != end:
            j += 1
        if j >= self.n:
            raise self.err("unterminated group name")
        nm = self.s[self.i:j]
        if not nm or not (nm[0].isalpha() or nm[0] == "_") or not all(c.isalnum() or c == "_" for c in nm):
            raise self.err(f"bad group name {nm!r}")
        self.i = j + (1 if consume_end else 0)
        return nm

    # ---- escapes -------------------------------------------------------------------------
    def _hex(self, count: int) -> int:
        digits = self.s[self.i:self.i + count]
        if len(digits) != count or any(c not in _HEX for c in digits):
            raise self.err("bad hexadecimal escape")
        self.i += count
        return int(digits, 16)

    def _braced_hex(self) -> int:
        end = self.s.find("}", self.i)
        if end == -1:
            raise self.err("unterminated \\u{...} / \\x{...}")
        digits = self.s[self.i + 1:end]
        if not digits or any(c not in _HEX for c in digits):
            raise self.err("bad braced hexadecimal escape")
        self.i = end + 1
        cp = int(digits, 16)
        if cp > 0x10FFFF:
            raise self.err("code point beyond U+10FFFF")
        return cp

    def _char_escape(self, in_class: bool) -> Tuple[str, object]:
        """Parse the part after a backslash that denotes ONE character or a class escape.

        returns ("lit", cp) | ("cls", letter) | ("prop", name, neg) | ("anchor", kind) | ("ref", ...)"""
        if self.i >= self.n:
            raise self.err("trailing backslash")
        c = self.take()
        if c in "dDwWsS":
            return ("cls", c)
        if c == "t":
            return ("lit", 9)
        if c == "n":
            return ("lit", 10)
        if c == "r":
            return ("lit", 13)
        if c == "f":
            return ("lit", 12)
        if c == "v":
            return ("lit", 11)
        if c == "a" and self.dialect != "es":
            return ("lit", 7)
        if c == "0" and not (self.peek().isdigit()):
            return ("lit", 0)
        if c == "x":
            if self.peek() == "{" and self.dialect != "es":
                return ("lit", self._braced_hex())
            return ("lit", self._hex(2))
        if c == "u":
            if self.peek() == "{":
                return ("lit", self._braced_hex())
            cp = self._hex(4)
            # join a UTF-16 surrogate pair written as two escapes
            if 0xD800 <= cp <= 0xDBFF and self.starts("\\u"):
                save = self.i
                self.i += 2
                try:
                    low = self._hex(4)
                except RegexError:
                    self.i = save
                    return ("lit", cp)
                if 0xDC00 <= low <= 0xDFFF:
                    return ("lit", 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00))
                self.i = save
            return ("lit", cp)
        if c == "U" and self.dialect == "py":
            return ("lit", self._hex(8))
        if c == "c" and self.peek().isalpha():
            return ("lit", ord(self.take()) % 32)
        if c in "pP" and (self.peek() == "{" or self.dialect != "es"):
            neg = c == "P"
            if self.peek() == "{":
                end = self.s.find("}", self.i)
                if end == -1:
                    raise self.err("unterminated \\p{...}")
                name = self.s[self.i + 1:end]
                self.i = end + 1
            else:
                name = self.take()
            if name.startswith("^"):
                neg, name = not neg, name[1:]
            return ("prop", name, neg)
        if in_class and c == "b":
            return ("lit", 8)
        if in_class and c == "-":
            return ("lit", ord("-"))
        if c.isalpha() and c.isascii():
            # identity escape of a letter: ES non-unicode mode allows it, Python rejects it
            if self.dialect == "py":
                raise self.err(f"bad escape \\{c}")
            self.notes.append(f"identity escape \\{c} treated as literal {c!r}")
            return ("lit", ord(c))
        return ("lit", ord(c))

    def escape_outside(self) -> Node:
        if self.i >= self.n:
            raise self.err("trailing backslash")
        c = self.peek()
        if c in "bB":
            self.i += 1
            return Anchor(c)
        if c in "AZz" and self.dialect != "es":
            self.i += 1
            return Anchor(c)
        if c == "k" and self.dialect != "py" and self.s.startswith("k<", self.i):
            self.i += 2
            nm = self._group_name(">")
            self.named_backrefs.append(nm)
            return Backref(nm)
        if c.isdigit() and c != "0":
            j = self.i
            while j < self.n and self.s[j].isdigit():
                j += 1
            num = int(self.s[self.i:j])
            self.i = j
            self.max_backref = max(self.max_backref, num)
            return Backref(num)
        kind = self._char_escape(False)
        if kind[0] == "lit":
            return Lit(kind[1])             # type: ignore[arg-type]
        if kind[0] == "cls":
            return Esc(kind[1])             # type: ignore[arg-type]
        if kind[0] == "prop":
            return Prop(kind[1], kind[2])   # type: ignore[arg-type]
        raise self.err("unsupported escape")

    # ---- character classes ---------------------------------------------------------------
    def charclass(self) -> Node:
        negated = False
        if self.peek() == "^":
            negated = True
            self.i += 1
        items: List[tuple] = []
        first = True
        while True:
            if self.i >= self.n:
                raise self.err("unterminated character class")
            ch = self.peek()
            if ch == "]" and not (first and self.dialect != "es"):
                self.i += 1
                break
            first = False
            lo = self._class_atom()
            if lo[0] == "r" and self.peek() == "-" and self.i + 1 < self.n and self.s[self.i + 1] != "]":
                save = self.i
                self.i += 1
                hi = self._class_atom()
                if hi[0] == "r":
                    if hi[1] < lo[1]:
                        raise self.err("character class range out of order")
                    items.append(("r", lo[1], hi[2]))
                    continue
                # '-' next to a class escape is a literal hyphen
                self.i = save
            items.append(lo)          # "[\w-.]": a hyphen after an escape class stays a literal
        return Cls(negated, items)

    def _class_atom(self) -> tuple:
        ch = self.take()
        if ch == "\\":
            kind = self._char_escape(True)
            if kind[0] == "lit":
                return ("r", kind[1], kind[1])
            if kind[0] == "cls":
                return ("e", kind[1])
            if kind[0] == "prop":
                return ("p", kind[1], kind[2])
            raise self.err("unsupported escape in character class")
        cp = ord(ch)
        return ("r", cp, cp)


def _split_leading_flags(src: str, dialect: str) -> Tuple[str, str, List[str]]:
    """Strip a LEADING global inline flag group: (?i) (?is) ... Returns (rest, flags, notes)."""
    notes: List[str] = []
    flags = ""
    rest = src
    while rest.startswith("(?"):
        j = 2
        while j < len(rest) and rest[j] in "imsxu":
            j += 1
        if j > 2 and j < len(rest) and rest[j] == ")":
            notes.append("leading inline flags (?%s) moved to the flag set" % rest[2:j])
            flags += rest[2:j]
            rest = rest[j + 1:]
            continue
        break
    return rest, flags, notes


def parse(src: str, dialect: str, flags: str = "") -> ParsedRegex:
    """Parse `src` written for `dialect` ('es' | 'py' | 'pcre'), returning the AST + flag set."""
    if dialect not in ("es", "py", "pcre"):
        raise ValueError(f"unknown dialect {dialect!r}")
    rest, lead, notes = _split_leading_flags(src, dialect)
    all_flags = set(flags) | set(lead)
    if "x" in all_flags:
        raise RegexError("verbose (x) mode is not supported")
    if "u" in all_flags and dialect == "es":
        pass  # ES unicode mode: affects only escapes, which the parser accepts anyway
    p = _Parser(rest, dialect)
    node = p.parse()
    node = _hoist_global_flags(node, all_flags, p.notes)
    eff = "".join(sorted(all_flags & set("ims")))
    return ParsedRegex(node=node, dialect=dialect, flags=eff, ncap=p.ncap, notes=notes + p.notes)


def _hoist_global_flags(node: Node, flags: Set[str], notes: List[str]) -> Node:
    """A bare `(?i)` group in the middle of a pattern is only meaningful at the very start of a
    top-level sequence; anything else changes semantics and is rejected."""
    if isinstance(node, Seq):
        out = []
        for idx, it in enumerate(node.items):
            if isinstance(it, Group) and it.kind == "flags" and isinstance(it.body, Seq) and not it.body.items:
                if idx == 0:
                    flags.update(it.on)
                    for f in it.off:
                        flags.discard(f)
                    notes.append("leading inline flag group moved to the flag set")
                    continue
                raise RegexError("inline flag group in the middle of a pattern is not supported")
            out.append(it)
        return Seq(out) if len(out) != 1 else out[0]
    if isinstance(node, Group) and node.kind == "flags" and isinstance(node.body, Seq) and not node.body.items:
        flags.update(node.on)
        for f in node.off:
            flags.discard(f)
        return Seq([])
    return node


# =============================================================================================
# Emitter (canonical PCRE-compatible string)
# =============================================================================================
_SPECIAL_OUT = set("\\^$.|?*+()[]{}")


def _emit_cp(cp: int, in_class: bool) -> str:
    ch = chr(cp)
    if in_class:
        if ch in "\\]^-[":
            return "\\" + ch
    elif ch in _SPECIAL_OUT:
        return "\\" + ch
    if cp == 0x20:
        return " "
    if 0x21 <= cp <= 0x7E:
        return ch
    if cp < 0x20 or cp == 0x7F:
        named = {9: "\\t", 10: "\\n", 13: "\\r", 12: "\\f", 11: "\\v"}.get(cp)
        return named or "\\x%02X" % cp
    if unicodedata.category(ch)[0] in "LNPS":
        return ch                     # letters, digits, punctuation, symbols stay readable
    return "\\x{%X}" % cp             # spaces, controls, format/invisible characters, marks ...


def _emit_class_item(it: tuple) -> str:
    if it[0] == "r":
        lo, hi = it[1], it[2]
        if lo == hi:
            return _emit_cp(lo, True)
        return _emit_cp(lo, True) + "-" + _emit_cp(hi, True)
    if it[0] == "e":
        return "\\" + it[1]
    if it[0] == "p":
        return ("\\P{" if it[2] else "\\p{") + it[1] + "}"
    raise RegexError("bad class item")


def emit(node: Node, keep_captures: bool = False) -> str:
    """Canonical PCRE-compatible text for an AST. Capturing groups become non-capturing unless
    the pattern contains backreferences (`keep_captures=True`)."""
    if isinstance(node, Lit):
        return _emit_cp(node.cp, False)
    if isinstance(node, Dot):
        return "."
    if isinstance(node, Esc):
        return "\\" + node.kind
    if isinstance(node, Prop):
        return ("\\P{" if node.negated else "\\p{") + node.name + "}"
    if isinstance(node, Anchor):
        return node.kind if node.kind in "^$" else "\\" + node.kind
    if isinstance(node, Cls):
        if not node.items:               # ES "[]" (never matches) and "[^]" (any character)
            return "[\\s\\S]" if node.negated else "[^\\s\\S]"
        body = "".join(_emit_class_item(it) for it in node.items)
        return "[" + ("^" if node.negated else "") + body + "]"
    if isinstance(node, Backref):
        if isinstance(node.ref, int):
            return "\\%d" % node.ref
        return "\\k<%s>" % node.ref
    if isinstance(node, Group):
        inner = emit(node.body, keep_captures)
        if node.kind in ("cap", "named"):
            if keep_captures:
                return ("(?<%s>" % node.name if node.kind == "named" else "(") + inner + ")"
            return "(?:" + inner + ")"
        prefix = {"nocap": "(?:", "la": "(?=", "nla": "(?!", "lb": "(?<=", "nlb": "(?<!", "atomic": "(?>"}.get(node.kind)
        if prefix is None:
            if node.kind == "flags":
                on, off = node.on, node.off
                return "(?%s%s:%s)" % (on, ("-" + off) if off else "", inner)
            raise RegexError(f"cannot emit group kind {node.kind}")
        return prefix + inner + ")"
    if isinstance(node, Quant):
        inner = emit(node.body, keep_captures)
        if not isinstance(node.body, (Lit, Dot, Esc, Prop, Cls, Group, Backref)):
            inner = "(?:" + inner + ")"
        elif isinstance(node.body, Group) and node.body.kind == "flags":
            inner = "(?:" + inner + ")"
        if node.lo == 0 and node.hi is None:
            q = "*"
        elif node.lo == 1 and node.hi is None:
            q = "+"
        elif node.lo == 0 and node.hi == 1:
            q = "?"
        elif node.hi is None:
            q = "{%d,}" % node.lo
        elif node.lo == node.hi:
            q = "{%d}" % node.lo
        else:
            q = "{%d,%d}" % (node.lo, node.hi)
        return inner + q + {"greedy": "", "lazy": "?", "possessive": "+"}[node.mode]
    if isinstance(node, Seq):
        return "".join(emit(c, keep_captures) if not isinstance(c, Alt) else "(?:" + emit(c, keep_captures) + ")"
                       for c in node.items)
    if isinstance(node, Alt):
        return "|".join(emit(b, keep_captures) for b in node.branches)
    raise RegexError(f"cannot emit {type(node).__name__}")


# =============================================================================================
# Analysis
# =============================================================================================
@dataclass
class Features:
    tags: Set[str] = field(default_factory=set)
    min_len: int = 0
    max_len: Optional[int] = 0
    literal_cps: List[int] = field(default_factory=list)

    @property
    def nullable(self) -> bool:
        return self.min_len == 0


def _lens(node: Node, feats: Set[str]) -> Tuple[int, Optional[int]]:
    if isinstance(node, (Lit, Dot, Esc, Prop, Cls)):
        if isinstance(node, Lit) and node.cp > 0xFFFF:
            feats.add("astral")
        if isinstance(node, Lit) and 0xD800 <= node.cp <= 0xDFFF:
            feats.add("lone_surrogate")
        if isinstance(node, Prop):
            feats.add("unicode_property")
        if isinstance(node, Cls):
            for it in node.items:
                if it[0] == "p":
                    feats.add("unicode_property")
                if it[0] == "r" and (it[1] > 0xFFFF or it[2] > 0xFFFF):
                    feats.add("astral")
                if it[0] == "r" and (0xD800 <= it[1] <= 0xDFFF or 0xD800 <= it[2] <= 0xDFFF):
                    feats.add("lone_surrogate")
        return 1, 1
    if isinstance(node, Anchor):
        if node.kind in "bB":
            feats.add("word_boundary")
        elif node.kind == "^":
            feats.add("anchor_start")
        else:
            feats.add("anchor_end")
        return 0, 0
    if isinstance(node, Backref):
        feats.add("backreference")
        return 0, None
    if isinstance(node, Group):
        tag = {"la": "lookahead", "nla": "neg_lookahead", "lb": "lookbehind", "nlb": "neg_lookbehind",
               "atomic": "atomic_group", "named": "named_group", "flags": "scoped_flags"}.get(node.kind)
        if tag:
            feats.add(tag)
        lo, hi = _lens(node.body, feats)
        if node.kind in ("la", "nla", "lb", "nlb"):
            return 0, 0
        return lo, hi
    if isinstance(node, Quant):
        lo, hi = _lens(node.body, feats)
        if node.mode == "lazy":
            feats.add("lazy_quantifier")
        if node.mode == "possessive":
            feats.add("possessive_quantifier")
        big = node.hi if node.hi is not None else node.lo
        if big and big > 1000:
            feats.add("large_repeat")
        mx = None if (node.hi is None and (hi is None or hi > 0)) else (
            None if hi is None else (hi * node.hi if node.hi is not None else 0))
        return lo * node.lo, mx
    if isinstance(node, Seq):
        tlo, thi = 0, 0
        for c in node.items:
            lo, hi = _lens(c, feats)
            tlo += lo
            thi = None if (thi is None or hi is None) else thi + hi
        return tlo, thi
    if isinstance(node, Alt):
        lows, highs = [], []
        for b in node.branches:
            lo, hi = _lens(b, feats)
            lows.append(lo)
            highs.append(hi)
        return min(lows), (None if any(h is None for h in highs) else max(highs))
    raise RegexError(f"cannot analyse {type(node).__name__}")


def iter_nodes(node: Node):
    """Pre-order walk over every node of an AST."""
    yield node
    if isinstance(node, (Group, Quant)):
        yield from iter_nodes(node.body)
    elif isinstance(node, Seq):
        for c in node.items:
            yield from iter_nodes(c)
    elif isinstance(node, Alt):
        for b in node.branches:
            yield from iter_nodes(b)


def width_range(node: Node) -> Tuple[int, Optional[int]]:
    """(min, max) number of characters a node can consume; max None = unbounded."""
    return _lens(node, set())


def variable_width_lookbehind(node: Node) -> bool:
    """True if some lookbehind has an alternative that is not of fixed width.

    PCRE2 before 10.43 (Ubuntu 22.04/24.04, Debian 12, RHEL 9 ship 10.39-10.42) rejects those, so
    such a pattern cannot be verified exactly and must not be compiled."""
    for n in iter_nodes(node):
        if isinstance(n, Group) and n.kind in ("lb", "nlb"):
            body = n.body
            for b in (body.branches if isinstance(body, Alt) else [body]):
                lo, hi = width_range(b)
                if hi is None or lo != hi:
                    return True
    return False


def fix_surrogates(node: Node) -> Node:
    """Rewrite UTF-16 surrogate-pair idioms (written for JavaScript) to astral code points.

        \\uDB40[\\uDC00-\\uDC7F]            -> [\\x{E0000}-\\x{E007F}]    (Unicode tag characters)
        [\\uD800-\\uDBFF][\\uDC00-\\uDFFF]  -> [\\x{10000}-\\x{10FFFF}]  (any astral character)
    Anything else that still contains a lone surrogate is reported by `analyse` as unsupported."""
    def fn(n: Node) -> Optional[Node]:
        if not isinstance(n, Seq):
            return None
        items = n.items
        out: List[Node] = []
        i = 0
        changed = False
        while i < len(items):
            a = items[i]
            b = items[i + 1] if i + 1 < len(items) else None
            if (isinstance(a, Lit) and 0xD800 <= a.cp <= 0xDBFF and isinstance(b, Cls) and not b.negated
                    and b.items and all(it[0] == "r" and 0xDC00 <= it[1] <= it[2] <= 0xDFFF for it in b.items)):
                base = 0x10000 + ((a.cp - 0xD800) << 10)
                out.append(Cls(False, [("r", base + (it[1] - 0xDC00), base + (it[2] - 0xDC00)) for it in b.items]))
                i += 2
                changed = True
                continue
            if (isinstance(a, Cls) and isinstance(b, Cls) and not a.negated and not b.negated
                    and len(a.items) == 1 and len(b.items) == 1 and a.items[0][0] == "r" and b.items[0][0] == "r"
                    and 0xD800 <= a.items[0][1] <= a.items[0][2] <= 0xDBFF
                    and b.items[0][1] == 0xDC00 and b.items[0][2] == 0xDFFF):
                lo = 0x10000 + ((a.items[0][1] - 0xD800) << 10)
                hi = 0x10000 + ((a.items[0][2] - 0xD800) << 10) + 0x3FF
                out.append(Cls(False, [("r", lo, hi)]))
                i += 2
                changed = True
                continue
            out.append(a)
            i += 1
        if not changed:
            return None
        return out[0] if len(out) == 1 else Seq(out)

    return _map_node(node, fn)


def _expand_branches(node: Node, limit: int) -> Optional[List[Node]]:
    """Expand alternations / small bounded repeats into a flat list of alternative-free sequences."""
    if isinstance(node, (Lit, Dot, Esc, Prop, Cls, Anchor)):
        return [node]
    if isinstance(node, Group) and node.kind in ("nocap", "cap", "named"):
        return _expand_branches(node.body, limit)
    if isinstance(node, Alt):
        res: List[Node] = []
        for b in node.branches:
            r = _expand_branches(b, limit)
            if r is None:
                return None
            res.extend(r)
            if len(res) > limit:
                return None
        return res
    if isinstance(node, Seq):
        combos: List[List[Node]] = [[]]
        for it in node.items:
            r = _expand_branches(it, limit)
            if r is None:
                return None
            combos = [c + [x] for c in combos for x in r]
            if len(combos) > limit:
                return None
        return [Seq(c) for c in combos]
    if isinstance(node, Quant):
        if node.hi is None or node.hi > 6 or node.mode == "possessive":
            return None
        r = _expand_branches(node.body, limit)
        if r is None:
            return None
        res = []
        for k in range(node.lo, node.hi + 1):
            combos = [[]]
            for _ in range(k):
                combos = [c + [x] for c in combos for x in r]
                if len(combos) > limit:
                    return None
            res.extend(Seq(c) for c in combos)
            if len(res) > limit:
                return None
        return res
    return None


def distribute_lookbehinds(node: Node, limit: int = 64) -> Node:
    """Make lookbehinds acceptable to PCRE2 < 10.43: every top-level alternative must be of fixed
    width, so nested alternations / `x?` are distributed into a top-level alternation.
    (?<!\\b(?:a|bc)\\s) -> (?<!\\ba\\s|\\bbc\\s). Exactly equivalent; skipped when too many branches."""
    def fn(n: Node) -> Optional[Node]:
        if isinstance(n, Group) and n.kind in ("lb", "nlb"):
            body = n.body
            branches = body.branches if isinstance(body, Alt) else [body]
            if all(width_range(b)[1] is not None and width_range(b)[0] == width_range(b)[1] for b in branches):
                return None
            expanded = _expand_branches(body, limit)
            if expanded is None:
                return None
            if all(width_range(b)[1] is not None and width_range(b)[0] == width_range(b)[1] for b in expanded):
                return Group(n.kind, expanded[0] if len(expanded) == 1 else Alt(expanded))
        return None

    return _map_node(node, fn)


def py_fidelity(node: Node) -> Node:
    """Python `re` -> PCRE: `\\Z` (end of string only) becomes `\\z`; `\\s` also covers the Unicode
    spaces Python matches (our PCRE/Hyperscan classes are ASCII-only without UCP)."""
    def fn(n: Node) -> Optional[Node]:
        if isinstance(n, Anchor) and n.kind == "Z":
            return Anchor("z")
        if isinstance(n, Esc) and n.kind in "sS":
            return Cls(n.kind == "S", [("e", "s")] + _extra_space_items())
        if isinstance(n, Cls) and any(it[0] == "e" and it[1] == "s" for it in n.items):
            return Cls(n.negated, n.items + _extra_space_items())
        return None

    return _map_node(node, fn)


def _collect_literals(node: Node, out: List[int], in_group_ok: bool = True) -> None:
    if isinstance(node, Lit):
        out.append(node.cp)
    elif isinstance(node, Group):
        _collect_literals(node.body, out)
    elif isinstance(node, Quant):
        _collect_literals(node.body, out)
    elif isinstance(node, Seq):
        for c in node.items:
            _collect_literals(c, out)
    elif isinstance(node, Alt):
        for b in node.branches:
            _collect_literals(b, out)


def analyse(node: Node) -> Features:
    feats: Set[str] = set()
    lo, hi = _lens(node, feats)
    lits: List[int] = []
    _collect_literals(node, lits)
    return Features(tags=feats, min_len=lo, max_len=hi, literal_cps=lits)


def literal_runs(node: Node) -> List[str]:
    """Maximal runs of directly adjacent literal characters (regex operators break a run)."""
    out: List[str] = []
    cur: List[int] = []

    def flush() -> None:
        if cur:
            out.append("".join(chr(c) for c in cur))
            cur.clear()

    def walk(n: Node) -> None:
        if isinstance(n, Lit):
            cur.append(n.cp)
            return
        if isinstance(n, Seq):
            for c in n.items:
                walk(c)
            return
        flush()
        if isinstance(n, (Group, Quant)):
            walk(n.body)
            flush()
        elif isinstance(n, Alt):
            for b in n.branches:
                walk(b)
                flush()

    walk(node)
    flush()
    return out


def literal_words(node: Node) -> List[str]:
    """Maximal runs of Latin letters inside the literal text of a (sub)expression."""
    words: List[str] = []
    for run in literal_runs(node):
        cur: List[str] = []
        for ch in run:
            if ch.isalpha() and script_of(ord(ch)) == "latin":
                cur.append(ch)
            elif cur:
                words.append("".join(cur))
                cur = []
        if cur:
            words.append("".join(cur))
    return words


def literal_scripts(node: Node, class_scripts: Iterable[str] = ("han", "kana", "hangul")) -> Dict[str, int]:
    """Count literal characters per script.

    Characters inside [...] only count for `class_scripts`: a class such as [\\u0430\\u0435\\u043E] is
    a homoglyph *reference* (obfuscation), not Russian text, whereas [你您] is Chinese text."""
    counts: Dict[str, int] = {}
    in_class = set(class_scripts)

    def add(cp: int, from_class: bool = False) -> None:
        sc = script_of(cp)
        if sc != "common" and (not from_class or sc in in_class):
            counts[sc] = counts.get(sc, 0) + 1

    def walk(n: Node) -> None:
        if isinstance(n, Lit):
            add(n.cp)
        elif isinstance(n, Cls):
            for it in n.items:
                if it[0] == "r" and it[1] == it[2]:
                    add(it[1], True)
        elif isinstance(n, (Group, Quant)):
            walk(n.body)
        elif isinstance(n, Seq):
            for c in n.items:
                walk(c)
        elif isinstance(n, Alt):
            for b in n.branches:
                walk(b)

    walk(node)
    return counts


# =============================================================================================
# Dialect-fidelity rewrites (ECMAScript -> PCRE semantics)
# =============================================================================================
def _map_node(node: Node, fn: Callable[[Node], Optional[Node]]) -> Node:
    """Bottom-up rewrite helper: fn may return a replacement for a node (or None to keep it)."""
    if isinstance(node, Group):
        node = Group(node.kind, _map_node(node.body, fn), node.name, node.on, node.off)
    elif isinstance(node, Quant):
        node = Quant(_map_node(node.body, fn), node.lo, node.hi, node.mode)
    elif isinstance(node, Seq):
        node = Seq([_map_node(c, fn) for c in node.items])
    elif isinstance(node, Alt):
        node = Alt([_map_node(b, fn) for b in node.branches])
    rep = fn(node)
    return rep if rep is not None else node


def _extra_space_items() -> List[tuple]:
    items: List[tuple] = []
    for e in _ES_SPACE_EXTRA:
        if isinstance(e, tuple):
            items.append(("r", e[0], e[1]))
        else:
            items.append(("r", e, e))
    return items


def es_fidelity(node: Node, flags: str) -> Node:
    """Rewrite constructs whose ECMAScript meaning differs from PCRE/Hyperscan.

    * `.`  : ES excludes \\n \\r U+2028 U+2029 (unless the s flag is set); PCRE only \\n.
    * `\\s` : ES whitespace includes U+00A0 U+2028 U+3000 U+FEFF ...; PCRE (no UCP) is ASCII only.
    * `$`  : ES (no m flag) matches only at the very end; PCRE also before a final newline -> \\z.
    """
    dotall = "s" in flags
    multiline = "m" in flags

    def fn(n: Node) -> Optional[Node]:
        if isinstance(n, Dot) and not dotall:
            return Cls(True, [("r", c, c) for c in _ES_LINE_TERMINATORS])
        if isinstance(n, Esc) and n.kind in "sS":
            return Cls(n.kind == "S", [("e", "s")] + _extra_space_items())
        if isinstance(n, Cls):
            if any(it[0] == "e" and it[1] == "s" for it in n.items) and not n.negated:
                return Cls(False, n.items + _extra_space_items())
            if any(it[0] == "e" and it[1] == "s" for it in n.items) and n.negated:
                return Cls(True, n.items + _extra_space_items())
        if isinstance(n, Anchor) and n.kind == "$" and not multiline:
            return Anchor("z")
        return None

    return _map_node(node, fn)


# =============================================================================================
# Alternative pruning (language scoping) and flag-scope splitting
# =============================================================================================
def _group_optional(q: Quant) -> bool:
    return q.lo == 0


def prune_alternatives(node: Node, is_foreign: Callable[[Node], bool]) -> Tuple[Optional[Node], List[str]]:
    """Remove alternation branches for which is_foreign(branch) is true.

    The result accepts a SUBSET of the original language (only the foreign-language phrases are
    gone). Returns (new_node | None, removed_branch_texts). None = a mandatory part of the pattern
    consisted only of foreign branches, so nothing language-appropriate is left.
    """
    removed: List[str] = []

    def visit(n: Node) -> Optional[Node]:
        # returns None when the node can no longer match anything useful
        if isinstance(n, Alt):
            kept: List[Node] = []
            for b in n.branches:
                nb = visit(b)                 # inner alternatives first ...
                if nb is None:
                    removed.append(emit(b))
                    continue
                if is_foreign(nb):            # ... then judge what is left of the branch itself
                    removed.append(emit(b))
                    continue
                kept.append(nb)
            if not kept:
                return None
            return kept[0] if len(kept) == 1 else Alt(kept)
        if isinstance(n, Seq):
            items: List[Node] = []
            for c in n.items:
                nc = visit(c)
                if nc is None:
                    return None
                items.append(nc)
            return Seq(items)
        if isinstance(n, Group):
            nb = visit(n.body)
            if nb is None:
                return None
            return Group(n.kind, nb, n.name, n.on, n.off)
        if isinstance(n, Quant):
            nb = visit(n.body)
            if nb is None:
                if _group_optional(n):
                    return Seq([])           # optional foreign part: simply drop it
                return None
            return Quant(nb, n.lo, n.hi, n.mode)
        return n

    return visit(node), removed


def split_scoped_alternatives(parsed: ParsedRegex) -> Optional[List[Tuple[Node, str]]]:
    """Handle `A|(?-i:B)` style patterns: when the TOP-LEVEL alternatives carry different inline
    flag scopes, return [(branch_node, effective_flags), ...]; otherwise None.

    A branch that is entirely wrapped in `(?flags:...)` is emitted as its own pattern with the
    adjusted global flags -- an exact rewrite because a rule matches if ANY branch matches."""
    node = parsed.node
    branches = node.branches if isinstance(node, Alt) else [node]
    result: List[Tuple[Node, str]] = []
    changed = False
    for b in branches:
        eff = set(parsed.flags)
        inner = b
        if isinstance(inner, Seq) and len(inner.items) == 1:
            inner = inner.items[0]
        if isinstance(inner, Group) and inner.kind == "flags":
            eff |= set(inner.on)
            eff -= set(inner.off)
            inner = inner.body
            changed = True
        result.append((inner, "".join(sorted(eff & set("ims")))))
    return result if changed else None


def has_scoped_flags(node: Node) -> bool:
    found = []

    def fn(n: Node) -> Optional[Node]:
        if isinstance(n, Group) and n.kind == "flags":
            found.append(True)
        return None

    _map_node(node, fn)
    return bool(found)


# =============================================================================================
# Python `re` bridge (TEST ORACLE ONLY -- never used by the engine)
# =============================================================================================
def to_python_re(canonical: str) -> str:
    """Translate our canonical PCRE-ish text into something Python's `re` accepts."""
    out: List[str] = []
    i = 0
    n = len(canonical)
    while i < n:
        c = canonical[i]
        if c == "\\" and i + 1 < n:
            d = canonical[i + 1]
            if d == "x" and i + 2 < n and canonical[i + 2] == "{":
                end = canonical.index("}", i)
                cp = int(canonical[i + 3:end], 16)
                out.append("\\U%08X" % cp)
                i = end + 1
                continue
            if d == "z":
                out.append("\\Z")
                i += 2
                continue
            if d == "k" and canonical.startswith("<", i + 2):
                end = canonical.index(">", i)
                out.append("(?P=" + canonical[i + 3:end] + ")")
                i = end + 1
                continue
            out.append(c + d)
            i += 2
            continue
        if c == "(" and canonical.startswith("(?<", i) and not canonical.startswith("(?<=", i) \
                and not canonical.startswith("(?<!", i):
            out.append("(?P<")
            i += 3
            continue
        out.append(c)
        i += 1
    text = "".join(out)
    return _split_lookbehind_alternatives(text) if "(?<" in text else text


def _class_end(text: str, i: int) -> int:
    """Index just after the character class that starts at text[i] == '['."""
    n = len(text)
    j = i + 1
    if j < n and text[j] == "^":
        j += 1
    if j < n and text[j] == "]":                      # a leading ] is a literal
        j += 1
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == "[" and j + 1 < n and text[j + 1] == ":":
            k = text.find(":]", j + 2)
            if k >= 0:
                j = k + 2
                continue
        if text[j] == "]":
            return j + 1
        j += 1
    return n


def _group_end(text: str, i: int) -> int:
    """Index just after the group that starts at text[i] == '('."""
    n = len(text)
    depth = 0
    j = i
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            j = _class_end(text, j)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return n


def _top_level_alternatives(inner: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    j = 0
    n = len(inner)
    while j < n:
        c = inner[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            j = _class_end(inner, j)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(inner[start:j])
            start = j + 1
        j += 1
    parts.append(inner[start:])
    return parts


def _split_lookbehind_alternatives(text: str) -> str:
    """Python's `re` wants ONE fixed width for a whole look-behind; PCRE2 (which confirms Hyperscan prefilter hits in the
    engine) only wants every top-level alternative to be fixed.  The two are the same assertion written differently:

        (?<!a|bc)  ==  (?<!a)(?<!bc)          (?<=a|bc)  ==  (?:(?<=a)|(?<=bc))
    """
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == "[":
            j = _class_end(text, i)
            out.append(text[i:j])
            i = j
            continue
        if c == "(" and (text.startswith("(?<=", i) or text.startswith("(?<!", i)):
            negative = text[i + 3] == "!"
            j = _group_end(text, i)
            inner = text[i + 4:j - 1]
            alts = [_split_lookbehind_alternatives(a) for a in _top_level_alternatives(inner)]
            if len(alts) == 1:
                out.append(text[i:i + 4] + alts[0] + ")")
            elif negative:
                out.append("".join("(?<!" + a + ")" for a in alts))
            else:
                out.append("(?:" + "|".join("(?<=" + a + ")" for a in alts) + ")")
            i = j
            continue
        out.append(c)
        i += 1
    return "".join(out)
