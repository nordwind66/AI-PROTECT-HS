"""Tiny boolean expression parser used for ATR `detection.condition` combinators.

Grammar (case-insensitive keywords, ATR SPEC section 6.2):
    expr   := term (OR term)*
    term   := factor (AND factor)*
    factor := NOT factor | '(' expr ')' | ALIAS
Precedence: NOT > AND > OR. ALIAS is any other token (letters, digits, '_', '-', '.').

The result is a nested tuple tree:
    ("or", [..]) / ("and", [..]) / ("not", node) / ("ref", alias)
which `to_ast()` turns into the JSON condition AST used by the rule database
({"op": "any"|"all"|"not"|"leaf"}). The expression is NEVER evaluated with eval().
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

__all__ = ["BoolExprError", "parse_expr", "to_ast", "aliases_of"]


class BoolExprError(ValueError):
    pass


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_.\-]+)")


def _tokenise(text: str) -> List[str]:
    tokens: List[str] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise BoolExprError(f"unexpected character {text[pos]!r} in condition expression {text!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class _P:
    def __init__(self, tokens: List[str]):
        self.t = tokens
        self.i = 0

    def peek(self) -> str:
        return self.t[self.i] if self.i < len(self.t) else ""

    def next(self) -> str:
        tok = self.peek()
        self.i += 1
        return tok

    def expr(self):
        items = [self.term()]
        while self.peek().lower() == "or":
            self.next()
            items.append(self.term())
        return items[0] if len(items) == 1 else ("or", items)

    def term(self):
        items = [self.factor()]
        while self.peek().lower() == "and":
            self.next()
            items.append(self.factor())
        return items[0] if len(items) == 1 else ("and", items)

    def factor(self):
        tok = self.next()
        if tok == "":
            raise BoolExprError("unexpected end of condition expression")
        if tok.lower() == "not":
            return ("not", self.factor())
        if tok == "(":
            node = self.expr()
            if self.next() != ")":
                raise BoolExprError("missing ')' in condition expression")
            return node
        if tok == ")" or tok.lower() in ("and", "or"):
            raise BoolExprError(f"unexpected {tok!r} in condition expression")
        return ("ref", tok)


def parse_expr(text: str):
    p = _P(_tokenise(text))
    node = p.expr()
    if p.i != len(p.t):
        raise BoolExprError(f"trailing tokens in condition expression: {p.t[p.i:]}")
    return node


def aliases_of(node) -> List[str]:
    if node[0] == "ref":
        return [node[1]]
    if node[0] == "not":
        return aliases_of(node[1])
    out: List[str] = []
    for c in node[1]:
        out.extend(aliases_of(c))
    return out


def to_ast(node, leaf_for_alias: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
    kind = node[0]
    if kind == "ref":
        return leaf_for_alias(node[1])
    if kind == "not":
        return {"op": "not", "args": [to_ast(node[1], leaf_for_alias)]}
    op = "any" if kind == "or" else "all"
    return {"op": op, "args": [to_ast(c, leaf_for_alias) for c in node[1]]}
