"""Pattern conversion: one upstream regular expression -> zero or more canonical pieces.

A *piece* is what is stored in `rule_patterns` and finally compiled: a canonical PCRE-compatible
expression, a flag set (subset of "imsu"), a normalisation profile and an engine class

    hs_native           -> compiled by Hyperscan, a match is a real match
    hs_prefilter_pcre2  -> Hyperscan HS_FLAG_PREFILTER finds candidates, PCRE2 decides
    (unsupported        -> not compiled; kept in the audit tables with the reason)

Source patterns that are excluded because of their language never become pieces
(fate `excluded_language`).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Set

from . import langscope as ls
from . import regexkit as rk

CONVERTER_VERSION = 1

PREFILTER_TAGS = {"lookahead", "neg_lookahead", "lookbehind", "neg_lookbehind", "backreference",
                  "atomic_group", "possessive_quantifier"}
UNSUPPORTED_TAGS = {"lone_surrogate", "scoped_flags"}


@dataclass
class Piece:
    regex: str
    flags: str
    lang: str
    engine_class: str
    class_reason: str
    features: List[str]
    min_len: int
    max_len: Optional[int]


@dataclass
class Conversion:
    fate: str                        # hs_native | hs_prefilter_pcre2 | excluded_language | unsupported
    reason: str
    lang_detected: str
    pieces: List[Piece] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def expr_hash(regex: str, flags: str, profile: str) -> str:
    """Identity of a pattern: two pieces are the same pattern iff this hash is equal."""
    payload = "\x1f".join([regex, flags, profile]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _flagstr(flags: Set[str]) -> str:
    return "".join(sorted(flags & set("imsu")))


def _combine_lang(langs: List[str]) -> str:
    s = set(langs) - {"any"}
    if not s:
        return "any"
    if s == {"zh"}:
        return "zh"
    if s == {"en"}:
        return "en"
    return "mixed"


def convert_pattern(regex: str, dialect: str, declared_flags: str = "", *, description: str = "",
                    force_flags: str = "") -> Conversion:
    """Convert one upstream expression. `dialect` is es | py | pcre."""
    notes: List[str] = []
    try:
        parsed = rk.parse(regex, dialect, declared_flags)
    except rk.RegexError as exc:
        return Conversion("unsupported", f"regular expression not supported: {exc}", "any")
    notes.extend(parsed.notes)
    force = set(force_flags)

    split = rk.split_scoped_alternatives(parsed)
    if split is None:
        if rk.has_scoped_flags(parsed.node):
            return Conversion("unsupported",
                              "inline flag group inside the expression cannot be rewritten exactly", "any", [], notes)
        parts = [(parsed.node, set(parsed.flags) | force)]
    else:
        parts = [(node, set(f) | force) for node, f in split]
        notes.append(f"top-level alternatives carry different inline flags: split into {len(parts)} patterns")

    pieces: List[Piece] = []
    dropped_lang: List[str] = []
    dropped_other: List[str] = []
    for node, flags in parts:
        verdict, kept, lnotes = ls.classify_pattern(node, description)
        if kept is None:
            dropped_lang.append(verdict.lang)
            continue
        notes.extend(lnotes)
        node = kept
        if dialect == "es":
            node = rk.es_fidelity(node, "".join(sorted(flags)))
            node = rk.fix_surrogates(node)
        elif dialect == "py":
            node = rk.py_fidelity(node)
        node = rk.distribute_lookbehinds(node)
        feats = rk.analyse(node)
        tags = feats.tags
        if feats.nullable:
            dropped_other.append("the expression can match the empty string (would fire on every input)")
            continue
        bad = tags & UNSUPPORTED_TAGS
        if bad:
            dropped_other.append("unsupported construct: " + ",".join(sorted(bad)))
            continue
        if rk.variable_width_lookbehind(node):
            dropped_other.append("variable-length lookbehind: PCRE2 < 10.43 cannot verify it exactly")
            continue
        keep_caps = "backreference" in tags
        try:
            canonical = rk.emit(node, keep_captures=keep_caps)
        except rk.RegexError as exc:
            dropped_other.append(f"cannot emit canonical form: {exc}")
            continue
        triggers = sorted(tags & PREFILTER_TAGS)
        if triggers:
            cls, why = "hs_prefilter_pcre2", "Hyperscan cannot match exactly: " + ",".join(triggers)
        else:
            cls, why = "hs_native", "plain regular language"
        pieces.append(Piece(canonical, _flagstr(flags), verdict.lang, cls, why, sorted(tags),
                            feats.min_len, feats.max_len))
        if dialect in ("py",) and {"word_boundary"} & tags:
            notes.append("\\b/\\w use ASCII semantics (no UCP) so that CJK next to Latin text is a boundary")

    if not pieces:
        if dropped_other:
            return Conversion("unsupported", "; ".join(dict.fromkeys(dropped_other)), "any", [], notes)
        code = dropped_lang[0] if dropped_lang else "xx"
        return Conversion("excluded_language", f"pattern is {code}-language specific (target languages: en, zh)",
                          code, [], notes)
    if dropped_other:
        notes.append("not converted: " + "; ".join(dict.fromkeys(dropped_other)))
    if dropped_lang:
        notes.append("dropped non-target-language pattern part(s): " + ",".join(dropped_lang))
    # Remove exact duplicates produced by splitting
    unique: List[Piece] = []
    seen = set()
    for p in pieces:
        k = (p.regex, p.flags)
        if k not in seen:
            seen.add(k)
            unique.append(p)
    fate = "hs_prefilter_pcre2" if any(p.engine_class == "hs_prefilter_pcre2" for p in unique) else "hs_native"
    reason = unique[0].class_reason if len(unique) == 1 else f"{len(unique)} pieces"
    return Conversion(fate, reason, _combine_lang([p.lang for p in unique]), unique, notes)
