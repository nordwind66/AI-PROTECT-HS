"""Python reference oracle for rule tests (`rules.py verify-tests`).

This is NOT the production engine. It re-evaluates every stored test sample against the stored
canonical patterns with Python's `re` (ASCII semantics, like Hyperscan without UCP) after applying
the same normalisation profiles (normalize_ref), with the same three-valued condition logic the
C++ engine implements. It is useful to
  * catch conversion bugs (a positive upstream sample that no converted pattern matches),
  * give `rule_tests.verification` a meaningful value before any C++ run is possible,
  * produce the expected results for the cross-implementation differential tests.
The authoritative verification is the C++ engine run on a Linux/Windows test machine.
"""
from __future__ import annotations

import json
import re
import sqlite3
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from . import db as dbm
from . import normalize_ref as nr
from . import regexkit as rk
from .publish import PROFILES, SOURCE_FIELD_MAP

TRI = Optional[bool]


@lru_cache(maxsize=None)
def compile_pattern(regex: str, flags: str):
    f = re.ASCII
    if "i" in flags:
        f |= re.IGNORECASE
    if "s" in flags:
        f |= re.DOTALL
    if "m" in flags:
        f |= re.MULTILINE
    try:
        return re.compile(rk.to_python_re(regex), f)
    except re.error:
        return None


def views_for(profile: str, text: str) -> List[str]:
    out: List[str] = []
    for v in PROFILES[profile]["views"]:
        s = nr.PROFILE_FUNCS[v](text)[0]
        if s not in out:
            out.append(s)
    return out


def eval_tree(node: Dict[str, Any], leaf_value) -> TRI:
    op = node["op"]
    if op == "leaf":
        return leaf_value(node["id"])
    vals = [eval_tree(a, leaf_value) for a in node["args"]]
    if op == "any":
        if any(v is True for v in vals):
            return True
        return False if all(v is False for v in vals) else None
    if op == "all":
        if any(v is False for v in vals):
            return False
        return True if all(v is True for v in vals) else None
    if op == "not":
        return None if vals[0] is None else (not vals[0])
    raise ValueError(op)


def evaluate_rule(doc: Dict[str, Any], patterns: Dict[int, sqlite3.Row], text: str, scan_source: str,
                  extra_fields: Optional[Dict[str, str]] = None) -> Tuple[TRI, Dict[str, bool]]:
    available: Dict[str, str] = {}
    if not (extra_fields and text == ""):         # a test that only supplies named fields has no primary text
        available = {f: text for f in SOURCE_FIELD_MAP.get(scan_source, ["content"])}
    if extra_fields:
        available.update(extra_fields)
    cache: Dict[Tuple[str, str], List[str]] = {}
    leaf_hits: Dict[str, bool] = {}
    leaves = {lf["id"]: lf for lf in doc["leaves"]}

    def leaf_value(lid: str) -> TRI:
        lf = leaves[lid]
        field_text = available.get(lf["field"])
        if field_text is None:
            return None
        p = patterns[lf["pattern_id"]]
        key = (p["norm_profile"], lf["field"])
        if key not in cache:
            cache[key] = views_for(p["norm_profile"], field_text)
        rx = compile_pattern(p["regex"], p["flags"])
        if rx is None:
            return None
        hit = any(rx.search(v) for v in cache[key])
        leaf_hits[lid] = hit
        return hit

    return eval_tree(doc["condition"], leaf_value), leaf_hits


def run(conn: sqlite3.Connection, args) -> int:
    patterns = {r["pattern_id"]: r for r in conn.execute("SELECT * FROM rule_patterns")}
    rules = {r["rule_id"]: r for r in conn.execute("SELECT * FROM rules")}
    docs: Dict[str, Dict[str, Any]] = {}
    partial = {r[0] for r in conn.execute(
        "SELECT DISTINCT p.rule_id FROM rule_provenance p JOIN source_rules s ON s.source_rule_id = p.source_rule_id "
        "WHERE p.kind='rule' AND (s.decision = 'partial')")}
    stats = {"ok": 0, "mismatch": 0, "skipped": 0, "uncompilable": 0, "known_gap_now_detected": 0, "known_gap_total": 0}
    mismatches: List[Tuple[str, str, str, str]] = []
    rows = conn.execute("SELECT * FROM rule_tests ORDER BY test_id").fetchall()
    if getattr(args, "limit", None):
        rows = rows[: args.limit]
    updates: List[Tuple[str, Optional[str], int]] = []
    for t in rows:
        rid = t["rule_id"]
        if rid not in rules:
            continue
        if rid not in docs:
            docs[rid] = dbm.head_doc(conn, rid) or {}
        doc = docs[rid]
        if not doc or rules[rid]["status"] == "deleted":
            continue
        extra = json.loads(t["fields_json"]) if t["fields_json"] else None
        if any(compile_pattern(patterns[lf["pattern_id"]]["regex"], patterns[lf["pattern_id"]]["flags"]) is None
               for lf in doc["leaves"]):
            # Python's `re` is stricter than PCRE2 about lookbehind widths: cannot judge, leave unverified
            stats["uncompilable"] += 1
            continue
        value, _ = evaluate_rule(doc, patterns, t["text"], t["scan_source"], extra)
        hit = value is True
        if t["kind"] == "known_gap":
            stats["known_gap_total"] += 1
            if hit:
                stats["known_gap_now_detected"] += 1
            continue
        expected = bool(t["expect_hit"])
        if hit == expected:
            stats["ok"] += 1
            updates.append(("python_oracle_ok", None, t["test_id"]))
        elif rid in partial:
            stats["skipped"] += 1
            updates.append(("skipped_scope", "source rule was only partially converted (non-target-language or "
                            "unsupported patterns dropped)", t["test_id"]))
        else:
            stats["mismatch"] += 1
            note = f"oracle says {'hit' if hit else 'no hit'}, expected {'hit' if expected else 'no hit'}"
            updates.append(("python_oracle_mismatch", note, t["test_id"]))
            mismatches.append((rid, t["kind"], note, t["text"][:90].replace("\n", " ")))
    with dbm.tx(conn):
        for ver, note, tid in updates:
            if note is None:
                conn.execute("UPDATE rule_tests SET verification=? WHERE test_id=?", (ver, tid))
            else:
                conn.execute("UPDATE rule_tests SET verification=?, note=COALESCE(note || ' | ', '') || ? WHERE test_id=?",
                             (ver, note, tid))
    print(f"[verify-tests] Python oracle: {stats}")
    for m in mismatches[:40]:
        print("  MISMATCH", m)
    if len(mismatches) > 40:
        print(f"  ... {len(mismatches) - 40} more")
    return 0
