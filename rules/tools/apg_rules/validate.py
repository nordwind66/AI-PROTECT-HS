"""Database and rule-set validation (`rules.py validate`, `rules.py db check`, publish gate)."""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import convert
from . import db as dbm
from . import regexkit as rk
from .util import canonical_json, sha256_text

from .model import CATEGORIES as _CAT_LIST, KNOWN_FIELDS, PROFILES as _PROFILES  # noqa: E402

CATEGORIES = set(_CAT_LIST)
PROFILES = set(_PROFILES)
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.\-]+))?$")


@dataclass
class Finding:
    level: str            # error | warning | info
    code: str
    message: str
    rule_id: Optional[str] = None


@dataclass
class ValidationResult:
    findings: List[Finding] = field(default_factory=list)
    checked_rules: int = 0
    checked_patterns: int = 0

    def add(self, level: str, code: str, message: str, rule_id: Optional[str] = None) -> None:
        self.findings.append(Finding(level, code, message, rule_id))

    def count(self, level: str) -> int:
        return sum(1 for f in self.findings if f.level == level)

    def failed(self, strict: bool) -> bool:
        return self.count("error") > 0 or (strict and self.count("warning") > 0)

    def render(self, verbose: bool = False) -> str:
        lines = [f"validated {self.checked_rules} enabled rule(s), {self.checked_patterns} pattern(s): "
                 f"{self.count('error')} error(s), {self.count('warning')} warning(s), {self.count('info')} info"]
        by_code: Dict[str, List[Finding]] = {}
        for f in self.findings:
            by_code.setdefault(f"{f.level}:{f.code}", []).append(f)
        for key in sorted(by_code, key=lambda k: ({"error": 0, "warning": 1, "info": 2}[k.split(":")[0]], k)):
            items = by_code[key]
            lines.append(f"  [{key}] x{len(items)}")
            limit = len(items) if verbose else 3
            for f in items[:limit]:
                lines.append(f"      {f.rule_id or '-'}: {f.message}")
            if len(items) > limit:
                lines.append(f"      ... {len(items) - limit} more (use -v)")
        return "\n".join(lines)


def check_database(conn: sqlite3.Connection) -> List[str]:
    problems: List[str] = []
    row = conn.execute("PRAGMA integrity_check").fetchone()
    if row[0] != "ok":
        problems.append("PRAGMA integrity_check: " + str(row[0]))
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    for r in fk[:20]:
        problems.append(f"foreign key violation in {r[0]} rowid {r[1]} -> {r[2]}")
    try:
        applied = dbm.applied_migrations(conn)
        for version, name, path in dbm.migration_files():
            if version not in applied:
                problems.append(f"migration {path.name} not applied")
            elif applied[version]["checksum"] != __import__("hashlib").sha256(path.read_bytes()).hexdigest():
                problems.append(f"migration {path.name} checksum differs from the recorded one")
    except sqlite3.Error as exc:
        problems.append(f"cannot read migrations: {exc}")
    problems += dbm.verify_audit_chain(conn)
    for r in conn.execute("SELECT rule_id FROM rules r WHERE NOT EXISTS (SELECT 1 FROM rule_revisions v "
                          "WHERE v.rule_id = r.rule_id AND v.revision = r.revision)"):
        problems.append(f"{r['rule_id']}: head revision row missing")
    for r in conn.execute("SELECT v.version, v.snapshot_sha256, s.body, s.sha256 FROM ruleset_versions v "
                          "LEFT JOIN ruleset_snapshots s ON s.version_id = v.version_id WHERE v.status <> 'draft'"):
        if r["body"] is None:
            problems.append(f"version {r['version']}: snapshot missing")
        elif sha256_text(bytes(r["body"]).decode("utf-8")) != r["snapshot_sha256"]:
            problems.append(f"version {r['version']}: snapshot bytes do not match the recorded sha256")
    return problems


def validate_rules(conn: sqlite3.Connection, strict: bool = False) -> ValidationResult:
    res = ValidationResult()
    for p in check_database(conn):
        res.add("error", "database", p)

    # ---- patterns ---------------------------------------------------------------------------------
    pats = {r["pattern_id"]: r for r in conn.execute("SELECT * FROM rule_patterns")}
    res.checked_patterns = len(pats)
    for pid, p in pats.items():
        h = convert.expr_hash(p["regex"], p["flags"], p["norm_profile"])
        if h != p["expr_hash"]:
            res.add("error", "pattern_hash", f"pattern {pid}: expr_hash does not match its content")
        if p["norm_profile"] not in PROFILES:
            res.add("error", "pattern_profile", f"pattern {pid}: unknown normalisation profile {p['norm_profile']}")
        if set(p["flags"]) - set("imsu"):
            res.add("error", "pattern_flags", f"pattern {pid}: bad flags {p['flags']!r}")
        try:
            parsed = rk.parse(p["regex"], "pcre", p["flags"])
            feats = rk.analyse(parsed.node)
            if feats.nullable:
                res.add("error", "pattern_nullable", f"pattern {pid}: matches the empty string")
            again = rk.emit(parsed.node, keep_captures="backreference" in feats.tags)
            if again != p["regex"]:
                res.add("warning", "pattern_not_canonical", f"pattern {pid}: stored form is not canonical")
        except rk.RegexError as exc:
            res.add("error", "pattern_syntax", f"pattern {pid}: {exc}")

    # ---- rules --------------------------------------------------------------------------------
    rules = conn.execute("SELECT * FROM rules WHERE status = 'enabled' ORDER BY rule_id").fetchall()
    res.checked_rules = len(rules)
    for r in rules:
        rid = r["rule_id"]
        doc = dbm.head_doc(conn, rid)
        if doc is None:
            res.add("error", "no_revision", "no revision row for the head revision", rid)
            continue
        if r["category"] not in CATEGORIES:
            res.add("error", "category", f"bad category {r['category']}", rid)
        if not (0 <= r["weight"] <= 1 and 0 <= r["confidence"] <= 1):
            res.add("error", "range", "weight/confidence outside [0,1]", rid)
        if r["scope"] == "translation_only" and not r["context_requires"]:
            res.add("error", "scope_context", "scope=translation_only needs context_requires", rid)
        if r["context_requires"]:
            try:
                ctx = json.loads(r["context_requires"])
                if not isinstance(ctx, dict) or not ctx:
                    raise ValueError("not a non-empty object")
            except ValueError as exc:
                res.add("error", "context_requires", f"invalid context_requires: {exc}", rid)
        leaves = {lf["id"]: lf for lf in doc["leaves"]}
        used = _tree_leaf_ids(doc["condition"], res, rid)
        if set(leaves) != set(used):
            res.add("error", "leaves", f"condition leaves {sorted(used)} differ from link leaves {sorted(leaves)}", rid)
        for lf in leaves.values():
            p = pats.get(lf["pattern_id"])
            if p is None:
                res.add("error", "dangling_pattern", f"leaf {lf['id']}: pattern {lf['pattern_id']} missing", rid)
            elif p["engine_class"] == "unsupported":
                res.add("error", "unsupported_pattern", f"leaf {lf['id']}: pattern {p['pattern_id']} is unsupported", rid)
            if lf["field"] not in KNOWN_FIELDS:
                res.add("error", "field", f"leaf {lf['id']}: unknown field {lf['field']}", rid)
        # head tables must agree with the frozen revision
        db_links = conn.execute("SELECT leaf_key, pattern_id, field_name FROM rule_pattern_links WHERE rule_id=? "
                                "AND revision=? ORDER BY ordinal", (rid, r["revision"])).fetchall()
        if [(x["leaf_key"], x["pattern_id"], x["field_name"]) for x in db_links] != \
                [(lf["id"], lf["pattern_id"], lf["field"]) for lf in doc["leaves"]]:
            res.add("error", "links_mismatch", "rule_pattern_links differ from the frozen revision", rid)
        pos = conn.execute("SELECT COUNT(*) FROM rule_tests WHERE rule_id=? AND expect_hit=1 AND kind='positive'", (rid,)).fetchone()[0]
        neg = conn.execute("SELECT COUNT(*) FROM rule_tests WHERE rule_id=? AND expect_hit=0 AND kind='negative'", (rid,)).fetchone()[0]
        if pos == 0:
            res.add("warning", "missing_positive_test", "no positive test sample", rid)
        if neg == 0:
            res.add("warning", "missing_negative_test", "no negative test sample", rid)
        bad = conn.execute("SELECT COUNT(*) FROM rule_tests WHERE rule_id=? AND verification='python_oracle_mismatch'", (rid,)).fetchone()[0]
        if bad:
            res.add("warning", "oracle_mismatch", f"{bad} test(s) disagree with the Python reference oracle", rid)
        if not conn.execute("SELECT 1 FROM rule_provenance WHERE rule_id=? AND kind='rule'", (rid,)).fetchone() \
                and r["origin"] == "imported":
            res.add("error", "no_provenance", "imported rule without provenance", rid)
    # ---- issues ----------------------------------------------------------------------------------
    open_conflicts = conn.execute("SELECT COUNT(*) FROM rule_issues WHERE kind='merge_conflict' AND status='open'").fetchone()[0]
    if open_conflicts:
        res.add("warning", "merge_conflict", f"{open_conflicts} open merge conflict issue(s) between upstream and local edits")
    # near-duplicate rules (information only: identical pattern sets)
    dup: Dict[str, List[str]] = {}
    for r in rules:
        doc = dbm.head_doc(conn, r["rule_id"])
        key = sha256_text(canonical_json(sorted(lf["pattern_id"] for lf in doc["leaves"])) + r["category"])
        dup.setdefault(key, []).append(r["rule_id"])
    for ids in dup.values():
        if len(ids) > 1:
            res.add("info", "duplicate_rule_candidate", f"rules with identical pattern sets: {', '.join(ids)}", ids[0])
    return res


def _tree_leaf_ids(tree: Dict[str, Any], res: ValidationResult, rid: str) -> List[str]:
    op = tree.get("op")
    if op == "leaf":
        return [tree["id"]]
    if op in ("any", "all"):
        if not tree.get("args"):
            res.add("error", "condition", f"{op} without arguments", rid)
        out: List[str] = []
        for a in tree.get("args", []):
            out += _tree_leaf_ids(a, res, rid)
        return out
    if op == "not":
        if len(tree.get("args", [])) != 1:
            res.add("error", "condition", "not needs exactly one argument", rid)
            return []
        return _tree_leaf_ids(tree["args"][0], res, rid)
    res.add("error", "condition", f"unknown operator {op!r}", rid)
    return []
