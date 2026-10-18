"""Import pipeline: upstream IR -> converted patterns -> authoritative SQLite database.

    plan_import()   pure computation + read-only look at the database  (used by `diff` and `--dry-run`)
    apply_plan()    one transaction per source; idempotent (same commit + same tool = no new revisions)

Principles
  * a rule that is already in the database keeps its business rule_id forever; new upstream rules
    get new ids; ids are never reassigned or reused,
  * patterns are de-duplicated ONLY when canonical expression + flags + normalisation profile are
    identical (expr_hash); near duplicates are reported, never merged,
  * `import` never touches published rule-set versions (they reference immutable revisions),
  * local edits (rules.modified_locally = 1) are never overwritten by an import: they become a
    `merge_conflict` issue instead.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import EXTRACTOR_API_VERSION, TOOL_VERSION, convert
from . import db as dbm
from .util import canonical_json, sha256_text, utc_now

from .model import CATEGORY_CODE  # noqa: E402


class PolarityError(Exception):
    """A dropped (non-target-language / unsupported) leaf sits under NOT: dropping it would invert meaning."""


# =============================================================================================
# preparation (pure)
# =============================================================================================
@dataclass
class PreparedLeaf:
    leaf_id: str
    source_key: str            # pattern key inside the source rule
    piece: convert.Piece
    field_name: str
    expr_hash: str
    profile: str


@dataclass
class PreparedRule:
    src: Any                                   # sources.base.SrcRule
    conversions: Dict[str, convert.Conversion]
    decision: str
    reason: str
    leaves: List[PreparedLeaf] = field(default_factory=list)
    tree: Optional[Dict[str, Any]] = None
    lang: str = "any"
    pre_doc: Optional[Dict[str, Any]] = None   # rule doc with expr_hash instead of pattern_id
    content_hash: str = ""
    notes: List[str] = field(default_factory=list)


def fold_tree(node: Dict[str, Any], leaf_map: Dict[str, List[str]]) -> Optional[Dict[str, Any]]:
    """Substitute dropped leaves by FALSE and constant-fold. None = FALSE."""
    op = node["op"]
    if op == "leaf":
        subs = leaf_map.get(node["id"])
        if not subs:
            return None
        if len(subs) == 1:
            return {"op": "leaf", "id": subs[0]}
        return {"op": "any", "args": [{"op": "leaf", "id": s} for s in subs]}
    if op == "any":
        kids = [fold_tree(a, leaf_map) for a in node["args"]]
        kids = [k for k in kids if k is not None]
        if not kids:
            return None
        return kids[0] if len(kids) == 1 else {"op": "any", "args": kids}
    if op == "all":
        kids = [fold_tree(a, leaf_map) for a in node["args"]]
        if any(k is None for k in kids):
            return None
        return kids[0] if len(kids) == 1 else {"op": "all", "args": kids}
    if op == "not":
        k = fold_tree(node["args"][0], leaf_map)
        if k is None:
            raise PolarityError()
        return {"op": "not", "args": [k]}
    raise ValueError(f"unknown condition op {op!r}")


def leaf_ids(tree: Dict[str, Any]) -> List[str]:
    if tree["op"] == "leaf":
        return [tree["id"]]
    out: List[str] = []
    for a in tree["args"]:
        out.extend(leaf_ids(a))
    return out


def _combine_lang(langs: List[str]) -> str:
    s = set(langs) - {"any"}
    if not s:
        return "any"
    if s == {"en"}:
        return "en"
    if s == {"zh"}:
        return "zh"
    return "mixed"


def prepare_rule(src, importer_version: str) -> PreparedRule:
    conversions: Dict[str, convert.Conversion] = {}
    for p in src.patterns:
        if p.pre_fate:
            conversions[p.key] = convert.Conversion(p.pre_fate, p.pre_reason, "any")
        else:
            conversions[p.key] = convert.convert_pattern(p.regex, p.dialect, p.flags, description=p.description,
                                                         force_flags=p.force_flags)
    pr = PreparedRule(src=src, conversions=conversions, decision=src.decision, reason=src.decision_reason)
    profile = src.unified.norm_profile if src.unified else "fold_v1"

    if src.decision == "included" and src.unified is not None:
        leaf_map: Dict[str, List[str]] = {}
        leaves: List[PreparedLeaf] = []
        dropped: List[Tuple[str, str]] = []
        for p in src.patterns:
            conv = conversions[p.key]
            if not conv.pieces:
                dropped.append((p.key, conv.fate))
                continue
            ids = [p.key] if len(conv.pieces) == 1 else [f"{p.key}.{i + 1}" for i in range(len(conv.pieces))]
            leaf_map[p.key] = ids
            for lid, piece in zip(ids, conv.pieces):
                leaves.append(PreparedLeaf(lid, p.key, piece, p.field_name or "content",
                                           convert.expr_hash(piece.regex, piece.flags, profile), profile))
        tree: Optional[Dict[str, Any]]
        try:
            tree = fold_tree(src.cond_tree or {"op": "any", "args": [{"op": "leaf", "id": p.key} for p in src.patterns]},
                             leaf_map)
        except PolarityError:
            tree = None
            pr.reason = "a dropped pattern sits under NOT; keeping the rule would invert its meaning"
            pr.decision = "unsupported"
        if tree is None and pr.decision == "included":
            only_lang = dropped and all(f == "excluded_language" for _, f in dropped)
            pr.decision = "excluded_language" if only_lang else "unsupported"
            pr.reason = ("every pattern is non-target-language" if only_lang else
                         "no usable pattern remains for the rule's condition (" +
                         ", ".join(f"{k}:{f}" for k, f in dropped[:6]) + ")")
        elif tree is not None:
            used = set(leaf_ids(tree))
            pr.leaves = [lf for lf in leaves if lf.leaf_id in used]
            pr.tree = tree
            pr.lang = _combine_lang([lf.piece.lang for lf in pr.leaves])
            pruned = [p.key for p in src.patterns if any(
                n.startswith("removed non-target-language") or n.startswith("dropped non-target")
                or n.startswith("top-level alternatives carry") or n.startswith("not converted")
                for n in conversions[p.key].notes)]
            if dropped or pruned:
                pr.decision = "partial"
                parts = []
                if dropped:
                    parts.append(f"{len(src.patterns) - len(dropped)} of {len(src.patterns)} patterns converted; "
                                 "dropped: " + ", ".join(f"{k}:{f}" for k, f in dropped[:8]) +
                                 (" ..." if len(dropped) > 8 else ""))
                if pruned:
                    parts.append("alternatives pruned / split in: " + ", ".join(pruned[:8]) +
                                 (" ..." if len(pruned) > 8 else ""))
                pr.reason = "; ".join(parts)
            else:
                pr.decision = "included"
            h = src.unified
            pr.pre_doc = {
                "name": h.name, "category": h.category, "lang": pr.lang, "severity": h.severity,
                "weight": h.weight, "confidence": h.confidence, "default_action": h.default_action,
                "status": h.status, "scope": h.scope, "context_requires": h.context_requires,
                "score_group": h.score_group, "description": h.description, "tags": h.tags,
                "condition": tree,
                "leaves": [{"id": lf.leaf_id, "expr_hash": lf.expr_hash, "field": lf.field_name} for lf in pr.leaves],
            }
    payload = {
        "versions": [EXTRACTOR_API_VERSION, importer_version, convert.CONVERTER_VERSION],
        "raw": src.raw, "combinator": src.combinator, "cond_tree": src.cond_tree,
        "patterns": [{"k": p.key, "re": p.regex, "fl": p.flags, "d": p.dialect, "f": p.field_name, "o": p.operator,
                      "ff": p.force_flags, "pf": p.pre_fate, "desc": p.description} for p in src.patterns],
        "tests": [[t.kind, t.text, t.expect_hit, t.origin] for t in src.tests],
        "decision": pr.decision, "unified": pr.pre_doc,
    }
    pr.content_hash = sha256_text(canonical_json(payload))
    return pr


# =============================================================================================
# planning (read-only against the database)
# =============================================================================================
@dataclass
class PlannedRule:
    prepared: PreparedRule
    existing: Optional[sqlite3.Row]
    action: str                                  # new | unchanged | changed
    changes: List[str] = field(default_factory=list)


@dataclass
class Plan:
    source_id: str
    commit_sha: str
    importer_id: str
    importer_version: str
    lock_entry: Dict[str, Any]
    rules: List[PlannedRule]
    removed: List[sqlite3.Row]
    warnings: List[str]
    stats: Dict[str, Any]

    def counts(self) -> Dict[str, int]:
        c = {"new": 0, "changed": 0, "unchanged": 0, "removed": len(self.removed)}
        for r in self.rules:
            c[r.action] += 1
        return c


def _describe_existing(conn: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
    pats = conn.execute("SELECT regex_original, flags_original, fate FROM source_patterns WHERE source_rule_id = ? "
                        "ORDER BY ordinal", (row["source_rule_id"],)).fetchall()
    rule_id = _linked_rule_id(conn, row["source_rule_id"])
    doc = dbm.head_doc(conn, rule_id) if rule_id else None
    return {"decision": row["decision"], "patterns": {(p["regex_original"], p["flags_original"]): p["fate"] for p in pats},
            "doc": doc, "rule_id": rule_id}


def _linked_rule_id(conn: sqlite3.Connection, source_rule_id: int) -> Optional[str]:
    r = conn.execute("SELECT rule_id FROM rule_provenance WHERE source_rule_id = ? AND kind = 'rule' "
                     "AND rule_id IS NOT NULL ORDER BY prov_id LIMIT 1", (source_rule_id,)).fetchone()
    return r["rule_id"] if r else None


def plan_import(conn: Optional[sqlite3.Connection], sd, importer, lock_entry: Dict[str, Any],
                log: Callable[[str], None] = print) -> Plan:
    res = importer.extract(sd.dir, lock_entry, log)
    planned: List[PlannedRule] = []
    seen = set()
    for src in sorted(res.rules, key=lambda r: r.source_key):      # deterministic id allocation order
        pr = prepare_rule(src, importer.version)
        seen.add(src.source_key)
        existing = None
        if conn is not None:
            existing = conn.execute("SELECT * FROM source_rules WHERE source_id = ? AND source_key = ?",
                                    (sd.source_id, src.source_key)).fetchone()
        if existing is None:
            planned.append(PlannedRule(pr, None, "new"))
            continue
        if existing["content_hash"] == pr.content_hash and existing["state"] == "active":
            planned.append(PlannedRule(pr, existing, "unchanged"))
            continue
        changes = _diff_rule(conn, existing, pr)
        planned.append(PlannedRule(pr, existing, "changed", changes))
    removed: List[sqlite3.Row] = []
    if conn is not None:
        for row in conn.execute("SELECT * FROM source_rules WHERE source_id = ? AND state = 'active'", (sd.source_id,)):
            if row["source_key"] not in seen:
                removed.append(row)
    return Plan(sd.source_id, lock_entry["commit_sha"], sd.importer, importer.version, lock_entry, planned, removed,
                list(res.warnings), dict(res.stats))


def _diff_rule(conn: sqlite3.Connection, existing: sqlite3.Row, pr: PreparedRule) -> List[str]:
    old = _describe_existing(conn, existing)
    changes: List[str] = []
    if old["decision"] != pr.decision:
        changes.append(f"decision {old['decision']} -> {pr.decision}")
    new_pats = {(p.regex, p.flags): pr.conversions[p.key].fate for p in pr.src.patterns}
    for k in sorted(set(new_pats) - set(old["patterns"])):
        changes.append(f"regex added: {k[0][:90]!r}")
    for k in sorted(set(old["patterns"]) - set(new_pats)):
        changes.append(f"regex removed: {k[0][:90]!r}")
    for k in sorted(set(new_pats) & set(old["patterns"])):
        if old["patterns"][k] != new_pats[k]:
            changes.append(f"pattern fate {old['patterns'][k]} -> {new_pats[k]}: {k[0][:60]!r}")
    od, nd = old["doc"], pr.pre_doc
    if od and nd:
        for key in ("category", "lang", "severity", "weight", "confidence", "default_action", "scope", "status"):
            if od.get(key) != nd.get(key):
                changes.append(f"{key} {od.get(key)} -> {nd.get(key)}")
        if od.get("condition") != nd.get("condition"):
            changes.append("condition tree changed")
    if not changes:
        changes.append("definition/tool version changed (no visible field difference)")
    return changes


# =============================================================================================
# apply
# =============================================================================================
def _resolve_doc(conn: sqlite3.Connection, pr: PreparedRule, profile: str) -> Tuple[Dict[str, Any], int, int]:
    """Allocate/reuse pattern ids and produce the final rule doc. Returns (doc, patterns_new, patterns_reused)."""
    new = reused = 0
    leaves = []
    id_by_hash: Dict[str, int] = {}
    for lf in pr.leaves:
        if lf.expr_hash not in id_by_hash:
            p = lf.piece
            pid, created = dbm.get_or_create_pattern(
                conn, regex=p.regex, flags=p.flags, profile=profile, lang=p.lang, engine_class=p.engine_class,
                class_reason=p.class_reason, features=p.features, min_len=p.min_len, max_len=p.max_len,
                expr_hash=lf.expr_hash)
            id_by_hash[lf.expr_hash] = pid
            new += 1 if created else 0
            reused += 0 if created else 1
        leaves.append({"id": lf.leaf_id, "pattern_id": id_by_hash[lf.expr_hash], "field": lf.field_name})
    doc = dict(pr.pre_doc)  # type: ignore[arg-type]
    doc["leaves"] = leaves
    return doc, new, reused


def apply_plan(conn: sqlite3.Connection, plan: Plan, *, actor: str, log: Callable[[str], None] = print,
               sd=None) -> Dict[str, Any]:
    now = utc_now()
    summary: Dict[str, Any] = {"new": 0, "changed": 0, "unchanged": 0, "removed": 0, "conflicts": 0,
                               "rules_created": 0, "rules_updated": 0, "rules_deprecated": 0,
                               "patterns_new": 0, "patterns_reused": 0, "tests": 0}
    lock = plan.lock_entry
    with dbm.tx(conn):
        conn.execute(
            "INSERT INTO upstream_sources (source_id, display_name, repo_url, branch, commit_sha, commit_date, "
            "commit_subject, license_spdx, lock_tree_sha256, extractor_id, extractor_version, synced_at, status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'active') ON CONFLICT(source_id) DO UPDATE SET "
            "display_name=excluded.display_name, repo_url=excluded.repo_url, branch=excluded.branch, "
            "commit_sha=excluded.commit_sha, commit_date=excluded.commit_date, commit_subject=excluded.commit_subject, "
            "license_spdx=excluded.license_spdx, lock_tree_sha256=excluded.lock_tree_sha256, "
            "extractor_id=excluded.extractor_id, extractor_version=excluded.extractor_version, "
            "synced_at=excluded.synced_at, status='active'",
            (plan.source_id, getattr(sd, "display_name", plan.source_id), lock["repo_url"], lock.get("branch"),
             lock["commit_sha"], lock.get("commit_date"), lock.get("commit_subject"), lock["license_spdx_detected"],
             lock.get("tree_sha256"), plan.importer_id, plan.importer_version, now))
        job_id = conn.execute(
            "INSERT INTO import_jobs (source_id, commit_sha, mode, started_at, status, tool_version) "
            "VALUES (?,?, 'apply', ?, 'running', ?)", (plan.source_id, plan.commit_sha, now, TOOL_VERSION)).lastrowid

        for item in plan.rules:
            pr = item.prepared
            summary[item.action] += 1
            if item.action == "unchanged":
                continue
            sr_id = _upsert_source_rule(conn, plan, item, now)
            _write_source_patterns(conn, sr_id, pr)
            _apply_unified(conn, plan, item, sr_id, actor, summary, job_id)
        for row in plan.removed:
            summary["removed"] += 1
            conn.execute("UPDATE source_rules SET state='removed_upstream', updated_at=? WHERE source_rule_id=?",
                         (now, row["source_rule_id"]))
            rid = _linked_rule_id(conn, row["source_rule_id"])
            if rid:
                _deprecate(conn, rid, actor, "rule removed upstream", summary)
        for w in plan.warnings:
            dbm.add_issue(conn, "source_warning", "warning", w, source_id=plan.source_id, job_id=job_id)
        conn.execute("UPDATE import_jobs SET finished_at=?, status='ok', summary_json=? WHERE job_id=?",
                     (utc_now(), canonical_json(summary), job_id))
        dbm.audit(conn, actor, "import", "source", plan.source_id,
                  {"commit": plan.commit_sha, "importer": plan.importer_version, **summary})
    return summary


def _upsert_source_rule(conn: sqlite3.Connection, plan: Plan, item: PlannedRule, now: str) -> int:
    pr, src = item.prepared, item.prepared.src
    raw_json = canonical_json(src.raw)
    existing = item.existing
    if existing is None:
        cur = conn.execute(
            "INSERT INTO source_rules (source_id, source_key, name, source_path, locator, group_key, lang_declared, "
            "upstream_status, upstream_severity, upstream_maturity, upstream_confidence, combinator, raw_json, "
            "content_hash, file_blob_sha, first_commit, last_commit, decision, decision_reason, state, imported_at, "
            "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'active', ?, ?)",
            (plan.source_id, src.source_key, src.name, src.source_path, src.locator, src.group_key, src.lang_declared,
             src.upstream_status, src.upstream_severity, src.upstream_maturity, src.upstream_confidence,
             src.combinator, raw_json, pr.content_hash, src.file_blob_sha, plan.commit_sha, plan.commit_sha,
             pr.decision, pr.reason, now, now))
        return int(cur.lastrowid)
    sid = int(existing["source_rule_id"])
    conn.execute("INSERT INTO source_rule_history (source_rule_id, commit_sha, content_hash, raw_json, replaced_at) "
                 "VALUES (?,?,?,?,?)", (sid, existing["last_commit"], existing["content_hash"], existing["raw_json"], now))
    conn.execute(
        "UPDATE source_rules SET name=?, source_path=?, locator=?, group_key=?, lang_declared=?, upstream_status=?, "
        "upstream_severity=?, upstream_maturity=?, upstream_confidence=?, combinator=?, raw_json=?, content_hash=?, "
        "file_blob_sha=?, last_commit=?, decision=?, decision_reason=?, state='active', updated_at=? "
        "WHERE source_rule_id=?",
        (src.name, src.source_path, src.locator, src.group_key, src.lang_declared, src.upstream_status,
         src.upstream_severity, src.upstream_maturity, src.upstream_confidence, src.combinator, raw_json,
         pr.content_hash, src.file_blob_sha, plan.commit_sha, pr.decision, pr.reason, now, sid))
    return sid


def _write_source_patterns(conn: sqlite3.Connection, sr_id: int, pr: PreparedRule) -> None:
    # provenance rows of the old patterns must go first (FK), rule-level provenance stays
    conn.execute("DELETE FROM rule_provenance WHERE kind='pattern' AND source_rule_id = ?", (sr_id,))
    conn.execute("DELETE FROM source_patterns WHERE source_rule_id = ?", (sr_id,))
    for p in pr.src.patterns:
        conv = pr.conversions[p.key]
        conn.execute(
            "INSERT INTO source_patterns (source_rule_id, ordinal, locator, line_no, field_name, operator, dialect, "
            "regex_original, flags_original, description, lang_detected, fate, fate_reason, transform_notes) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sr_id, p.ordinal, p.locator, p.line_no, p.field_name, p.operator, p.dialect, p.regex, p.flags,
             p.description, conv.lang_detected, conv.fate, conv.reason, json.dumps(conv.notes, ensure_ascii=False)))


def _source_pattern_ids(conn: sqlite3.Connection, sr_id: int) -> Dict[int, int]:
    return {r["ordinal"]: r["source_pattern_id"] for r in conn.execute(
        "SELECT ordinal, source_pattern_id FROM source_patterns WHERE source_rule_id = ?", (sr_id,))}


def _deprecate(conn: sqlite3.Connection, rule_id: str, actor: str, reason: str, summary: Dict[str, Any]) -> None:
    row = conn.execute("SELECT status, modified_locally, origin FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if row is None or row["status"] in ("deprecated", "deleted"):
        return
    doc = dbm.head_doc(conn, rule_id)
    if doc is None:
        return
    doc["status"] = "deprecated"
    dbm.write_revision(conn, doc, change_kind="disable", actor=actor, reason=reason, origin=row["origin"],
                       modified_locally=bool(row["modified_locally"]))
    summary["rules_deprecated"] += 1


def _apply_unified(conn: sqlite3.Connection, plan: Plan, item: PlannedRule, sr_id: int, actor: str,
                   summary: Dict[str, Any], job_id: int) -> None:
    pr = item.prepared
    src = pr.src
    rule_id = _linked_rule_id(conn, sr_id)
    sp_ids = _source_pattern_ids(conn, sr_id)

    if pr.pre_doc is None:                           # excluded / unsupported at rule level
        if rule_id:
            _deprecate(conn, rule_id, actor, f"source rule now {pr.decision}: {pr.reason}", summary)
        dbm.add_issue(conn, "source_excluded", "info", f"{src.source_key}: {pr.decision} - {pr.reason}",
                      source_id=plan.source_id, source_key=src.source_key, rule_id=rule_id, job_id=job_id)
        return

    profile = src.unified.norm_profile
    doc, p_new, p_reused = _resolve_doc(conn, pr, profile)
    summary["patterns_new"] += p_new
    summary["patterns_reused"] += p_reused
    category = doc["category"]

    if rule_id is None:
        rule_id = dbm.alloc_rule_id(conn, CATEGORY_CODE[category])
        doc["rule_id"] = rule_id
        dbm.write_revision(conn, doc, change_kind="create", actor=actor,
                           reason=f"import {plan.source_id}@{plan.commit_sha[:10]}", origin="imported",
                           modified_locally=False)
        conn.execute("INSERT INTO rule_provenance (kind, rule_id, source_rule_id, source_commit, note) "
                     "VALUES ('rule', ?, ?, ?, ?)", (rule_id, sr_id, plan.commit_sha, "primary source rule"))
        summary["rules_created"] += 1
    else:
        doc["rule_id"] = rule_id
        head = dbm.head_doc(conn, rule_id)
        row = conn.execute("SELECT modified_locally, status FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
        if head is not None and dbm.rule_doc_hash(head) == dbm.rule_doc_hash(doc):
            pass                                      # derived content identical: nothing to do
        elif row["modified_locally"]:
            summary["conflicts"] += 1
            dbm.add_issue(conn, "merge_conflict", "warning",
                          f"{rule_id}: upstream changed but the rule has local modifications; keeping local version",
                          source_id=plan.source_id, source_key=src.source_key, rule_id=rule_id, job_id=job_id,
                          detail={"changes": item.changes})
        else:
            dbm.write_revision(conn, doc, change_kind="import_update", actor=actor,
                               reason=f"import {plan.source_id}@{plan.commit_sha[:10]}: " + "; ".join(item.changes)[:300],
                               origin="imported", modified_locally=False)
            summary["rules_updated"] += 1
    # --- provenance of patterns --------------------------------------------------------------
    leaf_src_ordinal = {p.key: p.ordinal for p in src.patterns}
    pid_by_leaf = {lf["id"]: lf["pattern_id"] for lf in doc["leaves"]}
    for lf in pr.leaves:
        ordinal = leaf_src_ordinal[lf.source_key]
        conn.execute("INSERT INTO rule_provenance (kind, pattern_id, rule_id, source_rule_id, source_pattern_id, "
                     "source_commit, note) VALUES ('pattern', ?, ?, ?, ?, ?, ?)",
                     (pid_by_leaf[lf.leaf_id], rule_id, sr_id, sp_ids.get(ordinal), plan.commit_sha, lf.leaf_id))
    # --- tests -----------------------------------------------------------------------------------
    conn.execute("DELETE FROM rule_tests WHERE source_rule_id = ? AND origin IN ('upstream', 'manual')", (sr_id,))
    now = utc_now()
    pos = neg = 0
    for t in src.tests:
        fields_json = canonical_json(t.fields) if t.fields else None
        sha = sha256_text(t.text + ("\x1f" + fields_json if fields_json else ""))
        cur = conn.execute(
            "INSERT OR IGNORE INTO rule_tests (rule_id, kind, text, fields_json, text_sha256, lang, scan_source, "
            "expect_hit, origin, source_rule_id, note, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (rule_id, t.kind, t.text, fields_json, sha, None, t.scan_source, 1 if t.expect_hit else 0, t.origin,
             sr_id, (t.description or "")[:300] or None, now))
        if cur.rowcount:
            summary["tests"] += 1
            if t.kind == "positive":
                pos += 1
            elif t.kind == "negative":
                neg += 1
    if pos == 0 or neg == 0:
        dbm.add_issue(conn, "missing_test", "warning",
                      f"{rule_id}: no {'positive' if pos == 0 else 'negative'} upstream test sample",
                      source_id=plan.source_id, source_key=src.source_key, rule_id=rule_id, job_id=job_id)
    if pr.decision == "partial":
        dbm.add_issue(conn, "partial_conversion", "info", f"{rule_id}: {pr.reason}", source_id=plan.source_id,
                      source_key=src.source_key, rule_id=rule_id, job_id=job_id)
    for p in src.patterns:
        conv = pr.conversions[p.key]
        for n in conv.notes:
            if n.startswith("not converted"):
                dbm.add_issue(conn, "conversion", "warning", f"{rule_id} {p.key}: {n}", source_id=plan.source_id,
                              source_key=src.source_key, rule_id=rule_id, job_id=job_id)
