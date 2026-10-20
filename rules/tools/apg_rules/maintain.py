"""Rule maintenance commands: add / update / enable / disable / delete / restore-upstream.

Every command creates a NEW revision of the rule (with actor, reason, before/after hash, audit entry).
Published rule-set versions reference immutable revisions, so none of these commands can change what
is already published; the change becomes effective only after an explicit stage/publish + compile.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import convert
from . import db as dbm
from .pipeline import CATEGORY_CODE, fold_tree, leaf_ids
from .util import canonical_json, read_text, sha256_text, utc_now
from .validate import CATEGORIES, KNOWN_FIELDS, PROFILES

SEVERITIES = ("info", "low", "medium", "high", "critical")
ACTIONS = ("allow", "alert", "review", "block")
LANGS = ("zh", "en", "mixed", "any")
SCOPES = ("general", "translation_only", "context_required")
NOTE_PUBLISH = "Note: published versions are unchanged. Run `stage`/`publish` and then compile to ship this change."


class MaintainError(Exception):
    pass


class _DryRun(Exception):
    """Raised inside a transaction to roll everything back after a dry run."""


def run(name: str, conn: sqlite3.Connection, args) -> int:
    from .cli import CliError
    try:
        if name in ("enable", "disable", "delete"):
            return _set_status(conn, args, {"enable": "enabled", "disable": "disabled", "delete": "deleted"}[name], name)
        if name == "update":
            return _update(conn, args)
        if name == "add":
            return _add(conn, args)
        if name == "sync-manual":
            return _sync_manual(conn, args)
        if name == "restore-upstream":
            return _restore_upstream(conn, args)
    except MaintainError as exc:
        raise CliError(str(exc)) from exc
    raise CliError(f"unknown maintenance command {name}")


def _row(conn: sqlite3.Connection, rule_id: str) -> sqlite3.Row:
    r = conn.execute("SELECT * FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
    if r is None:
        raise MaintainError(f"rule {rule_id} does not exist")
    return r


def _set_status(conn: sqlite3.Connection, args, new_status: str, kind: str) -> int:
    r = _row(conn, args.id)
    doc = dbm.head_doc(conn, args.id)
    assert doc is not None
    if r["status"] == new_status:
        print(f"{args.id} is already {new_status}; nothing to do")
        return 0
    if r["status"] == "deleted" and kind != "enable":
        raise MaintainError(f"{args.id} is deleted; only `enable` can restore it")
    doc["status"] = new_status
    reason = args.reason or f"{kind} by {args.actor}"
    if args.dry_run:
        print(f"[dry-run] {args.id}: {r['status']} -> {new_status}")
        return 0
    change = {"enable": "enable", "disable": "disable", "delete": "delete"}[kind]
    if r["status"] == "deleted" and kind == "enable":
        change = "restore"
    with dbm.tx(conn):
        rev = dbm.write_revision(conn, doc, change_kind=change, actor=args.actor, reason=reason,
                                 origin=r["origin"], modified_locally=True)
    print(f"{args.id}: {r['status']} -> {new_status} (revision {rev})")
    print(NOTE_PUBLISH)
    return 0


def _parse_value(key: str, raw: str) -> Any:
    if key in ("weight", "confidence"):
        v = float(raw)
        if not 0.0 <= v <= 1.0:
            raise MaintainError(f"{key} must be within [0, 1]")
        return round(v, 4)
    if key == "category":
        if raw not in CATEGORIES:
            raise MaintainError(f"category must be one of {sorted(CATEGORIES)}")
    elif key == "severity":
        if raw not in SEVERITIES:
            raise MaintainError(f"severity must be one of {SEVERITIES}")
    elif key == "default_action":
        if raw not in ACTIONS:
            raise MaintainError(f"default_action must be one of {ACTIONS}")
    elif key == "lang":
        if raw not in LANGS:
            raise MaintainError(f"lang must be one of {LANGS}")
    elif key == "scope":
        if raw not in SCOPES:
            raise MaintainError(f"scope must be one of {SCOPES}")
    elif key == "context_requires":
        if raw.strip().lower() in ("", "null", "none"):
            return None
        try:
            v = json.loads(raw)
        except ValueError as exc:
            raise MaintainError(f"context_requires must be JSON: {exc}") from exc
        if not isinstance(v, dict) or not v:
            raise MaintainError("context_requires must be a non-empty JSON object")
        return v
    elif key == "score_group":
        return None if raw.strip().lower() in ("", "null", "none") else raw
    elif key == "tags":
        return [t.strip() for t in raw.split(",") if t.strip()]
    elif key not in ("name", "description"):
        raise MaintainError(f"key {key!r} cannot be changed with --set "
                            "(allowed: name category lang severity weight confidence default_action scope "
                            "context_requires score_group description tags; use enable/disable for status)")
    return raw


def _update(conn: sqlite3.Connection, args) -> int:
    r = _row(conn, args.id)
    doc = dbm.head_doc(conn, args.id)
    assert doc is not None
    changes: List[str] = []
    for item in args.set:
        if "=" not in item:
            raise MaintainError(f"--set expects KEY=VALUE, got {item!r}")
        key, raw = item.split("=", 1)
        value = _parse_value(key.strip(), raw)
        if doc.get(key) != value:
            changes.append(f"{key}: {doc.get(key)!r} -> {value!r}")
            doc[key] = value
    if not changes:
        print("no change")
        return 0
    if doc["scope"] == "translation_only" and not doc.get("context_requires"):
        raise MaintainError("scope=translation_only needs context_requires")
    if args.dry_run:
        print("[dry-run] " + "; ".join(changes))
        return 0
    with dbm.tx(conn):
        rev = dbm.write_revision(conn, doc, change_kind="edit", actor=args.actor,
                                 reason=args.reason or "; ".join(changes)[:300], origin=r["origin"],
                                 modified_locally=True)
    print(f"{args.id} updated (revision {rev}): " + "; ".join(changes))
    print(NOTE_PUBLISH)
    return 0


# ---------------------------------------------------------------------------------------------
# add (manual rules)
# ---------------------------------------------------------------------------------------------
_SPEC_KEYS = {"name", "category", "severity", "weight", "confidence", "default_action", "lang", "scope",
              "context_requires", "score_group", "description", "tags", "profile", "condition", "patterns",
              "tests", "status"}


def build_manual_doc(conn: sqlite3.Connection, spec: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, List[str]], List[str]]:
    unknown = set(spec) - _SPEC_KEYS
    if unknown:
        raise MaintainError(f"unknown rule spec key(s): {sorted(unknown)}")
    for k in ("name", "category", "severity", "patterns"):
        if k not in spec:
            raise MaintainError(f"rule spec needs '{k}'")
    category = spec["category"]
    if category not in CATEGORIES:
        raise MaintainError(f"category must be one of {sorted(CATEGORIES)}")
    severity = spec["severity"]
    if severity not in SEVERITIES:
        raise MaintainError(f"severity must be one of {SEVERITIES}")
    profile = spec.get("profile", "fold_v1")
    if profile not in PROFILES:
        raise MaintainError(f"profile must be one of {sorted(PROFILES)}")
    default_w = {"critical": 0.85, "high": 0.70, "medium": 0.50, "low": 0.30, "info": 0.15}[severity]
    weight = float(spec.get("weight", default_w))
    confidence = float(spec.get("confidence", 0.7))
    if not (0 <= weight <= 1 and 0 <= confidence <= 1):
        raise MaintainError("weight/confidence must be within [0, 1]")
    action = spec.get("default_action", "alert")
    if action not in ACTIONS:
        raise MaintainError(f"default_action must be one of {ACTIONS}")
    scope = spec.get("scope", "general")
    if scope not in SCOPES:
        raise MaintainError(f"scope must be one of {SCOPES}")
    ctx = spec.get("context_requires")
    if scope == "translation_only" and not ctx:
        ctx = {"task": "translation"}
    # ---- patterns -> pieces ---------------------------------------------------------------------
    notes: List[str] = []
    leaf_map: Dict[str, List[str]] = {}
    leaves: List[Dict[str, Any]] = []
    langs: List[str] = []
    seen_keys = set()
    keys: List[str] = []
    for i, pspec in enumerate(spec["patterns"]):
        if not isinstance(pspec, dict) or "regex" not in pspec:
            raise MaintainError(f"patterns[{i}] needs a 'regex'")
        key = str(pspec.get("key") or f"p{i + 1}")
        if key in seen_keys:
            raise MaintainError(f"duplicate pattern key {key}")
        seen_keys.add(key)
        keys.append(key)
        fld = pspec.get("field", "content")
        if fld not in KNOWN_FIELDS:
            raise MaintainError(f"patterns[{i}].field {fld!r} unknown (allowed: {sorted(KNOWN_FIELDS)})")
        conv = convert.convert_pattern(pspec["regex"], pspec.get("dialect", "pcre"), pspec.get("flags", ""),
                                       description="", force_flags="")
        if conv.fate not in ("hs_native", "hs_prefilter_pcre2") or not conv.pieces:
            raise MaintainError(f"patterns[{i}] ({key}) cannot be used: {conv.fate}: {conv.reason}")
        for n in conv.notes:
            if "removed non-target" in n or n.startswith("dropped") or n.startswith("not converted"):
                raise MaintainError(f"patterns[{i}] ({key}) would be altered by language scoping: {n}")
        ids = [key] if len(conv.pieces) == 1 else [f"{key}.{j + 1}" for j in range(len(conv.pieces))]
        leaf_map[key] = ids
        for lid, piece in zip(ids, conv.pieces):
            pid, _ = dbm.get_or_create_pattern(
                conn, regex=piece.regex, flags=piece.flags, profile=profile, lang=piece.lang,
                engine_class=piece.engine_class, class_reason=piece.class_reason, features=piece.features,
                min_len=piece.min_len, max_len=piece.max_len,
                expr_hash=convert.expr_hash(piece.regex, piece.flags, profile))
            leaves.append({"id": lid, "pattern_id": pid, "field": fld})
            langs.append(piece.lang)
    cond = spec.get("condition", "any")
    if isinstance(cond, str):
        if cond not in ("any", "all"):
            raise MaintainError("condition must be 'any', 'all' or a condition tree object")
        tree = {"op": cond, "args": [{"op": "leaf", "id": k} for k in keys]}
    else:
        tree = cond
        unknown_leaf = set(leaf_ids(tree)) - set(keys)
        if unknown_leaf:
            raise MaintainError(f"condition references unknown pattern key(s) {sorted(unknown_leaf)}")
    folded = fold_tree(tree, leaf_map)
    if folded is None:
        raise MaintainError("condition can never be satisfied")
    lang_set = set(langs) - {"any"}
    lang = spec.get("lang") or ("any" if not lang_set else "en" if lang_set == {"en"} else "zh" if lang_set == {"zh"} else "mixed")
    if lang not in LANGS:
        raise MaintainError(f"lang must be one of {LANGS}")
    doc = {
        "name": spec["name"], "category": category, "lang": lang, "severity": severity, "weight": round(weight, 4),
        "confidence": round(confidence, 4), "default_action": action, "status": spec.get("status", "enabled"),
        "scope": scope, "context_requires": ctx, "score_group": spec.get("score_group"),
        "description": spec.get("description", ""), "tags": list(spec.get("tags", [])) + ["manual"],
        "condition": folded, "leaves": leaves,
    }
    tests = spec.get("tests") or {}
    for kind in tests:
        if kind not in ("positive", "negative", "mixed"):
            raise MaintainError(f"unknown test kind {kind!r}")
    return doc, {k: list(v) for k, v in tests.items()}, notes


def _add(conn: sqlite3.Connection, args) -> int:
    spec_doc = json.loads(read_text(Path(args.file)))
    specs = spec_doc["rules"] if isinstance(spec_doc, dict) and "rules" in spec_doc else \
        spec_doc if isinstance(spec_doc, list) else [spec_doc]
    created: List[str] = []
    try:
        with dbm.tx(conn):
            for spec in specs:
                doc, tests, _ = build_manual_doc(conn, spec)
                existing = conn.execute("SELECT rule_id FROM rules WHERE origin='manual' AND name = ?",
                                        (doc["name"],)).fetchone()
                if existing:
                    print(f"skip: manual rule named {doc['name']!r} already exists as {existing['rule_id']}")
                    continue
                rule_id = dbm.alloc_rule_id(conn, CATEGORY_CODE[doc["category"]])
                doc["rule_id"] = rule_id
                rev = dbm.write_revision(conn, doc, change_kind="create", actor=args.actor,
                                         reason=args.reason or f"manual rule from {Path(args.file).name}",
                                         origin="manual", modified_locally=False)
                now = utc_now()
                for kind, samples in tests.items():
                    for text in samples:
                        conn.execute(
                            "INSERT OR IGNORE INTO rule_tests (rule_id, kind, text, text_sha256, lang, scan_source, "
                            "expect_hit, origin, note, created_at) VALUES (?,?,?,?,?,?,?, 'manual', ?, ?)",
                            (rule_id, kind, text, sha256_text(text), None, "user_input",
                             0 if kind == "negative" else 1, "manual rule test", now))
                created.append(rule_id)
                print(f"{'[dry-run] would create' if args.dry_run else 'created'} {rule_id} (revision {rev}): {doc['name']}")
            if args.dry_run:
                raise _DryRun()
    except _DryRun:
        return 0                                   # the transaction was rolled back
    if created:
        print(NOTE_PUBLISH)
    return 0


# ---------------------------------------------------------------------------------------------
# sync-manual: make the manual rules of the database equal to what the JSON files say
# ---------------------------------------------------------------------------------------------
def _load_specs(files: List[str]) -> List[Dict[str, Any]]:
    specs: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    for f in files:
        doc = json.loads(read_text(Path(f)))
        items = doc["rules"] if isinstance(doc, dict) and "rules" in doc else doc if isinstance(doc, list) else [doc]
        for spec in items:
            name = spec.get("name")
            if not name:
                raise MaintainError(f"{f}: a rule has no 'name' (the name is the key that ties a JSON rule to a database rule)")
            if name in seen:
                raise MaintainError(f"rule name {name!r} appears in {seen[name]} and in {f}")
            seen[name] = f
            specs.append(spec)
    return specs


def _sync_tests(conn: sqlite3.Connection, rule_id: str, tests: Dict[str, List[str]]) -> Tuple[int, int]:
    wanted = {(kind, sha256_text(text)): (kind, text) for kind, texts in tests.items() for text in texts}
    have = {(r["kind"], r["text_sha256"]) for r in conn.execute(
        "SELECT kind, text_sha256 FROM rule_tests WHERE rule_id = ? AND origin = 'manual'", (rule_id,))}
    now = utc_now()
    for key in sorted(set(wanted) - have):
        kind, text = wanted[key]
        conn.execute(
            "INSERT OR IGNORE INTO rule_tests (rule_id, kind, text, text_sha256, lang, scan_source, expect_hit, origin, "
            "note, created_at) VALUES (?,?,?,?,?,?,?, 'manual', ?, ?)",
            (rule_id, kind, text, key[1], None, "user_input", 0 if kind == "negative" else 1, "manual rule test", now))
    for key in sorted(have - set(wanted)):
        conn.execute("DELETE FROM rule_tests WHERE rule_id = ? AND kind = ? AND text_sha256 = ? AND origin = 'manual'",
                     (rule_id, key[0], key[1]))
    return len(set(wanted) - have), len(have - set(wanted))


def _sync_manual(conn: sqlite3.Connection, args) -> int:
    specs = _load_specs(args.file)
    counts = {"created": 0, "updated": 0, "unchanged": 0, "removed": 0}
    try:
        with dbm.tx(conn):
            for spec in specs:
                doc, tests, _ = build_manual_doc(conn, spec)
                row = conn.execute("SELECT rule_id FROM rules WHERE origin='manual' AND name = ?", (doc["name"],)).fetchone()
                if row is None:
                    doc["rule_id"] = dbm.alloc_rule_id(conn, CATEGORY_CODE[doc["category"]])
                    rev = dbm.write_revision(conn, doc, change_kind="create", actor=args.actor,
                                             reason=args.reason or "manual rule (sync-manual)", origin="manual",
                                             modified_locally=False)
                    _sync_tests(conn, doc["rule_id"], tests)
                    counts["created"] += 1
                    print(f"created   {doc['rule_id']} (revision {rev}): {doc['name']}")
                    continue
                doc["rule_id"] = row["rule_id"]
                head = dbm.head_doc(conn, row["rule_id"])
                if head is not None and dbm.rule_doc_hash(head) == dbm.rule_doc_hash(doc):
                    added, dropped = _sync_tests(conn, row["rule_id"], tests)
                    counts["unchanged"] += 1
                    if added or dropped:
                        print(f"tests     {row['rule_id']}: +{added} -{dropped} sample(s): {doc['name']}")
                    continue
                rev = dbm.write_revision(conn, doc, change_kind="edit", actor=args.actor,
                                         reason=args.reason or "manual rule changed in its JSON file (sync-manual)",
                                         origin="manual", modified_locally=False)
                _sync_tests(conn, row["rule_id"], tests)
                counts["updated"] += 1
                print(f"updated   {row['rule_id']} (revision {rev}): {doc['name']}")
            names = {sp["name"] for sp in specs}
            for r in conn.execute("SELECT rule_id, name FROM rules WHERE origin='manual' AND status <> 'deleted' ORDER BY rule_id").fetchall():
                if r["name"] in names:
                    continue
                if not args.prune:
                    print(f"kept      {r['rule_id']}: {r['name']!r} is in the database but in none of the given files "
                          "(add --prune to delete such rules)")
                    continue
                head = dbm.head_doc(conn, r["rule_id"])
                assert head is not None
                head["status"] = "deleted"
                dbm.write_revision(conn, head, change_kind="delete", actor=args.actor,
                                   reason=args.reason or "no longer in the manual rule files (sync-manual --prune)",
                                   origin="manual", modified_locally=False)
                counts["removed"] += 1
                print(f"removed   {r['rule_id']}: {r['name']}")
            if args.dry_run:
                raise _DryRun()
    except _DryRun:
        print("[dry-run] nothing was written: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
        return 0
    print("sync-manual: " + ", ".join(f"{k} {v}" for k, v in counts.items()))
    if counts["created"] or counts["updated"] or counts["removed"]:
        print(NOTE_PUBLISH)
    return 0


# ---------------------------------------------------------------------------------------------
def _restore_upstream(conn: sqlite3.Connection, args) -> int:
    from . import pipeline, sources
    import sources as plugins
    r = _row(conn, args.id)
    prov = conn.execute(
        "SELECT s.source_id, s.source_key, s.source_rule_id FROM rule_provenance p JOIN source_rules s "
        "ON s.source_rule_id = p.source_rule_id WHERE p.rule_id = ? AND p.kind='rule'", (args.id,)).fetchone()
    if prov is None:
        raise MaintainError(f"{args.id} has no upstream source (manual rule)")
    defs = sources.load_defs()
    lock = sources.load_lock()
    sd = defs[prov["source_id"]]
    importer = plugins.get_importer(sd.importer)
    res = importer.extract(sd.dir, lock["sources"][prov["source_id"]], lambda *_: None)
    src = next((x for x in res.rules if x.source_key == prov["source_key"]), None)
    if src is None:
        raise MaintainError("the source rule no longer exists upstream")
    pr = pipeline.prepare_rule(src, importer.version)
    if pr.pre_doc is None:
        raise MaintainError(f"upstream rule is {pr.decision}: {pr.reason}")
    if args.dry_run:
        print(f"[dry-run] {args.id} would be restored from {prov['source_id']}:{prov['source_key']}")
        return 0
    with dbm.tx(conn):
        doc, _, _ = pipeline._resolve_doc(conn, pr, src.unified.norm_profile)
        doc["rule_id"] = args.id
        rev = dbm.write_revision(conn, doc, change_kind="restore", actor=args.actor,
                                 reason=args.reason or "restored from upstream definition", origin=r["origin"],
                                 modified_locally=False)
    print(f"{args.id} restored from upstream (revision {rev})")
    print(NOTE_PUBLISH)
    return 0
