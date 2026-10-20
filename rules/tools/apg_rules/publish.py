"""Rule-set versions: stage, publish (immutable), list, diff, activate, rollback, artifact registry.

A published version is
  * a row in ruleset_versions (status=published, frozen by triggers),
  * ruleset_members: (rule_id, revision) -> immutable rule_revisions rows,
  * ruleset_patterns: the pattern ids used,
  * ruleset_snapshots: the canonical JSON document the C++ compiler/engine consume.
The snapshot is built ONLY from rule_revisions / rule_patterns, never from mutable head state.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import SNAPSHOT_FORMAT_VERSION, TOOL_VERSION
from . import db as dbm
from .util import (atomic_write_bytes, atomic_write_text, canonical_json, canonical_json_bytes, pretty_json,
                   project_root, read_text, rel_to_root, sha256_bytes, sha256_text, utc_now)
from .validate import SEMVER, validate_rules

from .model import PROFILES, SOURCE_FIELD_MAP  # noqa: E402

SCORING_DEFAULTS = {
    "model": "noisy_or_v1",
    "thresholds": {"review": 0.30, "alert": 0.50, "block": 0.85},
    "source_multiplier": {"user_input": 1.0, "tool_output": 1.15, "rag_document": 1.15, "agent_message": 1.10},
    "risk_levels": [["critical", 0.80], ["high", 0.60], ["medium", 0.40], ["low", 0.15]],
    "group_combine": "max",
    # A rule that matched (or partly matched) but could not be evaluated completely (required context / field
    # missing) is always reported in `needs_context[]`; if its risk reaches this value -- i.e. it WOULD have produced
    # an alert had the context been supplied -- the decision is raised to `review` ("one notch down", never to alert).
    # Deployments without context-dependent workflows (e.g. no translation) can raise it at run time with
    # `policy.needs_context_review_at` (1.0 effectively disables the escalation).
    "needs_context_review_at": 0.50,
}


class PublishError(Exception):
    pass


# =============================================================================================
# semver
# =============================================================================================
def semver_key(v: str) -> Tuple:
    m = SEMVER.match(v)
    if not m:
        raise PublishError(f"{v!r} is not a semantic version (MAJOR.MINOR.PATCH[-prerelease])")
    pre = m.group(4)
    # a release sorts after its own pre-releases
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 1 if pre is None else 0, pre or "")


# =============================================================================================
# snapshot
# =============================================================================================
def source_digest(conn: sqlite3.Connection) -> str:
    rows = conn.execute("SELECT source_id, commit_sha, lock_tree_sha256, extractor_version FROM upstream_sources "
                        "ORDER BY source_id").fetchall()
    return sha256_text(canonical_json([[r["source_id"], r["commit_sha"], r["lock_tree_sha256"], r["extractor_version"]]
                                       for r in rows]))


def head_members(conn: sqlite3.Connection) -> List[Tuple[str, int]]:
    return [(r["rule_id"], int(r["revision"])) for r in
            conn.execute("SELECT rule_id, revision FROM rules WHERE status = 'enabled' ORDER BY rule_id")]


def evidence_signature(rule: Dict[str, Any]) -> str:
    """Hash of WHAT a rule looks at: its condition tree with every leaf replaced by (pattern id, field).
    Two rules with the same signature fire on exactly the same evidence."""
    leaves = {lf["id"]: (lf["pattern_id"], lf["field"]) for lf in rule["leaves"]}

    def norm(node: Dict[str, Any]) -> Any:
        if node["op"] == "leaf":
            return ["leaf", *leaves[node["id"]]]
        kids = [norm(a) for a in node["args"]]
        if node["op"] in ("any", "all"):
            kids.sort(key=canonical_json)
        return [node["op"], kids]

    return sha256_text(canonical_json(norm(rule["condition"])))


def assign_same_evidence_groups(rules: List[Dict[str, Any]]) -> int:
    """Rules that fire on exactly the same evidence (typically the same pattern imported from two sources) must not
    stack in the noisy-OR: they get a shared score_group (their risk is combined with max). Rules that already
    carry an explicit score_group are left alone. Returns the number of rules put into a derived group."""
    by_sig: Dict[str, List[Dict[str, Any]]] = {}
    for r in rules:
        if r.get("score_group") is None:
            by_sig.setdefault(evidence_signature(r), []).append(r)
    n = 0
    for sig, group in by_sig.items():
        if len(group) > 1:
            for r in group:
                r["score_group"] = "same-evidence:" + sig[:12]
                n += 1
    return n


def build_snapshot(conn: sqlite3.Connection, version: str, members: List[Tuple[str, int]]) -> Dict[str, Any]:
    rules: List[Dict[str, Any]] = []
    pattern_ids = set()
    for rule_id, revision in members:
        row = conn.execute("SELECT content_json FROM rule_revisions WHERE rule_id = ? AND revision = ?",
                           (rule_id, revision)).fetchone()
        if row is None:
            raise PublishError(f"revision {rule_id}#{revision} missing")
        d = json.loads(row["content_json"])
        rules.append({
            "id": rule_id, "revision": revision, "name": d["name"], "category": d["category"], "lang": d["lang"],
            "severity": d["severity"], "weight": d["weight"], "confidence": d["confidence"],
            "action": d["default_action"], "scope": d["scope"], "context_requires": d.get("context_requires"),
            "score_group": d.get("score_group"), "condition": d["condition"],
            "leaves": [{"id": lf["id"], "pattern_id": lf["pattern_id"], "field": lf["field"]} for lf in d["leaves"]],
        })
        pattern_ids.update(lf["pattern_id"] for lf in d["leaves"])
    assign_same_evidence_groups(rules)
    patterns: List[Dict[str, Any]] = []
    profiles_used = set()
    for pid in sorted(pattern_ids):
        p = conn.execute("SELECT * FROM rule_patterns WHERE pattern_id = ?", (pid,)).fetchone()
        if p is None or p["engine_class"] == "unsupported":
            raise PublishError(f"pattern {pid} is missing or unsupported")
        patterns.append({"id": pid, "regex": p["regex"], "flags": p["flags"], "profile": p["norm_profile"],
                         "class": p["engine_class"], "lang": p["lang"]})
        profiles_used.add(p["norm_profile"])
    payload = {
        "format": "apg-ruleset-snapshot", "format_version": SNAPSHOT_FORMAT_VERSION,
        "normalizer": {"tables_version": 1, "profiles": {k: PROFILES[k] for k in sorted(profiles_used)}},
        "field_map": SOURCE_FIELD_MAP, "scoring": SCORING_DEFAULTS,
        "patterns": patterns, "rules": rules,
    }
    digest = sha256_text(canonical_json(payload))
    doc = dict(payload)
    doc["ruleset"] = {"version": version, "content_digest": digest, "source_digest": source_digest(conn)}
    return doc


def snapshot_bytes(doc: Dict[str, Any]) -> bytes:
    return canonical_json_bytes(doc)


# =============================================================================================
# commands
# =============================================================================================
def run(name: str, conn: sqlite3.Connection, args) -> int:
    from .cli import CliError
    try:
        return {"stage": _stage, "publish": _publish, "versions": _versions, "activate": _activate,
                "rollback": _rollback, "export-snapshot": _export, "register-artifact": _register}[name](conn, args)
    except PublishError as exc:
        raise CliError(str(exc)) from exc


def _gate(conn: sqlite3.Connection, args) -> None:
    if getattr(args, "no_validate", False):
        print("[validate] SKIPPED (--no-validate)")
        return
    res = validate_rules(conn)
    print(res.render())
    if res.count("error"):
        raise PublishError("validation failed; fix the errors above (or inspect with `rules.py validate -v`)")


def _stage(conn: sqlite3.Connection, args) -> int:
    _gate(conn, args)
    label = args.version or "draft"
    members = head_members(conn)
    doc = build_snapshot(conn, label, members)
    body = snapshot_bytes(doc)
    print(f"[stage] {len(members)} enabled rule(s), {len(doc['patterns'])} pattern(s), content digest "
          f"{doc['ruleset']['content_digest'][:16]}")
    if args.dry_run:
        print("[stage] dry-run: nothing written")
        return 0
    with dbm.tx(conn):
        _drop_drafts(conn)
        vid = _insert_version(conn, label, "draft", members, doc, body, args, promote=False)
        dbm.audit(conn, args.actor, "stage", "ruleset", label, {"digest": doc["ruleset"]["content_digest"]})
    print(f"[stage] draft version '{label}' stored (version_id {vid}); inspect: rules.py export-snapshot --version {label} --out FILE")
    return 0


def _drop_drafts(conn: sqlite3.Connection) -> None:
    for d in conn.execute("SELECT version_id FROM ruleset_versions WHERE status = 'draft'").fetchall():
        vid = d["version_id"]
        conn.execute("DELETE FROM ruleset_snapshots WHERE version_id = ?", (vid,))
        conn.execute("DELETE FROM ruleset_patterns WHERE version_id = ?", (vid,))
        conn.execute("DELETE FROM ruleset_members WHERE version_id = ?", (vid,))
        conn.execute("DELETE FROM ruleset_versions WHERE version_id = ?", (vid,))


def _insert_version(conn: sqlite3.Connection, version: str, status: str, members: List[Tuple[str, int]],
                    doc: Dict[str, Any], body: bytes, args, promote: bool) -> int:
    prev = conn.execute("SELECT version_id FROM ruleset_versions WHERE status IN ('published','retired') "
                        "ORDER BY version_id DESC LIMIT 1").fetchone()
    vid = dbm.alloc_counter(conn, "ruleset_version_id", 1)
    now = utc_now()
    conn.execute("INSERT INTO ruleset_versions (version_id, version, status, created_at, created_by, notes, "
                 "snapshot_format) VALUES (?,?, 'draft', ?, ?, ?, ?)",
                 (vid, version, now, args.actor, getattr(args, "notes", "") or None, SNAPSHOT_FORMAT_VERSION))
    for rule_id, revision in members:
        conn.execute("INSERT INTO ruleset_members (version_id, rule_id, revision, enabled) VALUES (?,?,?,1)",
                     (vid, rule_id, revision))
    for p in doc["patterns"]:
        conn.execute("INSERT INTO ruleset_patterns (version_id, pattern_id) VALUES (?,?)", (vid, p["id"]))
    sha = sha256_bytes(body)
    conn.execute("INSERT INTO ruleset_snapshots (version_id, body, sha256) VALUES (?,?,?)", (vid, body, sha))
    conn.execute("UPDATE ruleset_versions SET content_digest=?, snapshot_sha256=?, rule_count=?, pattern_count=?, "
                 "source_digest=?, previous_version_id=? WHERE version_id=?",
                 (doc["ruleset"]["content_digest"], sha, len(members), len(doc["patterns"]),
                  doc["ruleset"]["source_digest"], prev["version_id"] if prev else None, vid))
    if promote:
        conn.execute("UPDATE ruleset_versions SET status='published', published_at=? WHERE version_id=?", (now, vid))
    return vid


def _publish(conn: sqlite3.Connection, args) -> int:
    version = args.version
    new_key = semver_key(version)
    if conn.execute("SELECT 1 FROM ruleset_versions WHERE version = ? AND status <> 'draft'", (version,)).fetchone():
        raise PublishError(f"version {version} already exists and is immutable; choose a new version number")
    last = conn.execute("SELECT version, content_digest FROM ruleset_versions WHERE status <> 'draft' "
                        "ORDER BY version_id DESC LIMIT 1").fetchone()
    for row in conn.execute("SELECT version FROM ruleset_versions WHERE status <> 'draft'"):
        if semver_key(row["version"]) >= new_key:
            raise PublishError(f"version {version} must be greater than every existing version "
                               f"(found {row['version']}); versions only move forward, use `rollback` to go back")
    _gate(conn, args)
    members = head_members(conn)
    if not members:
        raise PublishError("no enabled rules to publish")
    doc = build_snapshot(conn, version, members)
    body = snapshot_bytes(doc)
    digest = doc["ruleset"]["content_digest"]
    if last and last["content_digest"] == digest:
        raise PublishError(f"the rule content is identical to version {last['version']}; nothing to publish")
    staged = conn.execute("SELECT version, content_digest FROM ruleset_versions WHERE status='draft'").fetchone()
    print(f"[publish] version {version}: {len(members)} rule(s), {len(doc['patterns'])} pattern(s), "
          f"digest {digest[:16]}" + (" (matches staged draft)" if staged and staged["content_digest"] else ""))
    if args.dry_run:
        print("[publish] dry-run: nothing written")
        return 0
    with dbm.tx(conn):
        _drop_drafts(conn)
        vid = _insert_version(conn, version, "published", members, doc, body, args, promote=True)
        dbm.audit(conn, args.actor, "publish", "ruleset", version,
                  {"version_id": vid, "rules": len(members), "patterns": len(doc["patterns"]), "digest": digest,
                   "snapshot_sha256": sha256_bytes(body)})
    print(f"[publish] published {version} (version_id {vid}, snapshot sha256 {sha256_bytes(body)[:16]}...)")
    print("Next: compile for the target platform, e.g.\n"
          f"  ai-prompt-guard compile --db {rel_to_root(args.db)} --version {version} --target native --out dist/\n"
          f"then:  rules.py register-artifact --manifest dist/<os>/<arch>/{version}/manifest.json\n"
          f"       rules.py activate --version {version}")
    return 0


def _versions(conn: sqlite3.Connection, args) -> int:
    from .cli import _table
    active = conn.execute("SELECT version_id FROM active_ruleset WHERE channel='default'").fetchone()
    rows = []
    for v in conn.execute("SELECT * FROM ruleset_versions ORDER BY version_id"):
        arts = conn.execute("SELECT COUNT(*) FROM compiled_artifacts WHERE version_id=?", (v["version_id"],)).fetchone()[0]
        rows.append([v["version"], v["status"], v["rule_count"], v["pattern_count"], (v["content_digest"] or "")[:12],
                     (v["published_at"] or v["created_at"] or "")[:19], arts,
                     "ACTIVE" if active and active["version_id"] == v["version_id"] else ""])
    print(_table(rows, ["version", "status", "rules", "patterns", "digest", "published", "artifacts", "active"]))
    return 0


def _version_row(conn: sqlite3.Connection, version: str) -> sqlite3.Row:
    r = conn.execute("SELECT * FROM ruleset_versions WHERE version = ?", (version,)).fetchone()
    if r is None:
        raise PublishError(f"version {version} does not exist")
    return r


def _export(conn: sqlite3.Connection, args) -> int:
    v = _version_row(conn, args.version)
    s = conn.execute("SELECT body FROM ruleset_snapshots WHERE version_id = ?", (v["version_id"],)).fetchone()
    if s is None:
        raise PublishError("no snapshot stored for this version")
    atomic_write_bytes(args.out, bytes(s["body"]))
    print(f"[export] {args.version}: {len(bytes(s['body']))} bytes -> {args.out}")
    return 0


def _write_pointer(pointer_dir: Optional[str], conn: sqlite3.Connection, version_row: sqlite3.Row, channel: str) -> None:
    if not pointer_dir:
        return
    art = conn.execute("SELECT manifest_sha256, rel_path FROM compiled_artifacts WHERE version_id=? ORDER BY artifact_id DESC LIMIT 1",
                       (version_row["version_id"],)).fetchone()
    ptr = {"kind": "apg-active-pointer", "schema_version": 1, "channel": channel, "version": version_row["version"],
           "manifest": f"{version_row['version']}/manifest.json",
           "manifest_sha256": art["manifest_sha256"] if art else None, "activated_at": utc_now()}
    atomic_write_text(Path(pointer_dir) / "active.json", pretty_json(ptr))
    print(f"[activate] pointer file written: {Path(pointer_dir) / 'active.json'}")


def _activate(conn: sqlite3.Connection, args) -> int:
    v = _version_row(conn, args.version)
    if v["status"] != "published":
        raise PublishError(f"version {args.version} is {v['status']}; only published versions can be activated")
    return _set_active(conn, args, v, "activate")


def _rollback(conn: sqlite3.Connection, args) -> int:
    v = _version_row(conn, args.to)
    if v["status"] != "published":
        raise PublishError(f"version {args.to} is {v['status']}; only published versions can be a rollback target")
    cur = conn.execute("SELECT version_id FROM active_ruleset WHERE channel = ?", (args.channel,)).fetchone()
    if cur is not None and cur["version_id"] == v["version_id"]:
        raise PublishError(f"{args.to} is already the active version")
    return _set_active(conn, args, v, "rollback")


def _set_active(conn: sqlite3.Connection, args, v: sqlite3.Row, action: str) -> int:
    cur = conn.execute("SELECT * FROM active_ruleset WHERE channel = ?", (args.channel,)).fetchone()
    now = utc_now()
    reason = getattr(args, "reason", "") or f"{action} by {args.actor}"
    with dbm.tx(conn):
        if cur is None:
            conn.execute("INSERT INTO active_ruleset (channel, version_id, previous_version_id, activated_at, "
                         "activated_by, reason) VALUES (?,?,NULL,?,?,?)",
                         (args.channel, v["version_id"], now, args.actor, reason))
        else:
            conn.execute("UPDATE active_ruleset SET version_id=?, previous_version_id=?, activated_at=?, "
                         "activated_by=?, reason=? WHERE channel=?",
                         (v["version_id"], cur["version_id"], now, args.actor, reason, args.channel))
        dbm.audit(conn, args.actor, action, "ruleset", v["version"],
                  {"channel": args.channel, "from_version_id": cur["version_id"] if cur else None, "reason": reason})
    print(f"[{action}] channel '{args.channel}' now points to {v['version']}")
    _write_pointer(getattr(args, "pointer_dir", None), conn, v, args.channel)
    return 0


def _register(conn: sqlite3.Connection, args) -> int:
    mpath = Path(args.manifest)
    manifest = json.loads(read_text(mpath))
    if manifest.get("kind") != "apg-manifest":
        raise PublishError("not an apg-manifest document")
    rs, tg, files = manifest["ruleset"], manifest["target"], manifest["files"]
    v = _version_row(conn, rs["version"])
    if v["status"] != "published":
        raise PublishError("artifacts can only be registered for published versions")
    if v["snapshot_sha256"] != rs["snapshot_sha256"]:
        raise PublishError("manifest snapshot_sha256 does not match the published snapshot of that version")
    base = mpath.parent
    meta = files["meta"]
    if sha256_bytes((base / meta["path"]).read_bytes()) != meta["sha256"]:
        raise PublishError("ruleset metadata file does not match the hash in the manifest")
    hsdb_hash = ",".join(d["sha256"] for d in files.get("databases", [])) or None
    msha = sha256_bytes(mpath.read_bytes())
    counts = manifest.get("patterns", {})
    status = manifest.get("status", "ok")
    report = None
    rp = base / "build_report.json"
    if rp.is_file():
        report = read_text(rp)
    with dbm.tx(conn):
        cur = conn.execute(
            "INSERT INTO compiled_artifacts (version_id, target_os, arch, backend, hs_version, cpu_features, cpu_target, "
            "engine_abi, compiler_version, manifest_sha256, hsdb_sha256, meta_sha256, rel_path, status, pattern_total, "
            "pattern_native, pattern_prefilter, pattern_failed, built_at, report_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (v["version_id"], tg["os"], tg["arch"], tg["backend"], tg.get("hyperscan_version"), tg.get("cpu_features"),
             tg.get("cpu_target"), manifest["engine"]["abi_version"], tg.get("compiler"), msha, hsdb_hash, meta["sha256"],
             rel_to_root(mpath), status, counts.get("total"), counts.get("native"), counts.get("prefilter"),
             counts.get("failed"), manifest.get("built_at") or utc_now(), report))
        aid = cur.lastrowid
        if report:
            for item in json.loads(report).get("patterns", []):
                conn.execute("INSERT OR REPLACE INTO compiled_pattern_results (artifact_id, pattern_id, final_class, "
                             "error_text) VALUES (?,?,?,?)", (aid, item["id"], item["class"], item.get("error")))
        dbm.audit(conn, args.actor, "register_artifact", "ruleset", rs["version"],
                  {"artifact_id": aid, "os": tg["os"], "arch": tg["arch"], "manifest_sha256": msha})
    print(f"[register] artifact {aid} recorded for {rs['version']} ({tg['os']}/{tg['arch']}, {tg['backend']}, {status})")
    return 0


# =============================================================================================
# diff between versions
# =============================================================================================
@dataclass
class VersionDiff:
    a: str
    b: str
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    changed: List[Tuple[str, List[str]]] = field(default_factory=list)
    patterns_added: int = 0
    patterns_removed: int = 0
    same_digest: bool = False

    def render(self) -> str:
        lines = [f"diff {self.a} -> {self.b}: +{len(self.added)} rules, -{len(self.removed)} rules, "
                 f"~{len(self.changed)} changed, patterns +{self.patterns_added}/-{self.patterns_removed}"
                 + ("  (identical content digest)" if self.same_digest else "")]
        for r in self.added[:50]:
            lines.append(f"  + {r}")
        for r in self.removed[:50]:
            lines.append(f"  - {r}")
        for r, ch in self.changed[:80]:
            lines.append(f"  ~ {r}: " + "; ".join(ch[:4]))
        return "\n".join(lines)


def diff_versions(conn: sqlite3.Connection, a: str, b: str) -> VersionDiff:
    va, vb = _version_row(conn, a), _version_row(conn, b)

    def members(v):
        return {r["rule_id"]: r["revision"] for r in conn.execute(
            "SELECT rule_id, revision FROM ruleset_members WHERE version_id = ?", (v["version_id"],))}

    ma, mb = members(va), members(vb)
    d = VersionDiff(a, b, same_digest=(va["content_digest"] == vb["content_digest"]))
    d.added = sorted(set(mb) - set(ma))
    d.removed = sorted(set(ma) - set(mb))
    for rid in sorted(set(ma) & set(mb)):
        if ma[rid] == mb[rid]:
            continue
        da = json.loads(conn.execute("SELECT content_json FROM rule_revisions WHERE rule_id=? AND revision=?", (rid, ma[rid])).fetchone()[0])
        db_ = json.loads(conn.execute("SELECT content_json FROM rule_revisions WHERE rule_id=? AND revision=?", (rid, mb[rid])).fetchone()[0])
        ch = [f"{k}: {da.get(k)!r} -> {db_.get(k)!r}" for k in
              ("category", "lang", "severity", "weight", "confidence", "default_action", "scope", "context_requires",
               "score_group") if da.get(k) != db_.get(k)]
        if da["condition"] != db_["condition"]:
            ch.append("condition changed")
        pa = {lf["pattern_id"] for lf in da["leaves"]}
        pb = {lf["pattern_id"] for lf in db_["leaves"]}
        if pa != pb:
            ch.append(f"patterns +{len(pb - pa)}/-{len(pa - pb)}")
        d.changed.append((rid, ch or [f"revision {ma[rid]} -> {mb[rid]}"]))
    pa = {r[0] for r in conn.execute("SELECT pattern_id FROM ruleset_patterns WHERE version_id=?", (va["version_id"],))}
    pb = {r[0] for r in conn.execute("SELECT pattern_id FROM ruleset_patterns WHERE version_id=?", (vb["version_id"],))}
    d.patterns_added, d.patterns_removed = len(pb - pa), len(pa - pb)
    return d
