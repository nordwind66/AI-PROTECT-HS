"""SQLite access layer: connection, migrations, id allocation, audit chain, revision writer.

All mutations of the authoritative database go through this module inside explicit transactions,
so that rules, revisions, links and audit entries always change together.
"""
from __future__ import annotations

import getpass
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import TOOL_VERSION
from .util import canonical_json, project_root, sha256_bytes, sha256_text, utc_now

SQL_DIR = project_root() / "sql"
GENESIS = "0" * 64
MIN_SQLITE = (3, 24, 0)


class DbError(RuntimeError):
    pass


def default_actor() -> str:
    return os.environ.get("APG_ACTOR") or ("cli:" + _safe_user())


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover
        return "unknown"


# ---------------------------------------------------------------------------------------------
# connection / migrations
# ---------------------------------------------------------------------------------------------
_tracker = threading.local()


@contextmanager
def track_connections() -> Iterator[None]:
    """Closes every connection opened inside the block when it ends. The command line uses it so that no file
    handle survives a command (matters on Windows, where an open handle blocks deleting / replacing the file)."""
    previous = getattr(_tracker, "conns", None)
    _tracker.conns = []
    try:
        yield
    finally:
        conns = _tracker.conns
        _tracker.conns = previous
        for c in conns:
            try:
                c.close()
            except sqlite3.Error:  # pragma: no cover
                pass


def connect(path: os.PathLike, *, create: bool = False, readonly: bool = False, wal: bool = False,
            timeout: float = 15.0) -> sqlite3.Connection:
    p = Path(path)
    if sqlite3.sqlite_version_info < MIN_SQLITE:
        raise DbError(f"SQLite {sqlite3.sqlite_version} is too old; >= 3.24 required")
    if not p.exists() and not create:
        raise DbError(f"database {p} does not exist (run `rules.py db init`)")
    if readonly:
        uri = p.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=timeout, isolation_level=None)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p), timeout=timeout, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = %d" % int(timeout * 1000))
    if wal and not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
    tracked = getattr(_tracker, "conns", None)
    if tracked is not None:
        tracked.append(conn)
    return conn


@contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT (ROLLBACK on any exception)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def migration_files() -> List[Tuple[int, str, Path]]:
    out = []
    for p in sorted(SQL_DIR.glob("[0-9][0-9][0-9]_*.sql")):
        out.append((int(p.name[:3]), p.name[4:-4], p))
    return out


def applied_migrations(conn: sqlite3.Connection) -> Dict[int, sqlite3.Row]:
    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()
    if not exists:
        return {}
    return {r["version"]: r for r in conn.execute("SELECT * FROM schema_migrations ORDER BY version")}


def migrate(conn: sqlite3.Connection) -> List[int]:
    """Apply pending migrations (each atomically). Returns the versions applied now."""
    applied = applied_migrations(conn)
    done: List[int] = []
    for version, name, path in migration_files():
        data = path.read_bytes()
        checksum = sha256_bytes(data)
        if version in applied:
            if applied[version]["checksum"] != checksum:
                raise DbError(f"migration {path.name} was modified after it was applied "
                              f"(recorded {applied[version]['checksum'][:12]}, file {checksum[:12]}); "
                              "never edit an applied migration, add a new one")
            continue
        script = ("BEGIN IMMEDIATE;\n" + data.decode("utf-8") + "\n" +
                  "INSERT INTO schema_migrations (version, name, checksum, applied_at, tool_version) "
                  "VALUES (%d, '%s', '%s', '%s', '%s');\nCOMMIT;\n" % (version, name, checksum, utc_now(), TOOL_VERSION))
        try:
            conn.executescript(script)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        done.append(version)
    return done


def schema_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return int(row["v"] or 0)


def latest_known_version() -> int:
    files = migration_files()
    return files[-1][0] if files else 0


# ---------------------------------------------------------------------------------------------
# id allocation (monotonic, never reused)
# ---------------------------------------------------------------------------------------------
def alloc_counter(conn: sqlite3.Connection, name: str, start: int = 1) -> int:
    row = conn.execute("SELECT next_value FROM id_counters WHERE name = ?", (name,)).fetchone()
    if row is None:
        conn.execute("INSERT INTO id_counters (name, next_value) VALUES (?, ?)", (name, start + 1))
        return start
    value = int(row["next_value"])
    conn.execute("UPDATE id_counters SET next_value = ? WHERE name = ?", (value + 1, name))
    return value


def alloc_rule_id(conn: sqlite3.Connection, code: str) -> str:
    n = alloc_counter(conn, "rule_seq:" + code, 1)
    return "AIPS-%s-%04d" % (code, n)


def alloc_pattern_id(conn: sqlite3.Connection) -> int:
    pid = alloc_counter(conn, "pattern_id", 10001)
    if pid > 4294967295:
        raise DbError("pattern id space (uint32) exhausted")
    return pid


# ---------------------------------------------------------------------------------------------
# audit (hash chain)
# ---------------------------------------------------------------------------------------------
def _entry_hash(prev: str, ts: str, actor: str, action: str, otype: str, oid: Optional[str],
                detail: Optional[str]) -> str:
    return sha256_text("\n".join([prev, ts, actor, action, otype, oid or "", detail or ""]))


def audit(conn: sqlite3.Connection, actor: str, action: str, object_type: str,
          object_id: Optional[str] = None, detail: Optional[Dict[str, Any]] = None) -> None:
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY audit_id DESC LIMIT 1").fetchone()
    prev = row["entry_hash"] if row else GENESIS
    ts = utc_now()
    detail_s = canonical_json(detail) if detail is not None else None
    h = _entry_hash(prev, ts, actor, action, object_type, object_id, detail_s)
    conn.execute("INSERT INTO audit_log (ts, actor, action, object_type, object_id, detail, prev_hash, entry_hash) "
                 "VALUES (?,?,?,?,?,?,?,?)", (ts, actor, action, object_type, object_id, detail_s, prev, h))


def verify_audit_chain(conn: sqlite3.Connection) -> List[str]:
    problems: List[str] = []
    prev = GENESIS
    for r in conn.execute("SELECT * FROM audit_log ORDER BY audit_id"):
        if r["prev_hash"] != prev:
            problems.append(f"audit #{r['audit_id']}: prev_hash does not match the preceding entry")
        h = _entry_hash(r["prev_hash"], r["ts"], r["actor"], r["action"], r["object_type"], r["object_id"], r["detail"])
        if h != r["entry_hash"]:
            problems.append(f"audit #{r['audit_id']}: entry hash mismatch (row was modified)")
        prev = r["entry_hash"]
    return problems


# ---------------------------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------------------------
def get_or_create_pattern(conn: sqlite3.Connection, *, regex: str, flags: str, profile: str, lang: str,
                          engine_class: str, class_reason: str, features: List[str], min_len: int,
                          max_len: Optional[int], expr_hash: str) -> Tuple[int, bool]:
    row = conn.execute("SELECT pattern_id FROM rule_patterns WHERE expr_hash = ?", (expr_hash,)).fetchone()
    if row:
        return int(row["pattern_id"]), False
    pid = alloc_pattern_id(conn)
    conn.execute(
        "INSERT INTO rule_patterns (pattern_id, regex, flags, norm_profile, lang, engine_class, class_reason, "
        "features, min_len, max_len, expr_hash, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (pid, regex, flags, profile, lang, engine_class, class_reason, json.dumps(features), min_len, max_len,
         expr_hash, utc_now()))
    return pid, True


# ---------------------------------------------------------------------------------------------
# rule revisions
# ---------------------------------------------------------------------------------------------
RULE_FIELDS = ("name", "category", "lang", "severity", "weight", "confidence", "default_action", "status",
               "scope", "context_requires", "score_group", "description", "tags")


def rule_doc_hash(doc: Dict[str, Any]) -> str:
    return sha256_text(canonical_json(doc))


def head_doc(conn: sqlite3.Connection, rule_id: str) -> Optional[Dict[str, Any]]:
    """Frozen content of the current revision of a rule (None if the rule does not exist)."""
    row = conn.execute("SELECT r.revision, rv.content_json FROM rules r JOIN rule_revisions rv "
                       "ON rv.rule_id = r.rule_id AND rv.revision = r.revision WHERE r.rule_id = ?",
                       (rule_id,)).fetchone()
    return json.loads(row["content_json"]) if row else None


def write_revision(conn: sqlite3.Connection, doc: Dict[str, Any], *, change_kind: str, actor: str,
                   reason: str, origin: str, modified_locally: bool) -> int:
    """Create the next revision of rule doc['rule_id'] (rule row, condition, links, revision, audit).

    `doc` is the complete frozen rule: scalar fields + "condition" (AST) + "leaves" (links)."""
    rule_id = doc["rule_id"]
    now = utc_now()
    cur = conn.execute("SELECT revision, created_at FROM rules WHERE rule_id = ?", (rule_id,)).fetchone()
    revision = (int(cur["revision"]) + 1) if cur else 1
    before = None
    if cur:
        prev = conn.execute("SELECT content_hash FROM rule_revisions WHERE rule_id = ? AND revision = ?",
                            (rule_id, cur["revision"])).fetchone()
        before = prev["content_hash"] if prev else None
    content = canonical_json(doc)
    chash = sha256_text(content)
    ctx = doc.get("context_requires")
    values = dict(
        name=doc["name"], category=doc["category"], lang=doc["lang"], severity=doc["severity"],
        weight=doc["weight"], confidence=doc["confidence"], default_action=doc["default_action"],
        status=doc["status"], scope=doc["scope"], context_requires=canonical_json(ctx) if ctx else None,
        score_group=doc.get("score_group"), description=doc.get("description"),
        tags=json.dumps(doc.get("tags") or [], ensure_ascii=False),
    )
    if cur is None:
        conn.execute(
            "INSERT INTO rules (rule_id, name, category, lang, severity, weight, confidence, default_action, status, "
            "origin, scope, context_requires, score_group, description, tags, revision, modified_locally, created_at, "
            "updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rule_id, values["name"], values["category"], values["lang"], values["severity"], values["weight"],
             values["confidence"], values["default_action"], values["status"], origin, values["scope"],
             values["context_requires"], values["score_group"], values["description"], values["tags"], revision,
             1 if modified_locally else 0, now, now))
    else:
        deleted_at = now if values["status"] == "deleted" else None
        conn.execute(
            "UPDATE rules SET name=?, category=?, lang=?, severity=?, weight=?, confidence=?, default_action=?, "
            "status=?, scope=?, context_requires=?, score_group=?, description=?, tags=?, revision=?, "
            "modified_locally=?, updated_at=?, deleted_at=? WHERE rule_id=?",
            (values["name"], values["category"], values["lang"], values["severity"], values["weight"],
             values["confidence"], values["default_action"], values["status"], values["scope"],
             values["context_requires"], values["score_group"], values["description"], values["tags"], revision,
             1 if modified_locally else 0, now, deleted_at, rule_id))
    conn.execute("INSERT INTO rule_conditions (rule_id, revision, ast_json) VALUES (?,?,?)",
                 (rule_id, revision, canonical_json(doc["condition"])))
    for i, leaf in enumerate(doc["leaves"]):
        conn.execute("INSERT INTO rule_pattern_links (rule_id, revision, leaf_key, pattern_id, field_name, ordinal) "
                     "VALUES (?,?,?,?,?,?)", (rule_id, revision, leaf["id"], leaf["pattern_id"], leaf["field"], i))
    conn.execute("INSERT INTO rule_revisions (rule_id, revision, change_kind, content_json, content_hash, "
                 "before_hash, actor, reason, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                 (rule_id, revision, change_kind, content, chash, before, actor, reason, now))
    audit(conn, actor, "rule." + change_kind, "rule", rule_id,
          {"revision": revision, "content_hash": chash, "reason": reason})
    return revision


def add_issue(conn: sqlite3.Connection, kind: str, severity: str, message: str, *, source_id: Optional[str] = None,
              source_key: Optional[str] = None, rule_id: Optional[str] = None, pattern_id: Optional[int] = None,
              detail: Optional[Dict[str, Any]] = None, job_id: Optional[int] = None) -> None:
    conn.execute("INSERT INTO rule_issues (kind, severity, source_id, source_key, rule_id, pattern_id, message, "
                 "detail, status, import_job_id, created_at) VALUES (?,?,?,?,?,?,?,?,'open',?,?)",
                 (kind, severity, source_id, source_key, rule_id, pattern_id, message,
                  canonical_json(detail) if detail is not None else None, job_id, utc_now()))
