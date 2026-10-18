"""Command line front-end of the rule management tool (tools/rules.py)."""
from __future__ import annotations

import argparse
import csv
import io
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from . import db as dbm
from .util import canonical_json, default_db_path, eprint, pretty_json, project_root, rel_to_root, setup_console

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2


class CliError(Exception):
    def __init__(self, message: str, code: int = EXIT_FAIL):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------
def _open_db(args, *, create: bool = False, readonly: bool = False, migrate: bool = True) -> sqlite3.Connection:
    path = Path(args.db)
    conn = dbm.connect(path, create=create, readonly=readonly, wal=getattr(args, "wal", False))
    if migrate and not readonly:
        done = dbm.migrate(conn)
        if done and not create:
            print(f"[db] applied migration(s): {done}")
    return conn


def _table(rows: List[List[Any]], headers: List[str]) -> str:
    cols = list(zip(*([headers] + [[("" if c is None else str(c)) for c in r] for r in rows]))) if rows else \
        [[h] for h in headers]
    widths = [min(60, max(len(str(x)) for x in col)) for col in cols]
    def fmt(r):
        return "  ".join(str(c)[:w].ljust(w) for c, w in zip(r, widths))
    out = [fmt(headers), fmt(["-" * w for w in widths])]
    out += [fmt(["" if c is None else c for c in r]) for r in rows]
    return "\n".join(out)


def _csv(rows: List[List[Any]], headers: List[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(headers)
    w.writerows(rows)
    return buf.getvalue()


def _split(value: Optional[str]) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


# ---------------------------------------------------------------------------------------------
# db
# ---------------------------------------------------------------------------------------------
def cmd_db_init(args) -> int:
    path = Path(args.db)
    existed = path.exists()
    conn = dbm.connect(path, create=True, wal=args.wal)
    done = dbm.migrate(conn)
    ver = dbm.schema_version(conn)
    print(f"[db] {'opened existing' if existed else 'created'} {path} - schema version {ver}; applied now: {done or 'none'}")
    if done:
        with dbm.tx(conn):
            dbm.audit(conn, args.actor, "db.init", "database", str(path.name), {"applied": done, "tool": TOOL_VERSION})
    return EXIT_OK


def cmd_db_migrate(args) -> int:
    conn = dbm.connect(args.db)
    done = dbm.migrate(conn)
    print(f"[db] schema version {dbm.schema_version(conn)}; applied: {done or 'none'}")
    return EXIT_OK


def cmd_db_check(args) -> int:
    from . import validate as validate_mod
    conn = dbm.connect(args.db, readonly=True)
    problems = validate_mod.check_database(conn)
    if problems:
        for p in problems:
            print("PROBLEM:", p)
        return EXIT_FAIL
    print("[db] integrity_check ok, foreign_key_check ok, migrations ok, audit chain ok")
    return EXIT_OK


def cmd_db_backup(args) -> int:
    from . import backup
    out = backup.backup_database(Path(args.db), Path(args.out))
    print(f"[db] consistent backup written to {out}")
    return EXIT_OK


def cmd_db_snapshot(args) -> int:
    from . import backup
    out = backup.snapshot_database(Path(args.db), Path(args.out), actor=args.actor)
    print(f"[db] single-file delivery snapshot written to {out} (journal_mode=delete, checkpointed, verified)")
    return EXIT_OK


def cmd_db_restore(args) -> int:
    from . import backup
    backup.restore_database(Path(args.src), Path(args.db), force=args.force)
    print(f"[db] restored {args.src} -> {args.db}")
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# sources
# ---------------------------------------------------------------------------------------------
def cmd_sources_sync(args) -> int:
    from . import sources
    ids = _split(args.source) or None
    sources.sync(ids, update=args.update, offline=args.offline)
    problems = sources.verify(ids)
    if problems:
        for p in problems:
            print("PROBLEM:", p)
        return EXIT_FAIL
    return EXIT_OK


def cmd_sources_verify(args) -> int:
    from . import sources
    problems = sources.verify(_split(args.source) or None)
    for p in problems:
        print("PROBLEM:", p)
    if not problems:
        print("[sources] all materialised trees match sources.lock.json")
    return EXIT_FAIL if problems else EXIT_OK


def cmd_sources_status(args) -> int:
    from . import sources
    lock = sources.load_lock()
    if not lock:
        print("no sources.lock.json")
        return EXIT_FAIL
    rows = []
    for sid, e in lock["sources"].items():
        rows.append([sid, e["commit_sha"][:12], e["commit_date"][:10], e["license_spdx_detected"], e["file_count"],
                     len(e["skipped"]), e["tree_sha256"][:12]])
    print(_table(rows, ["source", "commit", "date", "licence", "files", "skipped", "tree"]))
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# import / diff
# ---------------------------------------------------------------------------------------------
def _selected_sources(args, defs) -> List[str]:
    ids = _split(args.source)
    if getattr(args, "all", False) or not ids or ids == ["all"]:
        return list(defs)
    for i in ids:
        if i not in defs:
            raise CliError(f"unknown source {i!r}; known: {', '.join(defs)}", EXIT_USAGE)
    return ids


def _print_plan(plan, detail: bool) -> None:
    c = plan.counts()
    print(f"[{plan.source_id}] commit {plan.commit_sha[:12]}: {len(plan.rules)} source rules -> "
          f"new {c['new']}, changed {c['changed']}, unchanged {c['unchanged']}, removed upstream {c['removed']}")
    fate: Dict[str, int] = {}
    dec: Dict[str, int] = {}
    for item in plan.rules:
        dec[item.prepared.decision] = dec.get(item.prepared.decision, 0) + 1
        for conv in item.prepared.conversions.values():
            fate[conv.fate] = fate.get(conv.fate, 0) + 1
    print("    rule decisions :", dict(sorted(dec.items())))
    print("    pattern fates  :", dict(sorted(fate.items())))
    if plan.warnings:
        print(f"    warnings       : {len(plan.warnings)}")
        for w in plan.warnings[:20 if detail else 5]:
            print("      !", w)
    if detail:
        for item in plan.rules:
            if item.action in ("new", "changed"):
                print(f"    {item.action:<9} {item.prepared.src.source_key}  [{item.prepared.decision}]  "
                      f"{item.prepared.src.name[:60]}")
                for ch in item.changes[:6]:
                    print("        -", ch)
        for row in plan.removed:
            print(f"    removed   {row['source_key']}")


def cmd_import(args) -> int:
    from . import pipeline, sources
    import sources as plugins  # tools/sources (importer plugins)
    defs = sources.load_defs()
    lock = sources.load_lock()
    if lock is None:
        raise CliError("third_party/sources.lock.json is missing: run `rules.py sources sync --update`")
    ids = _selected_sources(args, defs)
    problems = sources.verify(ids)
    if problems and not args.allow_unlocked:
        for p in problems[:20]:
            print("PROBLEM:", p)
        raise CliError("materialised sources do not match sources.lock.json (use --allow-unlocked to override)")
    conn = _open_db(args, create=False, readonly=args.dry_run, migrate=not args.dry_run)
    total_warnings = 0
    for sid in ids:
        importer = plugins.get_importer(defs[sid].importer)
        plan = pipeline.plan_import(conn, defs[sid], importer, lock["sources"][sid])
        _print_plan(plan, args.detail or args.dry_run)
        total_warnings += len(plan.warnings)
        if args.strict and plan.warnings:
            raise CliError(f"--strict: {len(plan.warnings)} warning(s) for source {sid}; nothing was imported")
        if args.dry_run:
            continue
        summary = pipeline.apply_plan(conn, plan, actor=args.actor, sd=defs[sid])
        print(f"    applied        : {canonical_json(summary)}")
    if args.dry_run:
        print("[import] dry-run: the database was not modified")
    return EXIT_OK


def cmd_diff(args) -> int:
    if args.versions:
        from . import publish
        conn = dbm.connect(args.db, readonly=True)
        report = publish.diff_versions(conn, args.versions[0], args.versions[1])
        print(report.render())
        return EXIT_OK
    from . import pipeline, sources
    import sources as plugins
    defs = sources.load_defs()
    lock = sources.load_lock()
    if lock is None:
        raise CliError("third_party/sources.lock.json is missing")
    conn = dbm.connect(args.db, readonly=True)
    for sid in _selected_sources(args, defs):
        importer = plugins.get_importer(defs[sid].importer)
        plan = pipeline.plan_import(conn, defs[sid], importer, lock["sources"][sid])
        _print_plan(plan, True)
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# list / show
# ---------------------------------------------------------------------------------------------
def cmd_list(args) -> int:
    conn = dbm.connect(args.db, readonly=True)
    where, params = ["1=1"], []
    if args.lang:
        langs = _split(args.lang)
        where.append("lang IN (%s)" % ",".join("?" * len(langs)))
        params += langs
    if args.category:
        cats = _split(args.category)
        where.append("category IN (%s)" % ",".join("?" * len(cats)))
        params += cats
    if args.status:
        sts = _split(args.status)
        where.append("status IN (%s)" % ",".join("?" * len(sts)))
        params += sts
    if args.severity:
        sv = _split(args.severity)
        where.append("severity IN (%s)" % ",".join("?" * len(sv)))
        params += sv
    if args.source:
        where.append("sources LIKE ?")
        params.append("%" + args.source + "%")
    if args.text:
        where.append("(name LIKE ? OR rule_id LIKE ?)")
        params += ["%" + args.text + "%"] * 2
    sql = ("SELECT rule_id, category, lang, severity, status, scope, weight, confidence, pattern_links, "
           "positive_tests, negative_tests, sources, name FROM v_rule_overview WHERE " + " AND ".join(where) +
           " ORDER BY rule_id")
    if args.limit:
        sql += " LIMIT %d" % args.limit
    rows = [list(r) for r in conn.execute(sql, params)]
    headers = ["rule_id", "category", "lang", "sev", "status", "scope", "weight", "conf", "pats", "pos", "neg", "src", "name"]
    if args.format == "json":
        print(json.dumps([dict(zip(headers, r)) for r in rows], ensure_ascii=False, indent=1))
    elif args.format == "csv":
        sys.stdout.write(_csv(rows, headers))
    else:
        print(_table(rows, headers))
        print(f"\n{len(rows)} rule(s)")
    return EXIT_OK


def cmd_show(args) -> int:
    conn = dbm.connect(args.db, readonly=True)
    r = conn.execute("SELECT * FROM rules WHERE rule_id = ?", (args.id,)).fetchone()
    if r is None:
        raise CliError(f"rule {args.id} not found")
    doc = dbm.head_doc(conn, args.id) or {}
    prov = [dict(x) for x in conn.execute(
        "SELECT s.source_id, s.source_key, s.source_path, s.locator, s.decision, p.source_commit, s.upstream_status, "
        "s.upstream_severity FROM rule_provenance p JOIN source_rules s ON s.source_rule_id = p.source_rule_id "
        "WHERE p.rule_id = ? AND p.kind = 'rule'", (args.id,))]
    revs = [dict(x) for x in conn.execute(
        "SELECT revision, change_kind, actor, created_at, reason, substr(content_hash,1,12) AS hash FROM rule_revisions "
        "WHERE rule_id = ? ORDER BY revision", (args.id,))]
    pats = [dict(x) for x in conn.execute(
        "SELECT l.leaf_key, l.field_name, p.pattern_id, p.engine_class, p.norm_profile, p.flags, p.lang, p.regex "
        "FROM rule_pattern_links l JOIN rule_patterns p ON p.pattern_id = l.pattern_id "
        "WHERE l.rule_id = ? AND l.revision = ? ORDER BY l.ordinal", (args.id, r["revision"]))]
    tests = [dict(x) for x in conn.execute(
        "SELECT kind, expect_hit, origin, verification, substr(text,1,100) AS text FROM rule_tests WHERE rule_id = ? "
        "ORDER BY test_id LIMIT 40", (args.id,))]
    versions = [x["version"] for x in conn.execute(
        "SELECT v.version FROM ruleset_members m JOIN ruleset_versions v ON v.version_id = m.version_id "
        "WHERE m.rule_id = ? ORDER BY v.version_id", (args.id,))]
    artifacts = [dict(x) for x in conn.execute(
        "SELECT v.version, a.target_os, a.arch, a.backend, a.status FROM ruleset_members m JOIN ruleset_versions v "
        "ON v.version_id = m.version_id JOIN compiled_artifacts a ON a.version_id = v.version_id "
        "WHERE m.rule_id = ?", (args.id,))]
    out = {"rule": {k: r[k] for k in r.keys()}, "condition": doc.get("condition"), "patterns": pats,
           "provenance": prov, "revisions": revs, "tests": tests, "in_versions": versions, "artifacts": artifacts}
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
        return EXIT_OK
    print(f"{r['rule_id']}  {r['name']}")
    print(f"  category={r['category']} lang={r['lang']} severity={r['severity']} weight={r['weight']} "
          f"confidence={r['confidence']} action={r['default_action']} status={r['status']} scope={r['scope']} "
          f"revision={r['revision']} origin={r['origin']} modified_locally={r['modified_locally']}")
    if r["context_requires"]:
        print(f"  context_requires={r['context_requires']}")
    print(f"  description: {r['description']}")
    print("  condition:", canonical_json(doc.get("condition")))
    print("  patterns:")
    for p in pats:
        print(f"    {p['leaf_key']:<6} #{p['pattern_id']} [{p['engine_class']}, {p['norm_profile']}, flags={p['flags'] or '-'}, "
              f"{p['lang']}] field={p['field_name']}  {p['regex'][:110]}")
    print("  provenance:")
    for p in prov:
        print(f"    {p['source_id']}:{p['source_key']} ({p['source_path']}) commit {p['source_commit'][:10]} [{p['decision']}]")
    print("  revisions:")
    for v in revs:
        print(f"    r{v['revision']} {v['created_at']} {v['change_kind']} by {v['actor']} {v['hash']} {v['reason'] or ''}"[:200])
    print(f"  tests: {len(tests)} shown; in published versions: {versions or 'none'}")
    for a in artifacts:
        print(f"  artifact: {a}")
    return EXIT_OK


# ---------------------------------------------------------------------------------------------
# thin dispatchers to the other modules
# ---------------------------------------------------------------------------------------------
def cmd_inventory(args) -> int:
    from . import reports
    conn = dbm.connect(args.db, readonly=True)
    written = reports.write_inventory(conn, project_root() / "reports")
    for w in written:
        print("[inventory] wrote", rel_to_root(w))
    return EXIT_OK


def cmd_report(args) -> int:
    from . import reports
    conn = dbm.connect(args.db, readonly=True)
    for w in reports.write_all(conn, project_root() / "reports"):
        print("[report] wrote", rel_to_root(w))
    return EXIT_OK


def cmd_validate(args) -> int:
    from . import validate as validate_mod
    conn = dbm.connect(args.db, readonly=True)
    res = validate_mod.validate_rules(conn, strict=args.strict)
    print(res.render(verbose=args.verbose))
    return EXIT_FAIL if res.failed(args.strict) else EXIT_OK


def cmd_rule_mutation(args) -> int:
    from . import maintain
    conn = _open_db(args)
    return maintain.run(args.command_name, conn, args)


def cmd_publish_family(args) -> int:
    from . import publish
    conn = _open_db(args)
    return publish.run(args.command_name, conn, args)


def cmd_verify_tests(args) -> int:
    from . import verify_tests
    conn = _open_db(args)
    return verify_tests.run(conn, args)


def cmd_explain(args) -> int:
    from . import explain
    conn = dbm.connect(args.db, readonly=True)
    try:
        return explain.run(conn, args)
    except ValueError as exc:
        raise CliError(str(exc)) from exc


def cmd_eval(args) -> int:
    from . import corpus_eval
    conn = dbm.connect(args.db, readonly=True)
    try:
        return corpus_eval.run(conn, args)
    except ValueError as exc:
        raise CliError(str(exc)) from exc


# ---------------------------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rules.py", description="AI Prompt Guard rule management (SQLite is the single source of truth).",
        epilog="Pipeline: sources sync -> db init -> import -> diff -> validate -> stage -> publish -> (C++) compile -> activate")
    p.add_argument("--db", default=str(default_db_path()), help="rule database (default: data/ai_prompt_rules.db)")
    p.add_argument("--actor", default=dbm.default_actor(), help="who is acting (recorded in the audit log)")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="group", metavar="COMMAND")

    # db ----------------------------------------------------------------------------------
    g = sub.add_parser("db", help="database lifecycle").add_subparsers(dest="cmd", metavar="SUBCOMMAND")
    x = g.add_parser("init", help="create the database / apply migrations")
    x.add_argument("--wal", action="store_true", help="use WAL journal (writable admin copy only; see docs)")
    x.set_defaults(func=cmd_db_init)
    g.add_parser("migrate", help="apply pending schema migrations").set_defaults(func=cmd_db_migrate)
    g.add_parser("check", help="integrity, foreign keys, migration checksums, audit chain").set_defaults(func=cmd_db_check)
    x = g.add_parser("backup", help="consistent online backup (SQLite backup API)")
    x.add_argument("--out", required=True)
    x.set_defaults(func=cmd_db_backup)
    x = g.add_parser("snapshot", help="checkpointed single-file copy for delivery (atomic rename)")
    x.add_argument("--out", required=True)
    x.set_defaults(func=cmd_db_snapshot)
    x = g.add_parser("restore", help="restore a backup over the database")
    x.add_argument("--from", dest="src", required=True)
    x.add_argument("--force", action="store_true")
    x.set_defaults(func=cmd_db_restore)

    # sources -----------------------------------------------------------------------------
    g = sub.add_parser("sources", help="pin / fetch / verify the upstream repositories").add_subparsers(dest="cmd", metavar="SUBCOMMAND")
    x = g.add_parser("sync", help="materialise third_party/sources from the lock (or re-lock with --update)")
    mode = x.add_mutually_exclusive_group()
    mode.add_argument("--locked", action="store_true", help="reproduce exactly the locked commits (default)")
    mode.add_argument("--update", action="store_true", help="move the lock to the current branch head")
    x.add_argument("--offline", action="store_true", help="do not use the network")
    x.add_argument("--source", help="comma separated source ids (default: all)")
    x.set_defaults(func=cmd_sources_sync)
    x = g.add_parser("verify", help="check the materialised trees against sources.lock.json")
    x.add_argument("--source")
    x.set_defaults(func=cmd_sources_verify)
    g.add_parser("status", help="show the locked commits").set_defaults(func=cmd_sources_status)

    # import / diff ----------------------------------------------------------------------
    x = sub.add_parser("import", help="import upstream rules into the database (does not touch published versions)")
    x.add_argument("--source", default="all", help="source id(s), comma separated, or 'all'")
    x.add_argument("--all", action="store_true", help="every source (same as --source all)")
    x.add_argument("--dry-run", action="store_true", help="compute and print the plan, change nothing")
    x.add_argument("--strict", action="store_true", help="fail on any extractor warning before importing")
    x.add_argument("--detail", action="store_true", help="list every new/changed rule")
    x.add_argument("--allow-unlocked", action="store_true", help="import even if sources differ from the lock")
    x.set_defaults(func=cmd_import)

    x = sub.add_parser("diff", help="upstream-vs-database diff, or --versions A B for two rule-set versions")
    x.add_argument("--source", default="all")
    x.add_argument("--all", action="store_true", help="every source (same as --source all)")
    x.add_argument("--versions", nargs=2, metavar=("A", "B"))
    x.set_defaults(func=cmd_diff)

    # query ---------------------------------------------------------------------------------
    x = sub.add_parser("list", help="list rules")
    for opt in ("--lang", "--category", "--status", "--severity", "--source", "--text"):
        x.add_argument(opt)
    x.add_argument("--limit", type=int)
    x.add_argument("--format", choices=["table", "csv", "json"], default="table")
    x.set_defaults(func=cmd_list)
    x = sub.add_parser("show", help="show one rule with patterns, provenance, revisions, tests")
    x.add_argument("--id", required=True)
    x.add_argument("--json", action="store_true")
    x.set_defaults(func=cmd_show)

    # maintenance -----------------------------------------------------------------------
    for name, helptext in (("enable", "enable a rule (new draft revision; published versions are unaffected)"),
                           ("disable", "disable a rule (new draft revision)"),
                           ("delete", "soft-delete a rule"),
                           ("update", "edit rule metadata (--set key=value ...)"),
                           ("add", "add a manual rule from a JSON file"),
                           ("restore-upstream", "re-derive an imported rule from its upstream definition")):
        x = sub.add_parser(name, help=helptext)
        if name == "add":
            x.add_argument("--file", required=True, help="rule specification (see docs/rule-maintenance.md)")
        else:
            x.add_argument("--id", required=True)
        if name == "update":
            x.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
        x.add_argument("--reason", default="", help="change reason recorded in revision + audit log")
        x.add_argument("--dry-run", action="store_true")
        x.set_defaults(func=cmd_rule_mutation, command_name=name)

    # quality / release -----------------------------------------------------------------
    x = sub.add_parser("validate", help="validate the draft rule set (schema, references, tests, patterns)")
    x.add_argument("--strict", action="store_true", help="warnings fail the command")
    x.add_argument("-v", "--verbose", action="store_true")
    x.set_defaults(func=cmd_validate)
    x = sub.add_parser("verify-tests", help="run rule tests against the Python reference oracle (not the C++ engine)")
    x.add_argument("--limit", type=int)
    x.set_defaults(func=cmd_verify_tests)
    x = sub.add_parser("explain", help="show which rules / patterns flag a text (Python reference engine)")
    x.add_argument("--text")
    x.add_argument("--source", default="user_input", choices=["user_input", "tool_output", "rag_document", "agent_message"])
    x.add_argument("--context", help='JSON object, e.g. \'{"task":"translation"}\'')
    x.add_argument("--corpus", help="JSONL corpus file (with --id)")
    x.add_argument("--id", help="sample id inside --corpus")
    x.add_argument("--version", help="published rule-set version (default: latest)")
    x.set_defaults(func=cmd_explain)
    x = sub.add_parser("eval", help="run the test corpora through the Python reference engine on a published "
                                    "version (expected results for differential tests, FP / detection reports)")
    x.add_argument("--version", help="published rule-set version (default: latest)")
    x.add_argument("--corpus-dir", help="default: tests/corpus")
    x.add_argument("--write-expected", action="store_true", help="write tests/corpus/expected/*.expected.jsonl")
    x.add_argument("--report", action="store_true", help="write reports/false_positive.md and reports/detection_eval.md")
    x.set_defaults(func=cmd_eval)

    for name, helptext in (("stage", "freeze the current draft into a draft version for review"),
                           ("publish", "publish an immutable rule-set version"),
                           ("versions", "list rule-set versions"),
                           ("activate", "move the runtime pointer to a published version"),
                           ("rollback", "move the runtime pointer back to an earlier published version"),
                           ("export-snapshot", "write the exact snapshot document of a version"),
                           ("register-artifact", "record a compiled artifact (manifest.json) for a version")):
        x = sub.add_parser(name, help=helptext)
        if name in ("stage", "publish"):
            x.add_argument("--version", required=(name == "publish"), help="semantic version, e.g. 1.0.0")
            x.add_argument("--notes", default="")
            x.add_argument("--dry-run", action="store_true")
            x.add_argument("--no-validate", action="store_true", help="skip the validation gate (not recommended)")
        if name in ("activate", "export-snapshot"):
            x.add_argument("--version", required=True)
        if name == "activate":
            x.add_argument("--reason", default="")
            x.add_argument("--channel", default="default")
            x.add_argument("--pointer-dir", help="also write <dir>/active.json (e.g. dist/linux/x86_64)")
        if name == "rollback":
            x.add_argument("--to", required=True, help="published version to return to")
            x.add_argument("--reason", default="")
            x.add_argument("--channel", default="default")
            x.add_argument("--pointer-dir", help="also write <dir>/active.json (e.g. dist/linux/x86_64)")
        if name == "export-snapshot":
            x.add_argument("--out", required=True)
        if name == "register-artifact":
            x.add_argument("--manifest", required=True)
        x.set_defaults(func=cmd_publish_family, command_name=name)

    # reports ---------------------------------------------------------------------------
    sub.add_parser("inventory", help="write reports/source_inventory.* and rule_inventory.csv from the database").set_defaults(func=cmd_inventory)
    sub.add_parser("report", help="write every report derived from the database").set_defaults(func=cmd_report)
    return p


def _hoist_global_options(argv: List[str]) -> List[str]:
    """`--db X` and `--actor X` are options of the top-level parser, but users (and the C++ front end that forwards
    its command line) naturally write them after the sub-command: move them to the front."""
    hoisted: List[str] = []
    rest: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--db", "--actor") and i + 1 < len(argv):
            hoisted += [a, argv[i + 1]]
            i += 2
            continue
        if a.startswith("--db=") or a.startswith("--actor="):
            hoisted.append(a)
        else:
            rest.append(a)
        i += 1
    return hoisted + rest


def main(argv: Optional[List[str]] = None) -> int:
    setup_console()
    parser = build_parser()
    args = parser.parse_args(_hoist_global_options(list(sys.argv[1:] if argv is None else argv)))
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        with dbm.track_connections():
            return int(args.func(args) or 0)
    except CliError as exc:
        eprint(f"error: {exc}")
        return exc.code
    except (dbm.DbError, sqlite3.Error) as exc:
        eprint(f"database error: {exc}")
        return EXIT_FAIL
    except KeyboardInterrupt:  # pragma: no cover
        eprint("interrupted")
        return 130
