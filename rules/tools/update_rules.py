#!/usr/bin/env python3
"""Upgrade the existing rule database from the manual rule JSON files (Python standard library only).

    python tools/update_rules.py                       # sync data/manual_rules/*.json, test, publish the next patch version
    python tools/update_rules.py --dry-run             # show what would change, write nothing
    python tools/update_rules.py --version 1.2.0       # choose the version yourself
    python tools/update_rules.py --prune               # also delete manual rules that are no longer in the JSON files
    python tools/update_rules.py --compile --cli PATH  # afterwards compile (with the engine's ai-prompt-guard) + register + activate (Linux)
    python tools/update_rules.py --file my_rules.json  # only these files (then --prune would delete everything else!)

The JSON files are the source of truth for the manual rules; the rule NAME is the key:

    name not in the database  -> new rule             (gets the next rule id)
    name in the database      -> compared; if anything changed (regex, weight, severity, tests ...) a new revision
    name missing from files   -> kept (listed), deleted only with --prune
    renamed rule              -> a new rule plus (with --prune) the old one deleted

Upstream rules (ATR / fevzi / trans) are not touched here; they are managed with `rules.py import`.

Steps (every one is an ordinary `tools/rules.py` command):
    1  sync-manual        JSON files -> draft revisions in the database
    2  verify-tests       every rule's positive / negative samples against the Python reference engine
    3  validate --strict  schema, references, tests, patterns
    4  publish            new immutable rule-set version (the previous versions stay and can be rolled back to)
    5  eval --write-expected   refreshes tests/corpus/expected/* for the new version (the C++ differential test needs it)
    6  db check + sha256  integrity, audit chain, data/ai_prompt_rules.db.sha256
    7  --compile          scripts/compile.sh: export the snapshot, compile it with the engine's ai-prompt-guard (--cli), register, activate dist/.../active.json

Nothing is published when the files describe exactly what the last version contains.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from apg_rules import cli as rules_cli  # noqa: E402
from apg_rules import db as dbm  # noqa: E402
from apg_rules.util import atomic_write_text, project_root, setup_console, sha256_file  # noqa: E402


def run_cli(db: str, actor: str, *argv: str) -> None:
    code = rules_cli.main(["--db", db, "--actor", actor, *argv])
    if code != 0:
        raise SystemExit(f"step failed (exit {code}): rules.py {' '.join(argv)}")


def step(title: str) -> None:
    print(f"\n== {title}", flush=True)


def revision_count(db: str) -> int:
    conn = dbm.connect(Path(db), readonly=True)
    try:
        return conn.execute("SELECT COUNT(*) FROM rule_revisions").fetchone()[0]
    finally:
        conn.close()


def latest_version(db: str) -> str:
    conn = dbm.connect(Path(db), readonly=True)
    try:
        row = conn.execute("SELECT version FROM ruleset_versions WHERE status='published' "
                           "ORDER BY version_id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    if row is None:
        raise SystemExit("the database has no published version: build it first with tools/build_rules_db.py --fresh")
    return row[0]


def next_patch(version: str) -> str:
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        raise SystemExit(f"cannot derive the next version from {version!r}: pass --version")
    return f"{m.group(1)}.{m.group(2)}.{int(m.group(3)) + 1}"


def main() -> int:
    setup_console()
    root = project_root()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(root / "data" / "ai_prompt_rules.db"))
    ap.add_argument("--file", nargs="+", help="rule JSON file(s) (default: data/manual_rules/*.json)")
    ap.add_argument("--version", help="version to publish (default: the next patch version of the latest one)")
    ap.add_argument("--notes", default="", help="release notes stored with the version")
    ap.add_argument("--prune", action="store_true", help="delete manual rules that are in none of the files")
    ap.add_argument("--dry-run", action="store_true", help="only report what would change")
    ap.add_argument("--no-eval", action="store_true", help="do not refresh tests/corpus/expected/*")
    ap.add_argument("--compile", action="store_true", help="afterwards run scripts/compile.sh (compile, register, activate)")
    ap.add_argument("--backend", default="hyperscan", choices=["hyperscan", "pcre2_fallback"], help="with --compile")
    ap.add_argument("--cli", default=os.environ.get("APG_CLI", ""), help="with --compile: the engine's ai-prompt-guard (its `compile` command builds the package); default: $APG_CLI")
    ap.add_argument("--actor", default="update_rules")
    args = ap.parse_args()

    db = args.db
    if not Path(db).is_file():
        raise SystemExit(f"{db} does not exist: build it once with tools/build_rules_db.py --fresh")
    files = args.file or sorted(glob.glob(str(root / "data" / "manual_rules" / "*.json")))
    if not files:
        raise SystemExit("no rule files found")
    previous = latest_version(db)

    step(f"1/6 sync {len(files)} rule file(s) into the database (latest published version: {previous})")
    before = revision_count(db)
    extra = ["--prune"] if args.prune else []
    if args.dry_run:
        run_cli(db, args.actor, "sync-manual", "--file", *files, *extra, "--dry-run")
        return 0
    run_cli(db, args.actor, "sync-manual", "--file", *files, *extra)
    if revision_count(db) == before:
        print(f"\nnothing changed: the files describe exactly what {previous} contains, nothing was published")
        return 0
    version = args.version or next_patch(previous)

    step("2/6 rule tests against the Python reference engine")
    run_cli(db, args.actor, "verify-tests")
    step("3/6 validate (strict)")
    run_cli(db, args.actor, "validate", "--strict")
    step(f"4/6 publish {version}")
    run_cli(db, args.actor, "publish", "--version", version,
            "--notes", args.notes or f"manual rules updated from {', '.join(Path(f).name for f in files)}")
    run_cli(db, args.actor, "versions")
    if args.no_eval:
        step("5/6 corpus evaluation: skipped (--no-eval; tests/corpus/expected/* is now stale)")
    else:
        step("5/6 corpus evaluation -> tests/corpus/expected/*")
        run_cli(db, args.actor, "eval", "--write-expected")
    step("6/6 database integrity + fingerprint")
    run_cli(db, args.actor, "db", "check")
    digest = sha256_file(Path(db))
    if Path(db).resolve() == (root / "data" / "ai_prompt_rules.db").resolve():
        atomic_write_text(root / "data" / "ai_prompt_rules.db.sha256", f"{digest}  ai_prompt_rules.db\n")
    print(f"sha256: {digest}")
    print(f"\nrule set {version} is published in {db}")
    if args.compile:
        step("compile + register + activate on this machine")
        script = root / "scripts" / "compile.sh"
        if not args.cli:
            print("--compile needs the engine's ai-prompt-guard: pass --cli PATH or set APG_CLI")
            return 1
        cmd = ["bash", str(script), "--db", db, "--version", version, "--backend", args.backend, "--cli", args.cli]
        print("+ " + " ".join(cmd), flush=True)
        if subprocess.call(cmd) != 0:
            return 1
    else:
        print("next: bash scripts/compile.sh --cli <engine>/bin/ai-prompt-guard   (compile, register and activate), "
              "or re-run with --compile")
    return 0


if __name__ == "__main__":
    sys.exit(main())
