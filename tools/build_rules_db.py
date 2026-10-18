#!/usr/bin/env python3
"""Reproducible baseline build of the authoritative rule database (build-time only, Python standard library).

    python tools/build_rules_db.py --fresh                      # data/ai_prompt_rules.db, version 1.0.0
    python tools/build_rules_db.py --db /tmp/x.db --version 1.0.0 --fresh --no-reports

Every step is an ordinary `tools/rules.py` command, so the same result can be produced (and inspected) by hand:

    1  sources verify           the materialised upstream trees must match third_party/sources.lock.json
                                (missing trees are first re-created with `sources sync --locked`)
    2  db init                  schema migrations (sql/*.sql)
    3  import --source all      extract -> convert -> de-duplicate -> store (stable rule/pattern ids)
    4  add --file ...           manual Chinese / mixed-language rules (data/manual_rules/*.json)
    5  verify-tests             every rule test against the Python reference engine (NOT the C++ engine)
    6  validate --strict        schema / reference / test-presence / pattern checks
    7  publish --version X      immutable rule-set version + canonical snapshot
    8  report + eval            reports/*.md|csv|json from the database; corpus evaluation with the Python reference
                                engine -> tests/corpus/expected/*.expected.jsonl (the contract of the C++ differential
                                test) and reports/false_positive.md, reports/detection_eval.md
    9  db check + checksum      integrity_check, foreign keys, migration checksums, audit hash chain

The build is deterministic with respect to *content*: running it twice yields the same snapshot sha256
(timestamps live outside the hashed snapshot).  The database file itself contains timestamps and is therefore
not byte-identical between runs; its checksum is recorded only as a delivery fingerprint.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from apg_rules import cli as rules_cli  # noqa: E402
from apg_rules import db as dbm  # noqa: E402
from apg_rules.util import atomic_write_text, project_root, rel_to_root, setup_console, sha256_file  # noqa: E402


class Tee(io.TextIOBase):
    """stdout that is also kept in memory so that the transcript can be stored as evidence."""

    def __init__(self, stream):
        self._stream = stream
        self.buffer_text = io.StringIO()

    def write(self, s):  # noqa: D401
        self.buffer_text.write(s)
        return self._stream.write(s)

    def flush(self):
        self._stream.flush()


def step(title: str) -> float:
    print(f"\n{'=' * 100}\n== {title}\n{'=' * 100}", flush=True)
    return time.time()


def run_cli(db: str, actor: str, *argv: str) -> None:
    code = rules_cli.main(["--db", db, "--actor", actor, *argv])
    if code != 0:
        raise SystemExit(f"step failed (exit {code}): rules.py {' '.join(argv)}")


def main() -> int:
    setup_console()
    root = project_root()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(root / "data" / "ai_prompt_rules.db"))
    ap.add_argument("--version", default="1.0.0", help="rule-set version to publish")
    ap.add_argument("--notes", default="Baseline: locked upstream sources + manual Chinese/mixed-language rules")
    ap.add_argument("--fresh", action="store_true", help="delete an existing database first (otherwise refuse)")
    ap.add_argument("--no-reports", action="store_true", help="do not (re)write reports/*")
    ap.add_argument("--actor", default="build_rules_db")
    ap.add_argument("--skip-sources-sync", action="store_true", help="never touch the network / third_party")
    args = ap.parse_args()

    db_path = Path(args.db)
    if db_path.exists():
        if not args.fresh:
            print(f"error: {db_path} exists; use --fresh to rebuild it from scratch "
                  f"(incremental maintenance is done with tools/rules.py)", file=sys.stderr)
            return 2
        for suffix in ("", "-wal", "-shm", "-journal"):
            p = Path(str(db_path) + suffix)
            if p.exists():
                p.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = str(db_path)

    tee = Tee(sys.stdout)
    sys.stdout = tee
    started = time.time()
    try:
        # 1 --------------------------------------------------------------------------------------------------
        step("1/9 upstream sources: verify against sources.lock.json")
        from apg_rules import sources
        problems = sources.verify(None)
        if problems and not args.skip_sources_sync:
            print(f"{len(problems)} mismatch(es); re-creating the trees with `sources sync --locked`")
            run_cli(db, args.actor, "sources", "sync", "--locked")
        elif problems:
            for p in problems[:20]:
                print("PROBLEM:", p)
            raise SystemExit("materialised sources do not match the lock (and --skip-sources-sync was given)")
        else:
            print("all materialised trees match sources.lock.json")
        run_cli(db, args.actor, "sources", "status")

        # 2 --------------------------------------------------------------------------------------------------
        step("2/9 database: init (schema migrations)")
        run_cli(db, args.actor, "db", "init")

        # 3 --------------------------------------------------------------------------------------------------
        step("3/9 import every upstream source")
        run_cli(db, args.actor, "import", "--source", "all")

        # 4 --------------------------------------------------------------------------------------------------
        step("4/9 manual rules")
        manual = sorted((root / "data" / "manual_rules").glob("*.json"))
        for f in manual:
            run_cli(db, args.actor, "add", "--file", str(f), "--reason", f"manual rules from {f.name}")
        print(f"{len(manual)} manual rule file(s)")

        # 5 --------------------------------------------------------------------------------------------------
        step("5/9 rule tests against the Python reference oracle")
        run_cli(db, args.actor, "verify-tests")

        # 6 --------------------------------------------------------------------------------------------------
        step("6/9 validate (strict)")
        run_cli(db, args.actor, "validate", "--strict")

        # 7 --------------------------------------------------------------------------------------------------
        step(f"7/9 publish {args.version}")
        run_cli(db, args.actor, "publish", "--version", args.version, "--notes", args.notes)
        run_cli(db, args.actor, "versions")

        # 8 --------------------------------------------------------------------------------------------------
        if args.no_reports:
            step("8/9 reports: skipped (--no-reports)")
        else:
            step("8/9 reports and corpus evaluation (Python reference engine)")
            run_cli(db, args.actor, "report")
            run_cli(db, args.actor, "eval", "--report", "--write-expected")

        # 9 --------------------------------------------------------------------------------------------------
        step("9/9 database integrity + delivery fingerprint")
        run_cli(db, args.actor, "db", "check")
        # leave a single self-contained file: journal_mode=delete, nothing pending in a WAL
        conn = dbm.connect(db_path)
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        digest = sha256_file(db_path)
        if args.db == str(root / "data" / "ai_prompt_rules.db"):
            atomic_write_text(root / "data" / "ai_prompt_rules.db.sha256", f"{digest}  ai_prompt_rules.db\n")
        print(f"database      : {rel_to_root(db_path)} ({db_path.stat().st_size} bytes, journal_mode={mode})")
        print(f"sha256        : {digest}")
        print(f"elapsed       : {time.time() - started:.1f}s")
    finally:
        sys.stdout = tee._stream
        if not args.no_reports:
            log = root / "reports" / "build_rules_db.log"
            try:
                atomic_write_text(log, tee.buffer_text.getvalue())
                print(f"transcript    : {rel_to_root(log)}")
            except OSError as exc:  # pragma: no cover
                print(f"warning: could not write the transcript: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
