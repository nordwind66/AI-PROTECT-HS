"""Shared helpers of the Python test-suite (standard library only; run with `python -m unittest discover -s tests/python`)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from apg_rules import cli as rules_cli  # noqa: E402
from apg_rules import db as dbm  # noqa: E402

SOURCES_PRESENT = (ROOT / "third_party" / "sources.lock.json").is_file() and \
    (ROOT / "third_party" / "sources" / "trans-prompt-injection-detector").is_dir()
DELIVERED_DB = ROOT / "data" / "ai_prompt_rules.db"


def run_cli(db: Path, *argv: str, expect: Optional[int] = 0) -> Tuple[int, str]:
    """Runs `rules.py --db DB <argv>` in-process; returns (exit code, stdout+stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = rules_cli.main(["--db", str(db), "--actor", "unittest", *argv])
    text = out.getvalue() + err.getvalue()
    if expect is not None and code != expect:
        raise AssertionError(f"rules.py {' '.join(argv)} exited with {code}, expected {expect}\n{text}")
    return code, text


def rule_spec(name: str, regex: str, *, category: str = "prompt_injection", positive: Sequence[str] = (),
              negative: Sequence[str] = (), **extra: Any) -> Dict[str, Any]:
    spec: Dict[str, Any] = {
        "name": name, "category": category, "severity": "high", "weight": 0.7, "confidence": 0.8,
        "description": "unit-test rule", "patterns": [{"key": "p1", "regex": regex, "flags": "i"}],
        "tests": {"positive": list(positive), "negative": list(negative)},
    }
    spec.update(extra)
    return spec


def write_json(path: Path, obj: Any) -> Path:
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


class TempCase(unittest.TestCase):
    """Gives every test a private temporary directory and a freshly initialised rule database."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="apg_test_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.db = self.tmp / "rules.db"
        run_cli(self.db, "db", "init")

    def connect(self, readonly: bool = True) -> sqlite3.Connection:
        return dbm.connect(self.db, readonly=readonly)

    def add_rules(self, *specs: Dict[str, Any], name: str = "rules.json") -> str:
        path = write_json(self.tmp / name, {"rules": list(specs)})
        _, out = run_cli(self.db, "add", "--file", str(path))
        return out

    def rule_ids(self) -> List[str]:
        return [r[0] for r in self.rows("SELECT rule_id FROM rules ORDER BY rule_id")]

    def rows(self, sql: str, *params: Any) -> List[sqlite3.Row]:
        c = self.connect()
        try:
            return c.execute(sql, params).fetchall()
        finally:
            c.close()

    def scalar(self, sql: str, *params: Any) -> Any:
        c = self.connect()
        try:
            row = c.execute(sql, params).fetchone()
            return None if row is None else row[0]
        finally:
            c.close()
