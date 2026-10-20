"""schemas/*.json of the rules project (snapshot, rule spec, active pointer): well-formed, only use keywords the bundled validator understands, and accept / reject the right documents.

The snapshot, the pointer and the rule-spec files are REAL documents produced by this project's Python tools. The
engine's own schemas (request / response / config / manifest ...) are tested in the engine project.
"""
import copy
import json
import unittest

from helpers import DELIVERED_DB, ROOT, TempCase, rule_spec, run_cli
from apg_rules import jsonschema_lite as js
from apg_rules.publish import SCORING_DEFAULTS

SCHEMAS = ROOT / "schemas"
NAMES = ["ruleset_snapshot", "rule_spec", "active_pointer"]


def schema(name):
    return js.load_schema(SCHEMAS / f"{name}.schema.json")


def walk(node, where, problems):
    """Every keyword of every (sub)schema must be one the validator implements or an annotation."""
    if not isinstance(node, dict):
        return
    for key, val in node.items():
        if key in ("properties", "$defs"):
            for k, sub in val.items():
                walk(sub, f"{where}.{key}.{k}", problems)
        elif key in ("items", "additionalProperties", "propertyNames", "not", "if", "then", "else"):
            if isinstance(val, dict):
                walk(val, f"{where}.{key}", problems)
        elif key in ("oneOf", "anyOf", "allOf", "prefixItems"):
            for i, sub in enumerate(val):
                walk(sub, f"{where}.{key}[{i}]", problems)
        elif key not in js.KNOWN and key not in js.ANNOTATIONS:
            problems.append(f"{where}: unsupported keyword {key!r}")


class SchemaFilesTests(unittest.TestCase):
    def test_files_exist_are_valid_json_and_use_supported_keywords(self):
        problems = []
        for n in NAMES:
            s = schema(n)
            self.assertEqual(s["$schema"], "https://json-schema.org/draft/2020-12/schema", n)
            self.assertIn("$id", s, n)
            walk(s, n, problems)
        self.assertEqual(problems, [])

    def test_validator_basics(self):
        s = {"type": "object", "required": ["a"], "additionalProperties": False,
             "properties": {"a": {"type": "integer", "minimum": 1}, "b": {"enum": ["x", "y"]}}}
        self.assertEqual(js.validate({"a": 1, "b": "x"}, s), [])
        self.assertTrue(js.validate({"a": 0}, s))
        self.assertTrue(js.validate({"b": "x"}, s))
        self.assertTrue(js.validate({"a": 1, "c": 1}, s))
        self.assertTrue(js.validate({"a": True}, s))               # booleans are not integers
        self.assertEqual(js.validate({"a": 2.0}, s), [])           # 2.0 is an integer in JSON
        with self.assertRaises(js.SchemaError):
            js.validate({}, {"nonsense": 1})


class RealDocumentTests(TempCase):
    """Documents produced by this repository's tools must satisfy their schemas."""

    def test_snapshot_and_pointer_of_a_small_release(self):
        self.add_rules(rule_spec("alpha injection", r"alpha\s+beta", positive=["alpha beta"], negative=["alphabet"]),
                       rule_spec("translation hijack", r"stop\s+translating", category="instruction_hijacking",
                                 scope="translation_only", positive=["stop translating"], negative=["keep translating"]))
        run_cli(self.db, "publish", "--version", "1.2.3-rc1")
        out = self.tmp / "s.json"
        run_cli(self.db, "export-snapshot", "--version", "1.2.3-rc1", "--out", str(out))
        snap = json.loads(out.read_text(encoding="utf-8"))
        js.assert_valid(snap, schema("ruleset_snapshot"), "snapshot")
        hijack = [r for r in snap["rules"] if r["scope"] == "translation_only"]
        self.assertEqual([r["context_requires"] for r in hijack], [{"task": "translation"}])
        self.assertEqual(snap["scoring"], json.loads(json.dumps(SCORING_DEFAULTS)))
        d = self.tmp / "dist"
        d.mkdir()
        run_cli(self.db, "activate", "--version", "1.2.3-rc1", "--pointer-dir", str(d))
        js.assert_valid(json.loads((d / "active.json").read_text(encoding="utf-8")), schema("active_pointer"), "pointer")


class ShippedDocumentTests(unittest.TestCase):
    def test_manual_rule_files_satisfy_the_rule_spec_schema(self):
        s = schema("rule_spec")
        files = sorted((ROOT / "data" / "manual_rules").glob("*.json"))
        self.assertTrue(files)
        for f in files:
            js.assert_valid(json.loads(f.read_text(encoding="utf-8")), s, f.name)

    @unittest.skipUnless(DELIVERED_DB.is_file(), "data/ai_prompt_rules.db has not been built")
    def test_delivered_snapshot_satisfies_the_snapshot_schema(self):
        import sqlite3
        c = sqlite3.connect(f"file:{DELIVERED_DB.as_posix()}?mode=ro", uri=True)
        try:
            body = c.execute("SELECT body FROM ruleset_snapshots ORDER BY version_id DESC LIMIT 1").fetchone()[0]
        finally:
            c.close()
        js.assert_valid(json.loads(bytes(body)), schema("ruleset_snapshot"), "delivered snapshot")


if __name__ == "__main__":
    unittest.main()
