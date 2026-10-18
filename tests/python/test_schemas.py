"""schemas/*.json: well-formed, only use keywords the bundled validator understands, and accept / reject the right documents.

The snapshot and the rule-spec files are REAL documents produced by this repository's Python tools. The scan response,
manifest, info and build-report samples below are written by hand from reading the C++ sources (the C++ code could not
be run in the development session); tests/e2e/run_e2e.py validates the real C++ output against the same schemas on Linux.
"""
import copy
import json
import unittest

from helpers import DELIVERED_DB, ROOT, TempCase, rule_spec, run_cli
from apg_rules import jsonschema_lite as js
from apg_rules.publish import SCORING_DEFAULTS

SCHEMAS = ROOT / "schemas"
NAMES = ["request", "response", "config", "info", "manifest", "ruleset_snapshot", "rule_spec", "active_pointer", "build_report"]


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


class RequestSchemaTests(unittest.TestCase):
    def setUp(self):
        self.s = schema("request")

    def test_examples_are_valid(self):
        for ex in self.s["examples"]:
            self.assertEqual(js.validate(ex, self.s), [], ex)

    def test_invalid_requests(self):
        for bad in ({}, {"request_id": "x"}, {"text": 5}, {"text": "x", "unknown": 1}, {"text": "x", "source": "bad source!"},
                    {"text": "x", "context": {"task": ["list"]}}, {"fields": {"bad name": "v"}}, {"text": "x", "schema_version": 2}):
            self.assertTrue(js.validate(bad, self.s), bad)


class ConfigSchemaTests(unittest.TestCase):
    def setUp(self):
        self.s = schema("config")

    def test_examples_are_valid(self):
        for ex in self.s["examples"]:
            self.assertEqual(js.validate(ex, self.s), [], ex)

    def test_invalid_configs(self):
        for bad in ({}, {"manifest_path": ""}, {"manifest_path": "m", "typo": 1}, {"manifest_path": "m", "limits": {"max_text_bytes": 0}},
                    {"manifest_path": "m", "policy": {"on_error": "ignore"}}, {"manifest_path": "m", "policy": {"thresholds": {"alert": 2}}}):
            self.assertTrue(js.validate(bad, self.s), bad)


class ResponseSchemaTests(unittest.TestCase):
    def setUp(self):
        self.s = schema("response")
        self.ok = copy.deepcopy(self.s["examples"][0])

    def test_example_is_valid(self):
        self.assertEqual(js.validate(self.ok, self.s), [])

    def test_error_result_shape(self):
        err = {"schema_version": 1, "request_id": "r1", "status": "error", "decision": "review", "score": 0, "risk_level": "none",
               "ruleset_version": "1.0.0", "engine_version": "1.0.0", "backend": "pcre2_fallback", "matched_rules": [],
               "needs_context": [], "inputs": {"text_bytes": 3}, "warnings": ["text is not valid UTF-8"], "duration_us": 5,
               "error_code": "invalid_utf8"}
        self.assertEqual(js.validate(err, self.s), [])
        bad = dict(err, error_code=None)
        self.assertTrue(js.validate(bad, self.s))                       # an error result must say which error
        bad = dict(self.ok, error_code="invalid_utf8")
        self.assertTrue(js.validate(bad, self.s))                       # an ok result has no error code

    def test_violations_are_detected(self):
        for mutate in (lambda d: d.pop("decision"), lambda d: d.update(decision="deny"), lambda d: d.update(score=1.5),
                       lambda d: d.update(backend="regex"), lambda d: d["matched_rules"][0].pop("rule_id"),
                       lambda d: d["matched_rules"][0].update(rule_id="RULE-1"), lambda d: d.update(extra=1),
                       lambda d: d["matched_rules"][0]["evidence"][0].update(view="nfkc")):
            d = copy.deepcopy(self.ok)
            mutate(d)
            self.assertTrue(js.validate(d, self.s), d)

    def test_needs_context_item(self):
        d = copy.deepcopy(self.ok)
        d["needs_context"] = [{"rule_id": "AIPS-IH-0001", "category": "instruction_hijacking", "severity": "high",
                               "reason": "context_missing", "missing": ["task"], "pattern_ids": [11001]}]
        self.assertEqual(js.validate(d, self.s), [])
        d["needs_context"][0]["reason"] = "unknown"
        self.assertTrue(js.validate(d, self.s))


def sample_manifest():
    h = "a" * 64
    return {
        "kind": "apg-manifest", "manifest_version": 1, "status": "ok",
        "engine": {"engine_version": "1.0.0", "abi_version": 65536, "norm_tables_version": 1},
        "ruleset": {"version": "1.0.0", "content_digest": h, "snapshot_sha256": h, "rule_count": 2, "pattern_count": 3},
        "target": {"os": "linux", "arch": "x86_64", "backend": "hyperscan", "hyperscan_version": "5.4.2 2023-04-22",
                   "pcre2_version": "10.42 2022-12-11", "cpu_target": "generic", "cpu_features": "0x0", "tune": 0,
                   "compiler": "gcc 12.2.0"},
        "files": {"meta": {"path": "ruleset.meta.json", "sha256": h, "bytes": 100},
                  "databases": [{"profile": "fold_v1", "path": "rules.fold_v1.hsdb", "sha256": h, "bytes": 2048,
                                 "native_ids": [10001, 10002], "prefilter_ids": [10003]}]},
        "patterns": {"total": 3, "native": 2, "prefilter": 1, "failed": 0, "failed_ids": []},
        "built_at": "2026-01-01T00:00:00Z", "build_hash": h}


class ArtifactSchemaTests(unittest.TestCase):
    def test_manifest(self):
        s = schema("manifest")
        m = sample_manifest()
        self.assertEqual(js.validate(m, s), [])
        for mutate in (lambda d: d.update(kind="other"), lambda d: d["files"]["databases"][0].update(path="../evil.hsdb"),
                       lambda d: d["target"].update(arch="arm64"), lambda d: d["ruleset"].update(snapshot_sha256="xyz"),
                       lambda d: d.pop("build_hash"), lambda d: d["target"].update(cpu_features="avx2")):
            d = copy.deepcopy(m)
            mutate(d)
            self.assertTrue(js.validate(d, s), d)

    def test_manifest_with_database_shards(self):
        # a profile split into several databases (parallel build): one entry per .hsdb file
        h = "a" * 64
        m = sample_manifest()
        m["files"]["databases"] = [
            {"profile": "fold_v1", "path": "rules.fold_v1.01.hsdb", "sha256": h, "bytes": 1024, "native_ids": [10001], "prefilter_ids": []},
            {"profile": "fold_v1", "path": "rules.fold_v1.02.hsdb", "sha256": h, "bytes": 1024, "native_ids": [10002], "prefilter_ids": [10003]},
            {"profile": "trans_v1", "path": "rules.trans_v1.hsdb", "sha256": h, "bytes": 512, "native_ids": [], "prefilter_ids": []}]
        self.assertEqual(js.validate(m, schema("manifest")), [])
        m["files"]["databases"][0]["path"] = "sub/dir.hsdb"
        self.assertTrue(js.validate(m, schema("manifest")))

    def test_info_build_report_pointer(self):
        h = "b" * 64
        info = {"schema_version": 1, "engine_version": "1.0.0", "abi_version": 65536, "norm_tables_version": 1,
                "ruleset": {"version": "1.0.0", "content_digest": h, "snapshot_sha256": h, "rules": 2, "patterns": 3,
                            "patterns_native": 2, "patterns_prefilter": 1, "patterns_failed": 0, "failed_pattern_ids": [],
                            "manifest_path": "dist/linux/x86_64/1.0.0/manifest.json", "built_at": "t", "loaded_at": "t"},
                "backend": {"name": "hyperscan", "hyperscan_version": "5.4.2", "pcre2_version": "10.42", "cpu_target": "generic",
                            "os": "linux", "arch": "x86_64"},
                "policy": {"allow_block": False, "on_error": "review", "on_verify_error": "review"},
                "limits": {"max_text_bytes": 1048576, "max_request_bytes": 4194304, "max_hits": 50000, "max_fields": 16}}
        self.assertEqual(js.validate(info, schema("info")), [])
        report = {"kind": "apg-build-report", "ruleset_version": "1.0.0", "total": 2, "native": 1, "prefilter": 0, "failed": 1,
                  "downgraded_to_prefilter": 0,
                  "patterns": [{"id": 10001, "class": "hs_native", "flags": "i", "profile": "fold_v1"},
                               {"id": 10002, "class": "unsupported", "flags": "", "profile": "fold_v1", "error": "bad", "provenance": ["atr:ATR-1 (x.yaml)"],
                                "rules": ["AIPS-PI-0001"], "regex": "(?<=a+)b"}]}
        self.assertEqual(js.validate(report, schema("build_report")), [])
        # optional fields written by the parallel compiler
        report["relaxed_repeats"] = 1
        report["build_stats"] = {"jobs": 8, "databases": 9, "native_timeout_s": 15, "pattern_timeout_s": 60, "shard_timeout_s": 1800, "relax_repeat": 32,
                                 "elapsed_s": 41.5}
        report["patterns"][0]["relaxed_repeats"] = True
        report["patterns"][0]["downgraded_from_native"] = True
        self.assertEqual(js.validate(report, schema("build_report")), [])
        report["build_stats"]["jobs"] = "many"
        self.assertTrue(js.validate(report, schema("build_report")))
        pointer = {"kind": "apg-active-pointer", "schema_version": 1, "channel": "default", "version": "1.0.0",
                   "manifest": "1.0.0/manifest.json", "manifest_sha256": h, "activated_at": "t"}
        self.assertEqual(js.validate(pointer, schema("active_pointer")), [])
        pointer["manifest"] = "../../etc/passwd"
        self.assertTrue(js.validate(pointer, schema("active_pointer")))


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

    def test_sample_request_fixture_satisfies_the_request_schema(self):
        js.assert_valid(json.loads((ROOT / "tests" / "fixtures" / "sample.json").read_text(encoding="utf-8")),
                        schema("request"), "tests/fixtures/sample.json")

    def test_every_corpus_sample_is_a_valid_request(self):
        from apg_rules import corpus_eval
        s = schema("request")
        for name, samples in corpus_eval.load_corpora(ROOT / "tests" / "corpus", ROOT).items():
            for sample in samples:
                req = {"request_id": sample["id"], "source": sample.get("source", "user_input"), "text": sample["text"]}
                if sample.get("context"):
                    req["context"] = sample["context"]
                self.assertEqual(js.validate(req, s), [], f"{name}/{sample['id']}")

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
