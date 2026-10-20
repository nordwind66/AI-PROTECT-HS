"""Consistency of the delivered artefacts: rule database, snapshot, corpora expectations, C/C++ sources, build files."""
import hashlib
import json
import sqlite3
import unittest
from pathlib import Path

from helpers import DELIVERED_DB, ROOT
from apg_rules import corpus_eval, validate as validate_mod
from apg_rules.refengine import RefEngine


@unittest.skipUnless(DELIVERED_DB.is_file(), "data/ai_prompt_rules.db has not been built")
class DeliveredDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conn = sqlite3.connect(f"file:{DELIVERED_DB.as_posix()}?mode=ro", uri=True)
        cls.conn.row_factory = sqlite3.Row

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_integrity_foreign_keys_migrations_and_audit_chain(self):
        from apg_rules import db as dbm
        conn = dbm.connect(DELIVERED_DB, readonly=True)
        try:
            self.assertEqual(validate_mod.check_database(conn), [])
        finally:
            conn.close()

    def test_checksum_file_matches(self):
        # The checksum is the fingerprint of the database AS DELIVERED. Using it (scripts/linux/init_rules.sh registers the
        # compiled artifact and activates the version in the file) legitimately changes the bytes.
        used = self.conn.execute("SELECT (SELECT COUNT(*) FROM compiled_artifacts) + (SELECT COUNT(*) FROM active_ruleset)").fetchone()[0]
        if used:
            self.skipTest("the database has been used (compiled artifacts registered / a version activated): "
                          "the delivered fingerprint no longer applies; work on a copy (--db /tmp/rules.db) to keep it")
        recorded = (ROOT / "data" / "ai_prompt_rules.db.sha256").read_text(encoding="utf-8").split()[0]
        self.assertEqual(recorded, hashlib.sha256(DELIVERED_DB.read_bytes()).hexdigest())

    def test_a_published_version_exists_and_its_snapshot_is_intact(self):
        row = self.conn.execute("SELECT v.version, v.snapshot_sha256, s.body, s.sha256 FROM ruleset_versions v "
                                "JOIN ruleset_snapshots s USING (version_id) WHERE v.status='published' "
                                "ORDER BY v.version_id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(row)
        body = bytes(row["body"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), row["sha256"])
        self.assertEqual(row["sha256"], row["snapshot_sha256"])
        doc = json.loads(body)
        self.assertEqual(doc["ruleset"]["version"], row["version"])
        self.assertGreater(len(doc["rules"]), 300)
        # every pattern is a native or prefilter pattern: unsupported ones never reach a snapshot
        self.assertEqual({p["class"] for p in doc["patterns"]} - {"hs_native", "hs_prefilter_pcre2"}, set())

    def test_every_enabled_rule_has_a_traceable_positive_and_negative_sample(self):
        missing = self.conn.execute(
            "SELECT r.rule_id FROM rules r WHERE r.status='enabled' AND "
            "((SELECT COUNT(*) FROM rule_tests t WHERE t.rule_id=r.rule_id AND t.kind='positive') = 0 OR "
            " (SELECT COUNT(*) FROM rule_tests t WHERE t.rule_id=r.rule_id AND t.kind='negative') = 0)").fetchall()
        self.assertEqual([r[0] for r in missing], [])

    def test_no_test_disagrees_with_the_python_oracle(self):
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM rule_tests WHERE verification='python_oracle_mismatch'").fetchone()[0], 0)

    def test_every_source_rule_and_pattern_is_accounted_for(self):
        n_rules = self.conn.execute("SELECT COUNT(*) FROM source_rules").fetchone()[0]
        self.assertGreater(n_rules, 800)
        by_source = {r[0]: r[1] for r in self.conn.execute("SELECT source_id, COUNT(*) FROM source_rules GROUP BY 1")}
        self.assertEqual(by_source, {"atr": 836, "fevzi_pidr": 20, "trans_pid": 11})
        fates = {r[0] for r in self.conn.execute("SELECT DISTINCT fate FROM source_patterns")}
        self.assertTrue(fates <= {"hs_native", "hs_prefilter_pcre2", "context_logic", "excluded_language", "excluded_scope", "unsupported"})
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM source_patterns WHERE fate_reason IS NULL OR fate_reason=''").fetchone()[0] , 0)


@unittest.skipUnless(DELIVERED_DB.is_file(), "data/ai_prompt_rules.db has not been built")
class CorpusExpectationTests(unittest.TestCase):
    """tests/corpus/expected/*.expected.jsonl are the results the C++ engine must reproduce. They must be exactly what
    the Python reference engine produces from the delivered snapshot."""

    def test_expected_files_are_current(self):
        conn = sqlite3.connect(f"file:{DELIVERED_DB.as_posix()}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            version, doc = corpus_eval.snapshot_doc(conn, None)
            sha = conn.execute("SELECT snapshot_sha256 FROM ruleset_versions WHERE version=?", (version,)).fetchone()[0]
        finally:
            conn.close()
        meta = json.loads((ROOT / "tests" / "corpus" / "expected" / "EXPECTED_FOR.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["snapshot_sha256"], sha, "expected files were generated for another snapshot: run `rules.py eval --write-expected`")
        engine = RefEngine(doc)
        corpora = corpus_eval.load_corpora(ROOT / "tests" / "corpus", ROOT)
        self.assertIn("attacks_zh_en", corpora)
        for name, samples in corpora.items():
            expected = (ROOT / "tests" / "corpus" / "expected" / f"{name}.expected.jsonl").read_text(encoding="utf-8")
            actual = corpus_eval.expected_lines(corpus_eval.scan_all(engine, samples))
            self.assertEqual(actual, expected, f"{name}: expected file is stale")

    def test_corpora_are_well_formed(self):
        for name in ("benign_zh_en", "benign_extended", "attacks_zh_en"):
            rows = corpus_eval.read_jsonl(ROOT / "tests" / "corpus" / f"{name}.jsonl")
            ids = [r["id"] for r in rows]
            self.assertEqual(len(ids), len(set(ids)), name)
            for r in rows:
                self.assertIn(r["label"], ("normal", "injection"))
                self.assertIsInstance(r["text"], str)
                self.assertTrue(r["text"])


class SourceTreeTests(unittest.TestCase):
    def test_every_python_module_imports(self):
        import importlib
        for p in sorted((ROOT / "tools" / "apg_rules").glob("*.py")):
            if p.name != "__init__.py":
                importlib.import_module(f"apg_rules.{p.stem}")


if __name__ == "__main__":
    unittest.main()
