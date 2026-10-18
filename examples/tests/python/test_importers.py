"""Importing real upstream rules: idempotence, stable ids, change detection, provenance, license/lock integrity."""
import json
import unittest

from helpers import DELIVERED_DB, ROOT, SOURCES_PRESENT, TempCase, run_cli


@unittest.skipUnless(SOURCES_PRESENT, "third_party/sources is not materialised (run: rules.py sources sync --locked)")
class ImporterTests(TempCase):
    def test_locked_sources_match_the_lock_file(self):
        _, out = run_cli(self.db, "sources", "verify")
        self.assertIn("match", out)
        lock = json.loads((ROOT / "third_party" / "sources.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(lock["sources"]), ["atr", "fevzi_pidr", "trans_pid"])
        for sid, entry in lock["sources"].items():
            self.assertRegex(entry["commit_sha"], r"^[0-9a-f]{40}$", sid)
            self.assertTrue(entry["license_spdx_detected"], sid)

    def test_import_is_idempotent_and_ids_are_stable(self):
        _, first = run_cli(self.db, "import", "--source", "trans_pid")
        self.assertIn("new 11, changed 0, unchanged 0", first)
        ids = self.rule_ids()
        self.assertEqual(len(ids), 11)
        _, second = run_cli(self.db, "import", "--source", "trans_pid")
        self.assertIn("new 0, changed 0, unchanged 11", second)
        self.assertEqual(self.rule_ids(), ids)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM rule_revisions"), 11)         # no duplicate revisions

    def test_a_changed_upstream_definition_creates_a_new_revision_of_the_same_rule(self):
        import sources.trans_pid as tp
        run_cli(self.db, "import", "--source", "trans_pid")
        rid = self.scalar("SELECT rule_id FROM rules WHERE name LIKE '%prompt%leak%' OR description LIKE '%hidden/system%' LIMIT 1")
        self.assertIsNotNone(rid)
        original = tp.GROUP_POLICY["prompt_leak"]
        try:
            tp.GROUP_POLICY["prompt_leak"] = (original[0], original[1], 0.9, original[3])
            _, out = run_cli(self.db, "diff", "--source", "trans_pid")
            self.assertIn("changed 1", out)
            run_cli(self.db, "import", "--source", "trans_pid")
        finally:
            tp.GROUP_POLICY["prompt_leak"] = original
        self.assertEqual(self.scalar("SELECT revision FROM rules WHERE rule_id=?", rid), 2)
        self.assertEqual(self.scalar("SELECT confidence FROM rules WHERE rule_id=?", rid), 0.9)
        self.assertEqual(len(self.rule_ids()), 11)                                        # same rule, new revision

    def test_provenance_points_at_the_locked_commit(self):
        run_cli(self.db, "import", "--source", "fevzi_pidr")
        lock = json.loads((ROOT / "third_party" / "sources.lock.json").read_text(encoding="utf-8"))
        commit = lock["sources"]["fevzi_pidr"]["commit_sha"]
        rows = self.rows("SELECT DISTINCT source_commit FROM rule_provenance")
        self.assertEqual([r[0] for r in rows], [commit])
        decisions = {r[0] for r in self.rows("SELECT decision FROM source_rules")}
        self.assertTrue(decisions <= {"included", "partial", "excluded_language", "excluded_scope", "unsupported"})
        # nothing disappears: every upstream rule (even the excluded ones) is recorded with a reason
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM source_rules WHERE decision_reason IS NULL OR decision_reason = ''"), 0)

    def test_imported_rules_pass_the_oracle_validation_and_publish(self):
        run_cli(self.db, "import", "--source", "trans_pid")
        _, out = run_cli(self.db, "verify-tests")
        self.assertIn("'mismatch': 0", out)
        run_cli(self.db, "validate")
        run_cli(self.db, "publish", "--version", "1.0.0")

    def test_dry_run_changes_nothing(self):
        _, out = run_cli(self.db, "import", "--source", "trans_pid", "--dry-run")
        self.assertIn("dry-run", out)
        self.assertEqual(self.rule_ids(), [])

    def test_license_files_are_shipped(self):
        for name in ("agent-threat-rules.MIT", "trans-prompt-injection-detector.MIT",
                     "prompt-injection-detection-rules.Apache-2.0"):
            self.assertTrue((ROOT / "LICENSES" / f"{name}.LICENSE.txt").is_file(), name)


@unittest.skipUnless(SOURCES_PRESENT and DELIVERED_DB.is_file(), "needs third_party/sources and the delivered database")
class FullImportIdempotenceTests(TempCase):
    def test_importing_everything_again_into_the_delivered_database_changes_nothing(self):
        import shutil
        shutil.copy2(DELIVERED_DB, self.db)
        before = {t: self.scalar(f"SELECT COUNT(*) FROM {t}") for t in
                  ("rules", "rule_revisions", "rule_patterns", "rule_tests", "source_rules", "source_patterns", "rule_provenance")}
        _, out = run_cli(self.db, "import", "--source", "all")
        self.assertIn("new 0, changed 0, unchanged 836", out)       # ATR
        self.assertIn("new 0, changed 0, unchanged 11", out)        # trans
        self.assertIn("new 0, changed 0, unchanged 20", out)        # fevzi
        after = {t: self.scalar(f"SELECT COUNT(*) FROM {t}") for t in before}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
