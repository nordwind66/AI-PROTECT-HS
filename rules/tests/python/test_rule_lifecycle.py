"""Rule maintenance and release flow: add -> update -> validate -> publish -> diff -> activate -> rollback."""
import hashlib
import json
import sqlite3
import unittest

from helpers import ROOT, TempCase, rule_spec, run_cli, write_json
from apg_rules import db as dbm


def two_rules():
    return [
        rule_spec("alpha injection", r"alpha\s+beta", positive=["please alpha beta now"], negative=["alphabet soup"]),
        rule_spec("gamma leak", r"gamma\s+delta", category="system_prompt_extraction",
                  positive=["gamma delta here"], negative=["gamma only"]),
    ]


class MaintenanceTests(TempCase):
    def test_add_list_show_and_idempotent_add(self):
        out = self.add_rules(*two_rules())
        self.assertIn("created AIPS-PI-0001", out)
        self.assertIn("created AIPS-SP-0001", out)
        _, listing = run_cli(self.db, "list", "--format", "json")
        rows = json.loads(listing)
        self.assertEqual([r["rule_id"] for r in rows], ["AIPS-PI-0001", "AIPS-SP-0001"])
        self.assertEqual({r["pos"] for r in rows}, {1})
        _, shown = run_cli(self.db, "show", "--id", "AIPS-PI-0001", "--json")
        doc = json.loads(shown)
        self.assertEqual(doc["rule"]["origin"], "manual")
        self.assertEqual(len(doc["patterns"]), 1)
        self.assertEqual(doc["patterns"][0]["engine_class"], "hs_native")
        again = self.add_rules(*two_rules(), name="again.json")
        self.assertIn("already exists", again)
        self.assertEqual(self.rule_ids(), ["AIPS-PI-0001", "AIPS-SP-0001"])

    def sync(self, *specs, extra=(), name="sync.json"):
        path = write_json(self.tmp / name, {"rules": list(specs)})
        _, out = run_cli(self.db, "sync-manual", "--file", str(path), *extra)
        return out

    def test_sync_manual_creates_updates_and_prunes_by_name(self):
        out = self.sync(*two_rules())
        self.assertIn("created 2, updated 0, unchanged 0, removed 0", out)
        self.assertIn("created 0, updated 0, unchanged 2, removed 0", self.sync(*two_rules()))      # idempotent
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM rule_revisions"), 2)
        changed = two_rules()
        changed[0] = rule_spec("alpha injection", r"alpha\s+beta\s+gamma", weight=0.5,
                               positive=["please alpha beta gamma now"], negative=["alphabet soup"])
        out = self.sync(*changed)
        self.assertIn("created 0, updated 1, unchanged 1, removed 0", out)
        self.assertEqual(self.scalar("SELECT revision FROM rules WHERE rule_id='AIPS-PI-0001'"), 2)
        self.assertEqual(self.scalar("SELECT weight FROM rules WHERE rule_id='AIPS-PI-0001'"), 0.5)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM rule_tests WHERE rule_id='AIPS-PI-0001'"), 2)
        # a rule that is missing from the files is kept unless --prune is given
        out = self.sync(changed[0])
        self.assertIn("kept      AIPS-SP-0001", out)
        self.assertEqual(self.scalar("SELECT status FROM rules WHERE rule_id='AIPS-SP-0001'"), "enabled")
        out = self.sync(changed[0], extra=["--prune"])
        self.assertIn("removed 1", out)
        self.assertEqual(self.scalar("SELECT status FROM rules WHERE rule_id='AIPS-SP-0001'"), "deleted")

    def test_sync_manual_dry_run_and_duplicate_names(self):
        out = self.sync(*two_rules(), extra=["--dry-run"])
        self.assertIn("[dry-run] nothing was written: created 2", out)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM rules"), 0)
        spec = two_rules()[0]
        code, _ = run_cli(self.db, "sync-manual", "--file", str(write_json(self.tmp / "d.json", {"rules": [spec, spec]})), expect=None)
        self.assertEqual(code, 1)

    def test_every_change_is_a_new_audited_revision(self):
        self.add_rules(*two_rules())
        run_cli(self.db, "update", "--id", "AIPS-PI-0001", "--set", "weight=0.5", "--reason", "tuning")
        run_cli(self.db, "disable", "--id", "AIPS-PI-0001", "--reason", "noisy")
        run_cli(self.db, "enable", "--id", "AIPS-PI-0001")
        self.assertEqual(self.scalar("SELECT revision FROM rules WHERE rule_id='AIPS-PI-0001'"), 4)
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM rule_revisions WHERE rule_id='AIPS-PI-0001'"), 4)
        # the first revision still has the original weight: history is never rewritten
        first = json.loads(self.scalar("SELECT content_json FROM rule_revisions WHERE rule_id='AIPS-PI-0001' AND revision=1"))
        self.assertEqual(first["weight"], 0.7)
        self.assertEqual(self.scalar("SELECT weight FROM rules WHERE rule_id='AIPS-PI-0001'"), 0.5)
        kinds = [r[0] for r in self.rows(
            "SELECT change_kind FROM rule_revisions WHERE rule_id='AIPS-PI-0001' ORDER BY revision")]
        self.assertEqual(kinds, ["create", "edit", "disable", "enable"])
        self.assertEqual(self.scalar("SELECT modified_locally FROM rules WHERE rule_id='AIPS-PI-0001'"), 1)
        c = self.connect()
        self.assertEqual(dbm.verify_audit_chain(c), [])
        c.close()

    def test_invalid_changes_are_refused(self):
        self.add_rules(*two_rules())
        code, out = run_cli(self.db, "update", "--id", "AIPS-PI-0001", "--set", "weight=2", expect=None)
        self.assertEqual(code, 1)
        code, _ = run_cli(self.db, "update", "--id", "AIPS-PI-0001", "--set", "regex=x", expect=None)
        self.assertEqual(code, 1)
        code, _ = run_cli(self.db, "disable", "--id", "AIPS-XX-9999", expect=None)
        self.assertEqual(code, 1)

    def test_dry_run_changes_nothing(self):
        self.add_rules(*two_rules())
        run_cli(self.db, "update", "--id", "AIPS-PI-0001", "--set", "weight=0.1", "--dry-run")
        run_cli(self.db, "delete", "--id", "AIPS-PI-0001", "--dry-run")
        self.assertEqual(self.scalar("SELECT weight FROM rules WHERE rule_id='AIPS-PI-0001'"), 0.7)
        self.assertEqual(self.scalar("SELECT status FROM rules WHERE rule_id='AIPS-PI-0001'"), "enabled")

    def test_bad_manual_rules_are_rejected_before_anything_is_written(self):
        for spec in (rule_spec("x", r"a*"),                                    # matches the empty string
                     rule_spec("x", r"(", positive=["a"]),                      # invalid expression
                     rule_spec("x", r"abc", category="nonsense"),
                     rule_spec("x", r"abc", weight=3)):
            path = write_json(self.tmp / "bad.json", {"rules": [spec]})
            code, _ = run_cli(self.db, "add", "--file", str(path), expect=None)
            self.assertEqual(code, 1, spec)
        self.assertEqual(self.rule_ids(), [])

    def test_validate_reports_missing_tests_and_strict_fails(self):
        self.add_rules(rule_spec("untested", r"zzz\s+yyy"))
        code, out = run_cli(self.db, "validate", expect=0)
        self.assertIn("missing_positive_test", out)
        code, _ = run_cli(self.db, "validate", "--strict", expect=None)
        self.assertEqual(code, 1)

    def test_oracle_catches_a_test_the_pattern_does_not_satisfy(self):
        self.add_rules(rule_spec("wrong test", r"alpha\s+beta", positive=["gamma"], negative=["alpha beta"]))
        _, out = run_cli(self.db, "verify-tests")
        self.assertIn("'mismatch': 2", out)
        code, _ = run_cli(self.db, "validate", "--strict", expect=None)
        self.assertEqual(code, 1)


class ReleaseTests(TempCase):
    def setUp(self):
        super().setUp()
        self.add_rules(*two_rules())

    def test_publish_makes_an_immutable_version_with_a_pinned_snapshot(self):
        run_cli(self.db, "publish", "--version", "1.0.0", "--notes", "first")
        out = self.tmp / "snap.json"
        run_cli(self.db, "export-snapshot", "--version", "1.0.0", "--out", str(out))
        body = out.read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), self.scalar("SELECT snapshot_sha256 FROM ruleset_versions WHERE version='1.0.0'"))
        snap = json.loads(body)
        self.assertEqual(snap["format"], "apg-ruleset-snapshot")
        self.assertEqual([r["id"] for r in snap["rules"]], ["AIPS-PI-0001", "AIPS-SP-0001"])
        self.assertEqual(snap["scoring"]["thresholds"], {"alert": 0.5, "block": 0.85, "review": 0.3})
        # the snapshot is canonical JSON (sorted keys, no whitespace)
        self.assertEqual(body.decode("utf-8"), json.dumps(snap, sort_keys=True, separators=(",", ":"), ensure_ascii=False))

    def test_versions_only_move_forward_and_identical_content_is_refused(self):
        run_cli(self.db, "publish", "--version", "1.0.0")
        code, out = run_cli(self.db, "publish", "--version", "1.0.0", expect=None)
        self.assertEqual(code, 1)
        code, out = run_cli(self.db, "publish", "--version", "0.9.0", expect=None)
        self.assertEqual(code, 1)
        code, out = run_cli(self.db, "publish", "--version", "1.0.1", expect=None)
        self.assertEqual(code, 1)
        self.assertIn("identical", out)

    def test_editing_after_publish_does_not_touch_the_published_version(self):
        run_cli(self.db, "publish", "--version", "1.0.0")
        before = self.scalar("SELECT sha256 FROM ruleset_snapshots WHERE version_id=1")
        run_cli(self.db, "update", "--id", "AIPS-PI-0001", "--set", "weight=0.4")
        run_cli(self.db, "disable", "--id", "AIPS-SP-0001")
        self.assertEqual(self.scalar("SELECT sha256 FROM ruleset_snapshots WHERE version_id=1"), before)
        run_cli(self.db, "publish", "--version", "1.1.0")
        _, diff = run_cli(self.db, "diff", "--versions", "1.0.0", "1.1.0")
        self.assertIn("-1 rules", diff)                                   # the disabled rule left the new version
        self.assertIn("~1 changed", diff)
        self.assertIn("weight: 0.7 -> 0.4", diff)
        # the old version still contains both rules with the old weight
        old = json.loads(bytes(self.scalar("SELECT body FROM ruleset_snapshots WHERE version_id=1")))
        self.assertEqual([r["weight"] for r in old["rules"]], [0.7, 0.7])

    def test_activate_and_rollback_move_the_pointer_and_leave_an_audit_trail(self):
        run_cli(self.db, "publish", "--version", "1.0.0")
        run_cli(self.db, "update", "--id", "AIPS-PI-0001", "--set", "weight=0.4")
        run_cli(self.db, "publish", "--version", "1.1.0")
        run_cli(self.db, "activate", "--version", "1.1.0", "--reason", "release")
        self.assertEqual(self.scalar("SELECT version FROM ruleset_versions WHERE version_id=(SELECT version_id FROM active_ruleset)"), "1.1.0")
        pointer_dir = self.tmp / "dist"
        pointer_dir.mkdir()
        run_cli(self.db, "rollback", "--to", "1.0.0", "--reason", "regression", "--pointer-dir", str(pointer_dir))
        self.assertEqual(self.scalar("SELECT version FROM ruleset_versions WHERE version_id=(SELECT version_id FROM active_ruleset)"), "1.0.0")
        pointer = json.loads((pointer_dir / "active.json").read_text(encoding="utf-8"))
        self.assertEqual(pointer["kind"], "apg-active-pointer")
        self.assertEqual(pointer["manifest"], "1.0.0/manifest.json")
        actions = [r[0] for r in self.rows("SELECT action FROM audit_log ORDER BY audit_id")]
        self.assertIn("rollback", actions)
        self.assertEqual(self.scalar("SELECT previous_version_id FROM active_ruleset"), 2)
        code, _ = run_cli(self.db, "rollback", "--to", "1.0.0", expect=None)       # already active
        self.assertEqual(code, 1)
        code, _ = run_cli(self.db, "activate", "--version", "9.9.9", expect=None)
        self.assertEqual(code, 1)

    def test_stage_creates_a_draft_that_is_not_publishable_content(self):
        run_cli(self.db, "stage", "--version", "2.0.0-rc1")
        self.assertEqual(self.scalar("SELECT status FROM ruleset_versions WHERE version='2.0.0-rc1'"), "draft")
        code, _ = run_cli(self.db, "activate", "--version", "2.0.0-rc1", expect=None)
        self.assertEqual(code, 1)                                          # only published versions can be activated

    def test_the_build_is_reproducible(self):
        run_cli(self.db, "publish", "--version", "1.0.0")
        other = self.tmp / "other.db"
        run_cli(other, "db", "init")
        run_cli(other, "add", "--file", str(self.tmp / "rules.json"))
        run_cli(other, "publish", "--version", "1.0.0")
        a = self.scalar("SELECT sha256 FROM ruleset_snapshots")
        c = dbm.connect(other, readonly=True)
        b = c.execute("SELECT sha256 FROM ruleset_snapshots").fetchone()[0]
        c.close()
        self.assertEqual(a, b)

    def test_rules_with_identical_evidence_do_not_stack(self):
        # the same pattern imported twice under different names must not be counted as two independent signals
        self.add_rules(rule_spec("alpha injection duplicate", r"alpha\s+beta", positive=["alpha beta"], negative=["alphabet"]),
                       name="dup.json")
        run_cli(self.db, "publish", "--version", "1.0.0")
        snap = json.loads(bytes(self.scalar("SELECT body FROM ruleset_snapshots")))
        groups = {r["id"]: r["score_group"] for r in snap["rules"]}
        self.assertTrue(groups["AIPS-PI-0001"].startswith("same-evidence:"))
        self.assertEqual(groups["AIPS-PI-0001"], groups["AIPS-PI-0002"])
        self.assertIsNone(groups["AIPS-SP-0001"])


class ShippedManualRuleFiles(TempCase):
    def test_every_shipped_manual_rule_file_imports_and_passes_its_own_tests(self):
        files = sorted((ROOT / "data" / "manual_rules").glob("*.json"))
        self.assertTrue(files)
        for f in files:
            run_cli(self.db, "add", "--file", str(f))
        _, out = run_cli(self.db, "verify-tests")
        self.assertIn("'mismatch': 0", out)
        run_cli(self.db, "validate", "--strict")
        run_cli(self.db, "publish", "--version", "1.0.0")


if __name__ == "__main__":
    unittest.main()
