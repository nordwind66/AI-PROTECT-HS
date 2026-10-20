"""SQLite schema: migrations, immutability triggers, append-only audit chain, backup / restore."""
import hashlib
import sqlite3
import unittest

from helpers import TempCase, rule_spec, run_cli
from apg_rules import db as dbm
from apg_rules import validate as validate_mod


class SchemaTests(TempCase):
    def test_fresh_database_has_the_expected_structure(self):
        c = self.connect()
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("rules", "rule_revisions", "rule_patterns", "rule_pattern_links", "rule_tests", "source_rules",
                  "source_patterns", "rule_provenance", "ruleset_versions", "ruleset_members", "ruleset_patterns",
                  "ruleset_snapshots", "active_ruleset", "compiled_artifacts", "audit_log", "id_counters",
                  "schema_migrations", "upstream_sources"):
            self.assertIn(t, tables)
        self.assertEqual(dbm.schema_version(c), 1)
        self.assertEqual(c.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(c.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        c.close()

    def test_migrate_is_idempotent_and_verified(self):
        conn = dbm.connect(self.db)
        self.assertEqual(dbm.migrate(conn), [])
        conn.close()
        run_cli(self.db, "db", "check")

    def test_migration_checksum_tampering_is_detected(self):
        conn = dbm.connect(self.db)
        conn.execute("UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1")
        conn.commit()
        conn.close()
        code, out = run_cli(self.db, "db", "check", expect=None)
        self.assertEqual(code, 1)
        self.assertIn("checksum", out.lower())


class ImmutabilityTests(TempCase):
    def setUp(self):
        super().setUp()
        self.add_rules(rule_spec("alpha rule", r"alpha\s+beta", positive=["alpha beta"], negative=["gamma"]))
        run_cli(self.db, "publish", "--version", "1.0.0")

    def _fails(self, sql, *params):
        c = dbm.connect(self.db)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                c.execute(sql, params)
        finally:
            c.rollback()
            c.close()

    def test_patterns_are_immutable_and_never_deleted(self):
        self._fails("UPDATE rule_patterns SET regex = 'changed'")
        self._fails("DELETE FROM rule_patterns")

    def test_revisions_and_audit_log_are_append_only(self):
        self._fails("UPDATE rule_revisions SET reason = 'x'")
        self._fails("DELETE FROM rule_revisions")
        self._fails("UPDATE audit_log SET actor = 'mallory'")
        self._fails("DELETE FROM audit_log")

    def test_a_published_version_is_frozen(self):
        self._fails("UPDATE ruleset_versions SET content_digest = 'x' WHERE status = 'published'")
        self._fails("DELETE FROM ruleset_versions WHERE status = 'published'")
        self._fails("DELETE FROM ruleset_members")
        self._fails("UPDATE ruleset_snapshots SET body = x'00'")
        self._fails("DELETE FROM ruleset_snapshots")

    def test_artifacts_need_a_published_version(self):
        c = dbm.connect(self.db)
        c.execute("INSERT INTO ruleset_versions (version_id, version, status, created_at, created_by, snapshot_format) "
                  "VALUES (99, '9.9.9', 'draft', '2026-01-01T00:00:00Z', 'x', 1)")
        with self.assertRaises(sqlite3.DatabaseError):
            c.execute("INSERT INTO compiled_artifacts (version_id, target_os, arch, backend, engine_abi, manifest_sha256, "
                      "meta_sha256, rel_path, status, built_at) VALUES (99,'linux','x86_64','hyperscan',65536,'a','b','p','ok','t')")
        c.rollback()
        c.close()

    def test_foreign_keys_are_enforced(self):
        c = dbm.connect(self.db)
        with self.assertRaises(sqlite3.IntegrityError):
            c.execute("INSERT INTO rule_tests (rule_id, kind, text, text_sha256, scan_source, expect_hit, origin, created_at) "
                      "VALUES ('AIPS-XX-9999','positive','t','h','user_input',1,'manual','2026-01-01T00:00:00Z')")
        c.rollback()
        c.close()


class AuditChainTests(TempCase):
    def test_hash_chain_detects_tampering(self):
        self.add_rules(rule_spec("alpha rule", r"alpha\s+beta", positive=["alpha beta"], negative=["gamma"]))
        c = dbm.connect(self.db)
        self.assertEqual(dbm.verify_audit_chain(c), [])
        c.execute("DROP TRIGGER trg_audit_no_update")                      # an attacker with file access
        c.execute("UPDATE audit_log SET actor = 'mallory' WHERE audit_id = (SELECT MIN(audit_id) FROM audit_log)")
        c.commit()
        problems = dbm.verify_audit_chain(c)
        c.close()
        self.assertTrue(problems)
        code, out = run_cli(self.db, "db", "check", expect=None)
        self.assertEqual(code, 1)


class BackupTests(TempCase):
    def test_backup_restore_and_delivery_snapshot(self):
        self.add_rules(rule_spec("alpha rule", r"alpha\s+beta", positive=["alpha beta"], negative=["gamma"]))
        run_cli(self.db, "publish", "--version", "1.0.0")
        backup = self.tmp / "backup.db"
        run_cli(self.db, "db", "backup", "--out", str(backup))
        run_cli(backup, "db", "check")
        snap = self.tmp / "delivery.db"
        run_cli(self.db, "db", "snapshot", "--out", str(snap))
        c = sqlite3.connect(str(snap))
        self.assertEqual(c.execute("PRAGMA journal_mode").fetchone()[0], "delete")
        self.assertEqual(c.execute("SELECT COUNT(*) FROM ruleset_versions WHERE status='published'").fetchone()[0], 1)
        c.close()
        # restore over a damaged database
        self.db.write_bytes(b"not a database")
        run_cli(self.db, "db", "restore", "--from", str(backup), "--force")
        run_cli(self.db, "db", "check")
        self.assertEqual(self.scalar("SELECT COUNT(*) FROM rules"), 1)

    def test_restore_refuses_to_overwrite_without_force(self):
        backup = self.tmp / "b.db"
        run_cli(self.db, "db", "backup", "--out", str(backup))
        code, _ = run_cli(self.db, "db", "restore", "--from", str(backup), expect=None)
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
