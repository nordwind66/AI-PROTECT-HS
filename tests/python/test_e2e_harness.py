"""Self-test of the end-to-end harness (tests/e2e/run_e2e.py).

The harness is run against tests/e2e/fake_cli.py, a PYTHON STAND-IN of the C++ command line tool. This checks the harness
itself (argument handling, schema validation, differential comparison, tamper checks, release flow, pointer files) so that it
does not fail for its own bugs on the Linux machine. It says nothing about the C++ engine.
"""
import json
import subprocess
import sys
import unittest

from helpers import DELIVERED_DB, ROOT, TempCase

E2E = ROOT / "tests" / "e2e"


@unittest.skipUnless(DELIVERED_DB.is_file(), "data/ai_prompt_rules.db has not been built")
class HarnessSelfTest(TempCase):
    def run_harness(self, *extra):
        cmd = [sys.executable, "-X", "utf8", str(E2E / "run_e2e.py"), "--cli", f"{sys.executable} -X utf8 {E2E / 'fake_cli.py'}",
               "--backend", "pcre2_fallback", "--workdir", str(self.tmp / "work"), "--skip", "examples,release", *extra]
        return subprocess.run(cmd, capture_output=True, timeout=900, cwd=str(ROOT))

    def test_harness_passes_against_the_stand_in(self):
        report = self.tmp / "report.json"
        p = self.run_harness("--report", str(report))
        out = p.stdout.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 0, out + p.stderr.decode("utf-8", "replace"))
        results = json.loads(report.read_text(encoding="utf-8"))["results"]
        self.assertTrue(all(r["status"] == "PASS" for r in results), results)
        self.assertGreaterEqual(len(results), 8)

    def test_harness_detects_a_wrong_engine(self):
        # a stand-in that always answers "allow" must fail the differential test (the harness has teeth)
        liar = self.tmp / "liar_cli.py"
        liar.write_text(
            "import sys, json\n"
            f"sys.path.insert(0, {str(E2E)!r})\n"
            "import fake_cli\n"
            "orig = fake_cli.Loaded.result\n"
            "def lie(self, *a, **k):\n"
            "    r = orig(self, *a, **k)\n"
            "    r['decision'] = 'allow'\n"
            "    r['matched_rules'] = []\n"
            "    r['score'] = 0\n"
            "    return r\n"
            "fake_cli.Loaded.result = lie\n"
            "sys.exit(fake_cli.main(sys.argv[1:]))\n", encoding="utf-8")
        cmd = [sys.executable, "-X", "utf8", str(E2E / "run_e2e.py"), "--cli", f"{sys.executable} -X utf8 {liar}",
               "--backend", "pcre2_fallback", "--workdir", str(self.tmp / "work2"), "--skip", "examples,release"]
        p = subprocess.run(cmd, capture_output=True, timeout=900, cwd=str(ROOT))
        out = p.stdout.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 1, out)
        self.assertIn("[FAIL]", out)
        self.assertIn("differential", out)


if __name__ == "__main__":
    unittest.main()
