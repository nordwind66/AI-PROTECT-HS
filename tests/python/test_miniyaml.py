"""miniyaml: the safe YAML-subset loader that replaces PyYAML (not installable on the build machine)."""
import unittest

from helpers import ROOT, SOURCES_PRESENT  # noqa: F401  (also puts tools/ on sys.path)
from apg_rules import miniyaml
from apg_rules.miniyaml import YamlError


class MiniYamlTests(unittest.TestCase):
    def test_scalars_follow_the_safe_resolver(self):
        doc = miniyaml.load("a: 1\nb: -2.5\nc: true\nd: null\ne: 'x'\nf: \"y\\n\"\ng: 2026-03-04\nh: 0x10\ni: no\n")
        self.assertEqual(doc, {"a": 1, "b": -2.5, "c": True, "d": None, "e": "x", "f": "y\n", "g": "2026-03-04",
                               "h": 16, "i": False})

    def test_nested_structures_and_sequences(self):
        doc = miniyaml.load("rules:\n  - id: A\n    tags: [x, y]\n    meta: {k: 1}\n  - id: B\n    list:\n    - 1\n    - 2\n")
        self.assertEqual(doc["rules"][0], {"id": "A", "tags": ["x", "y"], "meta": {"k": 1}})
        self.assertEqual(doc["rules"][1], {"id": "B", "list": [1, 2]})

    def test_block_scalars(self):
        doc = miniyaml.load("lit: |\n  line1\n  line2\nfold: >\n  a\n  b\n\n  c\nstrip: |-\n  x\n")
        self.assertEqual(doc["lit"], "line1\nline2\n")
        self.assertEqual(doc["fold"], "a b\nc\n")
        self.assertEqual(doc["strip"], "x")

    def test_comments_and_document_marker(self):
        self.assertEqual(miniyaml.load("---\n# c\na: 1  # trailing\nb: 'x # not a comment'\n"), {"a": 1, "b": "x # not a comment"})

    def test_locations_are_recorded(self):
        doc, locs = miniyaml.load_with_locs("a: 1\nb:\n  - x\n  - y\n")
        self.assertEqual(locs[("a",)], 1)
        self.assertEqual(locs[("b", 1)], 4)
        self.assertEqual(doc["b"], ["x", "y"])

    def test_unsupported_syntax_is_rejected_loudly(self):
        for bad in ("a: &x 1\nb: *x\n", "a: !!str 1\n", "a: 1\n---\nb: 2\n", "a:\n\t- 1\n",
                    "? complex\n: key\n", "<<: {a: 1}\n"):
            with self.assertRaises(YamlError, msg=bad):
                miniyaml.load(bad)

    def test_duplicate_keys_are_reported_not_hidden(self):
        doc, _, warnings = miniyaml.load_full("a: 1\na: 2\n")
        self.assertEqual(doc, {"a": 2})                    # last value wins, like PyYAML ...
        self.assertEqual(len(warnings), 1)                  # ... but the importer records a warning for it
        self.assertIn("duplicate", warnings[0][1])

    def test_quoted_regexes_survive_exactly(self):
        text = "value: '(?i)\\bignore\\s+(?:all\\s+)?previous'\nq: \"a\\\\b\"\n"
        doc = miniyaml.load(text)
        self.assertEqual(doc["value"], r"(?i)\bignore\s+(?:all\s+)?previous")
        self.assertEqual(doc["q"], "a\\b")

    @unittest.skipUnless(SOURCES_PRESENT, "third_party/sources not materialised")
    def test_every_atr_rule_file_parses(self):
        rules = sorted((ROOT / "third_party" / "sources" / "agent-threat-rules" / "rules").rglob("*.yaml"))
        self.assertGreater(len(rules), 800)
        bad = []
        for f in rules:
            try:
                doc = miniyaml.load(f.read_text(encoding="utf-8"))
                if not isinstance(doc, dict) or "id" not in doc:
                    bad.append(f.name)
            except YamlError as exc:
                bad.append(f"{f.name}: {exc}")
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
