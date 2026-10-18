"""Pattern conversion (ES / Python-re / PCRE -> canonical Hyperscan-compatible form) and its classification."""
import unittest

from helpers import ROOT  # noqa: F401
from apg_rules import convert


def one(regex, dialect="es", flags="", force=""):
    conv = convert.convert_pattern(regex, dialect, flags, force_flags=force)
    return conv


class ConvertTests(unittest.TestCase):
    def test_plain_english_pattern_is_native_and_caseless(self):
        c = one(r"\bignore\s+(?:all\s+)?previous\s+instructions", force="i")
        self.assertEqual(c.fate, "hs_native")
        self.assertEqual(len(c.pieces), 1)
        p = c.pieces[0]
        self.assertEqual(p.flags, "i")
        self.assertEqual(p.engine_class, "hs_native")
        self.assertEqual(p.lang, "en")
        # ES \s is wider than ASCII \s: the Unicode spaces are spelled out explicitly in the canonical form
        self.assertIn(r"\x{3000}", p.regex)

    def test_es_dot_and_dollar_follow_ecmascript(self):
        p = one(r"a.b$").pieces[0]
        self.assertIn(r"[^\n\r\x{2028}\x{2029}]", p.regex)      # '.' does not match line terminators
        self.assertTrue(p.regex.endswith(r"\z"))                 # '$' without the m flag = end of input

    def test_python_dialect_end_anchor(self):
        p = one(r"foo\Z", dialect="py").pieces[0]
        self.assertTrue(p.regex.endswith(r"\z"))

    def test_lookahead_and_backreference_need_pcre2_confirmation(self):
        la = one(r"foo(?=bar)", dialect="pcre").pieces[0]
        self.assertEqual(la.engine_class, "hs_prefilter_pcre2")
        br = one(r"(\w)\1", dialect="pcre").pieces[0]
        self.assertEqual(br.engine_class, "hs_prefilter_pcre2")
        self.assertIn("backreference", br.features)

    def test_expressions_that_would_always_fire_are_refused(self):
        c = one(r"a*", dialect="pcre")
        self.assertEqual(c.fate, "unsupported")
        self.assertIn("empty string", c.reason)

    def test_variable_length_lookbehind_is_not_silently_converted(self):
        c = one(r"(?<=a+)b", dialect="pcre")
        self.assertEqual(c.fate, "unsupported")

    def test_invalid_expression_is_unsupported_not_an_exception(self):
        self.assertEqual(one("(", dialect="pcre").fate, "unsupported")

    def test_chinese_literals_are_native_and_tagged_zh(self):
        c = one("忽略之前的所有指令", dialect="pcre")
        self.assertEqual(c.fate, "hs_native")
        self.assertEqual(c.pieces[0].lang, "zh")

    def test_foreign_language_patterns_are_excluded_with_a_reason(self):
        c = one(r"(?i)vergiss\s+alle\s+vorherigen\s+anweisungen")
        self.assertEqual(c.fate, "excluded_language")
        self.assertEqual(c.pieces, [])
        self.assertIn("de", c.reason)

    def test_mixed_alternatives_keep_only_the_target_languages(self):
        c = one(r"(?i)ignore\s+previous\s+instructions|vergiss\s+alle\s+vorherigen\s+anweisungen")
        self.assertEqual(c.fate, "hs_native")
        self.assertEqual(len(c.pieces), 1)
        self.assertNotIn("vergiss", c.pieces[0].regex)
        self.assertTrue(any("non-target" in n for n in c.notes))

    def test_expression_identity_depends_on_regex_flags_and_profile(self):
        a = convert.expr_hash("abc", "i", "fold_v1")
        self.assertEqual(a, convert.expr_hash("abc", "i", "fold_v1"))
        self.assertNotEqual(a, convert.expr_hash("abc", "", "fold_v1"))
        self.assertNotEqual(a, convert.expr_hash("abc", "i", "trans_v1"))
        self.assertNotEqual(a, convert.expr_hash("abd", "i", "fold_v1"))


if __name__ == "__main__":
    unittest.main()
