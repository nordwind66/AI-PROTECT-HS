"""The Python reference engine: three-valued conditions, context gating, scoring and decisions.

These are the semantics the C++ engine must reproduce (tests/cpp/test_engine.cpp and tests/e2e check the C++ side)."""
import copy
import re
import unittest

from helpers import ROOT  # noqa: F401
from apg_rules import regexkit as rk
from apg_rules.publish import SCORING_DEFAULTS
from apg_rules.refengine import RefEngine


def leaf(i):
    return {"op": "leaf", "id": i}


def make_rule(rid, leaves, condition, weight=0.8, confidence=0.9, **extra):
    r = {"id": rid, "revision": 1, "name": rid, "category": "prompt_injection", "lang": "en", "severity": "high",
         "weight": weight, "confidence": confidence, "action": "alert", "scope": "general", "context_requires": None,
         "score_group": None, "condition": condition,
         "leaves": [{"id": lid, "pattern_id": pid, "field": field} for lid, pid, field in leaves]}
    r.update(extra)
    return r


def make_engine(patterns, rules, scoring=None):
    return RefEngine({
        "format": "apg-ruleset-snapshot", "format_version": 1,
        "normalizer": {"tables_version": 1, "profiles": {"fold_v1": {"views": ["fold_v1", "raw"]}}},
        "field_map": {"user_input": ["user_input", "content"], "tool_output": ["tool_response", "user_input", "agent_output", "content"]},
        "scoring": scoring or copy.deepcopy(SCORING_DEFAULTS),
        "patterns": [{"id": pid, "regex": rx, "flags": "i", "profile": "fold_v1", "class": "hs_native", "lang": "en"} for pid, rx in patterns],
        "rules": rules, "ruleset": {"version": "t", "content_digest": "d", "source_digest": "s"}})


PATTERNS = [(1, r"ignore\s+previous"), (2, r"password"), (3, r"authorized"), (4, r"debug\s+mode")]


class RefEngineTests(unittest.TestCase):
    def test_single_rule_and_decision_thresholds(self):
        e = make_engine(PATTERNS, [make_rule("R1", [("c1", 1, "user_input")], {"op": "any", "args": [leaf("c1")]})])
        r = e.scan("Please IGNORE   previous things")
        self.assertEqual(r["decision"], "alert")
        self.assertAlmostEqual(r["score"], 0.72, places=6)
        self.assertEqual(r["risk_level"], "high")
        self.assertEqual(e.scan("hello")["decision"], "allow")

    def test_normalised_view_finds_obfuscated_text(self):
        e = make_engine(PATTERNS, [make_rule("R1", [("c1", 1, "user_input")], {"op": "any", "args": [leaf("c1")]})])
        self.assertEqual(e.scan("ig\u200bnore previous")["decision"], "alert")                               # zero-width
        self.assertEqual(e.scan("\uff49\uff47\uff4e\uff4f\uff52\uff45 previous")["decision"], "alert")         # full-width

    def test_all_requires_every_leaf_and_not_inverts(self):
        both = make_rule("R_ALL", [("c1", 1, "user_input"), ("c2", 2, "user_input")], {"op": "all", "args": [leaf("c1"), leaf("c2")]})
        notauth = make_rule("R_NOT", [("c1", 4, "user_input"), ("c2", 3, "user_input")],
                            {"op": "all", "args": [leaf("c1"), {"op": "not", "args": [leaf("c2")]}]})
        e = make_engine(PATTERNS, [both, notauth])
        self.assertEqual([m["rule_id"] for m in e.scan("ignore previous and password")["matched_rules"]], ["R_ALL"])
        self.assertEqual(e.scan("ignore previous only")["matched_rules"], [])
        self.assertEqual([m["rule_id"] for m in e.scan("enable debug mode")["matched_rules"]], ["R_NOT"])
        self.assertEqual(e.scan("enable debug mode, authorized")["matched_rules"], [])

    def test_missing_field_is_unknown_not_false(self):
        rule = make_rule("R_F", [("c1", 1, "user_input"), ("c2", 2, "tool_name")], {"op": "all", "args": [leaf("c1"), leaf("c2")]},
                         weight=0.9, confidence=0.9)
        e = make_engine(PATTERNS, [rule])
        r = e.scan("ignore previous")
        self.assertEqual(r["matched_rules"], [])
        self.assertEqual([n["reason"] for n in r["needs_context"]], ["field_missing"])
        self.assertEqual(r["needs_context"][0]["missing"], ["tool_name"])
        # supplying the field completes the evaluation
        r = e.scan("ignore previous", fields={"tool_name": "password"})
        self.assertEqual([m["rule_id"] for m in r["matched_rules"]], ["R_F"])
        # unknown AND false is false: a leaf that is known to be false makes the conjunction false
        self.assertEqual(e.scan("nothing here")["needs_context"], [])

    def test_context_gating(self):
        rule = make_rule("R_T", [("c1", 1, "content")], {"op": "any", "args": [leaf("c1")]}, scope="translation_only",
                         context_requires={"task": "translation"}, weight=0.9, confidence=0.9)
        e = make_engine(PATTERNS, [rule])
        r = e.scan("ignore previous")
        self.assertEqual(r["matched_rules"], [])
        self.assertEqual(r["needs_context"][0]["reason"], "context_missing")
        self.assertEqual(r["decision"], "review")                           # 0.81 >= needs_context_review_at
        self.assertEqual(e.scan("ignore previous", context={"task": "translation"})["decision"], "alert")
        other = e.scan("ignore previous", context={"task": "summary"})
        self.assertEqual((other["decision"], other["needs_context"]), ("allow", []))

    def test_missing_context_only_moves_one_notch_and_is_always_reported(self):
        # risk 0.42: it would NOT have produced an alert even with the context -> no escalation, but still reported
        weak = make_rule("R_T", [("c1", 1, "content")], {"op": "any", "args": [leaf("c1")]}, scope="translation_only",
                         context_requires={"task": "translation"}, weight=0.6, confidence=0.7)
        r = make_engine(PATTERNS, [weak]).scan("ignore previous")
        self.assertEqual(r["decision"], "allow")
        self.assertEqual(len(r["needs_context"]), 1)
        # risk 0.6: it WOULD have alerted -> review (never alert: the condition is not established)
        strong = make_rule("R_T", [("c1", 1, "content")], {"op": "any", "args": [leaf("c1")]}, scope="translation_only",
                           context_requires={"task": "translation"}, weight=0.75, confidence=0.8)
        e = make_engine(PATTERNS, [strong])
        self.assertEqual(e.scan("ignore previous")["decision"], "review")
        self.assertEqual(e.scan("ignore previous")["matched_rules"], [])
        # deployments without such workflows can switch the escalation off (the finding stays visible)
        r = e.scan("ignore previous", policy={"needs_context_review_at": 1.0})
        self.assertEqual((r["decision"], len(r["needs_context"])), ("allow", 1))

    def test_independent_signals_add_up_and_a_score_group_does_not(self):
        r1 = make_rule("R1", [("c1", 1, "user_input")], {"op": "any", "args": [leaf("c1")]}, weight=0.5, confidence=0.7)   # 0.35
        r2 = make_rule("R2", [("c1", 2, "user_input")], {"op": "any", "args": [leaf("c1")]}, weight=0.5, confidence=0.7)
        e = make_engine(PATTERNS, [r1, r2])
        self.assertAlmostEqual(e.scan("ignore previous password")["score"], 1 - 0.65 * 0.65, places=6)
        r1["score_group"] = r2["score_group"] = "g"
        e = make_engine(PATTERNS, [r1, r2])
        self.assertAlmostEqual(e.scan("ignore previous password")["score"], 0.35, places=6)

    def test_block_needs_explicit_opt_in(self):
        rule = make_rule("R1", [("c1", 1, "user_input")], {"op": "any", "args": [leaf("c1")]}, weight=1.0, confidence=0.95)
        e = make_engine(PATTERNS, [rule])
        self.assertEqual(e.scan("ignore previous")["decision"], "alert")
        self.assertEqual(e.scan("ignore previous", policy={"allow_block": True})["decision"], "block")

    def test_source_multiplier_raises_indirect_input_risk(self):
        rule = make_rule("R1", [("c1", 1, "user_input")], {"op": "any", "args": [leaf("c1")]}, weight=0.5, confidence=0.8)  # 0.4
        e = make_engine(PATTERNS, [rule])
        self.assertAlmostEqual(e.scan("ignore previous")["score"], 0.4, places=6)
        self.assertAlmostEqual(e.scan("ignore previous", source="tool_output")["score"], 0.46, places=6)


class LookbehindBridgeTests(unittest.TestCase):
    """Python's `re` wants one fixed width for a whole look-behind, PCRE2 only a fixed width per top-level alternative.
    The reference engine therefore rewrites  (?<!a|bc) -> (?<!a)(?<!bc)  so that it can judge the patterns the C++ engine
    confirms with PCRE2 (the first Linux differential run found 17 samples that differed only because of this)."""

    @staticmethod
    def compiled(canonical, flags=re.ASCII):
        return re.compile(rk.to_python_re(canonical), flags)

    def test_negative_lookbehind_with_alternatives_of_different_widths(self):
        rx = self.compiled(r"(?<!\bthey\s|\buser\s|\bpeople\s)exactly")
        self.assertIsNotNone(rx.search("please do exactly this"))
        self.assertIsNone(rx.search("they exactly"))
        self.assertIsNone(rx.search("the user exactly"))
        self.assertIsNone(rx.search("people exactly"))
        self.assertIsNotNone(rx.search("theyexactly"))            # the whitespace is part of the excluded context

    def test_positive_lookbehind_with_alternatives_of_different_widths(self):
        rx = self.compiled(r"(?<=a|bc)x")
        self.assertIsNotNone(rx.search("ax"))
        self.assertIsNotNone(rx.search("bcx"))
        self.assertIsNone(rx.search("cx"))
        self.assertIsNone(rx.search("x"))

    def test_bars_inside_classes_and_escapes_do_not_split(self):
        # three alternatives: the class [|a], an escaped bar and "bc"
        rx = self.compiled(r"(?<![|a]|\||bc)x")
        self.assertIsNone(rx.search("|x"))
        self.assertIsNone(rx.search("ax"))
        self.assertIsNone(rx.search("bcx"))
        self.assertIsNotNone(rx.search("zx"))
        self.assertEqual(rk.to_python_re(r"(?<![|a]|\||bc)x"), r"(?<![|a])(?<!\|)(?<!bc)x")

    def test_plain_patterns_are_left_alone(self):
        for text in (r"(?<!a)b", r"(?<=ab)c", r"foo(?:a|b)", r"(?<name>a)(?P=name)".replace("(?P=name)", r"\k<name>")):
            out = rk.to_python_re(text)
            re.compile(out)
        self.assertEqual(rk.to_python_re(r"(?<!a)b"), r"(?<!a)b")
        self.assertEqual(rk.to_python_re(r"(?<=ab)c"), r"(?<=ab)c")

    def test_every_pattern_of_the_delivered_snapshot_compiles(self):
        from helpers import DELIVERED_DB
        import sqlite3
        if not DELIVERED_DB.is_file():
            self.skipTest("data/ai_prompt_rules.db has not been built")
        c = sqlite3.connect(f"file:{DELIVERED_DB.as_posix()}?mode=ro", uri=True)
        try:
            rows = c.execute("SELECT pattern_id, regex, flags FROM rule_patterns WHERE engine_class != 'unsupported'").fetchall()
        finally:
            c.close()
        bad = []
        for pid, regex, flags in rows:
            try:
                self.compiled(regex, re.ASCII | (re.IGNORECASE if "i" in flags else 0))
            except re.error as exc:
                bad.append((pid, str(exc)[:60]))
        self.assertEqual(bad, [], "the reference engine cannot judge these patterns")


if __name__ == "__main__":
    unittest.main()
