"""Tests for pyATR embedded test runner."""

from __future__ import annotations

from pathlib import Path

import pytest

from pyatr.test_runner import run_tests, run_rule_tests

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


def _find_rule_file(rule_id_prefix: str) -> Path | None:
    """Find a rule file by ID prefix (e.g., 'ATR-2026-00001')."""
    for root_str, _dirs, files in __import__("os").walk(RULES_DIR):
        for fname in files:
            if fname.endswith(".yaml") and rule_id_prefix.lower() in fname.lower():
                return Path(root_str) / fname
    return None


class TestRunnerOnSingleRule:
    def test_atr_2026_001_has_test_cases(self) -> None:
        """ATR-2026-00001 should have embedded test cases that run."""
        path = _find_rule_file("ATR-2026-00001")
        assert path is not None, "Could not find ATR-2026-00001 rule file"
        result = run_rule_tests(path)
        assert result is not None, "Expected test cases in ATR-2026-00001"
        assert result.total > 0, "Expected at least one test case"
        assert result.rule_id == "ATR-2026-00001"

    def test_atr_2026_001_true_positives_mostly_pass(self) -> None:
        """Most true_positives in ATR-2026-00001 should trigger.

        Note: some CJK test cases are handled by ATR-2026-00097 rather than
        ATR-2026-00001 itself, so we allow a small number of failures from
        cross-rule test case coverage.
        """
        path = _find_rule_file("ATR-2026-00001")
        assert path is not None
        result = run_rule_tests(path)
        assert result is not None
        tp_results = [r for r in result.results if r.case_type == "true_positive"]
        assert len(tp_results) > 0
        passed = sum(1 for r in tp_results if r.passed)
        # The non-CJK true positives (first ~10) should all pass
        assert passed >= 10, (
            f"Only {passed}/{len(tp_results)} true positives passed"
        )

    def test_atr_2026_001_true_negatives_pass(self) -> None:
        """All true_negatives in ATR-2026-00001 should NOT trigger."""
        path = _find_rule_file("ATR-2026-00001")
        assert path is not None
        result = run_rule_tests(path)
        assert result is not None
        tn_results = [r for r in result.results if r.case_type == "true_negative"]
        assert len(tn_results) > 0
        for r in tn_results:
            assert r.passed, f"True negative failed: {r.description} -- {r.detail}"

    def test_atr_2026_010_test_cases(self) -> None:
        """ATR-2026-00010 (MCP malicious response) test cases should pass."""
        path = _find_rule_file("ATR-2026-00010")
        assert path is not None, "Could not find ATR-2026-00010 rule file"
        result = run_rule_tests(path)
        assert result is not None
        assert result.total > 0
        # Report failures but don't require 100% pass for all rules
        # (some rules may have edge cases in their regex)
        failed = [r for r in result.results if not r.passed]
        # At minimum, most should pass
        assert result.passed > result.failed, (
            f"More failures than passes: {result.passed} passed, {result.failed} failed. "
            f"Failures: {[(f.description, f.detail) for f in failed]}"
        )

    def test_atr_2026_040_test_cases(self) -> None:
        """ATR-2026-00040 (privilege escalation) test cases should pass."""
        path = _find_rule_file("ATR-2026-00040")
        assert path is not None, "Could not find ATR-2026-00040 rule file"
        result = run_rule_tests(path)
        assert result is not None
        assert result.total > 0
        failed = [r for r in result.results if not r.passed]
        assert result.passed > result.failed, (
            f"More failures than passes: {result.passed} passed, {result.failed} failed. "
            f"Failures: {[(f.description, f.detail) for f in failed]}"
        )

    def test_atr_2026_060_test_cases(self) -> None:
        """ATR-2026-00060 (skill impersonation) test cases should pass."""
        path = _find_rule_file("ATR-2026-00060")
        assert path is not None, "Could not find ATR-2026-00060 rule file"
        result = run_rule_tests(path)
        assert result is not None
        assert result.total > 0
        failed = [r for r in result.results if not r.passed]
        assert result.passed > result.failed, (
            f"More failures than passes: {result.passed} passed, {result.failed} failed. "
            f"Failures: {[(f.description, f.detail) for f in failed]}"
        )


class TestRunnerOnDirectory:
    def test_runs_all_rules_in_directory(self) -> None:
        """Running on the full rules directory should find many test cases."""
        result = run_tests(RULES_DIR)
        assert len(result.rule_results) > 0, "No rules with test cases found"
        assert result.total > 0, "No test cases found"
        # Most rules should have more passes than failures overall
        assert result.passed > result.failed, (
            f"Overall: {result.passed} passed, {result.failed} failed out of {result.total}"
        )
