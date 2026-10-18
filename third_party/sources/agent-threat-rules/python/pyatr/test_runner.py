"""Embedded test runner for ATR rule test_cases.

Loads a rule YAML, extracts test_cases (true_positives / true_negatives),
creates AgentEvent instances from each test case, evaluates against the
rule's detection conditions, and reports pass/fail counts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pyatr.engine import ATREngine
from pyatr.types import AgentEvent


@dataclass(frozen=True)
class TestCaseResult:
    """Result of running a single test case."""

    rule_id: str
    description: str
    case_type: str  # "true_positive" or "true_negative"
    passed: bool
    detail: str


@dataclass(frozen=True)
class RuleTestResult:
    """Aggregated results from testing one rule file."""

    rule_id: str
    file: str
    results: tuple[TestCaseResult, ...]

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0


@dataclass(frozen=True)
class TestRunResult:
    """Aggregated results from testing multiple rule files."""

    rule_results: tuple[RuleTestResult, ...]

    @property
    def passed(self) -> int:
        return sum(r.passed for r in self.rule_results)

    @property
    def failed(self) -> int:
        return sum(r.failed for r in self.rule_results)

    @property
    def total(self) -> int:
        return sum(r.total for r in self.rule_results)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0


def _load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _build_event_from_test_case(case: dict[str, Any]) -> AgentEvent:
    """Build an AgentEvent from a test_case entry.

    Test cases may contain fields like:
    - input: maps to user_input / llm_input event
    - tool_response: maps to tool_response event
    - tool_name: placed in fields
    - tool_args: placed in fields
    - tool_description: placed in fields
    - content: used as-is for content
    """
    fields: dict[str, str] = {}
    content = ""
    event_type = "llm_input"

    # Determine event type and content from available fields
    if "tool_response" in case:
        event_type = "tool_response"
        content = str(case["tool_response"])
        fields["tool_response"] = content
    elif "input" in case:
        event_type = "llm_input"
        content = str(case["input"])
        fields["user_input"] = content
    elif "content" in case:
        content = str(case["content"])

    # Add optional tool-related fields
    if "tool_name" in case:
        fields["tool_name"] = str(case["tool_name"])
        if event_type == "llm_input" and "input" not in case:
            event_type = "tool_call"
    if "tool_args" in case:
        fields["tool_args"] = str(case["tool_args"])
        if event_type == "llm_input" and "input" not in case and "tool_response" not in case:
            event_type = "tool_call"
    if "tool_description" in case:
        fields["tool_description"] = str(case["tool_description"])

    return AgentEvent(
        content=content,
        event_type=event_type,
        fields=fields,
    )


def run_rule_tests(rule_path: Path) -> RuleTestResult | None:
    """Run embedded test_cases for a single rule YAML file.

    Returns None if the file has no test_cases or cannot be parsed.
    """
    data = _load_yaml(rule_path)
    if data is None:
        return None

    rule_id = str(data.get("id", "unknown"))
    test_cases = data.get("test_cases")
    if not isinstance(test_cases, dict):
        return None

    # Build a single-rule engine
    engine = ATREngine()
    engine.load_rules_from_directory(rule_path.parent)
    # We only care about matches for this specific rule
    target_id = rule_id

    results: list[TestCaseResult] = []

    # True positives: should trigger the rule
    true_positives = test_cases.get("true_positives", [])
    if isinstance(true_positives, list):
        for case in true_positives:
            if not isinstance(case, dict):
                continue
            event = _build_event_from_test_case(case)
            matches = engine.evaluate(event)
            matched_ids = [m.rule_id for m in matches]
            triggered = target_id in matched_ids
            desc = str(case.get("description", ""))
            results.append(TestCaseResult(
                rule_id=target_id,
                description=desc,
                case_type="true_positive",
                passed=triggered,
                detail=f"Expected trigger, got {'triggered' if triggered else 'not triggered'}",
            ))

    # True negatives: should NOT trigger the rule
    true_negatives = test_cases.get("true_negatives", [])
    if isinstance(true_negatives, list):
        for case in true_negatives:
            if not isinstance(case, dict):
                continue
            event = _build_event_from_test_case(case)
            matches = engine.evaluate(event)
            matched_ids = [m.rule_id for m in matches]
            triggered = target_id in matched_ids
            desc = str(case.get("description", ""))
            results.append(TestCaseResult(
                rule_id=target_id,
                description=desc,
                case_type="true_negative",
                passed=not triggered,
                detail=f"Expected no trigger, got {'triggered' if triggered else 'not triggered'}",
            ))

    if not results:
        return None

    return RuleTestResult(
        rule_id=target_id,
        file=str(rule_path),
        results=tuple(results),
    )


def run_tests(path: Path) -> TestRunResult:
    """Run embedded test_cases for a file or directory of rule YAMLs."""
    rule_results: list[RuleTestResult] = []

    if path.is_file():
        result = run_rule_tests(path)
        if result is not None:
            rule_results.append(result)
    elif path.is_dir():
        for root_str, _dirs, files in os.walk(path):
            for fname in sorted(files):
                if not (fname.endswith(".yaml") or fname.endswith(".yml")):
                    continue
                fpath = Path(root_str) / fname
                result = run_rule_tests(fpath)
                if result is not None:
                    rule_results.append(result)

    return TestRunResult(rule_results=tuple(rule_results))
