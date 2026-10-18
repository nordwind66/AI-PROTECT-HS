"""Tests for pyATR rule validator."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml

from pyatr.validator import validate, validate_file, ValidationResult

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


class TestValidateRealRules:
    def test_all_rules_pass_validation(self) -> None:
        """Every rule in the rules/ directory should pass validation."""
        result = validate(RULES_DIR)
        assert result.files_checked > 0, "No rule files found"
        if not result.valid:
            error_msgs = [
                f"{e.file} [{e.field}]: {e.message}" for e in result.errors
            ]
            pytest.fail(
                f"Validation found {len(result.errors)} error(s):\n"
                + "\n".join(error_msgs[:20])
            )


class TestValidateMalformedRules:
    def test_missing_required_fields(self) -> None:
        """A rule missing required fields should produce errors."""
        rule_data = {
            "id": "ATR-TEST-001",
            "title": "Test Rule",
            # missing: status, description, author, date, severity, tags,
            #          agent_source, detection, response
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert not result.valid
            missing_fields = {e.field for e in result.errors}
            for req in ("status", "description", "author", "date", "severity",
                        "tags", "agent_source", "detection", "response"):
                assert req in missing_fields, f"Expected error for missing '{req}'"
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_invalid_severity(self) -> None:
        """An invalid severity value should be flagged."""
        rule_data = {
            "id": "ATR-TEST-002",
            "title": "Test",
            "status": "experimental",
            "description": "desc",
            "author": "test",
            "date": "2026/01/01",
            "severity": "mega-critical",
            "tags": {"category": "prompt-injection"},
            "agent_source": {"type": "llm_io"},
            "detection": {
                "conditions": [
                    {"field": "user_input", "operator": "contains", "value": "test"}
                ],
                "condition": "any",
            },
            "response": {"actions": ["alert"]},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert not result.valid
            sev_errors = [e for e in result.errors if e.field == "severity"]
            assert len(sev_errors) == 1
            assert "mega-critical" in sev_errors[0].message
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_non_string_category(self) -> None:
        """A non-string category should be flagged."""
        rule_data = {
            "id": "ATR-TEST-003",
            "title": "Test",
            "status": "experimental",
            "description": "desc",
            "author": "test",
            "date": "2026/01/01",
            "severity": "high",
            "tags": {"category": 12345},
            "agent_source": {"type": "llm_io"},
            "detection": {
                "conditions": [
                    {"field": "user_input", "operator": "regex", "value": "test"}
                ],
                "condition": "any",
            },
            "response": {"actions": ["alert"]},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert not result.valid
            cat_errors = [e for e in result.errors if e.field == "tags.category"]
            assert len(cat_errors) == 1
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_invalid_source_type(self) -> None:
        """An invalid agent_source.type should be flagged."""
        rule_data = {
            "id": "ATR-TEST-004",
            "title": "Test",
            "status": "experimental",
            "description": "desc",
            "author": "test",
            "date": "2026/01/01",
            "severity": "medium",
            "tags": {"category": "prompt-injection"},
            "agent_source": {"type": "invalid_source"},
            "detection": {
                "conditions": [
                    {"field": "user_input", "operator": "contains", "value": "test"}
                ],
                "condition": "any",
            },
            "response": {"actions": ["alert"]},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert not result.valid
            src_errors = [e for e in result.errors if e.field == "agent_source.type"]
            assert len(src_errors) == 1
            assert "invalid_source" in src_errors[0].message
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_invalid_operator(self) -> None:
        """An invalid operator in a condition should be flagged."""
        rule_data = {
            "id": "ATR-TEST-005",
            "title": "Test",
            "status": "experimental",
            "description": "desc",
            "author": "test",
            "date": "2026/01/01",
            "severity": "low",
            "tags": {"category": "prompt-injection"},
            "agent_source": {"type": "llm_io"},
            "detection": {
                "conditions": [
                    {"field": "user_input", "operator": "fuzzy_match", "value": "test"}
                ],
                "condition": "any",
            },
            "response": {"actions": ["alert"]},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert not result.valid
            op_errors = [e for e in result.errors if "operator" in e.field]
            assert len(op_errors) == 1
            assert "fuzzy_match" in op_errors[0].message
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_empty_conditions(self) -> None:
        """Empty conditions list should be flagged."""
        rule_data = {
            "id": "ATR-TEST-006",
            "title": "Test",
            "status": "experimental",
            "description": "desc",
            "author": "test",
            "date": "2026/01/01",
            "severity": "medium",
            "tags": {"category": "prompt-injection"},
            "agent_source": {"type": "llm_io"},
            "detection": {
                "conditions": [],
                "condition": "any",
            },
            "response": {"actions": ["alert"]},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert not result.valid
            cond_errors = [e for e in result.errors if "conditions" in e.field]
            assert len(cond_errors) >= 1
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_valid_rule_passes(self) -> None:
        """A well-formed rule should produce zero errors."""
        rule_data = {
            "id": "ATR-TEST-OK",
            "title": "Valid Test Rule",
            "status": "experimental",
            "description": "A valid test rule.",
            "author": "tester",
            "date": "2026/01/01",
            "severity": "medium",
            "tags": {"category": "prompt-injection", "confidence": "high"},
            "agent_source": {"type": "llm_io", "framework": ["any"]},
            "detection": {
                "conditions": [
                    {
                        "field": "user_input",
                        "operator": "regex",
                        "value": "(?i)test pattern",
                        "description": "Test",
                    }
                ],
                "condition": "any",
            },
            "response": {"actions": ["alert"]},
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(rule_data, f)
            tmp_path = Path(f.name)

        try:
            result = validate_file(tmp_path)
            assert result.valid, f"Expected valid but got errors: {result.errors}"
        finally:
            tmp_path.unlink(missing_ok=True)
