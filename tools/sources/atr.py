"""Importer for Agent Threat Rules (ATR) -- https://github.com/Agent-Threat-Rule/agent-threat-rules

Reads rules/**/*.yaml with the safe YAML-subset loader (nothing is executed), keeps the boolean
structure (`any`, `all`, boolean expressions over aliases) and the per-condition `field`, and applies
the explicit scope policy in atr_policy.py. Regex dialect: ECMAScript (ATR SPEC 6.4); the reference
engine applies the `i` flag to every condition, which is mirrored through `force_flags="i"`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from apg_rules import boolexpr, miniyaml
from apg_rules.util import read_text, sha256_text

from . import atr_policy
from .base import (AGENT_TYPE_TO_SOURCE, ExtractResult, KNOWN_FIELDS, SourceImporter, SrcPattern, SrcRule,
                   SrcTest, UnifiedHint)

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
                "informational": "info", "info": "info"}
WEIGHT_BY_SEVERITY = {"critical": 0.85, "high": 0.70, "medium": 0.50, "low": 0.30, "info": 0.15}
CONF_BY_TAG = {"high": 0.85, "medium": 0.60, "low": 0.40}
CONF_BY_MATURITY = {"stable": 0.80, "test": 0.60, "experimental": 0.50, "draft": 0.30, "deprecated": 0.30}
_OMIT_KEYS = {"compliance", "response", "test_cases", "evasion_tests"}


def _collapse(text: Any, limit: int = 400) -> str:
    s = re.sub(r"\s+", " ", str(text or "")).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _confidence(doc: Dict[str, Any]) -> float:
    c = doc.get("confidence")
    if isinstance(c, (int, float)) and not isinstance(c, bool):
        return min(0.99, max(0.05, float(c) / 100.0))
    tag = ((doc.get("tags") or {}).get("confidence") or "").lower() if isinstance(doc.get("tags"), dict) else ""
    if tag in CONF_BY_TAG:
        return CONF_BY_TAG[tag]
    return CONF_BY_MATURITY.get(str(doc.get("maturity") or doc.get("status") or "").lower(), 0.5)


class AtrImporter(SourceImporter):
    source_id = "atr"
    importer_id = "atr"
    version = "3"          # 2: local pattern-level quality exclusions (atr_policy.PATTERN_EXCLUSIONS)
                           # 3: engine-limit exclusions observed on a real machine (atr_policy.ENGINE_LIMIT_EXCLUSIONS)

    def extract(self, root: Path, lock_entry: Dict[str, Any], log: Callable[[str], None]) -> ExtractResult:
        rules: List[SrcRule] = []
        warnings: List[str] = []
        files = sorted((root / "rules").rglob("*.yaml"))
        stats = {"files": len(files), "malformed": 0}
        self._blobs = {f["path"]: f["git_blob"] for f in lock_entry.get("files", [])}
        for f in files:
            rel = f.relative_to(root).as_posix()
            try:
                text = read_text(f)
                doc, locs, warns = miniyaml.load_full(text)
            except Exception as exc:  # malformed upstream file must not abort the whole import
                stats["malformed"] += 1
                warnings.append(f"{rel}: YAML not parsed: {exc}")
                rules.append(self._malformed(rel, f, str(exc)))
                continue
            for line, msg in warns:
                warnings.append(f"{rel}:{line}: {msg}")
            if not isinstance(doc, dict) or "id" not in doc:
                stats["malformed"] += 1
                warnings.append(f"{rel}: not an ATR rule document")
                rules.append(self._malformed(rel, f, "not an ATR rule document"))
                continue
            try:
                rules.append(self._convert(doc, locs, rel, f.parent.name, self._blobs.get(rel, ""), text))
            except Exception as exc:  # one odd rule must not abort the import; it is recorded as unsupported
                stats["malformed"] += 1
                warnings.append(f"{rel}: could not be converted: {exc}")
                rules.append(self._malformed(rel, f, f"conversion error: {exc}"))
        return ExtractResult(rules=rules, warnings=warnings, stats=stats)

    # ------------------------------------------------------------------------------------------------
    @staticmethod
    def _malformed(rel: str, f: Path, why: str) -> SrcRule:
        key = f.stem.split("-")[0:3]
        sk = "-".join(key) if len(key) == 3 else f.stem
        return SrcRule(source_key=sk, name=f.stem, source_path=rel, raw={"_error": why}, combinator="any",
                       patterns=[], decision="unsupported", decision_reason=f"malformed rule file: {why}",
                       locator="")

    def _convert(self, doc: Dict[str, Any], locs: Dict[tuple, int], rel: str, directory: str,
                 blob: str, text: str) -> SrcRule:
        rid = str(doc["id"])
        tags = doc.get("tags") if isinstance(doc.get("tags"), dict) else {}
        sub = str(tags.get("subcategory") or "")
        title = str(doc.get("title") or rid)
        det = doc.get("detection") if isinstance(doc.get("detection"), dict) else {}
        method = det.get("method")
        raw_conds = det.get("conditions")
        patterns: List[SrcPattern] = []
        alias_of_index: List[str] = []

        if isinstance(raw_conds, dict):
            items = list(raw_conds.items())
        elif isinstance(raw_conds, list):
            items = [(f"c{i + 1}", c) for i, c in enumerate(raw_conds)]
        else:
            items = []
        for ordinal, (alias, cond) in enumerate(items):
            path = ("detection", "conditions", alias if isinstance(raw_conds, dict) else ordinal)
            patterns.append(self._pattern(ordinal, str(alias), cond, locs.get(path)))
            alias_of_index.append(str(alias))

        for p in patterns:
            why = atr_policy.PATTERN_EXCLUSIONS.get((rid, p.locator))
            if why and p.pre_fate is None:
                p.pre_fate, p.pre_reason = "excluded_scope", f"local_quality: {why}"
            why = atr_policy.ENGINE_LIMIT_EXCLUSIONS.get((rid, p.locator))
            if why and p.pre_fate is None:
                p.pre_fate, p.pre_reason = "unsupported", f"engine_limit: {why}"

        fields = sorted({p.field_name for p in patterns if p.field_name})
        decision, reason, forced = atr_policy.decide(rid, directory, sub, title, method, fields)
        if decision != "included":
            for p in patterns:
                if p.pre_fate is None:
                    p.pre_fate = "excluded_scope" if decision == "excluded_scope" else "unsupported"
                    p.pre_reason = reason

        combinator = str(det.get("condition") or "any").strip()
        cond_tree = self._cond_tree(combinator, alias_of_index)

        severity = SEVERITY_MAP.get(str(doc.get("severity") or "").lower(), "medium")
        category, why_cat = atr_policy.categorize(sub, title, directory, forced)
        status_src = str(doc.get("status") or "").lower()
        maturity = str(doc.get("maturity") or "").lower()
        status = "enabled"
        if status_src == "deprecated" or maturity == "deprecated":
            status = "deprecated"
        elif status_src == "draft" or maturity == "draft":
            status = "disabled"
        conf = _confidence(doc)
        refs = doc.get("references") if isinstance(doc.get("references"), dict) else {}
        tag_list = ["atr", f"atr-dir:{directory}"]
        if sub:
            tag_list.append(f"atr-sub:{sub}")
        for ref in (refs.get("owasp_llm") or [])[:3]:
            tag_list.append(f"owasp-llm:{ref}")
        unified = UnifiedHint(
            name=title, category=category, severity=severity, weight=WEIGHT_BY_SEVERITY[severity],
            confidence=round(conf, 2), default_action="alert" if conf >= 0.5 else "review", status=status,
            description=_collapse(doc.get("description")), tags=tag_list, norm_profile="fold_v1",
            category_reason=why_cat)

        tests: List[SrcTest] = []
        tc = doc.get("test_cases") if isinstance(doc.get("test_cases"), dict) else {}
        agent_type = str((doc.get("agent_source") or {}).get("type") or "llm_io") if isinstance(
            doc.get("agent_source"), dict) else "llm_io"
        rule_fields = set(fields)
        for kind, key, hit in (("positive", "true_positives", True), ("negative", "true_negatives", False)):
            for i, t in enumerate(tc.get(key) or []):
                st = self._test(kind, t, hit, f"test_cases.{key}[{i}]", agent_type, rule_fields)
                if st is not None:
                    tests.append(st)
        for i, t in enumerate(doc.get("evasion_tests") or []):
            st = self._test("known_gap", t, False, f"evasion_tests[{i}]", agent_type, rule_fields)
            if st is not None:
                tests.append(st)

        raw = {k: v for k, v in doc.items() if k not in _OMIT_KEYS}
        raw["_omitted_keys"] = sorted(k for k in doc if k in _OMIT_KEYS)
        raw["_file_sha256"] = sha256_text(text)

        return SrcRule(
            source_key=rid, name=title, source_path=rel, raw=raw, combinator=combinator, patterns=patterns,
            tests=tests, decision=decision, decision_reason=reason, unified=unified, group_key=directory,
            locator="rule file", upstream_status=status_src, upstream_severity=str(doc.get("severity") or ""),
            upstream_maturity=maturity, upstream_confidence=(float(doc["confidence"]) if isinstance(
                doc.get("confidence"), (int, float)) and not isinstance(doc.get("confidence"), bool) else None),
            lang_declared="", file_blob_sha=blob, cond_tree=cond_tree)

    # ------------------------------------------------------------------------------------------------
    # ATR test cases name their input differently: input / user_input / tool_response / content /
    # agent_output, optionally plus tool_name / tool_args / tool_description. This mirrors the
    # reference runner (python/pyatr/test_runner.py _build_event_from_test_case).
    def _test(self, kind: str, t: Any, hit: bool, locator: str, agent_type: str, rule_fields: set) -> Optional[SrcTest]:
        """Mirror of src/testcase-event.ts buildEventFromTestCase (the shared reference harness)."""
        if not isinstance(t, dict):
            return None

        def s(v: Any) -> str:
            return v if isinstance(v, str) else ""

        raw_input = t.get("input", t.get("user_input"))
        tool_name, tool_args, tool_response = s(t.get("tool_name")), s(t.get("tool_args")), s(t.get("tool_response"))
        agent_output, agent_message = s(t.get("agent_output")), s(t.get("agent_message"))
        tool_description, raw_content = s(t.get("tool_description")), s(t.get("content"))
        call = t.get("tool_call")
        if isinstance(call, dict):
            tool_name = tool_name or s(call.get("name"))
            tool_args = tool_args or s(call.get("args"))
        text_in = ""
        if isinstance(raw_input, dict):
            tool_name = tool_name or s(raw_input.get("tool_name"))
            tool_args = tool_args or s(raw_input.get("tool_args"))
            tool_response = tool_response or s(raw_input.get("response")) or s(raw_input.get("tool_response"))
            if tool_args:
                text_in = tool_args
            elif not tool_response:
                import json as _json
                text_in = _json.dumps(raw_input, ensure_ascii=False)
        else:
            text_in = s(raw_input)
        source = AGENT_TYPE_TO_SOURCE.get(agent_type or "llm_io", "user_input")
        if tool_response and source == "tool_output":
            content = tool_response
        else:
            content = text_in or tool_description or raw_content or tool_response or agent_output or agent_message
        fields: Dict[str, str] = {}
        # explicitly named values are always passed as fields (redundant with `content` is harmless)
        if tool_response:
            fields["tool_response"] = tool_response
        if agent_output:
            fields["agent_output"] = agent_output
        if agent_message:
            fields["agent_message"] = agent_message
        if tool_description:
            fields["tool_description"] = tool_description
        if tool_name:
            fields["tool_name"] = tool_name
        if tool_args:
            fields["tool_args"] = tool_args
        elif text_in and "tool_args" in rule_fields:
            fields["tool_args"] = text_in           # the reference harness offers the input string as tool_args
        if not content and not fields:
            return None
        desc = str(t.get("description") or t.get("reason") or t.get("notes") or t.get("bypass_technique") or "")
        return SrcTest(kind, content, hit, desc, source, locator, fields=fields)

    def _pattern(self, ordinal: int, alias: str, cond: Any, line: Optional[int]) -> SrcPattern:
        loc = f"detection.conditions[{ordinal}]"
        if not isinstance(cond, dict):
            return SrcPattern(ordinal, alias, "", locator=loc, line_no=line, pre_fate="unsupported",
                              pre_reason="condition is not a mapping")
        desc = str(cond.get("description") or "")
        if "metric" in cond and "field" not in cond:
            return SrcPattern(ordinal, alias, "", field_name=str(cond.get("metric")), operator=str(cond.get("operator")),
                              description=desc, locator=loc, line_no=line, pre_fate="excluded_scope",
                              pre_reason="behavioural metric condition (needs runtime counters, not text)")
        field_name = str(cond.get("field") or "content")
        operator = str(cond.get("operator") or "regex")
        value = cond.get("value")
        base = dict(ordinal=ordinal, key=alias, field_name=field_name, operator=operator, description=desc,
                    locator=loc, line_no=line, dialect="es", force_flags="i")
        if field_name not in KNOWN_FIELDS:
            return SrcPattern(regex=str(value) if isinstance(value, str) else "", pre_fate="excluded_scope",
                              pre_reason=f"field '{field_name}' is not available to a text scanner", **base)
        if not isinstance(value, str):
            return SrcPattern(regex="", pre_fate="unsupported",
                              pre_reason=f"operator {operator} with non-string value", **base)
        if operator == "regex":
            return SrcPattern(regex=value, **base)
        literal = re.sub(r"([\\^$.|?*+()\[\]{}])", r"\\\1", value)
        if operator == "contains":                    # case-sensitive substring (SPEC 6.3)
            return SrcPattern(regex=literal, **dict(base, force_flags=""))
        if operator == "equals":                      # exact equality of the whole field
            return SrcPattern(regex="^" + literal + "$", **dict(base, force_flags=""))
        return SrcPattern(regex=value, pre_fate="unsupported",
                          pre_reason=f"operator '{operator}' cannot be evaluated by a regex engine", **base)

    @staticmethod
    def _cond_tree(combinator: str, aliases: List[str]) -> Dict[str, Any]:
        low = combinator.lower()
        leaves = [{"op": "leaf", "id": a} for a in aliases]
        if low in ("any", "or"):
            return {"op": "any", "args": leaves}
        if low in ("all", "and"):
            return {"op": "all", "args": leaves}
        node = boolexpr.parse_expr(combinator)
        unknown = [a for a in boolexpr.aliases_of(node) if a not in aliases]
        if unknown:
            # numeric references like "1 and 2" address conditions by 1-based position
            mapping = {str(i + 1): a for i, a in enumerate(aliases)}
            if all(u in mapping for u in unknown):
                return boolexpr.to_ast(node, lambda a: {"op": "leaf", "id": mapping.get(a, a)})
            raise boolexpr.BoolExprError(f"condition references unknown alias(es) {unknown}")
        return boolexpr.to_ast(node, lambda a: {"op": "leaf", "id": a})
