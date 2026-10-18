"""Importer for trans-prompt-injection-detector -- https://github.com/Sirius1906/trans-prompt-injection-detector

`prompt_injection_detector.py` is NEVER imported or executed: the DETECTION_RULES literal, the
preprocessing tables and the upstream unit tests are read with Python's `ast` module.

Upstream scoring (kept): every detection group (a dict with name / category / weight / patterns) adds
its weight ONCE per text no matter how many of its patterns match; total >= threshold(3) is an
attack. In the unified model every group becomes ONE business rule whose condition is
`any(pattern ...)`, which has exactly that "same group is counted once" semantics.

Groups written for the translation scenario are marked scope=translation_only with
context_requires={"task": "translation"}: they must not block ordinary text, and without that
context a hit is reported as `needs_context` instead of an alert.
"""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from apg_rules.util import read_text, sha256_text

from .base import ExtractResult, SourceImporter, SrcPattern, SrcRule, SrcTest, UnifiedHint

DETECTOR_FILE = "prompt_injection_detector.py"
# Hash of stable_ast_dump(preprocess_text) (= ast.dump() of Python 3.13+) the `trans_v1` normalisation profile was written against.
EXPECTED_PREPROCESS_AST_SHA256 = "06b425621ca2d381a940ab49e6011646917f74f95562ba091f0644ca62a968bd"

# group category -> (unified category, scope, confidence, note)
GROUP_POLICY: Dict[str, Tuple[str, str, float, str]] = {
    "ignore_translation":   ("instruction_override", "translation_only", 0.80, "asks to ignore the translation task"),
    "force_output":         ("instruction_hijacking", "translation_only", 0.65, "forces a fixed output; generic wording, FP-prone outside translation"),
    "prompt_leak":          ("system_prompt_extraction", "general", 0.38, "asks for hidden/system instructions; patterns such as 'system prompt' also appear in benign security text, so a lone hit stays below the review threshold"),
    "roleplay_bypass":      ("jailbreak", "general", 0.38, "role-play to leave the translation task; 'act as a' is weak on its own, so a lone hit stays below the review threshold"),
    "fake_guidance":        ("role_spoofing", "translation_only", 0.70, "fake translator/editor notes"),
    "soft_boundary":        ("instruction_hijacking", "translation_only", 0.50, "soft, polite steering away from the task"),
    "cn_direct_injection":  ("instruction_override", "translation_only", 0.75, "Chinese direct instruction to stop translating / output directly"),
    "cn_codeswitch_bypass": ("instruction_override", "translation_only", 0.75, "Chinese-English code-switched bypass"),
    "cn_mixed_roleplay":    ("jailbreak", "general", 0.38, "Chinese-English mixed role-play; legitimate role-play is common, a lone hit stays below the review threshold"),
    "cn_fake_guidance":     ("role_spoofing", "translation_only", 0.65, "Chinese fake translation guidance"),
    "cn_soft_guidance":     ("instruction_hijacking", "translation_only", 0.45, "Chinese soft steering"),
}
WEIGHT_BY_GROUP_WEIGHT = {3: 0.75, 2: 0.50, 1: 0.25}


def _load_tree(root: Path):
    path = root / DETECTOR_FILE
    text = read_text(path)
    return ast.parse(text, filename=DETECTOR_FILE), text


def _find_assign(tree: ast.Module, name: str) -> Optional[ast.Assign]:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node
    return None


def extract_groups(tree: ast.Module) -> List[Dict[str, Any]]:
    node = _find_assign(tree, "DETECTION_RULES")
    if node is None or not isinstance(node.value, ast.List):
        raise ValueError("DETECTION_RULES list literal not found")
    groups = []
    for idx, elt in enumerate(node.value.elts):
        if not isinstance(elt, ast.Dict):
            raise ValueError(f"DETECTION_RULES[{idx}] is not a dict literal")
        data: Dict[str, Any] = {}
        pat_nodes: List[ast.Constant] = []
        for k, v in zip(elt.keys, elt.values):
            key = ast.literal_eval(k)
            if key == "patterns":
                if not isinstance(v, ast.List):
                    raise ValueError("patterns is not a list literal")
                pat_nodes = list(v.elts)  # type: ignore[assignment]
                data["patterns"] = [ast.literal_eval(p) for p in v.elts]
            else:
                data[key] = ast.literal_eval(v)
        data["_lineno"] = elt.lineno
        data["_pattern_lines"] = [getattr(p, "lineno", None) for p in pat_nodes]
        data["_index"] = idx
        groups.append(data)
    return groups


def stable_ast_dump(node: Any) -> str:
    """ast.dump() as Python 3.13 / 3.14 print it, on EVERY Python version.

    ast.dump() changed in 3.13 (fields that hold their default -- None or an empty list -- are no longer printed), so hashing
    its output made the "upstream changed" check depend on the interpreter that happens to run the import: the same
    upstream file looked changed on Python 3.12 (found on the first Linux run of the unit tests). This renders the tree itself
    and gives the same text on 3.12, 3.13 and 3.14 (tests/python/test_importers.py checks it against ast.dump where that
    has the 3.13+ format)."""
    if isinstance(node, ast.AST):
        parts: List[str] = []
        for name in node._fields:
            if not hasattr(node, name):
                continue
            value = getattr(node, name)
            if (value is None or (isinstance(value, list) and not value)) \
                    and not (name == "value" and isinstance(node, (ast.Constant, ast.MatchSingleton))):
                continue
            parts.append(f"{name}={stable_ast_dump(value)}")
        return f"{type(node).__name__}({', '.join(parts)})"
    if isinstance(node, list):
        return "[" + ", ".join(stable_ast_dump(x) for x in node) + "]"
    return repr(node)


def extract_preprocess(tree: ast.Module) -> Dict[str, Any]:
    """Tables and statement facts of preprocess_text, extracted without running it."""
    homog = _find_assign(tree, "_HOMOGLYPH_MAP")
    zw = _find_assign(tree, "_ZERO_WIDTH_CHARS")
    if homog is None or zw is None:
        raise ValueError("preprocessing tables not found")
    call = homog.value
    if not (isinstance(call, ast.Call) and call.args):
        raise ValueError("_HOMOGLYPH_MAP is not a str.maketrans({...}) call")
    homoglyphs = ast.literal_eval(call.args[0])
    zero_width = sorted(ast.literal_eval(zw.value))
    func = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "preprocess_text"), None)
    if func is None:
        raise ValueError("preprocess_text not found")
    replaces: List[Tuple[str, str]] = []
    for node in ast.walk(func):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "replace"
                and len(node.args) == 2 and all(isinstance(a, ast.Constant) and isinstance(a.value, str)
                                                for a in node.args)):
            replaces.append((node.args[0].value, node.args[1].value))
    ast_sha = hashlib.sha256(stable_ast_dump(func).encode("utf-8")).hexdigest()
    return {"homoglyphs": homoglyphs, "zero_width": zero_width, "replaces": replaces, "ast_sha256": ast_sha}


class TransReference:
    """Faithful re-implementation of the upstream algorithm (Python `re`) -- the differential oracle."""

    def __init__(self, groups: List[Dict[str, Any]], prep: Dict[str, Any]):
        self.groups = groups
        self.prep = prep
        self.table = {ord(k): v for k, v in prep["homoglyphs"].items()}
        self.zero_width = set(prep["zero_width"])
        # single-character -> single-character replacements are the effective punctuation map;
        # two of the upstream lines are corrupted (curly quotes became ASCII quotes) and are no-ops.
        self.replaces = [(a, b) for a, b in prep["replaces"] if len(a) <= 1 and a not in ("\n", "\t", "\r", " ", "")]
        self.compiled = [[re.compile(p) for p in g["patterns"]] for g in groups]

    def preprocess(self, text: str) -> str:
        text = text.strip()
        text = "".join(ch for ch in text if ch not in self.zero_width)
        text = text.translate(self.table)
        text = text.replace("\n", " ").replace("\t", " ").replace("\r", " ")
        while "  " in text:
            text = text.replace("  ", " ")
        text = "".join(ch for ch in text if ord(ch) >= 32)
        for a, b in self.replaces:
            text = text.replace(a, b)
        return text.lower().strip()

    def detect(self, raw_text: str, threshold: int = 3, preprocess: bool = True) -> Dict[str, Any]:
        text = self.preprocess(raw_text) if preprocess else raw_text
        low = text.lower()
        score = 0
        hit_groups: List[str] = []
        for g, rxs in zip(self.groups, self.compiled):
            if any(rx.search(low) for rx in rxs):
                score += int(g["weight"])
                hit_groups.append(g["category"])
        if score == 0:
            level, attack = "low", False
        elif score < threshold:
            level, attack = "low", False
        elif score < threshold + 2:
            level, attack = "medium", True
        else:
            level, attack = "high", True
        return {"score": score, "groups": hit_groups, "is_attack": attack, "risk_level": level}


def _collect_upstream_tests(root: Path) -> List[Dict[str, Any]]:
    """(text, expect_attack) pairs from tests/test_detection.py and tests/test_cn_detection.py."""
    out: List[Dict[str, Any]] = []
    for rel in ("tests/test_detection.py", "tests/test_cn_detection.py"):
        p = root / rel
        if not p.is_file():
            continue
        tree = ast.parse(read_text(p), filename=rel)
        for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)]:
            for fn in [n for n in cls.body if isinstance(n, ast.FunctionDef)]:
                vars_: Dict[str, str] = {}
                for stmt in fn.body:
                    if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                        tgt = stmt.targets[0].id
                        val = stmt.value
                        if isinstance(val, ast.Constant) and isinstance(val.value, str):
                            vars_[tgt] = val.value
                        elif (isinstance(val, ast.Call) and isinstance(val.func, ast.Name)
                              and val.func.id == "detect_injection" and val.args):
                            a0 = val.args[0]
                            text = None
                            if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                                text = a0.value
                            elif isinstance(a0, ast.Name) and a0.id in vars_:
                                text = vars_[a0.id]
                            if text is not None:
                                out.append({"text": text, "var": tgt, "func": f"{cls.name}.{fn.name}", "file": rel,
                                            "expect": None, "line": stmt.lineno})
                    elif isinstance(stmt, ast.Assert) and out:
                        t = stmt.test
                        neg = False
                        if isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not):
                            neg, t = True, t.operand
                        if (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                                and t.value.id == out[-1]["var"] and isinstance(t.slice, ast.Constant)
                                and t.slice.value == "is_attack" and out[-1]["func"] == f"{cls.name}.{fn.name}"):
                            out[-1]["expect"] = not neg
    return [t for t in out if t["expect"] is not None]


class TransImporter(SourceImporter):
    source_id = "trans_pid"
    importer_id = "trans_pid"
    version = "2"          # 2: lower confidence of the three `general` groups (lone weak hits must not reach `review`)

    def extract(self, root: Path, lock_entry: Dict[str, Any], log: Callable[[str], None]) -> ExtractResult:
        tree, text = _load_tree(root)
        groups = extract_groups(tree)
        prep = extract_preprocess(tree)
        blob = {f["path"]: f["git_blob"] for f in lock_entry.get("files", [])}.get(DETECTOR_FILE, "")
        warnings: List[str] = []
        if EXPECTED_PREPROCESS_AST_SHA256 and prep["ast_sha256"] != EXPECTED_PREPROCESS_AST_SHA256:
            warnings.append("preprocess_text changed upstream (AST hash differs): review the trans_v1 normalisation "
                            "profile in engine/core/normalize.cpp before trusting translation rules")
        oracle = TransReference(groups, prep)
        upstream_tests = _collect_upstream_tests(root)
        tests_by_group: Dict[str, List[SrcTest]] = {g["category"]: [] for g in groups}
        for t in upstream_tests:
            res = oracle.detect(t["text"])
            if t["expect"]:
                if not res["is_attack"]:
                    warnings.append(f"upstream test {t['func']} expects an attack but the reference oracle disagrees")
                for gk in res["groups"]:
                    tests_by_group[gk].append(SrcTest("positive", t["text"], True,
                                                      f"{t['file']}::{t['func']} (legacy score {res['score']})",
                                                      "user_input", f"{t['file']}:{t['line']}"))
        # The upstream repository ships a labelled dataset (800 normal + 200 injection samples). It is used
        # (a) as the source of per-group positive / negative test samples and (b) as the differential corpus.
        ds_path = root / "translation_pia_dataset_shuffled.jsonl"
        if ds_path.is_file():
            import json as _json
            pos_n: Dict[str, int] = {}
            neg_n: Dict[str, int] = {}
            for line in read_text(ds_path).splitlines():
                if not line.strip():
                    continue
                rec = _json.loads(line)
                res = oracle.detect(rec["text"])
                if rec.get("label") == "injection":
                    for gk in res["groups"]:
                        if pos_n.get(gk, 0) < 4:
                            pos_n[gk] = pos_n.get(gk, 0) + 1
                            tests_by_group[gk].append(SrcTest(
                                "positive", rec["text"], True,
                                f"dataset id={rec['id']} attack_type={rec.get('attack_type')}", "user_input",
                                f"translation_pia_dataset_shuffled.jsonl:{rec['id']}"))
                elif rec.get("label") == "normal":
                    for g in groups:
                        gk = g["category"]
                        if gk not in res["groups"] and neg_n.get(gk, 0) < 3:
                            neg_n[gk] = neg_n.get(gk, 0) + 1
                            tests_by_group[gk].append(SrcTest(
                                "negative", rec["text"], False, f"dataset id={rec['id']} (normal sample)",
                                "user_input", f"translation_pia_dataset_shuffled.jsonl:{rec['id']}"))
        rules: List[SrcRule] = []
        for g in groups:
            cat = g["category"]
            if cat not in GROUP_POLICY:
                warnings.append(f"unknown trans detector group {cat!r}: imported as general prompt_injection")
            ucat, scope, conf, note = GROUP_POLICY.get(cat, ("prompt_injection", "general", 0.5, "unreviewed group"))
            weight = WEIGHT_BY_GROUP_WEIGHT.get(int(g["weight"]), 0.25)
            patterns = []
            for i, rx in enumerate(g["patterns"]):
                line = g["_pattern_lines"][i] if i < len(g["_pattern_lines"]) else None
                patterns.append(SrcPattern(
                    ordinal=i, key=f"p{i + 1}", regex=rx, flags="", dialect="py", field_name="content",
                    description=f"{g['name']} #{i + 1}", locator=f"DETECTION_RULES[{g['_index']}].patterns[{i}]",
                    line_no=line, force_flags="i"))
            unified = UnifiedHint(
                name=g["name"], category=ucat, severity="high" if weight >= 0.75 else "medium" if weight >= 0.5 else "low",
                weight=weight, confidence=conf, default_action="alert" if conf >= 0.5 else "review",
                scope=scope, context_requires={"task": "translation"} if scope == "translation_only" else None,
                score_group=f"trans_pid:{cat}", description=note, tags=["trans-pid", f"trans-group:{cat}"],
                norm_profile="trans_v1", category_reason="curated group policy")
            raw = {"name": g["name"], "category": cat, "weight": g["weight"], "patterns": list(g["patterns"]),
                   "preprocess_ast_sha256": prep["ast_sha256"],
                   "scoring": "group weight is added once per text; total >= 3 is an attack (legacy)"}
            rules.append(SrcRule(
                source_key=cat, name=g["name"], source_path=DETECTOR_FILE, raw=raw, combinator="any",
                patterns=patterns, tests=tests_by_group.get(cat, []), decision="included",
                decision_reason="generic" if scope == "general" else
                "translation-specific group: scope=translation_only (context_requires task=translation)",
                unified=unified, group_key=cat, locator=f"DETECTION_RULES[{g['_index']}] line {g['_lineno']}",
                upstream_status="", upstream_severity=str(g["weight"]), file_blob_sha=blob,
                cond_tree={"op": "any", "args": [{"op": "leaf", "id": p.key} for p in patterns]}))
        stats = {"groups": len(groups), "patterns": sum(len(g["patterns"]) for g in groups),
                 "upstream_tests": len(upstream_tests), "preprocess_ast_sha256": prep["ast_sha256"],
                 "inert_replace_calls": sum(1 for a, _ in prep["replaces"] if len(a) > 1)}
        return ExtractResult(rules=rules, warnings=warnings, stats=stats)
