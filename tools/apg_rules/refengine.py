"""Python REFERENCE engine operating on a published snapshot document.

It implements, in plain Python and with Python's `re`, the same detection semantics as the C++ engine:
normalisation profiles -> pattern hits per field -> three-valued rule conditions -> context gating ->
risk scoring -> decision. It exists to

  * test the published snapshot end-to-end on the build machine (no Hyperscan required),
  * generate the expected results (tests/corpus/*.expected.jsonl) the C++ engine is compared with
    on the Linux / Windows test machines (differential testing),
  * measure false-positive / detection numbers of the RULES before the native engine is available.

It is NOT shipped and NOT a performance reference; `re` is not Hyperscan and ASCII-mode `re` is only an
approximation of Hyperscan/PCRE2 for exotic constructs.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from . import normalize_ref as nr
from . import regexkit as rk

TRI = Optional[bool]


@lru_cache(maxsize=None)
def _compile(regex: str, flags: str):
    f = re.ASCII
    if "i" in flags:
        f |= re.IGNORECASE
    if "s" in flags:
        f |= re.DOTALL
    if "m" in flags:
        f |= re.MULTILINE
    try:
        return re.compile(rk.to_python_re(regex), f)
    except re.error:
        return None


class RefEngine:
    def __init__(self, snapshot: Any):
        self.doc = json.loads(snapshot) if isinstance(snapshot, (bytes, str)) else snapshot
        self.patterns = {p["id"]: p for p in self.doc["patterns"]}
        self.rules = self.doc["rules"]
        self.profiles = self.doc["normalizer"]["profiles"]
        self.field_map = self.doc["field_map"]
        self.scoring = self.doc["scoring"]
        self.version = self.doc["ruleset"]["version"]
        self.uncompilable = [pid for pid, p in self.patterns.items() if _compile(p["regex"], p["flags"]) is None]

    # ---- pattern hits -------------------------------------------------------------------------
    def _views(self, profile: str, text: str, cache: Dict) -> List[str]:
        key = (profile, text)
        if key not in cache:
            out: List[str] = []
            for v in self.profiles[profile]["views"]:
                s = nr.PROFILE_FUNCS[v](text)[0]
                if s not in out:
                    out.append(s)
            cache[key] = out
        return cache[key]

    def _hit(self, pid: int, text: str, cache: Dict) -> bool:
        key = ("hit", pid, text)
        if key in cache:
            return cache[key]
        p = self.patterns[pid]
        rx = _compile(p["regex"], p["flags"])
        res = False
        if rx is not None:
            res = any(rx.search(v) for v in self._views(p["profile"], text, cache))
        cache[key] = res
        return res

    # ---- condition logic ----------------------------------------------------------------------
    @staticmethod
    def _tri(node: Dict[str, Any], leaf) -> TRI:
        op = node["op"]
        if op == "leaf":
            return leaf(node["id"])
        vals = [RefEngine._tri(a, leaf) for a in node["args"]]
        if op == "any":
            if any(v is True for v in vals):
                return True
            return False if all(v is False for v in vals) else None
        if op == "all":
            if any(v is False for v in vals):
                return False
            return True if all(v is True for v in vals) else None
        if op == "not":
            return None if vals[0] is None else (not vals[0])
        raise ValueError(op)

    # ---- the scan -----------------------------------------------------------------------------
    def scan(self, text: str, source: str = "user_input", fields: Optional[Dict[str, str]] = None,
             context: Optional[Dict[str, Any]] = None, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        policy = policy or {}
        thresholds = dict(self.scoring["thresholds"])
        thresholds.update(policy.get("thresholds", {}))
        available: Dict[str, str] = {}
        if not (fields and text == ""):
            available = {f: text for f in self.field_map.get(source, ["content"])}
        if fields:
            available.update(fields)
        context = context or {}
        cache: Dict = {}
        mult = self.scoring["source_multiplier"].get(source, 1.0)
        matched: List[Dict[str, Any]] = []
        needs: List[Dict[str, Any]] = []
        for r in self.rules:
            leaves = {lf["id"]: lf for lf in r["leaves"]}
            hits: Dict[str, bool] = {}
            missing_fields: List[str] = []

            def leaf_val(lid: str) -> TRI:
                lf = leaves[lid]
                t = available.get(lf["field"])
                if t is None:
                    if lf["field"] not in missing_fields:
                        missing_fields.append(lf["field"])
                    return None
                v = self._hit(lf["pattern_id"], t, cache)
                hits[lid] = v
                return v

            truth = self._tri(r["condition"], leaf_val)
            req = r.get("context_requires")
            ctx_state = "ok"
            if req:
                for k, v in req.items():
                    if k not in context:
                        ctx_state = "missing"
                    elif context[k] != v:
                        ctx_state = "mismatch"
                        break
            if ctx_state == "mismatch":
                continue
            evidence = [lf["pattern_id"] for lid, lf in leaves.items() if hits.get(lid)]
            risk = min(1.0, max(0.0, r["weight"] * r["confidence"] * mult))
            base = {"rule_id": r["id"], "category": r["category"], "severity": r["severity"],
                    "confidence": r["confidence"], "pattern_ids": sorted(set(evidence)), "risk": round(risk, 6),
                    "score_group": r.get("score_group")}
            if truth is True and ctx_state == "ok":
                matched.append(base)
            elif truth is True and ctx_state == "missing":
                needs.append(dict(base, reason="context_missing", missing=sorted(req.keys() - context.keys())))
            elif truth is None and evidence:
                needs.append(dict(base, reason="field_missing", missing=sorted(missing_fields)))
        score = self._combine(matched)
        potential = self._combine(matched + needs)
        decision = "allow"
        if score >= thresholds["alert"]:
            decision = "alert"
            if policy.get("allow_block") and score >= thresholds["block"]:
                decision = "block"
        elif score >= thresholds["review"] or (needs and potential >= policy.get(
                "needs_context_review_at", self.scoring["needs_context_review_at"])):
            decision = "review"
        level = "none"
        if matched:
            level = "info"
            for name, lo in self.scoring["risk_levels"]:
                if score >= lo:
                    level = name
                    break
        return {"status": "ok", "decision": decision, "score": round(score, 6), "risk_level": level,
                "potential_score": round(potential, 6), "ruleset_version": self.version,
                "matched_rules": matched, "needs_context": needs}

    @staticmethod
    def _combine(items: List[Dict[str, Any]]) -> float:
        best: Dict[Any, float] = {}
        for i, it in enumerate(items):
            key = it["score_group"] if it.get("score_group") else ("rule", i)
            best[key] = max(best.get(key, 0.0), it["risk"])
        prod = 1.0
        for v in best.values():
            prod *= (1.0 - v)
        return 1.0 - prod
