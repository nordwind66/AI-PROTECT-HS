#!/usr/bin/env python3
"""A PYTHON STAND-IN for the `ai-prompt-guard` command line tool -- used ONLY to test tests/e2e/run_e2e.py itself.

It implements the same command line contract (compile / verify / info / scan / scan-batch), the same
manifest layout and the same response shape as the C++ tool, on top of the Python reference engine.  It exists
because the C++ tool could not be built in the development session: the end-to-end harness (argument handling,
schema validation of the outputs, differential comparison, tamper checks, release flow) is exercised against this
stand-in so that it does not hide bugs of its own on the Linux test machine.

It proves NOTHING about the C++ engine: when the harness runs against this tool the "backend" it reports is
"pcre2_fallback" and the engine behind it is Python's `re`.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from apg_rules import jsonschema_lite as js  # noqa: E402
from apg_rules.refengine import RefEngine  # noqa: E402

ENGINE_VERSION = "1.0.0"
ABI_VERSION = 1 << 16
OS_NAME = "windows" if platform.system().lower().startswith("win") else "linux"
ARCH_NAME = "x86_64"
_ENGINE = Path(os.environ.get("APG_ENGINE_DIR", str(ROOT.parent / "engine")))
_REQ = _ENGINE / "schemas" / "request.schema.json"
REQUEST_SCHEMA = js.load_schema(_REQ) if _REQ.is_file() else None   # the engine project owns this schema


class Args:
    def __init__(self, argv: List[str]):
        self.v = argv

    def flag(self, name: str) -> bool:
        return name in self.v

    def get(self, name: str, default: str = "") -> str:
        for i, a in enumerate(self.v):
            if a == name and i + 1 < len(self.v):
                return self.v[i + 1]
            if a.startswith(name + "="):
                return a[len(name) + 1:]
        return default

    def has_value(self, name: str) -> bool:
        return any((a == name and i + 1 < len(self.v)) or a.startswith(name + "=") for i, a in enumerate(self.v))

    def get_all(self, name: str) -> List[str]:
        out = []
        for i, a in enumerate(self.v):
            if a == name and i + 1 < len(self.v):
                out.append(self.v[i + 1])
            elif a.startswith(name + "="):
                out.append(a[len(name) + 1:])
        return out


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fail(msg: str, code: int = 1) -> int:
    sys.stderr.write(f"error: {msg}\n")
    return code


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------------------------------------------------
class Loaded:
    def __init__(self, manifest_path: str):
        p = Path(manifest_path)
        if not p.exists():
            raise ValueError(f"APG_ERR_CONFIG: manifest_path '{manifest_path}' does not exist")
        doc = json.loads(p.read_text(encoding="utf-8"))
        if doc.get("kind") == "apg-active-pointer":
            target = p.parent / doc["manifest"]
            if doc.get("manifest_sha256") and sha256(target.read_bytes()) != doc["manifest_sha256"]:
                raise ValueError("APG_ERR_DATABASE: active pointer: manifest sha256 does not match (pointer is stale)")
            p = target
            doc = json.loads(p.read_text(encoding="utf-8"))
        if doc.get("kind") != "apg-manifest":
            raise ValueError("APG_ERR_DATABASE: not an apg-manifest document")
        stripped = {k: v for k, v in doc.items() if k != "build_hash"}
        if sha256(canonical(stripped).encode("utf-8")) != doc.get("build_hash"):
            raise ValueError("APG_ERR_DATABASE: manifest build_hash does not match its content (the manifest was modified)")
        meta = doc["files"]["meta"]
        body = (p.parent / meta["path"]).read_bytes()
        if sha256(body) != meta["sha256"] or sha256(body) != doc["ruleset"]["snapshot_sha256"]:
            raise ValueError("APG_ERR_DATABASE: ruleset metadata file does not match the sha256 recorded in the manifest")
        for d in doc["files"]["databases"]:
            if sha256((p.parent / d["path"]).read_bytes()) != d["sha256"]:
                raise ValueError(f"APG_ERR_DATABASE: database file {d['path']} does not match its sha256 in the manifest")
        if doc["target"]["os"] != OS_NAME or doc["target"]["arch"] != ARCH_NAME:
            raise ValueError("APG_ERR_PLATFORM: rule set was compiled for another platform")
        self.path = str(p)
        self.manifest = doc
        self.snapshot = json.loads(body)
        self.engine = RefEngine(self.snapshot)
        self.rule_by_id = {r["id"]: r for r in self.snapshot["rules"]}
        self.read_fields = {lf["field"] for r in self.snapshot["rules"] for lf in r["leaves"]}

    def info(self) -> Dict[str, Any]:
        m = self.manifest
        return {
            "schema_version": 1, "engine_version": ENGINE_VERSION, "abi_version": ABI_VERSION, "norm_tables_version": 1,
            "ruleset": {"version": m["ruleset"]["version"], "content_digest": m["ruleset"]["content_digest"],
                        "snapshot_sha256": m["ruleset"]["snapshot_sha256"], "rules": m["ruleset"]["rule_count"],
                        "patterns": m["ruleset"]["pattern_count"], "patterns_native": m["patterns"]["native"],
                        "patterns_prefilter": m["patterns"]["prefilter"], "patterns_failed": m["patterns"]["failed"],
                        "failed_pattern_ids": m["patterns"]["failed_ids"], "manifest_path": self.path,
                        "built_at": m["built_at"], "loaded_at": now()},
            "backend": {"name": m["target"]["backend"], "hyperscan_version": m["target"]["hyperscan_version"],
                        "pcre2_version": m["target"]["pcre2_version"], "cpu_target": m["target"]["cpu_target"],
                        "os": m["target"]["os"], "arch": m["target"]["arch"]},
            "policy": {"allow_block": False, "on_error": "review", "on_verify_error": "review"},
            "limits": {"max_text_bytes": 1048576, "max_request_bytes": 4194304, "max_hits": 50000, "max_fields": 16}}

    def result(self, text: Optional[str], source: str, request_id: Optional[str], fields: Dict[str, str],
               context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        text_bytes = len((text or "").encode("utf-8")) + sum(len(v.encode("utf-8")) for v in fields.values())
        known = {k: v for k, v in fields.items() if k in self.read_fields}
        ignored = [k for k in fields if k not in self.read_fields]
        res = self.engine.scan(text or "", source=source, fields=known or None, context=context)
        mult = self.snapshot["scoring"]["source_multiplier"].get(source, 1.0)
        best: Dict[str, float] = {}
        for m in res["matched_rules"]:
            g = m.get("score_group")
            if g:
                best[g] = max(best.get(g, 0.0), m["risk"])
        matched = []
        for m in sorted(res["matched_rules"], key=lambda x: (-x["risk"], x["rule_id"])):
            rule = self.rule_by_id[m["rule_id"]]
            g = m.get("score_group")
            matched.append({"rule_id": m["rule_id"], "pattern_ids": m["pattern_ids"], "category": m["category"],
                            "severity": m["severity"], "source": source, "confidence": round(rule["confidence"], 4),
                            "weight": round(rule["weight"], 4), "risk": m["risk"],
                            "counted": (not g) or m["risk"] >= best[g]})
        needs = [{"rule_id": n["rule_id"], "category": n["category"], "severity": n["severity"], "reason": n["reason"],
                  "missing": n["missing"], "pattern_ids": n["pattern_ids"]} for n in res["needs_context"]]
        checked = set(self.engine.field_map.get(source, ["content"])) if text else set()
        checked |= set(known)
        return {"schema_version": 1, "request_id": request_id, "status": "ok", "decision": res["decision"],
                "score": res["score"], "risk_level": res["risk_level"], "ruleset_version": res["ruleset_version"],
                "engine_version": ENGINE_VERSION, "backend": self.manifest["target"]["backend"], "matched_rules": matched,
                "needs_context": needs,
                "inputs": {"text_bytes": text_bytes, "fields_checked": sorted(checked), "fields_ignored": ignored,
                           "views_scanned": ["raw"]},
                "warnings": [], "duration_us": 0, "error_code": None}

    def error_result(self, code: str, detail: str, request_id: Optional[str], text_bytes: int) -> Dict[str, Any]:
        return {"schema_version": 1, "request_id": request_id, "status": "error", "decision": "review", "score": 0,
                "risk_level": "none", "ruleset_version": self.manifest["ruleset"]["version"], "engine_version": ENGINE_VERSION,
                "backend": self.manifest["target"]["backend"], "matched_rules": [], "needs_context": [],
                "inputs": {"text_bytes": text_bytes}, "warnings": [detail], "duration_us": 0, "error_code": code}

    def scan_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        errs = js.validate(req, REQUEST_SCHEMA) if REQUEST_SCHEMA else []
        if errs:
            raise ValueError("APG_ERR_INVALID_ARGUMENT: " + errs[0])
        return self.result(req.get("text"), req.get("source", "user_input"), req.get("request_id"),
                           dict(req.get("fields", {})), req.get("context"))


def emit(obj: Any, pretty: bool = True) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2 if pretty else None, separators=None if pretty else (",", ":"))
    sys.stdout.buffer.write((text + "\n").encode("utf-8"))
    sys.stdout.flush()


# ---------------------------------------------------------------------------------------------------------------------
def cmd_compile(a: Args) -> int:
    path = a.get("--snapshot")
    if not path:
        return fail("--snapshot is required")
    try:
        body = Path(path).read_bytes()
    except OSError as exc:
        return fail(f"APG_ERR_CONFIG: cannot read the snapshot: {exc}", 2)
    snap = json.loads(body)
    version = snap["ruleset"]["version"]
    final = Path(a.get("--out", "dist")) / OS_NAME / ARCH_NAME / version
    if final.exists() and not a.flag("--force"):
        return fail(f"APG_ERR_CONFIG: output directory {final} already exists (use --force to replace it)", 2)
    final.mkdir(parents=True, exist_ok=True)
    (final / "ruleset.meta.json").write_bytes(body)
    n_pat = len(snap["patterns"])
    pre = sum(1 for p in snap["patterns"] if p["class"] == "hs_prefilter_pcre2")
    report = {"kind": "apg-build-report", "ruleset_version": version, "total": n_pat, "native": n_pat, "prefilter": 0,
              "failed": 0, "downgraded_to_prefilter": 0,
              "patterns": [{"id": p["id"], "class": "hs_native", "flags": p["flags"], "profile": p["profile"]} for p in snap["patterns"]]}
    (final / "build_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    m = {"kind": "apg-manifest", "manifest_version": 1, "status": "ok",
         "engine": {"engine_version": ENGINE_VERSION, "abi_version": ABI_VERSION, "norm_tables_version": 1},
         "ruleset": {"version": version, "content_digest": snap["ruleset"]["content_digest"], "snapshot_sha256": sha256(body),
                     "rule_count": len(snap["rules"]), "pattern_count": n_pat},
         "target": {"os": OS_NAME, "arch": ARCH_NAME, "backend": "pcre2_fallback", "hyperscan_version": "",
                    "pcre2_version": "python-re (stand-in)", "cpu_target": "generic", "cpu_features": "0x0", "tune": 0,
                    "compiler": "python"},
         "files": {"meta": {"path": "ruleset.meta.json", "sha256": sha256(body), "bytes": len(body)}, "databases": []},
         "patterns": {"total": n_pat, "native": n_pat - 0, "prefilter": 0, "failed": 0, "failed_ids": []},
         "built_at": now()}
    m["patterns"]["native"] = n_pat
    m["build_hash"] = sha256(canonical(m).encode("utf-8"))
    (final / "manifest.json").write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
    sys.stderr.write(f"[compile] stand-in compile of {version}: {n_pat} patterns ({pre} prefilter in the snapshot)\n")
    emit({"manifest": str(final / "manifest.json"), "patterns": n_pat, "native": n_pat, "prefilter": 0,
          "downgraded_to_prefilter": 0, "failed": 0, "status": "ok"})
    return 0


def load(a: Args) -> Loaded:
    m = a.get("--manifest")
    if not m:
        raise ValueError("--manifest is required")
    return Loaded(m)


def cmd_verify_or_info(a: Args, info_only: bool) -> int:
    try:
        ld = load(a)
    except ValueError as exc:
        return fail(str(exc), 2)
    emit(ld.info())
    if not info_only:
        sys.stderr.write("OK: manifest, hashes, platform, Hyperscan/PCRE2 versions and databases verified\n")
    return 0


def read_arg_text(a: Args) -> Optional[bytes]:
    if a.has_value("--text"):
        return a.get("--text").encode("utf-8")
    if a.has_value("--file"):
        return Path(a.get("--file")).read_bytes()
    if a.flag("--stdin"):
        return sys.stdin.buffer.read()
    return None


def cmd_scan(a: Args) -> int:
    try:
        ld = load(a)
    except ValueError as exc:
        return fail(str(exc), 2)
    source = a.get("--source", "user_input")
    context = {}
    for kv in a.get_all("--context"):
        if "=" not in kv:
            return fail(f"--context expects key=value, got '{kv}'")
        k, v = kv.split("=", 1)
        context[k] = v
    request_id = a.get("--request-id") or None
    try:
        if a.has_value("--json-file"):
            result = ld.scan_request(json.loads(Path(a.get("--json-file")).read_text(encoding="utf-8")))
        else:
            raw = read_arg_text(a)
            if raw is None:
                return fail("one of --text, --file, --stdin or --json-file is required")
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                result = ld.error_result("invalid_utf8", f"text is not valid UTF-8 (first bad byte at offset {exc.start})", request_id, len(raw))
            else:
                result = ld.result(text, source, request_id, {}, context or None)
    except ValueError as exc:
        return fail(str(exc), 2)
    emit(result, pretty=a.flag("--pretty"))
    if a.flag("--exit-on-detect"):
        return {"alert": 10, "review": 11, "block": 12}.get(result["decision"], 0)
    return 0


def cmd_scan_batch(a: Args) -> int:
    try:
        ld = load(a)
    except ValueError as exc:
        return fail(str(exc), 2)
    lines = Path(a.get("--requests")).read_bytes().decode("utf-8").splitlines()
    out: List[str] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            res = ld.scan_request(json.loads(line))
        except (ValueError, json.JSONDecodeError) as exc:
            res = {"status": "call_error", "apg_status": "APG_ERR_INVALID_ARGUMENT", "error": str(exc)}
        out.append(json.dumps(res, ensure_ascii=False, separators=(",", ":")))
    text = "\n".join(out) + "\n"
    if a.get("--out"):
        Path(a.get("--out")).write_text(text, encoding="utf-8")
    else:
        sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stderr.write(f"[scan-batch] {len(out)} request(s)\n")
    return 0


def main(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        sys.stdout.write("stand-in for ai-prompt-guard (tests/e2e/fake_cli.py)\n")
        return 0 if argv else 1
    if argv[0] in ("--version", "version"):
        sys.stdout.write(f"ai-prompt-guard {ENGINE_VERSION} abi 1.0 (stand-in)\n")
        return 0
    cmd, a = argv[0], Args(argv[1:])
    table = {"compile": cmd_compile, "verify": lambda x: cmd_verify_or_info(x, False),
             "info": lambda x: cmd_verify_or_info(x, True), "scan": cmd_scan, "scan-batch": cmd_scan_batch}
    if cmd not in table:
        return fail(f"unknown command '{cmd}'")
    return table[cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
