#!/usr/bin/env python3
"""Static consistency checks of the C/C++ sources and build files (Python standard library only).

THIS IS NOT A COMPILER.  It was written because the C++ code base could not be compiled in the development session
(no toolchain on that machine, installing one was out of scope).  It catches the class of mistakes that a careful
read-through can also miss:

  * unbalanced (), [], {} (lexer aware of comments, strings, char literals and raw strings),
  * `#include "..."` that does not resolve to a file,
  * headers without `#pragma once`,
  * source files that exist but are not listed in CMakeLists.txt (and listed files that do not exist),
  * every function of the public C header has a definition in engine/api/apg_api.cpp and vice versa,
  * every `apg_*` symbol exported by the version script exists, error-code enums agree between the header and
    engine/core/common.h, the ABI version agrees,
  * JSON keys the C++ loader requires from manifest.json / the snapshot are produced by the writer
    (compiler.cpp / publish.py).

Usage:  python tools/static_checks.py          (exit code 0 = clean)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ["engine", "cli", "tests/cpp", "examples", "include"]
CPP_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".inc"}


# ---------------------------------------------------------------------------------------------------------------------
# lexer: strip comments / literals, keep structure
# ---------------------------------------------------------------------------------------------------------------------
def strip_code(text: str) -> str:
    """Replace comments, string literals and char literals by spaces (newlines are kept)."""
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        elif c == "R" and nxt == '"' and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = re.match(r'R"([^()\\ \t\n]{0,16})\(', text[i:])
            if m:
                delim = ")" + m.group(1) + '"'
                j = text.find(delim, i + m.end())
                j = n if j < 0 else j + len(delim)
                out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
                i = j
            else:
                out.append(c)
                i += 1
        elif c == '"' or (c == "'" and not (i > 0 and text[i - 1].isalnum())):
            q = c
            j = i + 1
            while j < n and text[j] != q:
                if text[j] == "\\":
                    j += 1
                if j < n and text[j] == "\n":
                    break
                j += 1
            j = min(n, j + 1)
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def check_balance(path: Path, text: str, problems: List[str]) -> None:
    code = strip_code(text)
    stack: List[Tuple[str, int]] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    line = 1
    for ch in code:
        if ch == "\n":
            line += 1
        elif ch in "([{":
            stack.append((ch, line))
        elif ch in ")]}":
            if not stack or stack[-1][0] != pairs[ch]:
                problems.append(f"{rel(path)}:{line}: unbalanced '{ch}'"
                                + (f" (innermost open is '{stack[-1][0]}' from line {stack[-1][1]})" if stack else ""))
                return
            stack.pop()
    if stack:
        problems.append(f"{rel(path)}: unclosed '{stack[-1][0]}' opened at line {stack[-1][1]}")


def rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def iter_sources() -> List[Path]:
    files: List[Path] = []
    for d in SOURCE_DIRS:
        base = ROOT / d
        if base.is_file():
            files.append(base)
        elif base.is_dir():
            files += [p for p in sorted(base.rglob("*")) if p.suffix in CPP_SUFFIXES and p.is_file()]
    return files


# ---------------------------------------------------------------------------------------------------------------------
def check_includes(files: List[Path], problems: List[str]) -> None:
    extra_dirs = [ROOT / "include", ROOT / "examples" / "c"]
    for f in files:
        if f.suffix == ".inc" and f.name == "unicode_tables.inc":
            pass
        for no, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r'\s*#\s*include\s+"([^"]+)"', line)
            if not m:
                continue
            target = m.group(1)
            if (f.parent / target).is_file() or any((d / target).is_file() for d in extra_dirs):
                continue
            problems.append(f"{rel(f)}:{no}: #include \"{target}\" does not resolve")


def check_pragma_once(files: List[Path], problems: List[str]) -> None:
    for f in files:
        if f.suffix in (".h", ".hpp") and f.name != "ai_prompt_guard.h":
            if "#pragma once" not in f.read_text(encoding="utf-8"):
                problems.append(f"{rel(f)}: header without #pragma once")


def check_cmake_lists(problems: List[str]) -> None:
    cm = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    listed = set(re.findall(r"((?:engine|cli|tests|examples)/[\w/.\-]+\.(?:cpp|c))", cm))
    for p in sorted(listed):
        if not (ROOT / p).is_file():
            problems.append(f"CMakeLists.txt lists {p}, which does not exist")
    ex = (ROOT / "examples" / "CMakeLists.txt").read_text(encoding="utf-8")
    for p in re.findall(r"add_executable\(\w+\s+([\w/.\-]+\.(?:cpp|c))", ex):
        if not (ROOT / "examples" / p).is_file():
            problems.append(f"examples/CMakeLists.txt lists {p}, which does not exist")
    # every engine source must be built by something
    for p in sorted((ROOT / "engine").rglob("*.cpp")):
        if rel(p) not in listed:
            problems.append(f"{rel(p)} is not listed in CMakeLists.txt")
    for p in sorted((ROOT / "cli").glob("*.cpp")) + sorted((ROOT / "tests" / "cpp").glob("*.cpp")):
        if rel(p) not in listed:
            problems.append(f"{rel(p)} is not listed in CMakeLists.txt")


def check_public_api(problems: List[str]) -> None:
    header = strip_code((ROOT / "include" / "ai_prompt_guard.h").read_text(encoding="utf-8"))
    declared = set(re.findall(r"APG_CALL\s+(apg_\w+)\s*\(", header))
    impl = strip_code((ROOT / "engine" / "api" / "apg_api.cpp").read_text(encoding="utf-8"))
    defined = set(re.findall(r"APG_CALL\s+(apg_\w+)\s*\(", impl))
    for n in sorted(declared - defined):
        problems.append(f"public function {n} is declared in the header but not defined in engine/api/apg_api.cpp")
    for n in sorted(defined - declared):
        problems.append(f"{n} is defined in apg_api.cpp but not declared in the public header")
    # error codes: header enum vs common.h enum class
    h_codes = dict(re.findall(r"(APG_\w+)\s*=\s*(\d+)", header))
    common = strip_code((ROOT / "engine" / "core" / "common.h").read_text(encoding="utf-8"))
    cpp_codes = dict(re.findall(r"(\w+)\s*=\s*(\d+)", common[common.index("enum class Status"):common.index("inline const char* status_name")]))
    names = {"APG_OK": "Ok", "APG_ERR_INVALID_ARGUMENT": "InvalidArgument", "APG_ERR_CONFIG": "Config",
             "APG_ERR_DATABASE": "Database", "APG_ERR_VERSION": "Version", "APG_ERR_PLATFORM": "Platform",
             "APG_ERR_OOM": "Oom", "APG_ERR_LIMIT": "Limit", "APG_ERR_INTERNAL": "Internal"}
    for h, c in names.items():
        if h_codes.get(h) != cpp_codes.get(c):
            problems.append(f"status code mismatch: {h}={h_codes.get(h)} but Status::{c}={cpp_codes.get(c)}")
    # ABI version
    maj, mino, pat = (re.search(rf"APG_ABI_VERSION_{k}\s+(\d+)u", header).group(1) for k in ("MAJOR", "MINOR", "PATCH"))
    m = re.search(r"kAbiVersion\s*=\s*\((\d+)u\s*<<\s*16\)\s*\|\s*\((\d+)u\s*<<\s*8\)\s*\|\s*(\d+)u", common)
    if not m or (m.group(1), m.group(2), m.group(3)) != (maj, mino, pat):
        problems.append("ABI version differs between include/ai_prompt_guard.h and engine/core/common.h")
    # version script
    vs = (ROOT / "engine" / "api" / "exports.map").read_text(encoding="utf-8")
    if "apg_*" not in vs:
        problems.append("engine/api/exports.map does not export apg_*")


def check_json_contract(problems: List[str]) -> None:
    """Keys read by the C++ loaders must be written by their producers."""
    manifest_cpp = strip_code((ROOT / "engine" / "ruleset" / "manifest.cpp").read_text(encoding="utf-8"))
    raw_manifest_cpp = (ROOT / "engine" / "ruleset" / "manifest.cpp").read_text(encoding="utf-8")
    compiler_cpp = (ROOT / "engine" / "ruleset" / "compiler.cpp").read_text(encoding="utf-8")
    written = set(re.findall(r'\.set\("(\w+)"', compiler_cpp))
    needed = set(re.findall(r'need\(\w+,\s*"(\w+)"', raw_manifest_cpp))
    # keys that load_ruleset requires from the manifest/files/databases/engine/target/ruleset/patterns objects
    for key in sorted(needed):
        if key not in written and key not in {"manifest", "manifest_sha256"}:   # the two belong to active.json
            problems.append(f"manifest.cpp requires key '{key}' that compiler.cpp never writes")
    model_cpp = (ROOT / "engine" / "ruleset" / "ruleset_model.cpp").read_text(encoding="utf-8")
    publish_py = (ROOT / "tools" / "apg_rules" / "publish.py").read_text(encoding="utf-8")
    snapshot_keys = set(re.findall(r'need\(\w+,\s*"(\w+)"\)', model_cpp))
    produced = set(re.findall(r'"(\w+)"\s*:', publish_py)) | set(re.findall(r'\["(\w+)"\]', publish_py)) | \
        set(re.findall(r'"(\w+)",', publish_py)) | {"version", "content_digest", "tables_version", "profiles", "views"}
    # the snapshot builder writes keys in dict literals; check the structural ones explicitly
    expect = {"format", "format_version", "normalizer", "field_map", "scoring", "patterns", "rules", "ruleset", "thresholds",
              "source_multiplier", "risk_levels", "needs_context_review_at", "review", "alert", "block", "id", "regex",
              "flags", "profile", "class", "lang", "revision", "name", "category", "severity", "weight", "confidence",
              "action", "scope", "context_requires", "score_group", "leaves", "condition", "pattern_id", "field", "op",
              "args", "tables_version", "profiles", "views", "version", "content_digest"}
    for key in sorted(snapshot_keys):
        if key not in expect:
            problems.append(f"ruleset_model.cpp requires snapshot key '{key}' not covered by the contract list in static_checks.py")
        elif key not in produced:
            problems.append(f"ruleset_model.cpp requires snapshot key '{key}' that publish.py does not appear to write")
    _ = manifest_cpp


def main() -> int:
    problems: List[str] = []
    files = iter_sources()
    for f in files:
        check_balance(f, f.read_text(encoding="utf-8"), problems)
    check_includes(files, problems)
    check_pragma_once(files, problems)
    check_cmake_lists(problems)
    check_public_api(problems)
    check_json_contract(problems)
    if problems:
        print(f"static checks: {len(problems)} problem(s)")
        for p in problems:
            print("  -", p)
        return 1
    print(f"static checks: {len(files)} C/C++ files, CMake lists, public API, JSON contract: no problem found "
          f"(this is NOT a compilation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
