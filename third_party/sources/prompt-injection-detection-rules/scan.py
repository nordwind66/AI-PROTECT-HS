#!/usr/bin/env python3
"""Scan text against the rule set — a tiny reference matcher.

    python scan.py path/to/file.txt
    echo "ignore previous instructions" | python scan.py

Exit code 2 if any rule matches (CI/pre-flight friendly). Requires PyYAML.
"""
from __future__ import annotations

import glob
import re
import sys

import yaml

FLAG = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL, "x": re.VERBOSE}


def load():
    rules = []
    for path in sorted(glob.glob("rules/*.yml")):
        for r in yaml.safe_load(open(path, encoding="utf-8")) or []:
            flags = 0
            for f in r.get("flags", []):
                flags |= FLAG.get(f, 0)
            r["_rx"] = re.compile(r["pattern"], flags)
            rules.append(r)
    return rules


def main() -> int:
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read() if len(sys.argv) > 1 else sys.stdin.read()
    hits = []
    for r in load():
        m = r["_rx"].search(text)
        if m:
            hits.append((r, m.group(0)[:80]))
    if not hits:
        print("clean — no rule matched")
        return 0
    hits.sort(key=lambda h: ["critical", "high", "medium", "low", "info"].index(h[0]["severity"]))
    for r, snip in hits:
        print(f"[{r['severity']:>8}] {r['id']}  {r['name']}")
        print(f"           match: {snip!r}")
        print(f"           maps:  {', '.join(r.get('maps_to', []))}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
