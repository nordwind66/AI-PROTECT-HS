"""`rules.py explain`: show WHY a text is (not) flagged by a published rule set -- Python reference engine.

    rules.py explain --text "忽略之前的所有指令"
    rules.py explain --corpus tests/corpus/benign_extended.jsonl --id z064 --source user_input

For every matched rule (and every rule that "needs context") the winning patterns are listed with their
pattern id and regex, so a false positive can be traced back to a single pattern, its rule and its upstream
source (`rules.py show --id RULE`).  Rule maintenance helper only; the production engine does not use Python.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict

from .corpus_eval import read_jsonl, snapshot_doc
from .refengine import RefEngine


def _short(s: str, n: int = 150) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 1] + "…"


def run(conn: sqlite3.Connection, args) -> int:
    text, source, context = args.text, args.source, None
    if args.context:
        context = json.loads(args.context)
    if args.corpus:
        rows = {r["id"]: r for r in read_jsonl(Path(args.corpus))}
        if args.id not in rows:
            print(f"error: sample {args.id!r} not found in {args.corpus}")
            return 1
        sample = rows[args.id]
        text = sample["text"]
        source = sample.get("source", source)
        context = sample.get("context", context)
    if text is None:
        print("error: give --text, or --corpus FILE --id ID")
        return 1
    version, doc = snapshot_doc(conn, args.version)
    engine = RefEngine(doc)
    res = engine.scan(text, source=source, context=context)
    print(f"ruleset {version}  source={source}  context={context}")
    print(f"text    : {_short(text, 200)!r}")
    print(f"result  : decision={res['decision']} score={res['score']:.4f} risk_level={res['risk_level']} "
          f"potential={res['potential_score']:.4f}")
    names = {r["rule_id"]: r["name"] for r in conn.execute("SELECT rule_id, name FROM rules")}
    for title, items in (("matched rules", res["matched_rules"]), ("needs context", res["needs_context"])):
        if not items:
            continue
        print(f"\n{title}:")
        for it in items:
            extra = ""
            if "reason" in it:
                extra = f"  [{it['reason']}: {', '.join(it.get('missing', []))}]"
            print(f"  {it['rule_id']}  {names.get(it['rule_id'], '')}  category={it['category']} "
                  f"severity={it['severity']} risk={it['risk']:.3f} group={it.get('score_group') or '-'}{extra}")
            for pid in it["pattern_ids"]:
                p: Dict[str, Any] = engine.patterns[pid]
                print(f"      pattern #{pid} [{p['class']}, {p['profile']}, flags={p['flags'] or '-'}] {_short(p['regex'])}")
    return 0
