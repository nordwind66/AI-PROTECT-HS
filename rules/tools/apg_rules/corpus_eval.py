"""Run the test corpora through the Python REFERENCE engine on a published snapshot (`rules.py eval`).

Outputs
  * tests/corpus/expected/<corpus>.expected.jsonl : the per-sample results the C++ engine must reproduce
    (decision, score, matched rule ids, needs-context rule ids) -- the contract of the differential tests;
  * reports/false_positive.md  : behaviour on benign text (author corpus + the 800 normal sentences of the
    trans-prompt-injection-detector dataset);
  * reports/detection_eval.md  : behaviour on the attack corpora, including the documented known gaps.

Honest scope: the corpora are small, hand-written (or, for the dataset, produced by an upstream project's
generator), were used while developing the rules, and the engine is the Python oracle -- not Hyperscan/PCRE2.
The numbers describe THIS rule set on THESE samples; they are not a detection-rate or false-positive-rate
estimate for real traffic.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import db as dbm
from .refengine import RefEngine
from .util import atomic_write_text, canonical_json, project_root, read_text, rel_to_root, utc_now

DATASET_REL = "third_party/sources/trans-prompt-injection-detector/translation_pia_dataset_shuffled.jsonl"
BENIGN_CORPORA = ("benign_zh_en", "benign_extended")
ATTACK_CORPORA = ("attacks_zh_en",)
FLAGGED = ("alert", "block")


# ---------------------------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------------------------
def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    for n, line in enumerate(read_text(path).splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{n}: {exc}") from exc
    return rows


def load_corpora(corpus_dir: Path, root: Path) -> Dict[str, List[Dict[str, Any]]]:
    """name -> samples. Every sample: id, label (normal|injection), text, optional source/context/expect/category."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    for name in BENIGN_CORPORA + ATTACK_CORPORA:
        p = corpus_dir / f"{name}.jsonl"
        if p.is_file():
            out[name] = read_jsonl(p)
    ds = root / DATASET_REL
    if ds.is_file():
        rows = []
        for r in read_jsonl(ds):
            rows.append({"id": "trans-" + str(r["id"]), "label": r["label"], "category": r.get("attack_type", "none"),
                         "lang": "en", "text": r["text"], "context": {"task": "translation"}, "expect": "detect"
                         if r["label"] == "injection" else "allow", "dataset_row": r["id"]})
        out["trans_dataset"] = rows
    return out


# ---------------------------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------------------------
def snapshot_doc(conn: sqlite3.Connection, version: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    if version:
        row = conn.execute("SELECT version_id, version FROM ruleset_versions WHERE version=? AND status<>'draft'",
                           (version,)).fetchone()
    else:
        row = conn.execute("SELECT version_id, version FROM ruleset_versions WHERE status='published' "
                           "ORDER BY version_id DESC LIMIT 1").fetchone()
    if row is None:
        raise ValueError("no published rule-set version (run `rules.py publish --version X` first)")
    body = conn.execute("SELECT body FROM ruleset_snapshots WHERE version_id=?", (row["version_id"],)).fetchone()
    return row["version"], json.loads(bytes(body["body"]).decode("utf-8"))


def scan_all(engine: RefEngine, samples: List[Dict[str, Any]], with_context: bool = True) -> List[Dict[str, Any]]:
    results = []
    for s in samples:
        ctx = s.get("context") if with_context else None
        res = engine.scan(s["text"], source=s.get("source", "user_input"), context=ctx)
        results.append({
            "id": s["id"], "source": s.get("source", "user_input"), "context": ctx, "decision": res["decision"],
            "score": res["score"], "risk_level": res["risk_level"],
            "matched": sorted(m["rule_id"] for m in res["matched_rules"]),
            "needs_context": sorted(n["rule_id"] for n in res["needs_context"]),
        })
    return results


def expected_lines(results: List[Dict[str, Any]]) -> str:
    return "".join(canonical_json(r) + "\n" for r in results)


def _pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:.1f}%" if d else "n/a"


def _fmt_rules(ids: List[str], limit: int = 4) -> str:
    return ", ".join(ids[:limit]) + (f" (+{len(ids) - limit})" if len(ids) > limit else "")


def _rule_names(conn: sqlite3.Connection) -> Dict[str, str]:
    return {r["rule_id"]: r["name"] for r in conn.execute("SELECT rule_id, name FROM rules")}


def _short(text: str, n: int = 70) -> str:
    t = text.replace("\n", " ").replace("|", "\\|")
    t = "".join(c if c.isprintable() else f"<U+{ord(c):04X}>" for c in t)
    return t if len(t) <= n else t[: n - 1] + "…"


# ---------------------------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------------------------
def render_false_positive(version: str, snap_sha: str, benign: List[Dict[str, Any]], br: List[Dict[str, Any]],
                          ds_normal: List[Dict[str, Any]], dr_ctx: List[Dict[str, Any]],
                          dr_noctx: List[Dict[str, Any]], names: Dict[str, str]) -> str:
    L: List[str] = []
    L.append("# 误报评估 / False positives\n")
    L.append(f"> 由 `python tools/rules.py eval` 生成（{utc_now()}），规则集 `{version}`，快照 sha256 `{snap_sha[:16]}…`。  ")
    L.append("> **引擎是 Python 参考实现（`refengine.py`，Python `re`），不是 Hyperscan/PCRE2 的 C++ 引擎。** "
             "语料是人工编写的小样本且在开发规则时参考过，数字**只描述这个规则集在这些样本上的表现**，"
             "不是真实流量的误报率估计。真实评估需要 Linux 环境 + 业务脱敏流量，见 `docs/linux-testing.md`。\n")
    flagged = [r for r in br if r["decision"] in FLAGGED]
    review = [r for r in br if r["decision"] == "review"]
    L.append("## 1. 人工编写的正常文本语料（`tests/corpus/benign_zh_en.jsonl` + `benign_extended.jsonl`）\n")
    L.append(f"- 样本 {len(br)}：`alert` {len(flagged)}，`review` {len(review)}，`allow` {len(br) - len(flagged) - len(review)}。")
    by_id = {s["id"]: s for s in benign}
    known = [r for r in flagged + review if by_id[r["id"]].get("expect") == "known_fp_risk"]
    other = [r for r in flagged + review if by_id[r["id"]].get("expect") != "known_fp_risk"]
    L.append(f"- 其中**预期会被触发的“引述攻击字符串”样本**（`known_fp_risk`，正则规则无法区分引用与使用）：{len(known)} / "
             f"{sum(1 for s in benign if s.get('expect') == 'known_fp_risk')}。")
    L.append(f"- 其余正常样本中被标记的：**{len(other)}** / {sum(1 for s in benign if s.get('expect') != 'known_fp_risk')}。\n")
    if flagged or review:
        L.append("| 样本 | 类别 | 决策 | 分数 | 触发规则 | 文本 |")
        L.append("|---|---|---|---|---|---|")
        for r in flagged + review:
            s = by_id[r["id"]]
            L.append(f"| {r['id']} | {s.get('category', '')} | {r['decision']} | {r['score']:.3f} | "
                     f"{_fmt_rules(r['matched'] or r['needs_context'])} | {_short(s['text'])} |")
        L.append("")
    cat_tot: Counter = Counter(s.get("category", "") for s in benign)
    cat_hit: Counter = Counter(by_id[r["id"]].get("category", "") for r in flagged + review)
    L.append("按类别（被标记 / 总数）：" + "，".join(f"{k} {cat_hit.get(k, 0)}/{v}" for k, v in sorted(cat_tot.items())) + "\n")
    L.append("## 2. 上游数据集的 800 条正常翻译句（`trans-prompt-injection-detector`，MIT）\n")
    n = len(dr_ctx)
    f_ctx = [r for r in dr_ctx if r["decision"] != "allow"]
    f_no = [r for r in dr_noctx if r["decision"] != "allow"]
    L.append(f"- 带 `context.task=translation`：{n} 条中非 `allow` 的 **{len(f_ctx)}**（{_pct(len(f_ctx), n)}）。")
    L.append(f"- 不带上下文：{n} 条中非 `allow` 的 **{len(f_no)}**（{_pct(len(f_no), n)}）。")
    if f_ctx:
        c = Counter(rid for r in f_ctx for rid in (r["matched"] or r["needs_context"]))
        L.append("- 触发最多的规则：" + "，".join(f"{rid}×{k}" for rid, k in c.most_common(8)))
    L.append("")
    L.append("## 3. 已知局限（误报来源）\n")
    L.append("- 引述攻击字符串的安全讨论、论文、培训材料会触发关键词规则；这是**正则规则的固有限制**，"
             "默认策略为 alert-only（`allow/alert/review`），不直接拦截。")
    L.append("- 上游规则以英文为主；中文规则只有 9 条手工规则和少量上游中文/混合规则，覆盖和误报都**缺少真实流量验证**。")
    L.append("- Python `re` 与 Hyperscan/PCRE2 在 Unicode 词边界、大小写折叠上存在差异，C++ 引擎的结果需在 Linux 上用 "
             "`tests/corpus/expected/*.expected.jsonl` 做差分确认。")
    return "\n".join(L) + "\n"


def render_detection(version: str, snap_sha: str, attacks: List[Dict[str, Any]], ar: List[Dict[str, Any]],
                     ds_inj: List[Dict[str, Any]], dr_ctx: List[Dict[str, Any]], dr_noctx: List[Dict[str, Any]],
                     names: Dict[str, str]) -> str:
    L: List[str] = []
    L.append("# 检出评估 / Detection on the sample corpora\n")
    L.append(f"> 由 `python tools/rules.py eval` 生成（{utc_now()}），规则集 `{version}`，快照 sha256 `{snap_sha[:16]}…`。  ")
    L.append("> 引擎为 **Python 参考实现**；样本为人工编写（并在开发手工规则时参考过），**不是**检出率估计。\n")
    by_id = {s["id"]: s for s in attacks}
    det = [(by_id[r["id"]], r) for r in ar if by_id[r["id"]].get("expect") == "detect"]
    gap = [(by_id[r["id"]], r) for r in ar if by_id[r["id"]].get("expect") == "known_gap"]
    det_alert = [x for x in det if x[1]["decision"] in FLAGGED]
    det_any = [x for x in det if x[1]["decision"] != "allow"]
    L.append("## 1. 人工编写的攻击语料（`tests/corpus/attacks_zh_en.jsonl`）\n")
    L.append(f"- 预期应检出（`detect`）{len(det)} 条：`alert` 及以上 **{len(det_alert)}**（{_pct(len(det_alert), len(det))}），"
             f"`review` 及以上 **{len(det_any)}**（{_pct(len(det_any), len(det))}）。")
    L.append(f"- 已记录的已知缺口（`known_gap`）{len(gap)} 条：其中仍被检出 {sum(1 for _, r in gap if r['decision'] != 'allow')} 条。\n")
    L.append("| 类别 | 应检出 | alert+ | review+ |")
    L.append("|---|---|---|---|")
    cats = sorted({s.get("category", "") for s, _ in det})
    for c in cats:
        d = [x for x in det if x[0].get("category") == c]
        L.append(f"| {c} | {len(d)} | {sum(1 for x in d if x[1]['decision'] in FLAGGED)} | "
                 f"{sum(1 for x in d if x[1]['decision'] != 'allow')} |")
    L.append("")
    L.append("按语言（应检出 / alert+）：" + "，".join(
        f"{lg} {sum(1 for x in det if x[0].get('lang') == lg)}/{sum(1 for x in det_alert if x[0].get('lang') == lg)}"
        for lg in sorted({x[0].get("lang", '') for x in det})) + "\n")
    miss = [x for x in det if x[1]["decision"] not in FLAGGED]
    L.append(f"### 未达到 alert 的“应检出”样本（{len(miss)}）\n")
    if miss:
        L.append("| 样本 | 类别 | 决策 | 分数 | 触发 | 文本 |")
        L.append("|---|---|---|---|---|---|")
        for s, r in miss:
            L.append(f"| {s['id']} | {s.get('category', '')} | {r['decision']} | {r['score']:.3f} | "
                     f"{_fmt_rules(r['matched'] or r['needs_context'])} | {_short(s['text'])} |")
    else:
        L.append("（无）")
    L.append("")
    L.append("### 已知缺口样本的实际结果\n")
    L.append("| 样本 | 说明 | 决策 | 文本 |")
    L.append("|---|---|---|---|")
    for s, r in gap:
        L.append(f"| {s['id']} | {s.get('note', '')} | {r['decision']} | {_short(s['text'])} |")
    L.append("")
    n = len(dr_ctx)
    L.append("## 2. 上游数据集的 200 条翻译劫持样本（`trans-prompt-injection-detector`，MIT）\n")
    ctx_alert = sum(1 for r in dr_ctx if r["decision"] in FLAGGED)
    ctx_any = sum(1 for r in dr_ctx if r["decision"] != "allow")
    no_alert = sum(1 for r in dr_noctx if r["decision"] in FLAGGED)
    no_any = sum(1 for r in dr_noctx if r["decision"] != "allow")
    L.append(f"- 带 `context.task=translation`：{n} 条中 `alert`+ **{ctx_alert}**（{_pct(ctx_alert, n)}），`review`+ **{ctx_any}**（{_pct(ctx_any, n)}）。")
    L.append(f"- 不带上下文（翻译专用规则只会产生 `needs_context`）：`alert`+ **{no_alert}**（{_pct(no_alert, n)}），`review`+ **{no_any}**（{_pct(no_any, n)}）。")
    bt: Dict[str, List[int]] = defaultdict(lambda: [0, 0])
    ds_by_id = {s["id"]: s for s in ds_inj}
    for r in dr_ctx:
        t = ds_by_id[r["id"]].get("category", "")
        bt[t][0] += 1
        bt[t][1] += 1 if r["decision"] in FLAGGED else 0
    L.append("\n| attack_type | 样本 | alert+ |")
    L.append("|---|---|---|")
    for k, (tot, ok) in sorted(bt.items()):
        L.append(f"| {k} | {tot} | {ok} |")
    L.append("\n> 数据集的样本是上游生成器按模板产生的英文句子，规则也出自同一项目，因此这里的数字**高度乐观**，只说明移植后的规则与上游行为一致。")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------------------------
def run(conn: sqlite3.Connection, args) -> int:
    root = project_root()
    corpus_dir = Path(args.corpus_dir) if args.corpus_dir else root / "tests" / "corpus"
    version, doc = snapshot_doc(conn, args.version)
    snap_sha = conn.execute("SELECT snapshot_sha256 FROM ruleset_versions WHERE version=?", (version,)).fetchone()[0]
    engine = RefEngine(doc)
    if engine.uncompilable:
        print(f"[eval] warning: {len(engine.uncompilable)} pattern(s) cannot be compiled by Python `re` "
              f"(they are treated as non-matching): {engine.uncompilable[:10]}")
    corpora = load_corpora(corpus_dir, root)
    names = _rule_names(conn)
    results: Dict[str, List[Dict[str, Any]]] = {}
    for name, samples in corpora.items():
        results[name] = scan_all(engine, samples, with_context=True)
        c = Counter(r["decision"] for r in results[name])
        print(f"[eval] {name}: {len(samples)} sample(s) -> {dict(sorted(c.items()))}")
    if args.write_expected:
        out_dir = corpus_dir / "expected"
        for name, res in results.items():
            atomic_write_text(out_dir / f"{name}.expected.jsonl", expected_lines(res))
            print(f"[eval] wrote {rel_to_root(out_dir / (name + '.expected.jsonl'))}")
        atomic_write_text(out_dir / "EXPECTED_FOR.json", json.dumps(
            {"ruleset_version": version, "snapshot_sha256": snap_sha, "engine": "python-reference (refengine.py)",
             "note": "results the C++ engine must reproduce on this exact snapshot"},
            indent=2) + "\n")
    if args.report and "benign_zh_en" in corpora and "attacks_zh_en" in corpora:
        benign_all = [s for n in BENIGN_CORPORA for s in corpora.get(n, [])]
        benign_res = [r for n in BENIGN_CORPORA for r in results.get(n, [])]
        ds = corpora.get("trans_dataset", [])
        ds_normal = [s for s in ds if s["label"] == "normal"]
        ds_inj = [s for s in ds if s["label"] == "injection"]
        dres = {r["id"]: r for r in results.get("trans_dataset", [])}
        dr_normal_ctx = [dres[s["id"]] for s in ds_normal]
        dr_inj_ctx = [dres[s["id"]] for s in ds_inj]
        dr_normal_no = scan_all(engine, ds_normal, with_context=False)
        dr_inj_no = scan_all(engine, ds_inj, with_context=False)
        reports = root / "reports"
        atomic_write_text(reports / "false_positive.md", render_false_positive(
            version, snap_sha, benign_all, benign_res, ds_normal, dr_normal_ctx, dr_normal_no, names))
        atomic_write_text(reports / "detection_eval.md", render_detection(
            version, snap_sha, corpora["attacks_zh_en"], results["attacks_zh_en"], ds_inj, dr_inj_ctx, dr_inj_no, names))
        print("[eval] wrote reports/false_positive.md, reports/detection_eval.md")
    return 0
