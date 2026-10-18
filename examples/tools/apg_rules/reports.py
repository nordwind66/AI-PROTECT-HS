"""Reports derived from the database (never hand-edited): inventory, CSV exports, coverage, language review."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any, Dict, List

from . import db as dbm
from .util import atomic_write_text, canonical_json, pretty_json, utc_now

README_CLAIMS = {
    "trans_pid": "README.md of the repository states '11 categories, 113 regex patterns'",
    "atr": "README badge states 836 rules",
}


def _count(conn: sqlite3.Connection, sql: str, params=()) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def source_inventory(conn: sqlite3.Connection) -> Dict[str, Any]:
    out: Dict[str, Any] = OrderedDict()
    out["generated_at"] = utc_now()
    out["definitions"] = {
        "source_rules": "rule definitions found in the locked upstream commit (ATR: one YAML file; trans: one detector "
                        "group; fevzi: one rule entry)",
        "groups": "upstream grouping unit (ATR: category directory; trans: detector group; fevzi: category)",
        "conditions_patterns": "regex patterns/conditions inside the source rules (one condition = one pattern)",
        "included": "source rules that produced a unified rule (included = all patterns converted, partial = some "
                    "dropped / pruned)",
        "native / prefilter / unsupported": "fate of every source pattern: Hyperscan-native, Hyperscan prefilter + PCRE2 "
                                            "verification, or not convertible; excluded_* patterns never reach the engine",
    }
    sources: Dict[str, Any] = OrderedDict()
    totals = Counter()
    for s in conn.execute("SELECT * FROM upstream_sources ORDER BY source_id"):
        sid = s["source_id"]
        rules = conn.execute("SELECT * FROM source_rules WHERE source_id = ?", (sid,)).fetchall()
        dec = Counter(r["decision"] for r in rules)
        groups = {r["group_key"] for r in rules}
        fates = Counter(r[0] for r in conn.execute(
            "SELECT sp.fate FROM source_patterns sp JOIN source_rules sr ON sr.source_rule_id = sp.source_rule_id "
            "WHERE sr.source_id = ?", (sid,)))
        n_patterns = sum(fates.values())
        unified = _count(conn, "SELECT COUNT(DISTINCT p.rule_id) FROM rule_provenance p JOIN source_rules sr ON "
                         "sr.source_rule_id = p.source_rule_id WHERE sr.source_id = ? AND p.kind='rule'", (sid,))
        distinct_patterns = _count(conn, "SELECT COUNT(DISTINCT p.pattern_id) FROM rule_provenance p JOIN source_rules sr "
                                   "ON sr.source_rule_id = p.source_rule_id WHERE sr.source_id = ? AND p.kind='pattern'", (sid,))
        classes = Counter(r[0] for r in conn.execute(
            "SELECT rp.engine_class FROM rule_patterns rp WHERE rp.pattern_id IN (SELECT DISTINCT p.pattern_id FROM "
            "rule_provenance p JOIN source_rules sr ON sr.source_rule_id = p.source_rule_id WHERE sr.source_id = ? "
            "AND p.kind='pattern')", (sid,)))
        reasons = Counter()
        for r in rules:
            if r["decision"] not in ("included", "partial"):
                reasons[f"{r['decision']}: {(r['decision_reason'] or '').split(':')[0][:70]}"] += 1
        entry = OrderedDict([
            ("display_name", s["display_name"]), ("repo_url", s["repo_url"]), ("commit_sha", s["commit_sha"]),
            ("commit_date", s["commit_date"]), ("license", s["license_spdx"]),
            ("extractor", f"{s['extractor_id']} v{s['extractor_version']}"),
            ("source_rules", len(rules)), ("groups", len(groups)), ("conditions_patterns", n_patterns),
            ("rules_by_decision", dict(sorted(dec.items()))),
            ("rules_included_or_partial", dec["included"] + dec["partial"]),
            ("rules_excluded_or_unsupported", len(rules) - dec["included"] - dec["partial"]),
            ("patterns_by_fate", dict(sorted(fates.items()))),
            ("patterns_native_hyperscan", fates["hs_native"]),
            ("patterns_needing_pcre2", fates["hs_prefilter_pcre2"]),
            ("patterns_unsupported", fates["unsupported"]),
            ("unified_rules_created", unified),
            ("distinct_canonical_patterns", distinct_patterns),
            ("distinct_pattern_classes", dict(sorted(classes.items()))),
            ("exclusion_reasons", dict(reasons.most_common(12))),
            ("readme_claim", README_CLAIMS.get(sid)),
        ])
        sources[sid] = entry
        for k in ("source_rules", "groups", "conditions_patterns", "unified_rules_created"):
            totals[k] += entry[k]
        totals["rules_included_or_partial"] += entry["rules_included_or_partial"]
        totals["rules_excluded_or_unsupported"] += entry["rules_excluded_or_unsupported"]
        totals["patterns_native_hyperscan"] += entry["patterns_native_hyperscan"]
        totals["patterns_needing_pcre2"] += entry["patterns_needing_pcre2"]
        totals["patterns_unsupported"] += entry["patterns_unsupported"]
        for fk, fv in fates.items():
            totals["fate:" + fk] += fv
    out["sources"] = sources
    out["totals"] = dict(totals)
    out["database"] = OrderedDict([
        ("unified_rules", _count(conn, "SELECT COUNT(*) FROM rules")),
        ("unified_rules_by_origin", {r[0]: r[1] for r in conn.execute("SELECT origin, COUNT(*) FROM rules GROUP BY origin")}),
        ("unified_rules_by_status", {r[0]: r[1] for r in conn.execute("SELECT status, COUNT(*) FROM rules GROUP BY status")}),
        ("distinct_patterns", _count(conn, "SELECT COUNT(*) FROM rule_patterns")),
        ("patterns_by_class", {r[0]: r[1] for r in conn.execute("SELECT engine_class, COUNT(*) FROM rule_patterns GROUP BY engine_class")}),
        ("patterns_by_profile", {r[0]: r[1] for r in conn.execute("SELECT norm_profile, COUNT(*) FROM rule_patterns GROUP BY norm_profile")}),
        ("source_patterns_deduplicated_into_shared_patterns",
         _count(conn, "SELECT COUNT(*) FROM rule_provenance WHERE kind='pattern'") - _count(conn, "SELECT COUNT(DISTINCT pattern_id) FROM rule_provenance WHERE kind='pattern'")),
        ("tests", _count(conn, "SELECT COUNT(*) FROM rule_tests")),
        ("rules_by_category", {r[0]: r[1] for r in conn.execute("SELECT category, COUNT(*) FROM rules GROUP BY category ORDER BY 2 DESC")}),
        ("rules_by_lang", {r[0]: r[1] for r in conn.execute("SELECT lang, COUNT(*) FROM rules GROUP BY lang")}),
    ])
    return out


def render_inventory_md(inv: Dict[str, Any]) -> str:
    L: List[str] = []
    L.append("# 规则源清点 / Source inventory")
    L.append("")
    L.append("> 本文件由 `python tools/rules.py inventory` 从 SQLite (`data/ai_prompt_rules.db`) 生成，**请勿手工修改**。"
             f"生成时间 {inv['generated_at']}。")
    L.append("")
    L.append("数字的含义不同，不能混为一个数：**源规则数 ≠ 分组数 ≠ 条件/Regex 模式数 ≠ 纳入数**。")
    L.append("")
    for term, text in inv["definitions"].items():
        L.append(f"- **{term}**: {text}")
    L.append("")
    L.append("## 总览")
    L.append("")
    hdr = ["来源", "commit", "许可证", "源规则数", "分组数", "条件/模式数", "纳入(含部分)", "排除/不支持", "原生 Hyperscan", "需 PCRE2 复核", "不支持"]
    L.append("| " + " | ".join(hdr) + " |")
    L.append("|" + "|".join(["---"] * len(hdr)) + "|")
    for sid, e in inv["sources"].items():
        L.append(f"| {sid} | `{e['commit_sha'][:10]}` | {e['license']} | {e['source_rules']} | {e['groups']} | "
                 f"{e['conditions_patterns']} | {e['rules_included_or_partial']} | {e['rules_excluded_or_unsupported']} | "
                 f"{e['patterns_native_hyperscan']} | {e['patterns_needing_pcre2']} | {e['patterns_unsupported']} |")
    t = inv["totals"]
    L.append(f"| **合计** | | | {t['source_rules']} | {t['groups']} | {t['conditions_patterns']} | "
             f"{t['rules_included_or_partial']} | {t['rules_excluded_or_unsupported']} | {t['patterns_native_hyperscan']} | "
             f"{t['patterns_needing_pcre2']} | {t['patterns_unsupported']} |")
    L.append("")
    L.append("`原生 Hyperscan / 需 PCRE2 / 不支持` 统计的是**源模式**（逐条正则）的最终去向；"
             "被语言/范围排除的模式（`excluded_language` / `excluded_scope`）不进入引擎，见下表。")
    L.append("")
    for sid, e in inv["sources"].items():
        L.append(f"## {sid} — {e['display_name']}")
        L.append("")
        L.append(f"- 仓库: {e['repo_url']}  ")
        L.append(f"- commit: `{e['commit_sha']}` ({e['commit_date']})，许可证 {e['license']}，提取器 {e['extractor']}")
        if e.get("readme_claim"):
            L.append(f"- 上游自述（仅作背景）: {e['readme_claim']}；**以锁定 commit 的真实解析结果为准**")
        L.append(f"- 源规则 {e['source_rules']}，分组 {e['groups']}，条件/模式 {e['conditions_patterns']}")
        L.append(f"- 规则决定: {e['rules_by_decision']}")
        L.append(f"- 模式去向: {e['patterns_by_fate']}")
        L.append(f"- 生成统一规则 {e['unified_rules_created']} 条，去重后的标准模式 {e['distinct_canonical_patterns']} 个 "
                 f"（类别 {e['distinct_pattern_classes']}）")
        if e["exclusion_reasons"]:
            L.append("- 主要排除原因:")
            for k, v in e["exclusion_reasons"].items():
                L.append(f"    - {v} × {k}")
        L.append("")
    d = inv["database"]
    L.append("## 数据库汇总")
    L.append("")
    for k, v in d.items():
        L.append(f"- {k}: {v}")
    L.append("")
    return "\n".join(L)


def rule_inventory_rows(conn: sqlite3.Connection) -> List[List[Any]]:
    rows = []
    last = conn.execute("SELECT version_id, version FROM ruleset_versions WHERE status='published' "
                        "ORDER BY version_id DESC LIMIT 1").fetchone()
    for r in conn.execute("SELECT * FROM rules ORDER BY rule_id"):
        links = conn.execute("SELECT p.pattern_id, p.engine_class, p.norm_profile FROM rule_pattern_links l JOIN rule_patterns p "
                             "ON p.pattern_id = l.pattern_id WHERE l.rule_id=? AND l.revision=?", (r["rule_id"], r["revision"])).fetchall()
        classes = Counter(x["engine_class"] for x in links)
        srcs = conn.execute("SELECT s.source_id, s.source_key FROM rule_provenance p JOIN source_rules s ON s.source_rule_id = p.source_rule_id "
                            "WHERE p.rule_id=? AND p.kind='rule'", (r["rule_id"],)).fetchall()
        tests = conn.execute("SELECT SUM(kind='positive'), SUM(kind='negative'), "
                             "SUM(verification='python_oracle_ok'), SUM(verification='python_oracle_mismatch') FROM rule_tests WHERE rule_id=?",
                             (r["rule_id"],)).fetchone()
        in_last = bool(last and conn.execute("SELECT 1 FROM ruleset_members WHERE version_id=? AND rule_id=?",
                                             (last["version_id"], r["rule_id"])).fetchone())
        rows.append([
            r["rule_id"], r["name"], r["category"], r["lang"], r["severity"], r["weight"], r["confidence"],
            r["default_action"], r["status"], r["scope"], r["origin"], r["revision"],
            ";".join(sorted({x["source_id"] for x in srcs})) or "manual",
            ";".join(sorted(x["source_key"] for x in srcs)),
            len(links), classes["hs_native"], classes["hs_prefilter_pcre2"],
            ";".join(sorted({x["norm_profile"] for x in links})),
            int(tests[0] or 0), int(tests[1] or 0), int(tests[2] or 0), int(tests[3] or 0),
            last["version"] if in_last else "",
        ])
    return rows


RULE_INVENTORY_HEADERS = ["rule_id", "name", "category", "lang", "severity", "weight", "confidence", "default_action",
                          "status", "scope", "origin", "revision", "sources", "source_keys", "patterns", "native_patterns",
                          "prefilter_patterns", "profiles", "positive_tests", "negative_tests", "oracle_ok",
                          "oracle_mismatch", "in_latest_published"]


def _csv_text(headers: List[str], rows: List[List[Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(headers)
    w.writerows(rows)
    return buf.getvalue()


def source_rules_csv(conn: sqlite3.Connection) -> str:
    headers = ["source_id", "source_key", "name", "source_path", "group", "decision", "decision_reason", "state",
               "patterns", "hs_native", "hs_prefilter_pcre2", "excluded_language", "excluded_scope", "unsupported", "unified_rule_id"]
    rows = []
    for s in conn.execute("SELECT * FROM source_rules ORDER BY source_id, source_key"):
        f = Counter(r[0] for r in conn.execute("SELECT fate FROM source_patterns WHERE source_rule_id=?", (s["source_rule_id"],)))
        rid = conn.execute("SELECT rule_id FROM rule_provenance WHERE source_rule_id=? AND kind='rule' LIMIT 1", (s["source_rule_id"],)).fetchone()
        rows.append([s["source_id"], s["source_key"], s["name"], s["source_path"], s["group_key"], s["decision"],
                     s["decision_reason"], s["state"], sum(f.values()), f["hs_native"], f["hs_prefilter_pcre2"],
                     f["excluded_language"], f["excluded_scope"], f["unsupported"], rid[0] if rid else ""])
    return _csv_text(headers, rows)


def write_inventory(conn: sqlite3.Connection, outdir: Path) -> List[Path]:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    inv = source_inventory(conn)
    written = []
    for name, text in (("source_inventory.json", pretty_json(inv)), ("source_inventory.md", render_inventory_md(inv)),
                       ("rule_inventory.csv", _csv_text(RULE_INVENTORY_HEADERS, rule_inventory_rows(conn))),
                       ("source_rules.csv", source_rules_csv(conn))):
        atomic_write_text(outdir / name, text)
        written.append(outdir / name)
    return written


def coverage_md(conn: sqlite3.Connection) -> str:
    L = ["# 覆盖统计 / Coverage", "",
         "> 由 `rules.py report` 从数据库生成。覆盖 = 已**导入并通过转换**的规则，不代表对真实流量的检出率。", ""]
    L.append("## 类别 × 语言（启用的规则数）")
    L.append("")
    langs = ["zh", "en", "mixed", "any"]
    L.append("| 类别 | " + " | ".join(langs) + " | 合计 |")
    L.append("|---|" + "|".join(["---"] * (len(langs) + 1)) + "|")
    cats = [r[0] for r in conn.execute("SELECT DISTINCT category FROM rules ORDER BY category")]
    for c in cats:
        cnt = {l: _count(conn, "SELECT COUNT(*) FROM rules WHERE category=? AND lang=? AND status='enabled'", (c, l)) for l in langs}
        L.append(f"| {c} | " + " | ".join(str(cnt[l]) for l in langs) + f" | {sum(cnt.values())} |")
    L.append("")
    L.append("## 来源 × 状态")
    L.append("")
    L.append("| 来源 | enabled | disabled | deprecated | deleted |")
    L.append("|---|---|---|---|---|")
    for src in [r[0] for r in conn.execute("SELECT source_id FROM upstream_sources ORDER BY 1")] + ["manual"]:
        if src == "manual":
            q = "SELECT status, COUNT(*) FROM rules WHERE origin='manual' GROUP BY status"
            p = ()
        else:
            q = ("SELECT r.status, COUNT(*) FROM rules r WHERE r.rule_id IN (SELECT p.rule_id FROM rule_provenance p JOIN source_rules s ON "
                 "s.source_rule_id=p.source_rule_id WHERE s.source_id=? AND p.kind='rule') GROUP BY r.status")
            p = (src,)
        c = Counter({r[0]: r[1] for r in conn.execute(q, p)})
        L.append(f"| {src} | {c['enabled']} | {c['disabled']} | {c['deprecated']} | {c['deleted']} |")
    L.append("")
    L.append("## 测试样例覆盖")
    L.append("")
    en = conn.execute("SELECT COUNT(*) FROM rules WHERE status='enabled'").fetchone()[0]
    nopos = [r[0] for r in conn.execute("SELECT rule_id FROM rules r WHERE status='enabled' AND NOT EXISTS "
                                        "(SELECT 1 FROM rule_tests t WHERE t.rule_id=r.rule_id AND t.kind='positive')")]
    noneg = [r[0] for r in conn.execute("SELECT rule_id FROM rules r WHERE status='enabled' AND NOT EXISTS "
                                        "(SELECT 1 FROM rule_tests t WHERE t.rule_id=r.rule_id AND t.kind='negative')")]
    L.append(f"- 启用规则 {en} 条；无正例 {len(nopos)} 条；无负例 {len(noneg)} 条。")
    if nopos:
        L.append("- 缺少正例: " + ", ".join(nopos))
    if noneg:
        L.append("- 缺少负例: " + ", ".join(noneg))
    ver = Counter({r[0]: r[1] for r in conn.execute("SELECT verification, COUNT(*) FROM rule_tests GROUP BY verification")})
    L.append(f"- 测试样例验证状态（Python 参考 oracle，**不是 C++ 引擎**）: {dict(ver)}")
    kinds = Counter({r[0]: r[1] for r in conn.execute("SELECT kind, COUNT(*) FROM rule_tests GROUP BY kind")})
    L.append(f"- 样例类型: {dict(kinds)}（known_gap 为上游记录的已知绕过，不作为通过/失败断言）")
    origin = Counter({r[0]: r[1] for r in conn.execute("SELECT origin, COUNT(*) FROM rule_tests GROUP BY origin")})
    L.append(f"- 样例来源: {dict(origin)}")
    L.append("")
    L.append("## 未解决的问题（rule_issues）")
    L.append("")
    for r in conn.execute("SELECT kind, severity, COUNT(*) FROM rule_issues WHERE status='open' GROUP BY kind, severity ORDER BY 3 DESC"):
        L.append(f"- {r[0]} ({r[1]}): {r[2]}")
    L.append("")
    return "\n".join(L)


def language_review_md(conn: sqlite3.Connection) -> str:
    L = ["# 语言过滤审计 / Language scoping review", "",
         "> 范围：中文、英文、中英混合。下列条目由 `langscope.py`（脚本类别 + 上游语言标签 + 区分度词表）判定，"
         "**逐条保留证据，请人工抽查**。", ""]
    rows = conn.execute(
        "SELECT sr.source_id, sr.source_key, sp.ordinal, sp.lang_detected, sp.fate, sp.fate_reason, sp.regex_original, sp.transform_notes "
        "FROM source_patterns sp JOIN source_rules sr ON sr.source_rule_id = sp.source_rule_id WHERE sp.fate = 'excluded_language' "
        "ORDER BY sr.source_id, sr.source_key, sp.ordinal").fetchall()
    by_lang = Counter(r["lang_detected"] for r in rows)
    L.append(f"## 整条排除的模式（excluded_language）：{len(rows)}")
    L.append("")
    L.append("语言分布: " + ", ".join(f"{k}: {v}" for k, v in by_lang.most_common()))
    L.append("")
    L.append("| 来源 | 源规则 | # | 判定语言 | 原始正则（截断） |")
    L.append("|---|---|---|---|---|")
    for r in rows:
        rx = r["regex_original"].replace("|", "\\|").replace("\n", " ")[:90]
        L.append(f"| {r['source_id']} | {r['source_key']} | {r['ordinal']} | {r['lang_detected']} | `{rx}` |")
    L.append("")
    pruned = []
    for r in conn.execute("SELECT sr.source_id, sr.source_key, sp.ordinal, sp.transform_notes FROM source_patterns sp JOIN "
                          "source_rules sr ON sr.source_rule_id = sp.source_rule_id WHERE sp.transform_notes LIKE '%removed non-target%' "
                          "ORDER BY 1,2,3"):
        for n in json.loads(r["transform_notes"] or "[]"):
            if n.startswith("removed non-target"):
                pruned.append((r["source_id"], r["source_key"], r["ordinal"], n))
    L.append(f"## 保留但剪除了非目标语言分支的模式：{len(pruned)}")
    L.append("")
    L.append("这些模式在英文/中文部分保持原语义；被剪除的是同一正则里的德/西/法/日/韩/俄等备选分支（剪除结果只会让匹配集合变小）。")
    L.append("")
    for s, k, o, n in pruned:
        L.append(f"- {s}:{k}#{o}: {n[:240]}")
    L.append("")
    return "\n".join(L)


def write_all(conn: sqlite3.Connection, outdir: Path) -> List[Path]:
    outdir = Path(outdir)
    written = write_inventory(conn, outdir)
    for name, text in (("coverage.md", coverage_md(conn)), ("language_review.md", language_review_md(conn))):
        atomic_write_text(outdir / name, text)
        written.append(outdir / name)
    return written
