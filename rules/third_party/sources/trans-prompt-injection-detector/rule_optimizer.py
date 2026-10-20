"""规则优化器：分析现有规则，生成优化建议报告（只读，不自动修改规则）。"""
from __future__ import annotations

import os
import re
from typing import Any

from evaluator import EvaluationResult, load_dataset, run_evaluation
from prompt_injection_detector import DETECTION_RULES, detect_injection, preprocess_text


def analyze_false_positives(
    per_record: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    fp_records = [r for r in per_record if r["label"] == "normal" and r["predicted"] == "injection"]
    rule_fp_counts: dict[str, int] = {}
    for rec in fp_records:
        for rule_name in rec["matched_rules"]:
            rule_fp_counts[rule_name] = rule_fp_counts.get(rule_name, 0) + 1
    return [
        {"record": rec, "rules_triggered": rec["matched_rules"]}
        for rec in fp_records
    ]


def analyze_false_negatives(
    per_record: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    fn_records = [r for r in per_record if r["label"] == "injection" and r["predicted"] == "normal"]
    return [
        {
            "id": rec["id"],
            "text": rec["text"],
            "attack_type": rec["attack_type"],
            "score": rec["score"],
        }
        for rec in fn_records
    ]


def suggest_word_boundaries() -> list[dict[str, Any]]:
    suggestions = []
    for rule_set in DETECTION_RULES:
        for pattern in rule_set["patterns"]:
            current = pattern
            improved = pattern

            # Add \b before leading word characters not already anchored
            if not current.startswith(r"\b") and not current.startswith("^"):
                m = re.match(r"^(\w)", current)
                if m:
                    improved = r"\b" + improved

            # Add \b after trailing word characters not already anchored
            if not current.endswith(r"\b") and not current.endswith("$"):
                m = re.search(r"(\w)$", current)
                if m:
                    improved = improved + r"\b"

            if improved != current:
                suggestions.append({
                    "rule_name": rule_set["name"],
                    "category": rule_set["category"],
                    "original": current,
                    "suggested": improved,
                })

    return suggestions


def analyze_rule_overlap() -> list[dict[str, Any]]:
    # Build a co-occurrence analysis: which rule categories fire together?
    if not os.path.exists("translation_pia_dataset_shuffled.jsonl"):
        return []
    from evaluator import load_dataset as ld
    records = ld("translation_pia_dataset_shuffled.jsonl")

    co_occurrence: dict[tuple[str, str], int] = {}
    category_hits: dict[str, int] = {}

    for rec in records:
        text = preprocess_text(rec["text"])
        result = detect_injection(text)
        categories = set()
        for rule_name in result["matched_rules"]:
            for rule_def in DETECTION_RULES:
                if rule_def["name"] == rule_name:
                    categories.add(rule_def["category"])
                    cat = rule_def["category"]
                    category_hits[cat] = category_hits.get(cat, 0) + 1
                    break

        cat_list = sorted(categories)
        for i in range(len(cat_list)):
            for j in range(i + 1, len(cat_list)):
                pair = (cat_list[i], cat_list[j])
                co_occurrence[pair] = co_occurrence.get(pair, 0) + 1

    overlap_report = []
    for (c1, c2), count in sorted(co_occurrence.items(), key=lambda x: -x[1]):
        overlap_report.append({
            "category_1": c1,
            "category_2": c2,
            "co_occurrence_count": count,
        })

    return overlap_report


def suggest_weight_adjustments(
    per_record: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rule_stats: dict[str, dict[str, Any]] = {}
    for rule_def in DETECTION_RULES:
        rule_stats[rule_def["name"]] = {
            "category": rule_def["category"],
            "current_weight": rule_def["weight"],
            "fp_count": 0,
            "fn_missed": 0,
            "tp_count": 0,
        }

    for rec in per_record:
        matched = set(rec["matched_rules"])
        if rec["predicted"] == "injection" and rec["label"] == "normal":
            for rn in matched:
                if rn in rule_stats:
                    rule_stats[rn]["fp_count"] += 1

        if rec["predicted"] == "normal" and rec["label"] == "injection":
            pass

        if rec["predicted"] == "injection" and rec["label"] == "injection":
            for rn in matched:
                if rn in rule_stats:
                    rule_stats[rn]["tp_count"] += 1

    suggestions = []
    for name, stats in rule_stats.items():
        if stats["fp_count"] > 0 or stats["tp_count"] > 0:
            suggestions.append(stats)

    return suggestions


def generate_optimization_report(
    result: EvaluationResult | None = None,
    output_path: str = "rule_optimization_report.md",
) -> None:
    if result is None:
        try:
            result = run_evaluation(detect_injection, "translation_pia_dataset_shuffled.jsonl")
        except FileNotFoundError:
            print("Dataset not found, cannot generate optimization report.")
            return

    per_record = result.per_record_predictions
    fps = analyze_false_positives(per_record)
    fns = analyze_false_negatives(per_record)
    boundary_suggestions = suggest_word_boundaries()
    overlaps = analyze_rule_overlap()
    weight_suggestions = suggest_weight_adjustments(per_record)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Rule Optimization Report\n\n")
        f.write(f"**Timestamp**: {result.timestamp}  \n")
        f.write(f"**Baseline**: Accuracy={result.accuracy:.4f}, F1={result.f1:.4f}  \n\n")

        # Section 1: FP Analysis
        f.write("## 1. False Positive Analysis\n\n")
        if fps:
            f.write(f"**Total FPs**: {len(fps)}  \n\n")
            f.write("| # | Text | Rules Triggered |\n")
            f.write("|---|------|----------------|\n")
            for i, fp in enumerate(fps[:20], 1):
                text_preview = fp["record"]["text"][:80].replace("\n", " ")
                rules = ", ".join(fp["rules_triggered"])
                f.write(f"| {i} | {text_preview} | {rules} |\n")
        else:
            f.write("**No false positives found** on the current dataset.  \n")
            f.write("This is ideal, but be aware: the regex rules may still produce FPs on unseen text. ")
            f.write("The word boundary suggestions in Section 3 can help reduce this risk.\n")

        # Section 2: FN Analysis
        f.write("\n## 2. False Negative Analysis\n\n")
        if fns:
            f.write(f"**Total FNs**: {len(fns)}  \n\n")
            f.write("| # | ID | Attack Type | Score | Text Preview |\n")
            f.write("|---|----|------------|-------|-------------|\n")
            for i, fn in enumerate(fns, 1):
                text_preview = fn["text"][:100].replace("\n", " ")
                f.write(f"| {i} | {fn['id']} | {fn['attack_type']} | {fn['score']} | {text_preview} |\n")
        else:
            f.write("**No false negatives found** on the current dataset.\n")

        # Section 3: Word Boundary Suggestions
        f.write(f"\n## 3. Word Boundary Suggestions ({len(boundary_suggestions)} patterns)\n\n")
        f.write("These patterns could benefit from `\\b` anchoring to reduce false positives on unseen text:\n\n")
        f.write("| Rule | Original | Suggested |\n")
        f.write("|------|----------|----------|\n")
        for s in boundary_suggestions:
            orig = s["original"].replace("|", "\\|")
            sugg = s["suggested"].replace("|", "\\|")
            f.write(f"| {s['rule_name']} | `{orig}` | `{sugg}` |\n")

        # Section 4: Overlap Analysis
        f.write(f"\n## 4. Rule Category Overlap Analysis\n\n")
        if overlaps:
            f.write("Categories that frequently fire together on the same text:\n\n")
            f.write("| Category 1 | Category 2 | Co-occurrence |\n")
            f.write("|-----------|-----------|--------------|\n")
            for o in overlaps:
                f.write(f"| {o['category_1']} | {o['category_2']} | {o['co_occurrence_count']} |\n")
        else:
            f.write("No significant overlap detected.\n")

        # Section 5: Weight Suggestions
        f.write("\n## 5. Weight Tuning Suggestions\n\n")
        if weight_suggestions:
            f.write("| Rule | Weight | TP | FP | Suggestion |\n")
            f.write("|------|--------|----|----|-----------|\n")
            for ws in weight_suggestions:
                suggestion = "Keep current weight"
                if ws["fp_count"] > 0:
                    suggestion = f"Consider reducing (has {ws['fp_count']} FPs)"
                f.write(f"| {ws['category']} | {ws['current_weight']} | {ws['tp_count']} | {ws['fp_count']} | {suggestion} |\n")
        else:
            f.write("No weight adjustments needed based on current evaluation data.\n")

        # Section 6: Summary
        f.write("\n## 6. Summary of Recommended Changes\n\n")
        if not fps and not fns:
            f.write("- **Current status**: Perfect on this dataset (100% accuracy).\n")
        f.write(f"- **Apply word boundary anchoring** to {len(boundary_suggestions)} patterns to improve robustness on unseen text.\n")
        f.write("- **Manually review** each suggested change before applying — re-run evaluation after each batch.\n")
        f.write("- **Test on adversarial examples** beyond the current dataset to validate robustness.\n")

    print(f"\n[Optimization report saved to {output_path}]")
