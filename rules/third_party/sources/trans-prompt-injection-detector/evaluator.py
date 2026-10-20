"""评估模块：对比检测器输出与 ground truth 标签，计算所有标准指标。"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Callable

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


@dataclass
class EvaluationResult:
    total_samples: int
    confusion_matrix: dict[str, int]
    accuracy: float
    precision: float
    recall: float
    f1: float
    specificity: float
    per_attack_type: dict[str, dict[str, Any]]
    per_record_predictions: list[dict[str, Any]]
    score_distribution: dict[str, list[int]]
    timestamp: str


def load_dataset(filepath: str) -> list[dict[str, Any]]:
    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def compute_confusion_matrix(y_true: list[str], y_pred: list[bool]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for true_label, pred_attack in zip(y_true, y_pred):
        actual_attack = true_label == "injection"
        if actual_attack and pred_attack:
            tp += 1
        elif actual_attack and not pred_attack:
            fn += 1
        elif not actual_attack and pred_attack:
            fp += 1
        else:
            tn += 1
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn}


def compute_metrics(cm: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = cm["TP"], cm["FP"], cm["TN"], cm["FN"]
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "specificity": round(specificity, 4),
    }


def per_attack_type_detection(
    records: list[dict[str, Any]], results: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for rec, res in zip(records, results):
        atype = rec.get("attack_type", "none")
        if atype not in groups:
            groups[atype] = {"total": 0, "detected": 0}
        groups[atype]["total"] += 1
        if res["is_attack"]:
            groups[atype]["detected"] += 1
    for atype, stats in groups.items():
        stats["rate"] = round(stats["detected"] / stats["total"], 4) if stats["total"] > 0 else 0.0
    return groups


def run_evaluation(
    detector_fn: Callable[[str], dict[str, Any]],
    dataset_path: str,
) -> EvaluationResult:
    from datetime import datetime
    from prompt_injection_detector import preprocess_text

    records = load_dataset(dataset_path)
    y_true: list[str] = []
    y_pred: list[bool] = []
    per_record: list[dict[str, Any]] = []
    normal_scores: list[int] = []
    injection_scores: list[int] = []

    for rec in records:
        text = rec["text"]
        cleaned = preprocess_text(text)
        result = detector_fn(cleaned)

        label = rec.get("label", "normal")
        y_true.append(label)
        y_pred.append(result["is_attack"])

        score = result["score"]
        if label == "injection":
            injection_scores.append(score)
        else:
            normal_scores.append(score)

        per_record.append({
            "id": rec.get("id", ""),
            "text": text,
            "label": label,
            "predicted": "injection" if result["is_attack"] else "normal",
            "score": score,
            "risk_level": result["risk_level"],
            "matched_rules": result.get("matched_rules", []),
            "matched_details": [
                (name, ctx) for name, ctx in result.get("matched_details", [])
            ],
            "attack_type": rec.get("attack_type", "none"),
            "correct": (label == "injection") == result["is_attack"],
        })

    cm = compute_confusion_matrix(y_true, y_pred)
    metrics = compute_metrics(cm)
    per_attack = per_attack_type_detection(records, [
        {"is_attack": p} for p in y_pred
    ])

    return EvaluationResult(
        total_samples=len(records),
        confusion_matrix=cm,
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1=metrics["f1"],
        specificity=metrics["specificity"],
        per_attack_type=per_attack,
        per_record_predictions=per_record,
        score_distribution={"normal": normal_scores, "injection": injection_scores},
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def save_evaluation_reports(result: EvaluationResult, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # JSON report
    json_path = os.path.join(output_dir, "evaluation_report.json")
    json_data = {
        "timestamp": result.timestamp,
        "total_samples": result.total_samples,
        "confusion_matrix": result.confusion_matrix,
        "metrics": {
            "accuracy": result.accuracy,
            "precision": result.precision,
            "recall": result.recall,
            "f1": result.f1,
            "specificity": result.specificity,
        },
        "per_attack_type": {
            k: {"total": v["total"], "detected": v["detected"], "rate": v["rate"]}
            for k, v in result.per_attack_type.items()
        },
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, ensure_ascii=False, indent=2)

    # Markdown report
    md_path = os.path.join(output_dir, "evaluation_report.md")
    cm = result.confusion_matrix
    total = result.total_samples
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Evaluation Report\n\n")
        f.write(f"**Timestamp**: {result.timestamp}  \n")
        f.write(f"**Total Samples**: {total}  \n\n")

        f.write("## Metrics\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Accuracy | {result.accuracy:.4f} |\n")
        f.write(f"| Precision | {result.precision:.4f} |\n")
        f.write(f"| Recall | {result.recall:.4f} |\n")
        f.write(f"| F1 Score | {result.f1:.4f} |\n")
        f.write(f"| Specificity | {result.specificity:.4f} |\n\n")

        f.write("## Confusion Matrix\n\n")
        f.write("|  | Predicted Normal | Predicted Injection |\n")
        f.write("|--|-----------------|--------------------|\n")
        f.write(f"| **Actual Normal** | TN = {cm['TN']} | FP = {cm['FP']} |\n")
        f.write(f"| **Actual Injection** | FN = {cm['FN']} | TP = {cm['TP']} |\n\n")

        f.write("## Per Attack Type Detection Rate\n\n")
        f.write("| Attack Type | Total | Detected | Rate |\n")
        f.write("|------------|-------|----------|------|\n")
        for atype, stats in sorted(result.per_attack_type.items()):
            f.write(f"| {atype} | {stats['total']} | {stats['detected']} | {stats['rate']:.2%} |\n")

    print(f"\n[JSON report saved to {json_path}]")
    print(f"[Markdown report saved to {md_path}]")


def plot_evaluation_charts(result: EvaluationResult, output_dir: str) -> None:
    if not HAS_MATPLOTLIB:
        print("\n(matplotlib not installed, skipping evaluation charts)")
        return

    os.makedirs(output_dir, exist_ok=True)
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "SimHei", "Microsoft YaHei", "Arial"]
    plt.rcParams["axes.unicode_minus"] = False

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # 1. Confusion matrix heatmap
    ax1 = axes[0][0]
    cm = result.confusion_matrix
    cm_data = [[cm["TN"], cm["FP"]], [cm["FN"], cm["TP"]]]
    im = ax1.imshow(cm_data, cmap="Blues", interpolation="nearest")
    ax1.set_xticks([0, 1])
    ax1.set_xticklabels(["Predicted Normal", "Predicted Injection"])
    ax1.set_yticks([0, 1])
    ax1.set_yticklabels(["Actual Normal", "Actual Injection"])
    ax1.set_title("Confusion Matrix", fontsize=14, fontweight="bold", pad=10)
    for i in range(2):
        for j in range(2):
            ax1.text(j, i, str(cm_data[i][j]), ha="center", va="center",
                     fontsize=18, fontweight="bold",
                     color="white" if cm_data[i][j] > (cm_data[0][0] / 2) else "black")
    plt.colorbar(im, ax=ax1, shrink=0.75)

    # 2. Per attack type detection rate
    ax2 = axes[0][1]
    pa = result.per_attack_type
    types = [k for k in sorted(pa.keys()) if k != "none"]
    rates = [pa[t]["rate"] * 100 for t in types]
    colors = ["#4CAF50" if r >= 80 else "#FF9800" if r >= 50 else "#F44336" for r in rates]
    bars = ax2.barh(types, rates, color=colors, edgecolor="black", height=0.6)
    ax2.set_title("Detection Rate by Attack Type", fontsize=14, fontweight="bold", pad=10)
    ax2.set_xlabel("Detection Rate (%)")
    ax2.set_xlim(0, 105)
    for bar, r in zip(bars, rates):
        ax2.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                 f"{r:.1f}%", va="center", fontsize=9)

    # 3. Score distribution (normal vs injection)
    ax3 = axes[1][0]
    sd = result.score_distribution
    score_max = max(max(sd["normal"], default=0), max(sd["injection"], default=0))
    bins = range(0, score_max + 2, 1)
    ax3.hist(sd["normal"], bins=bins, alpha=0.7, label="Normal", color="#4CAF50", edgecolor="black", rwidth=0.85)
    ax3.hist(sd["injection"], bins=bins, alpha=0.7, label="Injection", color="#F44336", edgecolor="black", rwidth=0.85)
    ax3.set_title("Score Distribution (Normal vs Injection)", fontsize=14, fontweight="bold", pad=10)
    ax3.set_xlabel("Score")
    ax3.set_ylabel("Count")
    ax3.legend()

    # 4. Metrics bar chart
    ax4 = axes[1][1]
    metric_names = ["Accuracy", "Precision", "Recall", "F1", "Specificity"]
    metric_vals = [result.accuracy, result.precision, result.recall, result.f1, result.specificity]
    bars = ax4.bar(metric_names, metric_vals,
                   color=["#2196F3", "#9C27B0", "#FF5722", "#009688", "#607D8B"],
                   edgecolor="black", width=0.5)
    ax4.set_title("Performance Metrics", fontsize=14, fontweight="bold", pad=10)
    ax4.set_ylim(0, 1.1)
    ax4.set_ylabel("Score")
    for bar, v in zip(bars, metric_vals):
        ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015,
                 f"{v:.4f}", ha="center", fontsize=11, fontweight="bold")

    plt.subplots_adjust(hspace=0.4, wspace=0.35)
    chart_path = os.path.join(output_dir, "evaluation_charts.png")
    plt.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[Charts saved to {chart_path}]")
