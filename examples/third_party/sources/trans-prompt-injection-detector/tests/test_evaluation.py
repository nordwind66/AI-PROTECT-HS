"""Tests for evaluation functions."""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluator import (
    compute_confusion_matrix,
    compute_metrics,
    load_dataset,
    per_attack_type_detection,
)


class TestConfusionMatrix:
    def test_perfect_predictions(self) -> None:
        y_true = ["normal", "normal", "injection", "injection"]
        y_pred = [False, False, True, True]
        cm = compute_confusion_matrix(y_true, y_pred)
        assert cm["TP"] == 2
        assert cm["TN"] == 2
        assert cm["FP"] == 0
        assert cm["FN"] == 0

    def test_with_false_positives(self) -> None:
        y_true = ["normal", "normal", "injection", "injection"]
        y_pred = [True, False, True, True]
        cm = compute_confusion_matrix(y_true, y_pred)
        assert cm["TP"] == 2
        assert cm["TN"] == 1
        assert cm["FP"] == 1
        assert cm["FN"] == 0

    def test_with_false_negatives(self) -> None:
        y_true = ["injection", "injection", "normal"]
        y_pred = [False, True, False]
        cm = compute_confusion_matrix(y_true, y_pred)
        assert cm["TP"] == 1
        assert cm["TN"] == 1
        assert cm["FP"] == 0
        assert cm["FN"] == 1

    def test_all_normal(self) -> None:
        y_true = ["normal"] * 5
        y_pred = [False] * 5
        cm = compute_confusion_matrix(y_true, y_pred)
        assert cm["TP"] == 0
        assert cm["TN"] == 5
        assert cm["FP"] == 0
        assert cm["FN"] == 0


class TestMetrics:
    def test_perfect_metrics(self) -> None:
        cm = {"TP": 10, "FP": 0, "TN": 90, "FN": 0}
        m = compute_metrics(cm)
        assert m["accuracy"] == 1.0
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0

    def test_mixed_metrics(self) -> None:
        cm = {"TP": 8, "FP": 2, "TN": 88, "FN": 2}
        m = compute_metrics(cm)
        assert m["accuracy"] == 0.96
        assert m["precision"] == 0.8
        assert m["recall"] == 0.8

    def test_zero_division_guard(self) -> None:
        cm = {"TP": 0, "FP": 0, "TN": 100, "FN": 0}
        m = compute_metrics(cm)
        assert m["accuracy"] == 1.0
        assert m["precision"] == 0.0
        assert m["recall"] == 0.0


class TestPerAttackType:
    def test_per_attack_type_counts(self) -> None:
        records = [
            {"attack_type": "ignore_translation_task"},
            {"attack_type": "ignore_translation_task"},
            {"attack_type": "force_game_output"},
            {"attack_type": "none"},
        ]
        results = [
            {"is_attack": True},
            {"is_attack": False},
            {"is_attack": True},
            {"is_attack": False},
        ]
        stats = per_attack_type_detection(records, results)
        assert stats["ignore_translation_task"]["total"] == 2
        assert stats["ignore_translation_task"]["detected"] == 1
        assert stats["ignore_translation_task"]["rate"] == 0.5
        assert stats["force_game_output"]["detected"] == 1
        assert stats["none"]["detected"] == 0


class TestLoadDataset:
    def test_load_dataset_structure(self) -> None:
        dataset_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "translation_pia_dataset_shuffled.jsonl",
        )
        if not os.path.exists(dataset_path):
            return
        records = load_dataset(dataset_path)
        assert len(records) == 1000
        for rec in records:
            assert "id" in rec
            assert "text" in rec
            assert "label" in rec
            assert "attack_type" in rec
