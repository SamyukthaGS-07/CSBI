from __future__ import annotations


def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    return {"precision": 0.0, "recall": 0.0, "f1": 0.0, "roc_auc": 0.0}
