"""
evaluation.metrics
==================
Metrics reported for every model in the paper.

Beyond accuracy / precision / recall / F1 / ROC-AUC we report:
  * PR-AUC (average precision) — honest under class imbalance.
  * TPR @ 1% FPR and TPR @ 0.1% FPR — what a browser warning actually needs:
    a detector that flags 5% of legitimate sites is unusable, whatever its
    accuracy.
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score, f1_score,
                             precision_score, recall_score, roc_auc_score, roc_curve)


def tpr_at_fpr(y_true, scores, fpr_target: float) -> float:
    y_true = np.asarray(y_true)
    if len(np.unique(y_true)) < 2:
        return float("nan")
    fpr, tpr, _ = roc_curve(y_true, scores)
    ok = fpr <= fpr_target
    return float(tpr[ok].max()) if ok.any() else 0.0


def compute_metrics(y_true, y_pred=None, scores=None, threshold: float = 0.5) -> dict[str, float]:
    y_true = np.asarray(y_true).astype(int)
    if scores is not None:
        scores = np.asarray(scores, dtype=float)
        if y_pred is None:
            y_pred = (scores >= threshold).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    both = len(np.unique(y_true)) == 2
    out = {
        "n": int(len(y_true)),
        "n_pos": int(y_true.sum()),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(((y_pred == 1) & (y_true == 0)).sum() / max((y_true == 0).sum(), 1)),
    }
    if scores is not None and both:
        out["roc_auc"] = float(roc_auc_score(y_true, scores))
        out["pr_auc"] = float(average_precision_score(y_true, scores))
        out["tpr_at_1fpr"] = tpr_at_fpr(y_true, scores, 0.01)
        out["tpr_at_01fpr"] = tpr_at_fpr(y_true, scores, 0.001)
    else:
        out.update({"roc_auc": float("nan"), "pr_auc": float("nan"),
                    "tpr_at_1fpr": float("nan"), "tpr_at_01fpr": float("nan")})
    return out


def bootstrap_ci(y_true, scores, metric="f1", threshold=0.5, n=1000, seed=0) -> tuple[float, float]:
    """95% bootstrap CI for one metric (used for the headline numbers)."""
    rng = np.random.default_rng(seed)
    y_true, scores = np.asarray(y_true), np.asarray(scores)
    vals = []
    for _ in range(n):
        idx = rng.integers(0, len(y_true), len(y_true))
        if len(np.unique(y_true[idx])) < 2:
            continue
        vals.append(compute_metrics(y_true[idx], scores=scores[idx], threshold=threshold)[metric])
    return (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))) if vals else (float("nan"),) * 2
