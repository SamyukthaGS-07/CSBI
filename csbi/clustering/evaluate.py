from __future__ import annotations


def evaluate_clusters(records: list[dict[str, object]]) -> dict[str, float]:
    return {"silhouette": 0.0, "purity": 0.0}
