from __future__ import annotations

from csbi.clustering.evaluate import evaluate_clusters


def run_clustering_eval(records: list[dict[str, object]]) -> dict[str, float]:
    return evaluate_clusters(records)
