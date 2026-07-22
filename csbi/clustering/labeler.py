from __future__ import annotations


def label_cluster(cluster_id: str, human_label: str) -> dict[str, str]:
    return {"cluster_id": cluster_id, "label": human_label}
