from __future__ import annotations


def cluster_records(records: list[dict[str, object]], eps: float = 0.5, min_samples: int = 5) -> dict[str, object]:
    return {"clusters": [], "eps": eps, "min_samples": min_samples}
