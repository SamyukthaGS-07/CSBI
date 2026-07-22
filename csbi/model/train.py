from __future__ import annotations

from pathlib import Path


def train_models(dataset_path: Path, artifacts_dir: Path) -> dict[str, str]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    return {"primary": str(artifacts_dir / "random_forest.pkl"), "comparison": str(artifacts_dir / "xgboost.json")}
