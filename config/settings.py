from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
STORE_DIR = DATA_DIR / "store"
DEFAULT_STORE_PATH = STORE_DIR / "scans.sqlite3"

RISK_THRESHOLD = 0.7
CSBI_THRESHOLD = 50
SNAPSHOT_RETENTION_DAYS = 30


@dataclass(frozen=True)
class Settings:
    base_dir: Path = BASE_DIR
    data_dir: Path = DATA_DIR
    artifacts_dir: Path = ARTIFACTS_DIR
    store_path: Path = DEFAULT_STORE_PATH
    risk_threshold: float = RISK_THRESHOLD
    csbi_threshold: int = CSBI_THRESHOLD
    snapshot_retention_days: int = SNAPSHOT_RETENTION_DAYS


settings = Settings()
