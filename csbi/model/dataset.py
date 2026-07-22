from __future__ import annotations

from pathlib import Path

import pandas as pd

from csbi.common.store import query


def build_training_matrix(store_path: Path, limit: int = 1000) -> pd.DataFrame:
    return pd.DataFrame(list(query(store_path, limit=limit)))
