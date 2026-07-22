from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from csbi.common.schema import ScanRecord
from csbi.extraction.fetch import fetch_url, save_snapshot
from csbi.extraction.layer1_structural import extract_structural_features
from csbi.extraction.layer2_temporal import extract_temporal_features
from csbi.extraction.layer3_behavioral import extract_behavioral_features
from csbi.extraction.layer4_upi import extract_upi_features


def extract_features(url: str, snapshot_dir: Path | None = None) -> ScanRecord:
    fetch_result = fetch_url(url)
    features = {}
    features.update(extract_structural_features(url))
    features.update(extract_temporal_features())
    features.update(extract_behavioral_features(fetch_result.html))
    features.update(extract_upi_features(fetch_result.html))
    if snapshot_dir is not None:
        features["snapshot_path"] = str(save_snapshot(snapshot_dir, url, fetch_result.html))
    return ScanRecord(url=url, status="fetched", features=features)
