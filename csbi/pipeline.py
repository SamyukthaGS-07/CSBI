from __future__ import annotations

from pathlib import Path

from csbi.common.schema import ScanRecord
from csbi.extraction.extractor import extract_features
from csbi.model.predict import predict_risk
from csbi.scoring.csbi import compute_csbi
from csbi.scoring.trust_scores import compute_trust_scores


def run_pipeline(url: str, snapshot_dir: Path | None = None) -> ScanRecord:
    record = extract_features(url, snapshot_dir=snapshot_dir)
    trust_scores = compute_trust_scores(record.features)
    prediction = predict_risk(record.features)
    record.trust_score = sum(trust_scores.values()) / max(len(trust_scores), 1)
    record.scam_probability = float(prediction["scam_probability"])
    record.csbi_score = compute_csbi(record.trust_score, record.scam_probability)
    record.risk_label = str(prediction["risk"])
    record.reasons = ["trust gap", "behavioral signals", "upi exposure"]
    return record
