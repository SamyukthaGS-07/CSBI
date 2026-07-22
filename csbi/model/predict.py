from __future__ import annotations


def predict_risk(features: dict[str, object]) -> dict[str, object]:
    scam_probability = 0.5
    trust = 0.5
    risk = "medium"
    return {"scam_probability": scam_probability, "trust": trust, "risk": risk}
