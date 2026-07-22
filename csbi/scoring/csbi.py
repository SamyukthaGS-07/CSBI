from __future__ import annotations


def compute_csbi(trust_score: float, scam_score: float) -> float:
    return max(0.0, 100.0 * max(0.0, scam_score - trust_score))
