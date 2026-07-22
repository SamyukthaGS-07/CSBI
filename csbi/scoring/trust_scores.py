from __future__ import annotations


def compute_trust_scores(features: dict[str, object]) -> dict[str, float]:
    structural = 1.0 if features.get("has_ip_host") else 0.5
    behavioral = max(0.0, 1.0 - float(features.get("login_mentions", 0)) * 0.1)
    temporal = 1.0 if features.get("whois_available") else 0.6
    upi = 1.0 if not features.get("has_upi_vpa") else 0.4
    return {"T1": structural, "T2": behavioral, "T3": temporal, "T4": upi}
