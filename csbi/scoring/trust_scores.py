"""
csbi.scoring.trust_scores
==========================
Per-layer trust scores T1..T4 (Blueprint §4.1). Each normalised to [0, 1],
where 1 = looks fully legitimate. These feed the CSBI aggregator (§4.2).

    T1 (Structural) = 0.30·HTTPS
                    + 0.20·(1 − norm_url_length)
                    + 0.20·(1 − norm_subdomain_count)
                    + 0.15·(1 − is_IP_domain)
                    + 0.15·(1 − special_char_ratio)

    T2 (Temporal)   = 0.40·min(domain_age_days / 365, 1)
                    + 0.35·min(ssl_age_days / 365, 1)
                    + 0.25·min(registration_years / 5, 1)

    T3 (Behavioral) = 1 − [0.40·brand_mismatch
                    + 0.35·urgency_language_score
                    + 0.25·external_script_ratio]

    T4 (UPI)        = 1 − [0.40·upi_field_presence
                    + 0.35·subsidy_refund_language_score
                    + 0.25·fake_gov_qr_score]

Weights are the blueprint's reasoned starting point and are meant to be revisited
with SHAP feature-importance after training (§4, §10) — kept as module constants
so that refinement is a one-line change and reportable in the paper.

Input: the raw `features` dict produced by the extraction layers (the same dict
stored in ScanRecord.features). Missing temporal values (e.g. WHOIS unavailable)
are treated as 0 = least trust; the layer-2 extractor is responsible for the
CT-log fallback (§10) that populates a proxy age before scoring.
"""

from __future__ import annotations

from typing import Mapping

try:
    from config.settings import SUBDOMAIN_NORM_CAP
except Exception:
    SUBDOMAIN_NORM_CAP = 3

# --- §4.1 weight vectors (revisit with SHAP; see §4/§10) ----------------------
W_T1 = {"https": 0.30, "url_len": 0.20, "subdomain": 0.20, "ip": 0.15, "special": 0.15}
W_T2 = {"domain_age": 0.40, "ssl_age": 0.35, "registration": 0.25}
W_T3 = {"brand_mismatch": 0.40, "urgency": 0.35, "external_script": 0.25}
W_T4 = {"upi_field": 0.40, "subsidy": 0.35, "fake_gov_qr": 0.25}

DOMAIN_AGE_CAP_DAYS = 365
SSL_AGE_CAP_DAYS = 365
REGISTRATION_CAP_YEARS = 5


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _num(features: Mapping[str, object], key: str, default: float = 0.0) -> float:
    v = features.get(key, default)
    return float(default) if v is None else float(v)


def t1_structural(features: Mapping[str, object]) -> float:
    https = _num(features, "https")
    norm_url_length = _clamp01(_num(features, "url_length_norm"))
    norm_subdomain = _clamp01(_num(features, "subdomain_count") / SUBDOMAIN_NORM_CAP)
    is_ip = _num(features, "is_ip_domain")
    special = _clamp01(_num(features, "special_char_ratio"))
    return round(
        W_T1["https"] * https
        + W_T1["url_len"] * (1 - norm_url_length)
        + W_T1["subdomain"] * (1 - norm_subdomain)
        + W_T1["ip"] * (1 - is_ip)
        + W_T1["special"] * (1 - special),
        4,
    )


def t2_temporal(features: Mapping[str, object]) -> float:
    domain_age = min(_num(features, "domain_age_days") / DOMAIN_AGE_CAP_DAYS, 1.0)
    ssl_age = min(_num(features, "ssl_age_days") / SSL_AGE_CAP_DAYS, 1.0)
    registration = min(_num(features, "registration_years") / REGISTRATION_CAP_YEARS, 1.0)
    return round(
        W_T2["domain_age"] * domain_age
        + W_T2["ssl_age"] * ssl_age
        + W_T2["registration"] * registration,
        4,
    )


def t3_behavioral(features: Mapping[str, object]) -> float:
    penalty = (
        W_T3["brand_mismatch"] * _clamp01(_num(features, "brand_mismatch"))
        + W_T3["urgency"] * _clamp01(_num(features, "urgency_language_score"))
        + W_T3["external_script"] * _clamp01(_num(features, "external_script_ratio"))
    )
    return round(1.0 - penalty, 4)


def t4_upi(features: Mapping[str, object]) -> float:
    penalty = (
        W_T4["upi_field"] * _clamp01(_num(features, "upi_field_presence"))
        + W_T4["subsidy"] * _clamp01(_num(features, "subsidy_refund_language_score"))
        + W_T4["fake_gov_qr"] * _clamp01(_num(features, "fake_gov_qr_score"))
    )
    return round(1.0 - penalty, 4)


def all_trust_scores(features: Mapping[str, object]) -> dict[str, float]:
    """Compute all four trust scores from the raw feature dict."""
    return {
        "T1": t1_structural(features),
        "T2": t2_temporal(features),
        "T3": t3_behavioral(features),
        "T4": t4_upi(features),
    }
