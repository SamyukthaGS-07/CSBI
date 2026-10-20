"""
module3_behavioral.scoring.platform_aware
=========================================
Platform-aware extension of CSBI (CSBI-PA) and the Borrowed-Credibility score.

    C          = mean(T1, T2)                apparent surface credibility (as before)
    C_earned   = mean(T1_earned, T2_earned)  only signals the publisher controls
    BC         = C - C_earned                borrowed credibility, in [0, 1]

On a free host the certificate, WHOIS age and registration length all belong
to the platform, so T2_earned = 0 and T1_earned drops the HTTPS credit. On a
self-hosted site nothing is borrowed and BC = 0.

    T5         = 1 - [0.30 * impersonation (page or subdomain)
                      + 0.25 * credential collection
                      + 0.25 * third-party exfiltration endpoint
                      + 0.20 * cross-site form target]
    S_PA       = min(T3, T4, T5)
    CSBI_PA    = 100 * max(0, C - S_PA)

Why min instead of the original mean: behavioural evidence is not additive.
A page that harvests passwords into a Telegram bot is not made safer by having
no UPI content, but mean(T3, T4, T5) lets an empty T4 = 1.0 dilute the one
layer that fired. Weakest-link aggregation keeps a single strong behavioural
red flag from being averaged away. (The original CSBI, which uses the mean, is
kept unchanged so both can be compared in the ablation.)

As with T1-T4, the T5 weights are a definitional rubric, not learned. The
trained classifier sees the raw features underneath, so the paper reports both
the rubric score and what the model learns from the raw signals.
"""
from __future__ import annotations

from typing import Mapping

from module3_behavioral.scoring.trust_scores import W_T1


def _f(features: Mapping, key: str) -> float:
    v = features.get(key, 0)
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def earned_trust(features: Mapping, T1: float, T2: float) -> tuple[float, float]:
    if not _f(features, "free_hosted"):
        return T1, T2
    t1_earned = max(0.0, T1 - W_T1["https"] * _f(features, "https"))
    return round(t1_earned, 4), 0.0


def t5_platform(features: Mapping) -> float:
    imp = max(_f(features, "p5_brand_impersonation"), _f(features, "p5_tenant_brand"))
    penalty = (0.30 * imp
               + 0.25 * _f(features, "p5_cred_form")
               + 0.25 * _f(features, "p5_exfil_endpoint")
               + 0.20 * _f(features, "p5_form_cross_site"))
    return round(max(0.0, min(1.0, 1.0 - penalty)), 4)


def platform_scores(features: Mapping, T1: float, T2: float, T3: float, T4: float) -> dict:
    c = (T1 + T2) / 2
    t1e, t2e = earned_trust(features, T1, T2)
    c_earned = (t1e + t2e) / 2
    t5 = t5_platform(features)
    s_pa = min(T3, T4, t5)
    return {
        "T5": t5,
        "C_apparent": round(c, 4),
        "C_earned": round(c_earned, 4),
        "borrowed_credibility": round(max(0.0, c - c_earned), 4),
        "CSBI_PA": round(100.0 * max(0.0, c - s_pa), 2),
    }
