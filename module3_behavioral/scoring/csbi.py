"""
csbi.scoring.csbi
=================
The CSBI aggregator (Blueprint §4.2).

    CSBI = 100 * max(0, C - S)

Cross-Signal Behavioral Inconsistency measures the gap between how trustworthy a
site *looks* on its surface signals and how trustworthy it actually *behaves*.
A scam site is often near-immaculate on the surface (valid HTTPS, plausible URL)
while behaving suspiciously (brand mismatch, urgency, UPI subsidy bait). That
gap is the signal.

    C = mean(surface-credibility trust scores)   -> structural (T1), temporal (T2)
    S = mean(behavioral-substance trust scores)  -> behavioral (T3), UPI (T4)

Each T is a trust score in [0, 1] where higher = more trustworthy. When the
surface is trustworthy (C high) but behavior is not (S low), C - S is large and
CSBI climbs toward 100.

Worked example (§5):  T1=0.85, T2=0.70, T3=0.15, T4=0.10
    C = (0.85 + 0.70) / 2 = 0.775
    S = (0.15 + 0.10) / 2 = 0.125
    CSBI = 100 * max(0, 0.775 - 0.125) = 65.0     ✓ matches the blueprint

Confirmed against Blueprint §4.2: C = 0.5·T1 + 0.5·T2, S = 0.5·T3 + 0.5·T4.
The grouping lives in config.settings (CSBI_C_LAYERS / CSBI_S_LAYERS) so any
future reweighting (e.g. after SHAP sensitivity analysis) is a one-line change.
"""

from __future__ import annotations

from typing import Mapping

try:
    from config.settings import CSBI_C_LAYERS, CSBI_S_LAYERS
except Exception:
    CSBI_C_LAYERS = ("T1", "T2")
    CSBI_S_LAYERS = ("T3", "T4")


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def credibility(trust: Mapping[str, float]) -> float:
    """C — surface-credibility component, mean of CSBI_C_LAYERS trust scores."""
    return _mean([float(trust[name]) for name in CSBI_C_LAYERS])


def substance(trust: Mapping[str, float]) -> float:
    """S — behavioral-substance component, mean of CSBI_S_LAYERS trust scores."""
    return _mean([float(trust[name]) for name in CSBI_S_LAYERS])


def compute_csbi(T1: float, T2: float, T3: float, T4: float) -> float:
    """CSBI = 100 * max(0, C - S), rounded to 2 dp. All Tn in [0, 1]."""
    trust = {"T1": T1, "T2": T2, "T3": T3, "T4": T4}
    for name, v in trust.items():
        if not (0.0 <= float(v) <= 1.0):
            raise ValueError(f"{name} must be in [0, 1], got {v}")
    c = credibility(trust)
    s = substance(trust)
    return round(100.0 * max(0.0, c - s), 2)
