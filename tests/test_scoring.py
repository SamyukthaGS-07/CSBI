"""
tests.test_scoring
==================
Pure scoring math: T1..T4 formulas (§4.1) and the CSBI aggregator (§4.2).
Expected values are hand-computed in comments so a reviewer can trace every one.
"""

import pytest

from csbi.scoring import trust_scores as ts
from csbi.scoring.csbi import compute_csbi, credibility, substance


# --- CSBI aggregator (§4.2) --------------------------------------------------
def test_worked_example_csbi_65():
    # §5: T1=0.85, T2=0.70, T3=0.15, T4=0.10 -> CSBI ~= 65
    assert compute_csbi(T1=0.85, T2=0.70, T3=0.15, T4=0.10) == pytest.approx(65.0, abs=0.5)


def test_credibility_and_substance_components():
    trust = {"T1": 0.85, "T2": 0.70, "T3": 0.15, "T4": 0.10}
    assert credibility(trust) == pytest.approx(0.775)
    assert substance(trust) == pytest.approx(0.125)


def test_csbi_clamped_at_zero():
    assert compute_csbi(T1=0.1, T2=0.1, T3=0.9, T4=0.9) == 0.0


def test_csbi_full_range_max():
    assert compute_csbi(T1=1.0, T2=1.0, T3=0.0, T4=0.0) == 100.0


@pytest.mark.parametrize("bad", [-0.1, 1.1, 2.0])
def test_out_of_range_trust_rejected(bad):
    with pytest.raises(ValueError):
        compute_csbi(T1=bad, T2=0.5, T3=0.5, T4=0.5)


# --- Per-layer trust scores (§4.1) -------------------------------------------
def test_t1_structural_handcalc():
    f = {"https": 1, "url_length_norm": 0.30, "subdomain_count": 1,
         "is_ip_domain": 0, "special_char_ratio": 0.10}
    # 0.30·1 + 0.20·0.70 + 0.20·(1−1/3) + 0.15·1 + 0.15·0.90 = 0.8583
    assert ts.t1_structural(f) == pytest.approx(0.8583, abs=1e-4)


def test_t2_temporal_handcalc():
    f = {"domain_age_days": 365, "ssl_age_days": 182.5, "registration_years": 5}
    # 0.40·1 + 0.35·0.5 + 0.25·1 = 0.825
    assert ts.t2_temporal(f) == pytest.approx(0.825, abs=1e-4)


def test_t2_caps_at_one_year_and_five_years():
    f = {"domain_age_days": 10000, "ssl_age_days": 10000, "registration_years": 50}
    assert ts.t2_temporal(f) == pytest.approx(1.0)


def test_t3_behavioral_handcalc():
    f = {"brand_mismatch": 1, "urgency_language_score": 0.5, "external_script_ratio": 0.2}
    # 1 − (0.40 + 0.175 + 0.05) = 0.375
    assert ts.t3_behavioral(f) == pytest.approx(0.375, abs=1e-4)


def test_t4_upi_handcalc():
    f = {"upi_field_presence": 1, "subsidy_refund_language_score": 0.8, "fake_gov_qr_score": 0.5}
    # 1 − (0.40 + 0.28 + 0.125) = 0.195
    assert ts.t4_upi(f) == pytest.approx(0.195, abs=1e-4)


def test_clean_legit_site_maxes_behavioral_layers():
    f = {"brand_mismatch": 0, "urgency_language_score": 0, "external_script_ratio": 0,
         "upi_field_presence": 0, "subsidy_refund_language_score": 0, "fake_gov_qr_score": 0}
    assert ts.t3_behavioral(f) == pytest.approx(1.0)
    assert ts.t4_upi(f) == pytest.approx(1.0)


def test_missing_temporal_features_score_zero():
    assert ts.t2_temporal({}) == pytest.approx(0.0)
