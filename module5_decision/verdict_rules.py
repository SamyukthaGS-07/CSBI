"""
Module 5 — Classification & Decision Model
Currently a rule-based stand-in (weighted signal rules -> probability).
TODO: replace with a trained classifier (Random Forest / XGBoost) once
Module 1's labelled dataset has been scanned through Modules 2-4.
"""

REASON_RULES = [
    ("brand_mismatch", lambda f: f.get("brand_mismatch") == 1,
     lambda f: "Impersonates a known brand not reflected in the domain", 30),
    ("upi_field_presence", lambda f: f.get("upi_field_presence") == 1,
     lambda f: "Collects a UPI payment ID directly on the page", 25),
    ("fake_gov_qr", lambda f: f.get("fake_gov_qr_score", 0) >= 0.9,
     lambda f: "Displays a QR alongside fake government branding", 22),
    ("subsidy_bait", lambda f: f.get("subsidy_refund_language_score", 0) >= 0.5,
     lambda f: "Uses subsidy / refund / cashback bait language", 20),
    ("urgency", lambda f: f.get("urgency_language_score", 0) >= 0.5,
     lambda f: "Pressures the visitor with urgency / threat language", 18),
    ("young_domain", lambda f: 0 < f.get("domain_age_days", 9999) <= 30,
     lambda f: f"Domain registered only {int(f.get('domain_age_days',0))} days ago", 24),
    ("ext_scripts", lambda f: f.get("external_script_ratio", 0) >= 0.3,
     lambda f: "Loads a high ratio of third-party scripts", 10),
    ("no_https", lambda f: f.get("https") == 0,
     lambda f: "Served without HTTPS", 15),
]


def verdict_and_reasons(record):
    f = record["features"]
    csbi = record["CSBI"] or 0.0
    fired = [(w, msg(f)) for _, cond, msg, w in REASON_RULES if cond(f)]
    fired.sort(key=lambda x: -x[0])
    top3 = [msg for _, msg in fired[:3]]
    behaviour = min(sum(w for w, _ in fired) / 80.0, 1.0)
    prob = round(min(0.05 + 0.6 * behaviour + 0.35 * (csbi / 100.0), 0.99), 3)
    risk = "HIGH" if prob >= 0.66 else "MEDIUM" if prob >= 0.33 else "LOW"
    return prob, risk, (top3 or ["No strong scam signals detected"])
