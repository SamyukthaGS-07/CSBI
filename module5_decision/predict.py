"""
module5_decision.predict
========================
Production inference: trained model -> probability, risk level, top-3 reasons.

Reasons are the features with the largest positive SHAP contribution for this
page (TreeSHAP, computed natively by XGBoost via pred_contribs), translated to
plain language. Only features that pushed the score *towards* phishing are
shown, so a legitimate verdict never lists alarming reasons.

This replaces the rule-based stand-in in verdict_rules.py, which is kept only
as a fallback when no trained model is present.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

ARTIFACT = Path(__file__).resolve().parent / "artifacts" / "csbi_model.joblib"


def _yes(v) -> bool:
    try:
        return float(v) > 0
    except (TypeError, ValueError):
        return False


# feature -> function(value, features) -> reason text (or None to skip)
REASON_TEXT: dict[str, Any] = {
    "p5_brand_impersonation": lambda v, f: (f"Presents itself as {f.get('_claimed_brand') or 'a known brand'}, "
                                            "but the brand does not own this domain") if _yes(v) else None,
    "p5_tenant_brand": lambda v, f: "Puts a brand name in a subdomain the brand does not own" if _yes(v) else None,
    "p5_exfil_endpoint": lambda v, f: "Sends form data to a third-party relay (e.g. a Telegram bot or form service)" if _yes(v) else None,
    "p5_static_cred_form": lambda v, f: ("Asks for credentials on a free static host that has no backend of its own"
                                         if _yes(v) else None),
    "p5_cred_form": lambda v, f: "Asks for login, card or recovery details" if _yes(v) else None,
    "p5_password_field": lambda v, f: "Has a password field" if _yes(v) else None,
    "p5_otp_field": lambda v, f: "Asks for an OTP / verification code" if _yes(v) else None,
    "p5_card_field": lambda v, f: "Asks for card details" if _yes(v) else None,
    "p5_seed_field": lambda v, f: "Asks for a crypto wallet recovery phrase" if _yes(v) else None,
    "p5_form_cross_site": lambda v, f: "A form submits to a different website" if _yes(v) else None,
    "p5_cross_site_redirect": lambda v, f: "Redirected through another domain on the way here" if _yes(v) else None,
    "borrowed_credibility": lambda v, f: ("Its HTTPS certificate and domain age belong to the hosting platform, not the site"
                                          if float(v or 0) > 0.2 else None),
    "CSBI_PA": lambda v, f: f"Trustworthy-looking surface contradicts its behaviour (CSBI-PA {float(v):.0f}/100)"
               if float(v or 0) >= 30 else None,
    "CSBI": lambda v, f: f"Surface/behaviour contradiction score is high (CSBI {float(v):.0f}/100)"
            if float(v or 0) >= 30 else None,
    "free_hosted": lambda v, f: (f"Hosted on a free publishing platform ({f.get('platform') or 'shared host'})"
                                 if _yes(v) else None),
    "brand_mismatch": lambda v, f: "Names a known brand in its title that the domain does not match" if _yes(v) else None,
    "urgency_language_score": lambda v, f: "Uses urgency or threat language" if float(v or 0) >= 0.34 else None,
    "upi_field_presence": lambda v, f: "Collects a UPI ID on the page" if _yes(v) else None,
    "subsidy_refund_language_score": lambda v, f: "Uses subsidy / refund / cashback bait" if float(v or 0) >= 0.34 else None,
    "fake_gov_qr_score": lambda v, f: "Shows a payment QR next to government branding" if float(v or 0) >= 0.9 else None,
    "domain_age_days": lambda v, f: (f"Domain registered only {int(float(v))} days ago"
                                     if 0 < float(v or 0) <= 90 else None),
    "ssl_age_days": lambda v, f: f"Certificate issued {int(float(v))} days ago" if 0 < float(v or 0) <= 14 else None,
    "url_suspicious_tokens": lambda v, f: "URL contains login / verify / account-style words" if float(v or 0) >= 1 else None,
    "url_risky_tld": lambda v, f: "Uses a top-level domain frequently abused for phishing" if _yes(v) else None,
    "url_is_ip": lambda v, f: "URL is a raw IP address" if _yes(v) else None,
    "url_has_at": lambda v, f: "URL contains an '@' that can hide the real destination" if _yes(v) else None,
    "url_punycode": lambda v, f: "Domain uses look-alike (punycode) characters" if _yes(v) else None,
    "url_https": lambda v, f: "Not served over HTTPS" if not _yes(v) else None,
    "tbdf_form_domain": lambda v, f: "Login form posts to another domain" if float(v or 0) < 0 else None,
    "tbdf_logo_domain": lambda v, f: "Logo is embedded or loaded from elsewhere" if float(v or 0) < 0 else None,
    "tbdf_link_domain": lambda v, f: "Most links point to a different site" if float(v or 0) < 0 else None,
    "html_null_link_ratio": lambda v, f: "Most links on the page go nowhere" if float(v or 0) >= 0.5 else None,
    "html_n_hidden": lambda v, f: "Many hidden form fields" if float(v or 0) >= 5 else None,
    "html_n_iframes": lambda v, f: "Loads content in hidden frames" if float(v or 0) >= 2 else None,
    "html_n_meta_refresh": lambda v, f: "Auto-redirects with a meta refresh" if _yes(v) else None,
    "p5_page_empty": lambda v, f: "Page is nearly empty (possible cloaking)" if _yes(v) else None,
}


# Fallback wording for features without a specific sentence, by prefix.
GENERIC_TEXT = (
    ("url_", "URL structure resembles known phishing URLs"),
    ("html_", "Page structure resembles known phishing pages (forms, links, text volume)"),
    ("tbdf_", "Page resources do not match its own domain"),
    ("T1", "Weak structural trust signals"), ("T2", "Domain or certificate is new"),
    ("T3", "Behavioural red flags on the page"), ("T4", "Payment-bait signals on the page"),
    ("T5", "Platform-aware red flags (credential collection / impersonation)"),
)


def reason_for(name: str, features: dict) -> str | None:
    fn = REASON_TEXT.get(name)
    if fn:
        try:
            return fn(features.get(name), features)
        except (TypeError, ValueError):
            return None
    for prefix, text in GENERIC_TEXT:
        if name.startswith(prefix):
            return text
    return None


@lru_cache(maxsize=1)
def load(path: str | None = None) -> dict | None:
    p = Path(path) if path else ARTIFACT
    if not p.exists():
        return None
    import joblib
    return joblib.load(p)


def _vector(features: dict, cols: list[str]) -> np.ndarray:
    row = []
    for c in cols:
        try:
            row.append(float(features.get(c, 0) or 0))
        except (TypeError, ValueError):
            row.append(0.0)
    return np.asarray([row], dtype=float)


def _contribs(model, x: np.ndarray) -> np.ndarray | None:
    try:
        import xgboost as xgb
        booster = model.get_booster()
        return booster.predict(xgb.DMatrix(x), pred_contribs=True)[0][:-1]
    except Exception:
        return None


def risk_band(p: float, thr: dict) -> str:
    if p >= thr.get("high", 0.65):
        return "HIGH"
    if p >= thr.get("medium", 0.35):
        return "MEDIUM"
    return "LOW"


def predict(features: dict, bundle: dict | None = None, k: int = 3) -> dict:
    """features: the ScanRecord.features dict plus T1..T4 / CSBI."""
    bundle = bundle or load()
    if bundle is None:
        raise RuntimeError("no trained model — run module5_decision/train.py")
    cols, model, thr = bundle["features"], bundle["model"], bundle["thresholds"]
    x = _vector(features, cols)
    p = float(model.predict_proba(x)[0, 1])
    reasons, drivers = [], []
    phi = _contribs(model, x)
    if phi is not None:
        order = np.argsort(-phi)
        for i in order:
            if phi[i] <= 0:
                break
            name = cols[i]
            text = reason_for(name, features)
            drivers.append({"feature": name, "value": features.get(name), "shap": round(float(phi[i]), 4)})
            if text and text not in reasons:
                reasons.append(text)
            if len(reasons) >= k:
                break
    level = risk_band(p, thr)
    if level == "LOW":
        reasons = []
    return {"scam_probability": round(p, 4), "risk_level": level,
            "top3_reasons": reasons or (["No strong phishing signals"] if level == "LOW"
                                        else ["Overall pattern matches known phishing pages"]),
            "drivers": drivers[:8], "thresholds": thr, "model_version": bundle.get("version")}
