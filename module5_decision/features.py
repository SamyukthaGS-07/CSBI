"""
module5_decision.features
=========================
Feature-set definitions for the classifier and the ablation. Every model in
the paper is one of these sets, trained and evaluated under the same splits.

    B1_url        URL-lexical baseline (the common URL-only detector family)
    B2_tbdf       Mishra & Varshney (2025) tightly-bound domain features
    B3_url_html   URL + generic HTML content statistics (content-based family)
    B4_csbi       B3 + CSBI layers 1-4 raw features + T1..T4 + CSBI
    OURS          B4 + Layer 5 platform-aware features + T5 + borrowed
                  credibility + CSBI-PA

Nothing that encodes the label source or collection process is ever a feature:
no meta_* fields, no http status, no platform *name* (only the binary
free_hosted flag), no from_snapshot flag.
"""
from __future__ import annotations

import json
from typing import Iterable

import numpy as np
import pandas as pd

URL = [
    "url_len", "url_host_len", "url_path_len", "url_query_len", "url_dots",
    "url_hyphens_host", "url_digits_host", "url_digits_total", "url_path_depth",
    "url_subdomain_levels", "url_has_at", "url_double_slash_path", "url_is_ip",
    "url_https", "url_port", "url_entropy_host", "url_entropy_path",
    "url_suspicious_tokens", "url_risky_tld", "url_hex_run", "url_php",
    "url_html_file", "url_punycode", "url_special_ratio",
]
TBDF = ["tbdf_cn_info", "tbdf_cookie_domain", "tbdf_logo_domain",
        "tbdf_link_domain", "tbdf_form_domain"]
HTML = [
    "html_len", "html_n_forms", "html_n_inputs", "html_n_hidden", "html_n_links",
    "html_ext_link_ratio", "html_null_link_ratio", "html_n_scripts", "html_n_iframes",
    "html_n_img", "html_text_len", "html_has_title", "html_n_meta_refresh",
]
CSBI_LAYERS = [
    # Layer 1-2 (surface)
    "https", "url_length_norm", "subdomain_count", "is_ip_domain", "special_char_ratio",
    "domain_age_days", "ssl_age_days", "registration_years", "whois_fallback_used",
    # Layer 3-4 (behaviour)
    "brand_mismatch", "urgency_language_score", "external_script_ratio",
    "upi_field_presence", "subsidy_refund_language_score", "fake_gov_qr_score",
]
CSBI_SCORES = ["T1", "T2", "T3", "T4", "CSBI"]
PLATFORM = [
    "free_hosted", "p5_brand_claimed", "p5_brand_impersonation", "p5_tenant_brand",
    "p5_cred_form", "p5_password_field", "p5_otp_field", "p5_card_field",
    "p5_seed_field", "p5_exfil_endpoint", "p5_static_cred_form",
    "p5_form_cross_site", "p5_cross_site_redirect", "p5_page_empty",
]
PLATFORM_SCORES = ["T5", "C_apparent", "C_earned", "borrowed_credibility", "CSBI_PA"]

FEATURE_SETS: dict[str, list[str]] = {
    "B1_url": URL,
    "B2_tbdf": TBDF,
    "B3_url_html": URL + HTML,
    "B4_csbi": URL + HTML + CSBI_LAYERS + CSBI_SCORES,
    "OURS": URL + HTML + CSBI_LAYERS + CSBI_SCORES + PLATFORM + PLATFORM_SCORES,
}
# Extra ablations: what does each new block add on its own?
ABLATIONS: dict[str, list[str]] = {
    "OURS_minus_platform": FEATURE_SETS["B4_csbi"],
    "OURS_minus_csbi": URL + HTML + PLATFORM + PLATFORM_SCORES,
    "OURS_minus_url": HTML + CSBI_LAYERS + CSBI_SCORES + PLATFORM + PLATFORM_SCORES,
    "TBDF_plus_platform": TBDF + PLATFORM + PLATFORM_SCORES,
}

# ---- Offline track (pages imported from saved HTML, e.g. PhreshPhish) -------
# TLS, WHOIS, DNS and cookies cannot be observed for a page that is no longer
# live, so every feature derived from them is removed — including T2 and the
# scores built on it (CSBI, C_apparent/C_earned, borrowed credibility, CSBI_PA).
# Behavioural layers (T3, T4, T5) and kit/HTML evidence remain.
_LIVE_ONLY = {"domain_age_days", "ssl_age_days", "registration_years", "whois_fallback_used",
              "T2", "CSBI", "C_apparent", "C_earned", "borrowed_credibility", "CSBI_PA",
              "tbdf_cn_info", "tbdf_cookie_domain", "p5_cross_site_redirect"}


def _offline(cols: list[str]) -> list[str]:
    return [c for c in cols if c not in _LIVE_ONLY]


TBDF_OFFLINE = _offline(TBDF)
FEATURE_SETS_OFFLINE: dict[str, list[str]] = {
    "B1_url": URL,
    "B2_tbdf": TBDF_OFFLINE,
    "B3_url_html": URL + HTML,
    "B4_csbi": _offline(URL + HTML + CSBI_LAYERS + CSBI_SCORES),
    "OURS": _offline(URL + HTML + CSBI_LAYERS + CSBI_SCORES + PLATFORM + PLATFORM_SCORES),
}
ABLATIONS_OFFLINE: dict[str, list[str]] = {k: _offline(v) for k, v in ABLATIONS.items()}

ALL_FEATURES = sorted({f for fs in list(FEATURE_SETS.values()) + list(ABLATIONS.values()) for f in fs})


def records_to_frame(rows: Iterable[dict]) -> pd.DataFrame:
    """Flatten store rows (scalar columns + features JSON) into one frame."""
    out = []
    for r in rows:
        f = r.get("features") or {}
        if isinstance(f, str):
            f = json.loads(f)
        d = {k: v for k, v in f.items() if not k.startswith("_")}
        for k in ("url", "T1", "T2", "T3", "T4", "CSBI", "ground_truth", "asn",
                  "hosting_provider", "ssl_issuer", "dom_tag_sequence_hash",
                  "resolved_ip", "nameserver", "scan_timestamp", "cluster_id", "cluster_label",
                  "snapshot_path"):
            if k in r:
                d[k] = r[k]
        d["_claimed_brand"] = f.get("_claimed_brand", "")
        d["_kit"] = f.get("_kit")
        out.append(d)
    return pd.DataFrame(out)


def matrix(df: pd.DataFrame, cols: list[str]) -> np.ndarray:
    X = df.reindex(columns=cols).apply(pd.to_numeric, errors="coerce")
    return X.fillna(0.0).to_numpy(dtype=float)
