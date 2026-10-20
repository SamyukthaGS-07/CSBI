"""
module3_behavioral.extraction.layer0_url
========================================
Baseline B1 — URL-lexical features (no network, no page).

This is the standard feature family used across the URL-based phishing
literature (length, character counts, entropy, suspicious tokens, TLD). It is
here only so the paper can compare CSBI against the most common baseline under
the same split. Every feature is prefixed `url_` so feature groups stay
separable for the ablation.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

from common.hosting import host_of, registrable_domain

_SUSPICIOUS_TOKENS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "wallet", "kyc",
    "support", "billing", "invoice", "payment", "unlock", "recover", "auth",
    "webscr", "session", "token", "reward", "claim", "gift", "bonus", "free",
)
# TLDs disproportionately abused in phishing feeds (Spamhaus / Interisle reports).
_RISKY_TLDS = {
    "xyz", "top", "icu", "cfd", "sbs", "click", "live", "shop", "online", "site",
    "buzz", "rest", "lol", "quest", "monster", "cyou", "bond", "info", "ru", "cn",
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "support", "work", "life",
}
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HEX_RE = re.compile(r"[0-9a-f]{12,}")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def extract(url: str) -> dict[str, float]:
    u = url if "//" in url else "http://" + url
    p = urlparse(u)
    host = host_of(u)
    reg = registrable_domain(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    path = p.path or ""
    low = u.lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    return {
        "url_len": len(u),
        "url_host_len": len(host),
        "url_path_len": len(path),
        "url_query_len": len(p.query or ""),
        "url_dots": host.count("."),
        "url_hyphens_host": host.count("-"),
        "url_digits_host": sum(ch.isdigit() for ch in host),
        "url_digits_total": sum(ch.isdigit() for ch in u),
        "url_path_depth": len([s for s in path.split("/") if s]),
        "url_subdomain_levels": len([s for s in sub.split(".") if s]),
        "url_has_at": int("@" in p.netloc or "@" in path),
        "url_double_slash_path": int("//" in path),
        "url_is_ip": int(bool(_IP_RE.match(host))),
        "url_https": int(p.scheme == "https"),
        "url_port": int(p.port is not None and p.port not in (80, 443)),
        "url_entropy_host": round(_entropy(host), 4),
        "url_entropy_path": round(_entropy(path), 4),
        "url_suspicious_tokens": sum(t in low for t in _SUSPICIOUS_TOKENS),
        "url_risky_tld": int(tld in _RISKY_TLDS),
        "url_hex_run": int(bool(_HEX_RE.search(low))),
        "url_php": int(".php" in path.lower()),
        "url_html_file": int(path.lower().endswith((".html", ".htm"))),
        "url_punycode": int("xn--" in host),
        "url_special_ratio": round(sum(not ch.isalnum() for ch in u) / max(len(u), 1), 4),
    }
