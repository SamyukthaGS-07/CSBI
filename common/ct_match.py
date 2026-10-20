"""
common.ct_match
===============
Decide whether a domain seen in a freshly issued TLS certificate is worth
scanning — i.e. it looks like brand impersonation or a high-risk lookalike.

This is the filter in front of the Certificate Transparency monitor. CT logs
publish every certificate issued on the web (hundreds per second), so almost
all are legitimate. We keep only domains that:

  * contain a known brand token but are NOT owned by that brand
    (paypal-verify.com, sbi-kyc.xyz, login-microsoft.support), or
  * put a brand token on a free-hosting platform
    (icloud-find.pages.dev), or
  * combine a brand token with a phishing action word (verify, secure, login,
    kyc, update, wallet, recover) on a non-brand domain.

Pure functions, no network — unit-tested offline. The monitor passes survivors
to the live scanner for a real verdict.
"""
from __future__ import annotations

import re

from common.brand_match import brand_owns_host, brands_in_host_label
from common.hosting import host_of, platform_of, registrable_domain

ACTION_WORDS = (
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "kyc", "wallet", "recover", "recovery", "unlock", "support",
    "billing", "payment", "refund", "alert", "auth", "reset", "limited", "suspend",
)
# generic words that make a brand token a false positive (applepie.com etc.)
_WORD = re.compile(r"[a-z0-9]+")


def _has_action(host: str) -> bool:
    label = registrable_domain(host).split(".")[0] + "." + host
    return any(a in host for a in ACTION_WORDS)


def classify(domain: str) -> dict | None:
    """Return a reason dict if `domain` is worth scanning, else None."""
    host = host_of(domain)
    if not host or "." not in host:
        return None
    # wildcard certs show up as *.example.com
    host = host.lstrip("*.").strip(".")
    brands = [b for b in brands_in_host_label(host) if not brand_owns_host(b, host)]
    if not brands:
        return None
    plat = platform_of(host)
    reasons = []
    if plat:
        reasons.append(f"brand '{brands[0]}' on free host {plat}")
    if _has_action(host):
        reasons.append("brand + phishing action word")
    # a bare brand on an ordinary domain only counts when the brand is a
    # standalone token (paypal-x), not buried inside a word (applepie)
    if not reasons:
        tokens = set(t for t in re.split(r"[.\-_0-9]+", host) if t)
        if any(b.replace(" ", "") in tokens for b in brands):
            reasons.append(f"brand '{brands[0]}' in a domain the brand doesn't own")
    return {"host": host, "brands": brands, "platform": plat or "", "reasons": reasons} if reasons else None


def is_candidate(domain: str) -> bool:
    return classify(domain) is not None
