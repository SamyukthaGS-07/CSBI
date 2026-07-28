"""
csbi.extraction.layer2_temporal
================================
Layer 2 — Temporal features (Blueprint §4, Layer 2), computed from a FetchResult.

    domain_age_days      days since WHOIS creation_date
    ssl_age_days         days since certificate notBefore
    registration_years   years between creation_date and expiration_date

WHOIS-privacy fallback (Blueprint §10)
--------------------------------------
Many domains hide WHOIS behind privacy services, so creation_date is often
missing. When it is, we fall back to the certificate's issuance date
(notBefore) as a proxy for "how long has this been around" — this stands in for
the certificate-transparency-log issuance date the blueprint calls for. When the
fallback fires we set whois_fallback_used = 1 so the pipeline can log the
fallback rate as a reported statistic (§10).

These are RAW features. They feed T2 in csbi.scoring.trust_scores, which does the
min(x/N, 1) normalisation from §4.1.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from csbi.extraction.fetch import FetchResult


def _as_naive(d: Optional[dt.datetime]) -> Optional[dt.datetime]:
    """WHOIS/SSL may return tz-aware OR naive datetimes. Normalise everything to
    naive UTC so subtraction never raises 'can't subtract offset-naive and
    offset-aware'. Aware values are converted to UTC first, then the tz is dropped."""
    if d is None:
        return None
    if d.tzinfo is not None:
        d = d.astimezone(dt.timezone.utc).replace(tzinfo=None)
    return d


def _days_between(later: dt.datetime, earlier: Optional[dt.datetime]) -> Optional[int]:
    earlier = _as_naive(earlier)
    if earlier is None:
        return None
    return max(0, (later - earlier).days)


def _utcnow() -> dt.datetime:
    # Naive UTC — python-whois returns naive datetimes, so we compare naive-to-naive.
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def extract(fr: FetchResult, now: Optional[dt.datetime] = None) -> dict:
    now = now or _utcnow()

    # Normalise everything to naive UTC up front (live WHOIS/SSL can be tz-aware).
    creation = _as_naive(fr.whois_creation)
    expiration = _as_naive(fr.whois_expiration)
    ssl_not_before = _as_naive(fr.ssl_not_before)
    fallback_used = 0

    # §10 fallback: no WHOIS creation date -> use cert issuance as a proxy.
    if creation is None and ssl_not_before is not None:
        creation = ssl_not_before
        fallback_used = 1

    domain_age_days = _days_between(now, creation)
    ssl_age_days = _days_between(now, ssl_not_before)

    registration_years = None
    if creation is not None and expiration is not None and expiration > creation:
        registration_years = round((expiration - creation).days / 365.0, 3)

    # Unknown temporal signals -> 0 (least trust). trust_scores treats None as 0
    # too, but we make it explicit here so the stored record is unambiguous.
    return {
        "domain_age_days": domain_age_days if domain_age_days is not None else 0,
        "ssl_age_days": ssl_age_days if ssl_age_days is not None else 0,
        "registration_years": registration_years if registration_years is not None else 0,
        "whois_fallback_used": fallback_used,   # §10 reported statistic
    }
