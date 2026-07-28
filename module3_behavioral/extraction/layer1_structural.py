"""
csbi.extraction.layer1_structural
==================================
Layer 1 — Structural features (Blueprint §4, Layer 1).

All features here are derived from the URL string alone, so this layer needs no
network and is fully unit-testable offline. Returns a plain dict merged into
ScanRecord.features.

Features
--------
    https               1 if scheme is https else 0
    url_length_norm     len(url) capped and normalised to [0, 1] (cap = 100 chars)
    subdomain_count     number of subdomain labels (excludes registrable domain)
    is_ip_domain        1 if the host is a raw IPv4/IPv6 address else 0
    special_char_ratio  ratio of non-alphanumeric chars in the URL to its length
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

try:
    import tldextract
    # Offline-friendly: don't hit the network for the public-suffix list at import.
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # tldextract missing -> naive fallback below
    tldextract = None
    _EXTRACT = None

URL_LENGTH_CAP = 100  # chars; urls at/above this normalise to 1.0
# Blueprint §3 Layer 1: special char ratio = hyphens/digits/underscores / length.
_SPECIAL = re.compile(r"[-_0-9]")


def _host(url: str) -> str:
    netloc = urlparse(url).netloc or urlparse("//" + url).netloc
    return netloc.split("@")[-1].split(":")[0].strip("[]")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _subdomain_count(host: str) -> int:
    if not host or _is_ip(host):
        return 0
    if _EXTRACT is not None:
        ext = _EXTRACT(host)
        sub = ext.subdomain
        return len([p for p in sub.split(".") if p]) if sub else 0
    # Fallback: labels minus a naive 2-label registrable domain (domain.tld).
    labels = [p for p in host.split(".") if p]
    return max(0, len(labels) - 2)


def extract(url: str) -> dict[str, float]:
    host = _host(url)
    length = len(url)
    special = len(_SPECIAL.findall(url))
    return {
        "https": 1 if urlparse(url).scheme == "https" else 0,
        "url_length_norm": round(min(length, URL_LENGTH_CAP) / URL_LENGTH_CAP, 4),
        "subdomain_count": _subdomain_count(host),
        "is_ip_domain": 1 if _is_ip(host) else 0,
        "special_char_ratio": round(special / length, 4) if length else 0.0,
    }
