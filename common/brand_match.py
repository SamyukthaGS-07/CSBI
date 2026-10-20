"""
common.brand_match
==================
Brand detection shared by Layer 3, the TBDF baseline and Layer 5.

Two questions, kept separate on purpose:
  * Which brand does the PAGE claim to be? (title, headings, logo alt/src)
  * Does the brand actually OWN the domain the page is served from?

The original Layer 3 treated "brand name appears anywhere in the host" as
"brand owns the site". On a free host that is backwards: paypal-verify.pages.dev
contains "paypal" in the host, yet PayPal does not own pages.dev. Ownership is
decided here against the brand's real registrable domains instead.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from common.hosting import platform_of, registrable_domain, tenant_label

_BRANDS_PATH = Path(__file__).resolve().parent / "brands.json"


@lru_cache(maxsize=1)
def brands() -> dict[str, dict]:
    raw = json.loads(_BRANDS_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


@lru_cache(maxsize=1)
def _alias_patterns() -> list[tuple[str, re.Pattern]]:
    out = []
    for brand, spec in brands().items():
        for alias in spec["aliases"]:
            out.append((brand, re.compile(r"(?<![a-z0-9])" + re.escape(alias.lower()) + r"(?![a-z0-9])")))
    return out


def brands_in_text(text: str) -> list[str]:
    """Brands named in `text` (whole-word alias match), most mentions first."""
    if not text:
        return []
    t = text.lower()
    counts: dict[str, int] = {}
    for brand, pat in _alias_patterns():
        n = len(pat.findall(t))
        if n:
            counts[brand] = counts.get(brand, 0) + n
    return sorted(counts, key=lambda b: -counts[b])


def brand_owns_host(brand: str, host: str) -> bool:
    """True when `host` sits under one of the brand's registrable domains."""
    host = host.lower().rstrip(".")
    if platform_of(host):            # nobody's brand owns a free-host tenant
        return False
    reg = registrable_domain(host)
    for d in brands().get(brand, {}).get("domains", []):
        d = d.lower()
        if host == d or host.endswith("." + d) or reg == d:
            return True
    return False


def any_brand_owns_host(host: str) -> str | None:
    for b in brands():
        if brand_owns_host(b, host):
            return b
    return None


def brands_in_host_label(host: str) -> list[str]:
    """Brands whose alias appears inside the publisher-chosen part of the host
    (the tenant label on a free host, the registrable label elsewhere). Short
    aliases (< 4 chars, e.g. 'ups', 'sbi') must appear as a delimited token to
    avoid matching inside unrelated words."""
    label = tenant_label(host)
    if not label:
        return []
    tokens = set(re.split(r"[.\-_0-9]+", label))
    collapsed = re.sub(r"[.\-_]", "", label)
    found = []
    for brand, spec in brands().items():
        for alias in spec["aliases"]:
            a = re.sub(r"[\s&\-]", "", alias.lower())
            if not a:
                continue
            if (len(a) >= 4 and a in collapsed) or a in tokens:
                found.append(brand)
                break
    return found
