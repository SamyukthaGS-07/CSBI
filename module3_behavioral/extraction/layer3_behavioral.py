"""
csbi.extraction.layer3_behavioral
==================================
Layer 3 — Behavioral features (Blueprint §4, Layer 3), from page HTML.

    brand_mismatch          1 if a known brand is named in the page (text / title /
                            logo alt-text) but that brand is NOT reflected in the
                            site's registrable domain — i.e. impersonation.
    urgency_language_score  weighted keyword score over the urgency word list [0,1].
    external_script_ratio   external <script src> hosts ÷ total scripts on the page.

These are RAW features feeding T3 (1 − weighted-penalty, §4.1).

Scoring is lightweight weighted keyword matching over the version-controlled
lists in csbi/common/keywords/. Upgrade path: swap _weighted_keyword_score for a
spaCy Matcher later without changing extract().
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup

try:
    from config.settings import KEYWORDS_DIR
except Exception:
    KEYWORDS_DIR = Path("common/keywords")

try:
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:
    _EXTRACT = None


# --- keyword loading / scoring (lightweight; spaCy-swappable) ----------------
def _load_keywords(name: str) -> tuple[str, ...]:
    path = Path(KEYWORDS_DIR) / f"{name}.txt"
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.append(line)
    return tuple(out)


def _weighted_keyword_score(text: str, keywords, saturation: int = 3) -> float:
    """Fraction in [0,1]: distinct keyword phrases present, capped at `saturation`."""
    if not text:
        return 0.0
    t = text.lower()
    hits = sum(1 for kw in keywords if kw in t)
    return round(min(hits / saturation, 1.0), 4)


def _matched_keywords(text: str, keywords) -> list[str]:
    if not text:
        return []
    t = text.lower()
    return [kw for kw in keywords if kw in t]


_BRANDS = _load_keywords("brand")
_URGENCY = _load_keywords("urgency")
_MIN_BRAND_TOKEN = 3   # brand tokens shorter than this are too generic


def _host(url: str) -> str:
    netloc = urlparse(url).netloc or urlparse("//" + url).netloc
    return netloc.split("@")[-1].split(":")[0].lower()


def _domain_blob(url: str) -> str:
    host = _host(url)
    if _EXTRACT is not None:
        ext = _EXTRACT(host)
        parts = [p for p in (ext.subdomain, ext.domain) if p]
        return "".join(parts).replace("-", "").replace(".", "")
    return host.replace(".", "").replace("-", "")


def _brand_in_domain(brand: str, domain_blob: str) -> bool:
    collapsed = brand.replace(" ", "")
    if collapsed and collapsed in domain_blob:
        return True
    for tok in brand.split():
        if len(tok) >= _MIN_BRAND_TOKEN and tok in domain_blob:
            return True
    return False


def _prominent_text(soup) -> str:
    """Brand impersonation is judged only on PROMINENT text — the title and the
    top headings — not body/footer. This avoids false positives from legit pages
    that merely mention a brand ('Sign in with Google', payment logos, links)."""
    parts = []
    if soup.title and soup.title.string:
        parts.append(soup.title.string)
    for tag in soup.find_all(["h1", "h2"]):
        parts.append(tag.get_text(" ", strip=True))
    return " ".join(parts).lower()


def _brand_mismatch(prominent: str, url: str) -> int:
    """Impersonation = a known brand is named PROMINENTLY (title/heading) but the
    domain reflects none of the named brands. A legit site names its own brand in
    its title and the domain matches, so it does not trip this."""
    domain_blob = _domain_blob(url)
    named = [brand for brand in _BRANDS if brand in prominent]
    if not named:
        return 0
    if any(_brand_in_domain(brand, domain_blob) for brand in named):
        return 0
    return 1


def _external_script_ratio(soup: BeautifulSoup, url: str) -> float:
    host = _host(url)
    scripts = soup.find_all("script")
    if not scripts:
        return 0.0
    external = 0
    for s in scripts:
        src = s.get("src")
        if not src:
            continue
        src_host = urlparse(src if "//" in src else "//" + src).netloc.lower()
        if src_host and src_host != host and not src.startswith("/"):
            external += 1
    return round(external / len(scripts), 4)


def extract(html: str, url: str) -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    text = soup.get_text(" ", strip=True)
    title = soup.title.string if (soup.title and soup.title.string) else ""
    alts = " ".join(img.get("alt", "") for img in soup.find_all("img"))
    haystack = " ".join([text, title, alts]).lower()
    prominent = _prominent_text(soup)

    return {
        "brand_mismatch": _brand_mismatch(prominent, url),
        "urgency_language_score": _weighted_keyword_score(haystack, _URGENCY),
        "external_script_ratio": _external_script_ratio(soup, url),
        "_urgency_terms": _matched_keywords(haystack, _URGENCY),  # for Module B reasons
    }
