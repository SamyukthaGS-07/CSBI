"""
csbi.extraction.layer4_upi
===========================
Layer 4 — UPI-specific signals (Blueprint §4, Layer 4 — the novel layer).

    upi_field_presence              1 if a UPI VPA (name@bank) appears in the page
                                    OR a form field looks like a UPI/VPA input.
    subsidy_refund_language_score   weighted keyword score over the subsidy list [0,1].
    fake_gov_qr_score               heuristic [0,1]: a QR image combined with
                                    government-emblem/authority keywords nearby.

These are RAW features feeding T4 (1 − weighted-penalty, §4.1).

Prototype note (Option 1): fake_gov_qr_score is an HTML heuristic. The blueprint's
full version decodes the QR image with OpenCV/pyzbar; that upgrade slots into
`_qr_present` without changing the score interface or T4.
"""

from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup

try:
    from config.settings import KEYWORDS_DIR
except Exception:
    KEYWORDS_DIR = Path("common/keywords")


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


_SUBSIDY = _load_keywords("subsidy")

# Government-emblem / authority keywords for the fake-gov QR proximity check.
# Kept inline (the keyword folder holds brand/urgency/subsidy word lists).
_GOV_EMBLEM = (
    "government of india", "govt of india", "national emblem", "ashoka",
    "satyameva jayate", "ministry of", "department of", "reserve bank of india",
    "rbi", "npci", "uidai", "aadhaar", "income tax department", "gst council",
    "pm kisan", "pmkisan", "pradhan mantri", "yojana", "official portal",
    "gov.in", "digital india",
)

# UPI VPA: local@handle, handle alphabetic and NOT followed by a dot (excludes emails).
_UPI_VPA = re.compile(r"\b[\w.\-]{2,256}@[a-zA-Z][a-zA-Z0-9]{1,63}\b(?![\w.])")
_KNOWN_HANDLES = {
    "oksbi", "okhdfcbank", "okaxis", "okicici", "ybl", "ibl", "axl", "paytm",
    "apl", "upi", "fbl", "hdfcbank", "axisbank", "icici", "sbi", "pnb", "cnrb",
    "barodampay", "kotak", "yapl", "rbl", "idfcbank", "jio", "airtel",
}
_QR_HINTS = ("qr", "scan to pay", "scan qr", "scan and pay", "qr code", "qrcode")


def _page_text(soup: BeautifulSoup) -> str:
    """Visible text + title + image alt-text (emblem/QR cues often live in alt)."""
    text = soup.get_text(" ", strip=True)
    title = soup.title.string if (soup.title and soup.title.string) else ""
    alts = " ".join(img.get("alt", "") for img in soup.find_all("img"))
    return " ".join([text, title, alts]).lower()


def _has_upi_field(soup: BeautifulSoup, text: str) -> int:
    for m in _UPI_VPA.finditer(text):
        handle = m.group().split("@")[-1].lower()
        if handle in _KNOWN_HANDLES or len(handle) >= 3:
            return 1
    for inp in soup.find_all(["input", "textarea"]):
        attrs = " ".join(
            str(inp.get(a, "")) for a in ("name", "id", "placeholder", "aria-label")
        ).lower()
        if "upi" in attrs or "vpa" in attrs:
            return 1
    return 0


def _qr_present(soup: BeautifulSoup, text: str) -> bool:
    for img in soup.find_all("img"):
        blob = " ".join(str(img.get(a, "")) for a in ("src", "alt", "class", "id")).lower()
        if any(h in blob for h in ("qr", "qrcode")):
            return True
    return any(h in text for h in _QR_HINTS)


def _fake_gov_qr_score(soup: BeautifulSoup, text: str) -> float:
    qr = _qr_present(soup, text)
    gov = any(kw in text for kw in _GOV_EMBLEM)
    if qr and gov:
        return 1.0
    if qr and not gov:
        return 0.4
    if gov and not qr:
        return 0.3
    return 0.0


def extract(html: str, url: str = "") -> dict:
    soup = BeautifulSoup(html or "", "html.parser")
    text = _page_text(soup)

    return {
        "upi_field_presence": _has_upi_field(soup, text),
        "subsidy_refund_language_score": _weighted_keyword_score(text, _SUBSIDY),
        "fake_gov_qr_score": _fake_gov_qr_score(soup, text),
        "_subsidy_terms": _matched_keywords(text, _SUBSIDY),  # for Module B reasons
    }
