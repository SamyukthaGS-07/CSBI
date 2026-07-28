#!/usr/bin/env python3
"""
scripts/pull_dataset.py
=======================
Build the URL dataset (Blueprint §8). Shared script — Module A scans what this
produces, Module B trains on it, Module C clusters it.

Sources
-------
  openphish   free community feed, no API key, refreshed ~6h
              https://openphish.com/feed.txt   (GitHub mirror as fallback)
  phishtank   requires a FREE registered app key; set PHISHTANK_API_KEY in .env
              http://data.phishtank.com/data/<key>/online-valid.csv.bz2
  legit       curated Indian bank / government / major-brand domains (the
              legitimate class; these are the sites scams impersonate)

IMPORTANT — UPI yield (measured, not assumed)
---------------------------------------------
A 300-URL sample of the live OpenPhish community feed contained ZERO
India/UPI-related URLs. The free feeds skew heavily global. So:

  * --filter upi   gives a high-precision but very small (often empty) set.
  * Default (no filter) keeps everything: still valid for CSBI, which measures
    surface-vs-behaviour contradiction generally, with UPI as the Layer-4 signal.
  * Use --filter freehost to target the strongest CSBI archetype: scams on free
    hosting platforms (pages.dev / github.io / blogspot / vercel / netlify),
    which were 34% of that same sample. These inherit clean SSL + a reputable
    platform domain while behaving maliciously — precisely the C-S gap.

For genuine UPI coverage you will need manual curation (see --seed-file), e.g.
URLs from CERT-In advisories, cybercrime.gov.in reports, or reported campaigns.

Usage
-----
    python scripts/pull_dataset.py                       # openphish + legit
    python scripts/pull_dataset.py --filter freehost     # CSBI archetype subset
    python scripts/pull_dataset.py --filter upi          # UPI/India only
    python scripts/pull_dataset.py --sources openphish phishtank
    python scripts/pull_dataset.py --seed-file my_upi_urls.txt --label scam

Outputs
-------
    data/raw/openphish_<date>.txt        raw pulls, unfiltered (audit trail)
    data/labeled/scam.txt                deduped scam URLs
    data/labeled/legit.txt               deduped legit URLs
"""

from __future__ import annotations

import argparse
import bz2
import csv
import datetime as dt
import io
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import requests
except Exception:
    requests = None

try:
    from config.settings import RAW_DIR, LABELED_DIR
except Exception:
    RAW_DIR = Path("data/raw")
    LABELED_DIR = Path("data/labeled")

OPENPHISH_URL = "https://openphish.com/feed.txt"
OPENPHISH_MIRROR = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
PHISHTANK_URL = "http://data.phishtank.com/data/{key}/online-valid.csv.bz2"
USER_AGENT = "CSBI-research-scanner/1.0"

# --- filters ----------------------------------------------------------------
UPI_PATTERN = re.compile(
    r"upi|vpa|paytm|phonepe|gpay|googlepay|bhim|npci|"
    r"sbi|hdfc|icici|axisbank|kotak|pnb|canara|barodampay|yesbank|"
    r"kyc|aadhaar|uidai|irctc|epfo|rbi|gst|"
    r"subsidy|yojana|pmkisan|scholarship|refund|cashback|"
    r"india|bharat|\.in(?:[/:]|$)",
    re.IGNORECASE,
)

# Free hosting platforms — the strongest CSBI archetype (clean surface, scam behaviour).
FREEHOST_PATTERN = re.compile(
    r"pages\.dev|workers\.dev|github\.io|blogspot|netlify\.app|vercel\.app|"
    r"weebly|wixsite|firebaseapp|web\.app|duckdns|on-forge|repl\.co|glitch\.me|"
    r"000webhost|herokuapp|surge\.sh|neocities",
    re.IGNORECASE,
)

# Legitimate class: the Indian banking / government / commerce sites scams impersonate.
LEGIT_SEEDS = [
    "https://www.onlinesbi.sbi/", "https://www.hdfcbank.com/", "https://www.icicibank.com/",
    "https://www.axisbank.com/", "https://www.kotak.com/", "https://www.pnbindia.in/",
    "https://www.bankofbaroda.in/", "https://www.canarabank.com/", "https://www.unionbankofindia.co.in/",
    "https://www.idfcfirstbank.com/", "https://www.yesbank.in/", "https://www.indusind.com/",
    "https://www.rbi.org.in/", "https://www.npci.org.in/", "https://www.uidai.gov.in/",
    "https://www.incometax.gov.in/", "https://www.gst.gov.in/", "https://www.epfindia.gov.in/",
    "https://www.india.gov.in/", "https://www.mygov.in/", "https://pmkisan.gov.in/",
    "https://www.irctc.co.in/", "https://www.licindia.in/", "https://www.nseindia.com/",
    "https://www.bseindia.com/", "https://www.sebi.gov.in/",
    "https://paytm.com/", "https://www.phonepe.com/", "https://pay.google.com/",
    "https://www.amazon.in/", "https://www.flipkart.com/", "https://www.myntra.com/",
    "https://www.jio.com/", "https://www.airtel.in/", "https://www.zomato.com/",
    "https://www.swiggy.com/", "https://www.makemytrip.com/", "https://www.bookmyshow.com/",
]


def _http_get(url: str, timeout: int = 30):
    if requests is None:
        raise RuntimeError("requests is not installed — pip install requests")
    return requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})


# --- sources ----------------------------------------------------------------
def pull_openphish() -> list[str]:
    """Free community feed (no key). Falls back to the GitHub mirror."""
    for src in (OPENPHISH_URL, OPENPHISH_MIRROR):
        try:
            r = _http_get(src)
            if r.ok and r.text.strip():
                urls = [ln.strip() for ln in r.text.splitlines() if ln.strip().startswith("http")]
                print(f"  openphish: {len(urls)} URLs from {src}")
                return urls
        except Exception as e:
            print(f"  openphish: {src} failed ({e})")
    return []


def pull_phishtank() -> list[str]:
    """Requires a free registered app key in PHISHTANK_API_KEY."""
    key = os.environ.get("PHISHTANK_API_KEY")
    if not key:
        print("  phishtank: skipped — set PHISHTANK_API_KEY in .env "
              "(free registration at phishtank.org/developer_info.php)")
        return []
    try:
        r = _http_get(PHISHTANK_URL.format(key=key), timeout=90)
        if not r.ok:
            print(f"  phishtank: HTTP {r.status_code}")
            return []
        text = bz2.decompress(r.content).decode("utf-8", errors="replace")
        rows = csv.DictReader(io.StringIO(text))
        urls = [row["url"].strip() for row in rows if row.get("url")]
        print(f"  phishtank: {len(urls)} URLs")
        return urls
    except Exception as e:
        print(f"  phishtank: failed ({e})")
        return []


def read_seed_file(path: str | Path) -> list[str]:
    """Manually curated URLs (one per line, '#' comments allowed)."""
    p = Path(path)
    if not p.exists():
        print(f"  seed file not found: {p}")
        return []
    urls = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    print(f"  seed file: {len(urls)} URLs from {p}")
    return urls


# --- filtering / io ---------------------------------------------------------
def apply_filter(urls: list[str], mode: str) -> list[str]:
    if mode == "upi":
        return [u for u in urls if UPI_PATTERN.search(u)]
    if mode == "freehost":
        return [u for u in urls if FREEHOST_PATTERN.search(u)]
    return urls


def dedupe(urls: list[str]) -> list[str]:
    seen, out = set(), []
    for u in urls:
        k = u.rstrip("/").lower()
        if k not in seen:
            seen.add(k)
            out.append(u)
    return out


def merge_into(path: Path, urls: list[str]) -> int:
    """Append new URLs to a labeled file, keeping it deduped. Returns count added."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        existing = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    before = len(existing)
    merged = dedupe(existing + urls)
    path.write_text("\n".join(merged) + "\n", encoding="utf-8")
    return len(merged) - before


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the CSBI URL dataset (§8).")
    ap.add_argument("--sources", nargs="+", default=["openphish"],
                    choices=["openphish", "phishtank"], help="scam URL sources")
    ap.add_argument("--filter", default="none", choices=["none", "upi", "freehost"],
                    help="relevance filter applied to scam URLs")
    ap.add_argument("--seed-file", help="extra manually-curated URLs, one per line")
    ap.add_argument("--label", default="scam", choices=["scam", "legit"],
                    help="label for --seed-file URLs")
    ap.add_argument("--no-legit", action="store_true", help="skip the legit seed list")
    args = ap.parse_args()

    today = dt.date.today().isoformat()
    Path(RAW_DIR).mkdir(parents=True, exist_ok=True)

    # --- scam class ---
    print("Pulling scam URLs:")
    raw: list[str] = []
    if "openphish" in args.sources:
        u = pull_openphish()
        if u:
            (Path(RAW_DIR) / f"openphish_{today}.txt").write_text("\n".join(u), encoding="utf-8")
        raw += u
    if "phishtank" in args.sources:
        u = pull_phishtank()
        if u:
            (Path(RAW_DIR) / f"phishtank_{today}.txt").write_text("\n".join(u), encoding="utf-8")
        raw += u

    raw = dedupe(raw)
    filtered = apply_filter(raw, args.filter)
    pct = (100.0 * len(filtered) / len(raw)) if raw else 0.0
    print(f"\n  pulled {len(raw)} unique -> {len(filtered)} after filter "
          f"'{args.filter}' ({pct:.1f}%)")
    if args.filter == "upi" and len(filtered) < 10:
        print("  ! low UPI yield is expected — the free feeds carry little Indian\n"
              "    phishing. Use --filter freehost, or curate URLs via --seed-file.")

    seed_scam, seed_legit = [], []
    if args.seed_file:
        seeds = read_seed_file(args.seed_file)
        if args.label == "scam":
            seed_scam = seeds
        else:
            seed_legit = seeds

    added_scam = merge_into(Path(LABELED_DIR) / "scam.txt", filtered + seed_scam)

    # --- legit class ---
    legit = [] if args.no_legit else LEGIT_SEEDS
    added_legit = merge_into(Path(LABELED_DIR) / "legit.txt", legit + seed_legit)

    scam_total = len((Path(LABELED_DIR) / "scam.txt").read_text(encoding="utf-8").split())
    legit_total = len((Path(LABELED_DIR) / "legit.txt").read_text(encoding="utf-8").split())

    print(f"\nLabeled sets ({LABELED_DIR}):")
    print(f"  scam.txt : {scam_total} total (+{added_scam} new)")
    print(f"  legit.txt: {legit_total} total (+{added_legit} new)")
    print("\nNext: scan them into the store, e.g.")
    print("  python scripts/run_scan.py <url>          # one URL")
    print("  (or loop over data/labeled/*.txt to populate the store for Modules B & C)")


if __name__ == "__main__":
    main()
