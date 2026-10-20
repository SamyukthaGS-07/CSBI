"""
module1_ingestion.feeds
=======================
Live phishing feeds. Each puller returns a list of URLs and never raises: a
feed that is down returns [] and the cycle carries on with the others.

Sources and how much we trust each label (keep `meta_source` on every record
so the paper can report results per source and drop a noisy one):

  openphish   OpenPhish community feed. Curated; high precision.
  phishtank   PhishTank online-valid (needs PHISHTANK_API_KEY). Community-verified.
  phishstats  PhishStats last-30-days CSV, kept only when its score >= 5
              (PhishStats scores 0-10; >= 5 is its own "likely phishing" band).
  certpl      CERT Polska warning list (domains). National CERT; high precision,
              Poland-heavy. Converted to https://<domain>/ URLs.
  phishunt    phishunt.io public feed. Automated detection; medium precision.
"""
from __future__ import annotations

import bz2
import csv
import io
import os

import requests

UA = {"User-Agent": "csbi-research-collector/1.0 (+https://github.com/SamyukthaGS-07/CSBI)"}


def _get(url: str, timeout: int = 40, **kw) -> requests.Response | None:
    try:
        r = requests.get(url, timeout=timeout, headers=UA, **kw)
        return r if r.ok else None
    except Exception:
        return None


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("http")]


def openphish() -> list[str]:
    for u in ("https://openphish.com/feed.txt",
              "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"):
        r = _get(u)
        if r is not None and r.text.strip():
            return _lines(r.text)
    return []


def phishtank() -> list[str]:
    key = os.environ.get("PHISHTANK_API_KEY")
    if not key:
        return []
    r = _get(f"http://data.phishtank.com/data/{key}/online-valid.csv.bz2", timeout=120)
    if r is None:
        return []
    try:
        rows = csv.DictReader(io.StringIO(bz2.decompress(r.content).decode("utf-8", "replace")))
        return [row["url"] for row in rows if row.get("url")]
    except Exception:
        return []


def phishstats(min_score: float = 5.0, max_rows: int = 3000) -> list[str]:
    r = _get("https://phishstats.info/phish_score.csv", timeout=90)
    if r is None:
        return []
    out = []
    # format: "date","score","url","ip"  — comment lines start with '#'
    for row in csv.reader(ln for ln in r.text.splitlines() if ln and not ln.startswith("#")):
        if len(row) < 3:
            continue
        try:
            if float(row[1]) >= min_score and row[2].startswith("http"):
                out.append(row[2].strip())
        except ValueError:
            continue
        if len(out) >= max_rows:
            break
    return out


def certpl(max_rows: int = 1500) -> list[str]:
    r = _get("https://hole.cert.pl/domains/v2/domains.txt", timeout=90)
    if r is None:
        return []
    doms = [d.strip() for d in r.text.splitlines() if d.strip() and not d.startswith("#")]
    return [f"https://{d}/" for d in doms[-max_rows:]]       # newest are appended last


def phishunt() -> list[str]:
    r = _get("https://phishunt.io/feed.txt")
    return _lines(r.text) if r is not None else []


FEEDS = {
    "openphish": openphish,
    "phishtank": phishtank,
    "phishstats": phishstats,
    "certpl": certpl,
    "phishunt": phishunt,
}


def pull_all(enabled: list[str] | None = None) -> dict[str, list[str]]:
    """{source: urls} for every enabled feed (all by default)."""
    out = {}
    for name, fn in FEEDS.items():
        if enabled and name not in enabled:
            continue
        try:
            out[name] = fn()
        except Exception:
            out[name] = []
    return out
