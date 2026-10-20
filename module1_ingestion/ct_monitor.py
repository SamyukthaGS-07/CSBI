#!/usr/bin/env python3
"""
module1_ingestion/ct_monitor.py
===============================
Certificate-Transparency early-warning monitor — the zero-day detector for
self-hosted phishing.

When an attacker registers their own domain for a phishing site, a TLS
certificate is issued for it, and every issuance is published to the public CT
logs within minutes. This watches that stream, keeps only brand-impersonation
lookalikes (common/ct_match.py), and runs each survivor through the real CSBI-PA
scanner. Domains the model rates HIGH are written as zero-day candidates —
flagged from the certificate alone, before the URL appears in any feed.

(CT only covers domains with their own certificate. Free-hosted pages reuse the
platform wildcard and never create a new CT entry, so those are caught by the
page-level model and kit matching instead — the two halves are complementary.)

Two sources, tried in order:
  certstream   live websocket firehose (pip install certstream) — best
  crt.sh       polled every few minutes as a fallback (no extra dependency)

Output (same store as the scanner, plus a small JSON for the dashboard):
  data/store/scans.db            full ScanRecord, meta_source = ct
  results/ct_candidates.json     recent HIGH/MEDIUM zero-day candidates

    python module1_ingestion/ct_monitor.py                 # run forever
    python module1_ingestion/ct_monitor.py --once          # one crt.sh poll
    python run_all.py ctwatch                               # same, via run_all
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.ct_match import classify  # noqa: E402
from common.hosting import host_of  # noqa: E402
from common.store import ScanStore  # noqa: E402

CAND_JSON = ROOT / "results" / "ct_candidates.json"
MAX_KEEP = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Candidates:
    """Rolling list of flagged domains, persisted for the dashboard."""

    def __init__(self):
        self.items: deque = deque(maxlen=MAX_KEEP)
        if CAND_JSON.exists():
            try:
                self.items.extend(json.loads(CAND_JSON.read_text()))
            except Exception:
                pass

    def add(self, rec: dict) -> None:
        self.items.appendleft(rec)
        CAND_JSON.parent.mkdir(parents=True, exist_ok=True)
        CAND_JSON.write_text(json.dumps(list(self.items), indent=1))


def scan_candidate(domain: str, reason: dict, store: ScanStore, cands: Candidates) -> None:
    """Scan one flagged domain with the real model and record it if risky."""
    from common.pipeline import scan_url
    url = f"https://{reason['host']}/"
    try:
        rec = scan_url(url, save_snapshot=True)
    except Exception:
        return
    rec.ground_truth = "unknown"
    rec.features["meta_source"] = "ct"
    rec.features["meta_ct_reason"] = "; ".join(reason["reasons"])
    rec.features["meta_listed_at"] = _now()
    try:
        store.write(rec.validate())
    except Exception:
        pass
    if rec.risk_level in ("HIGH", "MEDIUM"):
        cands.add({"host": reason["host"], "brand": (reason["brands"] or [""])[0],
                   "platform": reason["platform"], "risk": rec.risk_level,
                   "probability": rec.scam_probability, "reason": "; ".join(reason["reasons"]),
                   "reasons": rec.top3_reasons, "seen_at": _now()})
        print(f"  [{rec.risk_level}] {reason['host']}  p={rec.scam_probability}  "
              f"({'; '.join(reason['reasons'])})", flush=True)


# --------------------------------------------------------------------------- #
def run_certstream(store: ScanStore, cands: Candidates) -> bool:
    try:
        import certstream
    except Exception:
        return False
    seen: set[str] = set()

    def on_message(message, context):
        if message.get("message_type") != "certificate_update":
            return
        for d in message["data"]["leaf_cert"].get("all_domains", []):
            d = d.lower()
            if d in seen:
                continue
            seen.add(d)
            r = classify(d)
            if r:
                scan_candidate(d, r, store, cands)

    print("CT monitor: connected to certstream firehose")
    certstream.listen_for_events(on_message, url="wss://certstream.calidog.io/")
    return True


def poll_crtsh(store: ScanStore, cands: Candidates, hours: float, interval: int) -> None:
    import requests
    print(f"CT monitor: polling crt.sh every {interval}s (certstream not installed)")
    seen: set[str] = set()
    end = time.time() + hours * 3600
    # recent certs for a handful of the most-abused brands
    terms = ["paypal", "microsoft", "apple", "coinbase", "sbi", "hdfc", "netflix",
             "amazon", "whatsapp", "binance", "dhl", "icloud"]
    while time.time() < end:
        for term in terms:
            try:
                r = requests.get("https://crt.sh/", params={"q": f"%25{term}%25", "output": "json"},
                                 timeout=40, headers={"User-Agent": "csbi-ct-research/1.0"})
                rows = r.json() if r.ok else []
            except Exception:
                rows = []
            for row in rows:
                for d in str(row.get("name_value", "")).splitlines():
                    d = d.strip().lower()
                    if d and d not in seen:
                        seen.add(d)
                        rr = classify(d)
                        if rr:
                            scan_candidate(d, rr, store, cands)
            time.sleep(2)
        if interval > 0 and time.time() < end:
            time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=60.0, help="how long to run the crt.sh fallback")
    ap.add_argument("--interval", type=int, default=300, help="seconds between crt.sh polls")
    ap.add_argument("--once", action="store_true", help="one crt.sh poll then exit")
    args = ap.parse_args()
    store = ScanStore()
    cands = Candidates()
    if run_certstream(store, cands):
        return
    poll_crtsh(store, cands, hours=0.001 if args.once else args.hours,
               interval=0 if args.once else args.interval)


if __name__ == "__main__":
    main()
