#!/usr/bin/env python3
"""
scripts/collect_live.py
=======================
The phishing half of the dataset, collected the only way that works: scan each
URL within hours of it being listed, before it is taken down.

Every cycle it pulls the current OpenPhish feed (openphish.com, with the GitHub
mirror as fallback) and, if PHISHTANK_API_KEY is set, PhishTank's online-valid
list. Each URL not yet in the store is scanned immediately and stamped with:

    meta_source        openphish / phishtank
    meta_listed_at     when the feed first showed it (UTC ISO time)
    meta_scanned_at    when we scanned it
    meta_lag_hours     scan time minus listing time

Leave it running (overnight or for a few days). Ctrl+C is safe.

    python scripts/collect_live.py                    # every 60 min, forever
    python scripts/collect_live.py --once             # one cycle
    python scripts/collect_live.py --interval 30 --max-per-cycle 400
"""
from __future__ import annotations

import argparse
import bz2
import csv
import io
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

from common.scanner import scan_many  # noqa: E402
from common.store import ScanStore  # noqa: E402

FEEDS = {
    "openphish": ["https://openphish.com/feed.txt",
                  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"],
}
SEEN_LOG = Path("data/raw/live_seen.csv")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def pull_openphish() -> list[str]:
    for u in FEEDS["openphish"]:
        try:
            r = requests.get(u, timeout=30)
            if r.ok and r.text.strip():
                return [ln.strip() for ln in r.text.splitlines() if ln.strip().startswith("http")]
        except Exception:
            continue
    return []


def pull_phishtank() -> list[str]:
    key = os.environ.get("PHISHTANK_API_KEY")
    if not key:
        return []
    try:
        r = requests.get(f"http://data.phishtank.com/data/{key}/online-valid.csv.bz2",
                         timeout=120, headers={"User-Agent": "phishtank/csbi-research"})
        r.raise_for_status()
        rows = csv.DictReader(io.StringIO(bz2.decompress(r.content).decode("utf-8", "replace")))
        return [row["url"] for row in rows if row.get("url")]
    except Exception as e:  # noqa: BLE001
        print(f"phishtank pull failed: {e}")
        return []


def load_seen() -> dict[str, str]:
    if not SEEN_LOG.exists():
        return {}
    with SEEN_LOG.open(encoding="utf-8") as fh:
        return {r["url"]: r["listed_at"] for r in csv.DictReader(fh)}


def append_seen(rows: list[tuple[str, str, str]]) -> None:
    SEEN_LOG.parent.mkdir(parents=True, exist_ok=True)
    new = not SEEN_LOG.exists()
    with SEEN_LOG.open("a", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        if new:
            w.writerow(["url", "listed_at", "source"])
        w.writerows(rows)


def cycle(store: ScanStore, workers: int, max_per_cycle: int) -> None:
    seen = load_seen()
    listed_now = _now()
    batch: dict[str, str] = {}
    for src, urls in (("openphish", pull_openphish()), ("phishtank", pull_phishtank())):
        for u in urls:
            if u not in seen and u not in batch:
                batch[u] = src
    append_seen([(u, listed_now, s) for u, s in batch.items()])
    seen.update({u: listed_now for u in batch})
    in_store = store.urls()
    todo = [u for u in batch if u not in in_store][:max_per_cycle]
    print(f"[{listed_now}] {len(batch):,} newly listed, scanning {len(todo):,}")
    meta = {}
    for u in todo:
        lag = (datetime.now(timezone.utc) - datetime.fromisoformat(seen[u])).total_seconds() / 3600
        meta[u] = {"source": batch[u], "listed_at": seen[u], "scanned_at": _now(),
                   "lag_hours": round(lag, 2)}
    if todo:
        print(scan_many(todo, "scam", store, meta=meta, workers=workers))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interval", type=int, default=60, help="minutes between cycles")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--max-per-cycle", type=int, default=600)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    store = ScanStore()
    while True:
        try:
            cycle(store, args.workers, args.max_per_cycle)
        except KeyboardInterrupt:
            print("stopped.")
            return
        except Exception as e:  # noqa: BLE001
            print(f"cycle error (continuing): {e}")
        if args.once:
            return
        try:
            time.sleep(args.interval * 60)
        except KeyboardInterrupt:
            print("stopped.")
            return


if __name__ == "__main__":
    main()
