#!/usr/bin/env python3
"""
scripts/run_scan.py
===================
CLI: scan URLs end-to-end through Module A and write ScanRecords to the store.

Single URL
----------
    python scripts/run_scan.py https://example.com

Batch (a labeled URL list from pull_dataset.py)
-----------------------------------------------
    python scripts/run_scan.py --file data/labeled/scam.txt  --label scam
    python scripts/run_scan.py --file data/labeled/legit.txt --label legit
    python scripts/run_scan.py --file data/labeled/scam.txt  --label scam --limit 20

Summary of what's already in the store (the payoff — does CSBI separate the classes?)
------------------------------------------------------------------------------------
    python scripts/run_scan.py --stats

Notes
-----
* Batch mode is RESUMABLE: URLs already scanned are skipped, so you can stop
  with Ctrl+C and re-run. Use --rescan to force re-scanning.
* A delay between scans keeps the free ASN endpoint (ip-api.com, ~45 req/min)
  happy and avoids hammering WHOIS servers. Default 1.5s.
* Dead scam URLs are expected — phishing pages are taken down fast. They are
  counted as failures, not crashes, and the run continues (§8.3).
"""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from module3_behavioral.extraction.extractor import extract_features
from common.store import ScanStore


# --------------------------------------------------------------------------- #
def scan_one(url: str, store, label: str | None = None, save_snapshot: bool = True):
    """Scan a URL, optionally stamp its ground-truth label, persist it."""
    rec = extract_features(url, store=None, save_snapshot=save_snapshot)
    if label:
        rec.ground_truth = label
    if store is not None:
        store.write(rec.validate())
    return rec


def print_record(rec) -> None:
    d = rec.to_dict()
    print(f"\nURL   : {rec.url}")
    print(f"T1..T4: {rec.T1}  {rec.T2}  {rec.T3}  {rec.T4}")
    print(f"CSBI  : {rec.CSBI}   (higher = stronger surface/behaviour contradiction)")
    print(f"snapshot: {rec.snapshot_path or '-'}   from_snapshot="
          f"{d['features'].get('from_snapshot')}")
    print("\nfull record:")
    print(json.dumps(d, indent=2, default=str))


# --------------------------------------------------------------------------- #
def run_batch(path: Path, label: str, store, limit: int | None,
              delay: float, rescan: bool, save_snapshot: bool) -> None:
    if not path.exists():
        print(f"file not found: {path}")
        print("run  python scripts/pull_dataset.py  first")
        return

    urls = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")]
    if limit:
        urls = urls[:limit]

    total = len(urls)
    print(f"scanning {total} URLs from {path}  (label={label})")
    print("Ctrl+C is safe — progress is saved after every URL.\n")

    done = skipped = failed = 0
    scores: list[float] = []
    start = time.time()

    for i, url in enumerate(urls, 1):
        if not rescan:
            existing = store.read(url)
            if existing is not None and existing.CSBI is not None:
                skipped += 1
                continue
        try:
            rec = scan_one(url, store, label=label, save_snapshot=save_snapshot)
            reachable = bool(rec.features.get("brand_mismatch") is not None
                             and rec.dom_tag_sequence_hash)
            scores.append(rec.CSBI)
            done += 1
            flag = "" if reachable else "  (unreachable — no page content)"
            print(f"[{i}/{total}] CSBI={rec.CSBI:5.1f}  T1={rec.T1:.2f} T2={rec.T2:.2f} "
                  f"T3={rec.T3:.2f} T4={rec.T4:.2f}  {url[:60]}{flag}")
        except KeyboardInterrupt:
            print("\ninterrupted — progress saved.")
            break
        except Exception as e:
            failed += 1
            print(f"[{i}/{total}] FAILED  {url[:60]}  ({type(e).__name__}: {e})")
        time.sleep(delay)

    elapsed = time.time() - start
    print(f"\ndone in {elapsed/60:.1f} min — scanned {done}, skipped {skipped} "
          f"(already in store), failed {failed}")
    if scores:
        print(f"CSBI for this batch: mean={statistics.mean(scores):.1f}  "
              f"median={statistics.median(scores):.1f}  max={max(scores):.1f}")


# --------------------------------------------------------------------------- #
def show_stats(store) -> None:
    """Compare the labeled classes already in the store. This is the number that
    tells you whether CSBI actually works."""
    groups: dict[str, list] = {}
    for rec in store.all():
        if rec.CSBI is None:
            continue
        groups.setdefault(rec.ground_truth, []).append(rec)

    if not groups:
        print("store is empty — scan something first.")
        return

    print(f"\nstore: {store.count()} records\n")
    header = f"{'label':<8}{'n':>5}{'CSBI mean':>11}{'median':>9}{'T1':>7}{'T2':>7}{'T3':>7}{'T4':>7}"
    print(header)
    print("-" * len(header))
    for label in ("scam", "legit", "unknown"):
        recs = groups.get(label)
        if not recs:
            continue
        m = lambda f: statistics.mean([getattr(r, f) for r in recs if getattr(r, f) is not None])
        csbis = [r.CSBI for r in recs]
        print(f"{label:<8}{len(recs):>5}{statistics.mean(csbis):>11.1f}"
              f"{statistics.median(csbis):>9.1f}{m('T1'):>7.2f}{m('T2'):>7.2f}"
              f"{m('T3'):>7.2f}{m('T4'):>7.2f}")

    scam, legit = groups.get("scam"), groups.get("legit")
    if scam and legit:
        gap = statistics.mean([r.CSBI for r in scam]) - statistics.mean([r.CSBI for r in legit])
        print(f"\nseparation (scam mean - legit mean): {gap:+.1f} CSBI points")
        if gap > 15:
            print("  -> CSBI separates the classes. This is the core result for your paper.")
        elif gap > 5:
            print("  -> weak but present separation; more data will sharpen it.")
        else:
            print("  -> little separation yet. Check that scam URLs are still live —\n"
                  "     dead pages have no content, so Layers 3/4 see nothing.")

    unreachable = sum(1 for r in store.all()
                      if r.CSBI is not None and not r.dom_tag_sequence_hash)
    if unreachable:
        print(f"\nnote: {unreachable} records had no page content (site down / blocked).")
        print("      Those score T3=T4=1.0 by default, which drags scam CSBI down.")


# --------------------------------------------------------------------------- #
def main() -> None:
    ap = argparse.ArgumentParser(description="CSBI Module A - scan URLs.")
    ap.add_argument("url", nargs="?", help="single URL to scan")
    ap.add_argument("--file", help="text file of URLs, one per line (batch mode)")
    ap.add_argument("--label", default="unknown", choices=["scam", "legit", "unknown"],
                    help="ground-truth label to stamp on batch records")
    ap.add_argument("--limit", type=int, help="only scan the first N URLs")
    ap.add_argument("--delay", type=float, default=1.5,
                    help="seconds between scans (default 1.5; keeps free APIs happy)")
    ap.add_argument("--rescan", action="store_true", help="re-scan URLs already in the store")
    ap.add_argument("--stats", action="store_true", help="summarise the store and exit")
    ap.add_argument("--no-store", action="store_true", help="don't write to the store")
    ap.add_argument("--no-snapshot", action="store_true", help="don't cache page HTML")
    args = ap.parse_args()

    store = None if args.no_store else ScanStore()

    if args.stats:
        show_stats(store or ScanStore())
        return

    if args.file:
        run_batch(Path(args.file), args.label, store or ScanStore(), args.limit,
                  args.delay, args.rescan, not args.no_snapshot)
        print("\nnext:  python scripts/run_scan.py --stats")
        return

    if not args.url:
        ap.error("give a URL, or --file <list>, or --stats")

    rec = scan_one(args.url, store, label=None if args.label == "unknown" else args.label,
                   save_snapshot=not args.no_snapshot)
    print_record(rec)


if __name__ == "__main__":
    main()
