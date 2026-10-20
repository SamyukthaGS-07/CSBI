#!/usr/bin/env python3
"""
module1_ingestion/phreshphish.py
================================
Imports a sample of PhreshPhish (Hugging Face: phreshphish/phreshphish,
CC-BY-4.0, "for anti-phishing research only") into the scan store, running
every page's saved HTML through our layers OFFLINE.

  PhreshPhish: 666k pages (URL + rendered HTML + date + targeted brand),
  phishing from PhishTank / APWG eCrimeX / Netcraft, benign from browsing
  telemetry, collected Jul 2024 - Dec 2025.  arXiv:2507.10854

What can and cannot be computed offline
  yes  URL features, HTML statistics, layers 3/4/5 (page behaviour), the HTML
       parts of TBDF (logo / link / form domain), kit fingerprints
  no   TLS certificate, WHOIS age, DNS/ASN, cookies — the page is no longer
       live. Those are left empty and every offline record is tagged
       meta_offline = 1, so training uses the "offline" feature sets and never
       mixes missing-by-design values with live ones.

Sampling: the dataset is streamed (no 36 GB download). Free-hosted pages are
kept preferentially (up to --free-share of each class) because they are the
subset the paper is about.

    pip install datasets
    python module1_ingestion/phreshphish.py --n-phish 15000 --n-benign 15000 --workers 4
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MAX_HTML = 1_500_000


def _extract(row: dict) -> dict | None:
    """Worker: one PhreshPhish row -> ScanRecord dict (or None if unusable)."""
    from common.hosting import host_of
    from module3_behavioral.extraction import extractor as ex
    from module3_behavioral.extraction.fetch import FetchResult
    from module4_clustering.kit_fingerprint import kit_tokens

    url, html = row.get("url") or "", (row.get("html") or "")[:MAX_HTML]
    if not url.startswith(("http://", "https://")) or len(html) < 50:
        return None
    ex.lookup_asn = lambda ip: (None, None)          # offline: no ASN lookups

    def f(u, save=False):
        return FetchResult(url=u, final_url=u, status_code=200, ok=True, html=html,
                           redirect_hosts=[host_of(u)])
    try:
        rec = ex.extract_features(url, fetch_fn=f, save_snapshot=False)
    except Exception:
        return None
    rec.ground_truth = "scam" if row.get("label") == "phish" else "legit"
    feats = rec.features
    feats["meta_source"] = "phreshphish"
    feats["meta_offline"] = 1
    feats["meta_split"] = row.get("_split", "")
    feats["meta_target"] = row.get("target") or ""
    feats["meta_lang"] = row.get("lang") or ""
    if row.get("date"):
        feats["meta_listed_at"] = f"{row['date']}T00:00:00+00:00"
    feats["_kit"] = dict(kit_tokens(html, feats.get("_claimed_brand", "")))
    d = rec.to_dict()
    d["_html"] = html
    return d


def stream_sample(n_phish: int, n_benign: int, free_share: float, seed: int, splits: list[str]):
    from datasets import load_dataset

    from common.hosting import is_free_hosted
    quota = {"phish": n_phish, "benign": n_benign}
    free_quota = {k: int(v * free_share) for k, v in quota.items()}
    got = {"phish": 0, "benign": 0}
    got_free = {"phish": 0, "benign": 0}
    for split in splits:
        ds = load_dataset("phreshphish/phreshphish", split=split, streaming=True)
        ds = ds.shuffle(seed=seed, buffer_size=20_000)
        for row in ds:
            lab = row.get("label")
            if lab not in quota or got[lab] >= quota[lab]:
                if all(got[k] >= quota[k] for k in quota):
                    return
                continue
            free = is_free_hosted(row.get("url") or "")
            # reserve room so the free-hosted share is reached before the quota fills
            remaining = quota[lab] - got[lab]
            free_missing = max(0, free_quota[lab] - got_free[lab])
            if not free and remaining <= free_missing:
                continue
            got[lab] += 1
            got_free[lab] += int(free)
            row["_split"] = split
            yield row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-phish", type=int, default=15000)
    ap.add_argument("--n-benign", type=int, default=15000)
    ap.add_argument("--free-share", type=float, default=0.35,
                    help="target share of free-hosted pages within each class")
    ap.add_argument("--splits", default="train,test")
    ap.add_argument("--workers", type=int, default=max(1, mp.cpu_count()))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--store", default=str(ROOT / "data" / "store" / "scans.db"))
    ap.add_argument("--snapshots", default=str(ROOT / "data" / "snapshots"))
    args = ap.parse_args()

    from common.schema import ScanRecord
    from common.store import ScanStore
    store = ScanStore(args.store)
    snaps = Path(args.snapshots)
    snaps.mkdir(parents=True, exist_ok=True)
    have = store.urls()

    rows = (r for r in stream_sample(args.n_phish, args.n_benign, args.free_share, args.seed,
                                     args.splits.split(",")) if r["url"] not in have)
    t0, n, kept = time.time(), 0, {"scam": 0, "legit": 0}
    with mp.Pool(args.workers) as pool:
        for d in pool.imap_unordered(_extract, rows, chunksize=16):
            n += 1
            if d is None:
                continue
            html = d.pop("_html")
            from module3_behavioral.extraction.fetch import snapshot_path_for
            p = snapshot_path_for(d["url"], snaps)
            p.write_text(html, encoding="utf-8", errors="replace")
            d["snapshot_path"] = str(p)
            store.write(ScanRecord.from_dict(d).validate())
            kept[d["ground_truth"]] += 1
            if n % 500 == 0:
                rate = n / (time.time() - t0)
                print(f"  {n:,} processed  kept phish={kept['scam']:,} benign={kept['legit']:,}  "
                      f"{rate:.1f}/s", flush=True)
    print(f"done: {kept['scam']:,} phishing + {kept['legit']:,} benign pages imported "
          f"in {(time.time() - t0) / 60:.1f} min -> {args.store}")


if __name__ == "__main__":
    main()
