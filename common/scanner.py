"""
common.scanner
==============
Concurrent, resumable batch scanning shared by `scripts/run_scan.py` and
`scripts/collect_live.py`.

Network work (HTTP, TLS, WHOIS, ASN) runs in a thread pool; every finished
record is written to the SQLite store from the main thread, so a crash or
Ctrl+C never loses more than the in-flight URLs.
"""
from __future__ import annotations

import concurrent.futures as cf
import time
from typing import Iterable, Optional

from common.hosting import is_free_hosted
from common.schema import ScanRecord
from common.store import ScanStore
from module3_behavioral.extraction.extractor import extract_features

PER_URL_TIMEOUT = 90       # seconds; WHOIS servers occasionally hang


def _scan(url: str, label: str, meta: dict) -> ScanRecord:
    rec = extract_features(url, store=None, save_snapshot=True)
    rec.ground_truth = label
    for k, v in (meta or {}).items():
        rec.features[f"meta_{k}"] = v
    return rec.validate()


def scan_many(urls: Iterable[str], label: str, store: ScanStore,
              meta: Optional[dict[str, dict]] = None, workers: int = 16,
              rescan: bool = False, log_every: int = 25) -> dict:
    urls = list(dict.fromkeys(u.strip() for u in urls if u and u.strip()))
    done_before = set() if rescan else store.urls()
    todo = [u for u in urls if u not in done_before]
    stats = {"queued": len(todo), "skipped": len(urls) - len(todo),
             "ok": 0, "no_content": 0, "failed": 0}
    if not todo:
        return stats
    meta = meta or {}
    t0 = time.time()
    print(f"scanning {len(todo):,} URLs (label={label}, workers={workers}); "
          f"{stats['skipped']:,} already in store")
    pool = cf.ThreadPoolExecutor(max_workers=workers)
    try:
        futs = {pool.submit(_scan, u, label, meta.get(u, {})): u for u in todo}
        for i, fut in enumerate(cf.as_completed(futs), 1):
            u = futs[fut]
            try:
                rec = fut.result(timeout=PER_URL_TIMEOUT)
                store.write(rec)
                if rec.features.get("fetch_ok"):
                    stats["ok"] += 1
                else:
                    stats["no_content"] += 1
            except Exception as e:  # noqa: BLE001
                stats["failed"] += 1
                if stats["failed"] <= 5:
                    print(f"  failed {u[:70]}: {type(e).__name__}: {e}")
            if i % log_every == 0 or i == len(todo):
                rate = i / max(time.time() - t0, 1e-6)
                eta = (len(todo) - i) / max(rate, 1e-6) / 60
                print(f"  [{i:,}/{len(todo):,}] ok={stats['ok']:,} empty={stats['no_content']:,} "
                      f"failed={stats['failed']:,}  {rate:.1f}/s  eta {eta:.0f} min")
    except KeyboardInterrupt:
        print("\ninterrupted — finished records are saved; re-run to resume.")
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return stats


def free_hosted_share(urls: Iterable[str]) -> float:
    urls = list(urls)
    return sum(is_free_hosted(u) for u in urls) / max(len(urls), 1)
