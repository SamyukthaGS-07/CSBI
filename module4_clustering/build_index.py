#!/usr/bin/env python3
"""
module4_clustering/build_index.py
=================================
Clusters every confirmed phishing page by kit fingerprint, writes the campaign
id and a readable campaign label back to the store, and saves a KitIndex the
API uses to say "this page is a copy of campaign #N".

    python module4_clustering/build_index.py --store data/store/scans.db
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402

from common.store import ScanStore  # noqa: E402
from module4_clustering.campaign import KitIndex, kit_clusters, kit_matrix, load_html  # noqa: E402
from module5_decision.dataset import clean, load_store  # noqa: E402

OUT = ROOT / "module4_clustering" / "artifacts" / "kit_index.joblib"


def campaign_label(sub) -> str:
    brand = Counter(b for b in sub["_claimed_brand"].fillna("") if b).most_common(1)
    plats = Counter(p for p in sub["platform"].fillna("") if p).most_common(2)
    b = brand[0][0].title() if brand else "Unbranded"
    where = ", ".join(p for p, _ in plats) if plats else "self-hosted"
    return f"{b} kit · {where} · {len(sub)} pages"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=str(ROOT / "data" / "store" / "scans.db"))
    ap.add_argument("--snapshots", default=str(ROOT / "data" / "snapshots"))
    ap.add_argument("--eps", type=float, default=0.25)
    args = ap.parse_args()

    df, _ = clean(load_store(args.store), verbose=False)
    df = df[df.y == 1].reset_index(drop=True)
    html = load_html(df, args.snapshots)
    keep = np.array([bool(h) for h in html])
    df, html = df[keep].reset_index(drop=True), [h for h, k in zip(html, keep) if k]
    X, kv = kit_matrix(html, df["_claimed_brand"].fillna("").tolist(), return_vectorizer=True)
    labels = kit_clusters(X, eps=args.eps)

    store = ScanStore(args.store)
    summary = []
    for c in np.unique(labels[labels >= 0]):
        sub = df[labels == c]
        lab = campaign_label(sub)
        summary.append({"cluster_id": int(c), "label": lab, "size": len(sub),
                        "example": sub.url.iloc[0]})
        for u in sub.url:
            store.update_cluster(u, int(c), lab)
    summary.sort(key=lambda r: -r["size"])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    labels_by_id = {r["cluster_id"]: r["label"] for r in summary}
    joblib.dump({"index": KitIndex(X, df.url.tolist(), labels, kv), "labels": labels_by_id}, OUT)
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "campaigns.json").write_text(json.dumps(summary, indent=2))
    print(f"{len(df):,} phishing pages -> {len(summary):,} campaigns "
          f"({(labels >= 0).mean():.0%} of pages in a campaign). Saved {OUT}")
    for r in summary[:10]:
        print(f"  #{r['cluster_id']:<5}{r['size']:>5}  {r['label']}")


if __name__ == "__main__":
    main()
