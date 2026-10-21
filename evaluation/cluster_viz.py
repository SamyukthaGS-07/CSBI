#!/usr/bin/env python3
"""
evaluation/cluster_viz.py
=========================
The campaign-clustering picture — the headline visual.

Produces two static figures (no URLs, no page content, only cluster geometry):

  fig_campaign_map.png    a 2-D projection (truncated-SVD -> t-SNE) of every
                          confirmed-phishing page's KIT fingerprint, each point
                          coloured by the campaign (kit cluster) it belongs to.
                          Pages built from the same phishing kit land together;
                          grey points are unclustered singletons.
  fig_campaign_bars.png   the biggest campaigns by page count, labelled with the
                          brand they impersonate and the platforms they abuse.

Also writes results/campaign_map.json (points + campaign metadata) so the
dashboard can draw an interactive version.

    python evaluation/cluster_viz.py --store data/store/scans.db --out results
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from module4_clustering.campaign import kit_bags, kit_clusters, kit_matrix, load_html  # noqa: E402
from module5_decision.dataset import clean, load_store  # noqa: E402

INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e0"
# one highlight ramp of distinguishable hues for the largest campaigns; the long
# tail is a single muted grey so the eye reads "many small kits, a few big ones"
CAMPAIGN_HUES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4",
                 "#6250d6", "#008300", "#e34948", "#00a3a3", "#b5651d"]
NOISE = "#c7c6c1"


def _style(ax):
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    for sp in ("left", "bottom"):
        ax.spines[sp].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9)


def _project(X) -> np.ndarray:
    """Kit vectors -> 2-D coordinates. SVD to ~30 dims, then t-SNE (or SVD-2 if
    the sample is tiny)."""
    from sklearn.decomposition import TruncatedSVD
    n = X.shape[0]
    if n < 10:
        return np.zeros((n, 2))
    k = int(min(30, X.shape[1] - 1, n - 1))
    Z = TruncatedSVD(n_components=max(2, k), random_state=0).fit_transform(X)
    if n <= 30:
        return Z[:, :2]
    from sklearn.manifold import TSNE
    per = float(min(30, max(5, n // 15)))
    return TSNE(n_components=2, init="pca", perplexity=per, random_state=0,
               learning_rate="auto").fit_transform(Z)


def build(store_path: str, out: Path, eps: float, snapshots: str) -> dict:
    df, _ = clean(load_store(store_path), verbose=False)
    df = df[df.y == 1].reset_index(drop=True)
    html = load_html(df, snapshots)
    has_kit = (df["_kit"].map(lambda k: isinstance(k, dict) and bool(k)).to_numpy()
               if "_kit" in df else np.zeros(len(df), bool))
    keep = np.array([bool(h) for h in html]) | has_kit
    df, html = df[keep].reset_index(drop=True), [h for h, k in zip(html, keep) if k]
    if len(df) < 10:
        print(f"  cluster viz skipped: only {len(df)} phishing pages with kit evidence")
        return {}

    X = kit_matrix(html, bags=kit_bags(df, html))
    labels = kit_clusters(X, eps=eps)
    xy = _project(X)

    # order campaigns by size; the biggest get a colour, the rest share grey
    sizes = Counter(labels[labels >= 0])
    ranked = [c for c, _ in sizes.most_common()]
    colour_of = {c: CAMPAIGN_HUES[i] for i, c in enumerate(ranked[:len(CAMPAIGN_HUES)])}

    def brand_platform(mask):
        b = Counter(x for x in df.loc[mask, "_claimed_brand"].fillna("") if x).most_common(1)
        p = Counter(x for x in df.loc[mask, "platform"].fillna("") if x).most_common(2)
        return (b[0][0].title() if b else "Unbranded"), [k for k, _ in p]

    out.mkdir(parents=True, exist_ok=True)
    (out / "figures").mkdir(exist_ok=True)

    # ---- figure 1: the map -------------------------------------------------
    fig, ax = plt.subplots(figsize=(7.2, 6), dpi=160)
    noise = labels < 0
    ax.scatter(xy[noise, 0], xy[noise, 1], s=10, c=NOISE, alpha=0.6, linewidths=0,
               label=f"unclustered ({int(noise.sum())})")
    for c in ranked:
        m = labels == c
        col = colour_of.get(c, NOISE)
        brand, plats = brand_platform(m)
        lbl = f"{brand} · {'/'.join(plats) or 'mixed'} ({int(m.sum())})" if c in colour_of else None
        ax.scatter(xy[m, 0], xy[m, 1], s=22, c=col, alpha=0.85, linewidths=0.4,
                   edgecolors="white", label=lbl)
    ax.set_xticks([])
    ax.set_yticks([])
    _style(ax)
    ax.set_title(f"{len(df):,} phishing pages → {len(sizes):,} campaigns by shared kit",
                 color=INK, fontsize=12, loc="left")
    ax.legend(frameon=False, fontsize=8, loc="center left", bbox_to_anchor=(1.0, 0.5),
              title="Largest campaigns", title_fontsize=9)
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_campaign_map.svg", bbox_inches="tight")
    plt.close(fig)

    # ---- figure 2: biggest campaigns --------------------------------------
    top = ranked[:12][::-1]
    names, counts, cols = [], [], []
    for c in top:
        m = labels == c
        brand, plats = brand_platform(m)
        names.append(f"{brand} · {'/'.join(plats) or 'mixed'}")
        counts.append(int(m.sum()))
        cols.append(colour_of.get(c, "#8f8d86"))
    fig, ax = plt.subplots(figsize=(7.2, 4.6), dpi=160)
    ax.barh(range(len(top)), counts, color=cols, edgecolor="white")
    ax.set_yticks(range(len(top)), names, fontsize=8, color=INK)
    ax.set_xlabel("pages in the campaign", color=MUTED, fontsize=9)
    _style(ax)
    ax.xaxis.grid(True, color=GRID)
    fig.tight_layout()
    fig.savefig(out / "figures" / "fig_campaign_bars.svg", bbox_inches="tight")
    plt.close(fig)

    # ---- json for the interactive dashboard view (coords only, no URLs) ----
    pts = [{"x": round(float(xy[i, 0]), 2), "y": round(float(xy[i, 1]), 2),
            "c": int(labels[i])} for i in range(len(df))]
    camps = []
    for c in ranked:
        m = labels == c
        brand, plats = brand_platform(m)
        camps.append({"id": int(c), "brand": brand, "platforms": plats,
                      "size": int(m.sum()), "color": colour_of.get(c, NOISE)})
    summary = {"n_pages": len(df), "n_campaigns": len(sizes),
               "clustered_share": round(float((labels >= 0).mean()), 3),
               "largest": int(max(sizes.values())) if sizes else 0,
               "points": pts, "campaigns": camps, "noise_color": NOISE}
    (out / "campaign_map.json").write_text(json.dumps(summary))
    print(f"  campaign map: {len(df):,} pages, {len(sizes):,} campaigns "
          f"({summary['clustered_share']:.0%} clustered) -> 2 figures + campaign_map.json")
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=str(ROOT / "data" / "store" / "scans.db"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--snapshots", default=str(ROOT / "data" / "snapshots"))
    ap.add_argument("--eps", type=float, default=0.25)
    args = ap.parse_args()
    build(args.store, Path(args.out), args.eps, args.snapshots)


if __name__ == "__main__":
    main()
