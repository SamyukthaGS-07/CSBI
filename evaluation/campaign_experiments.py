#!/usr/bin/env python3
"""
evaluation/campaign_experiments.py
==================================
The three campaign-level experiments.

E1  Clustering quality: infrastructure (original Module 4) vs kit fingerprint.
    For each method: number of clusters, share of phishing pages clustered,
    label purity, share of clusters mixing phishing with legitimate pages, and
    size of the largest cluster — overall and on free-hosted pages.

E2  Label efficiency of cluster-based weak supervision.
    Kit clusters define the groups, so test campaigns never appear in training.
    In the training pool only a fraction p of phishing labels is revealed
    (the "seeds"); all other phishing pages plus half of the legitimate pages
    form an unlabelled pool, so propagation can make real mistakes. Compared:
        seeds_only     train on seeds + revealed legit
        self_training  classic pseudo-labelling (model confidence >= 0.95)
        propagation    seeds + kit-cluster propagation (ours)
        oracle         every training-pool label revealed
    Repeated for p in {1, 2, 5, 10, 20, 50}% over 5 random seeds.

E3  Kit-match lead time.
    Within each kit cluster, ordered by feed listing time, a member listed
    later whose kit matches an earlier-listed member could have been flagged
    when that earlier member was confirmed. Reports how many members that
    applies to and the time gap. This is an upper bound on lead time: it
    assumes the later page was crawled as soon as it went up.

    python evaluation/campaign_experiments.py --store data/store/scans.db
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold  # noqa: E402

from evaluation.metrics import compute_metrics  # noqa: E402
from module4_clustering.campaign import (infra_clusters, kit_bags, kit_clusters,  # noqa: E402
                                         kit_matrix, load_html, propagate)
from module5_decision.dataset import clean, load_store  # noqa: E402
from module5_decision.features import FEATURE_SETS, FEATURE_SETS_OFFLINE, matrix  # noqa: E402
from module5_decision.train import make_model  # noqa: E402

FRACTIONS = (0.01, 0.02, 0.05, 0.10, 0.20, 0.50)


def cluster_quality(labels: np.ndarray, y: np.ndarray, mask: np.ndarray) -> dict:
    lab, yy = labels[mask], y[mask]
    cl = lab >= 0
    stats = {"n_pages": int(mask.sum()), "n_clusters": int(len(np.unique(lab[cl]))),
             "phish_clustered": float((cl & (yy == 1)).sum() / max((yy == 1).sum(), 1)),
             "legit_clustered": float((cl & (yy == 0)).sum() / max((yy == 0).sum(), 1))}
    if cl.any():
        sizes, pure, mixed = [], 0, 0
        for c in np.unique(lab[cl]):
            m = lab == c
            sizes.append(m.sum())
            pure += max(yy[m].sum(), (1 - yy[m]).sum())
            mixed += int(0 < yy[m].sum() < m.sum())
        stats.update({"purity": float(pure / cl.sum()), "mixed_cluster_rate": float(mixed / len(sizes)),
                      "largest_cluster": int(max(sizes)), "median_cluster": float(np.median(sizes))})
    return stats


def e1(df, html, X, kit_eps, cap, rng):
    # infrastructure fields exist only for live scans
    live = pd.to_numeric(df.get("meta_offline", 0), errors="coerce").fillna(0).to_numpy() == 0
    idx = np.flatnonzero(live)
    if len(idx) < 20:
        print("  E1 skipped: needs live-scanned pages (infrastructure fields)")
        return {}
    if len(idx) > cap:
        idx = np.sort(rng.choice(idx, cap, replace=False))
    sub = df.iloc[idx].reset_index(drop=True)
    sub_html = [html[i] for i in idx]
    y = sub["y"].to_numpy()
    free = sub["free_hosted"].to_numpy() == 1
    res = {}
    for name, labels in (("infra (original)", infra_clusters(sub, sub_html)),
                         ("kit fingerprint", kit_clusters(X[idx], eps=kit_eps))):
        res[name] = {"all": cluster_quality(labels, y, np.ones(len(y), bool)),
                     "free_hosted": cluster_quality(labels, y, free),
                     "self_hosted": cluster_quality(labels, y, ~free)}
        print(f"  {name:<18} all: {res[name]['all']}")
        print(f"  {'':<18} free: {res[name]['free_hosted']}")
    return res


def self_training(Xtr, ytr, Xu, model_kind="xgb", conf=0.95, rounds=3):
    X, y = Xtr, ytr
    remaining = np.arange(len(Xu))
    for _ in range(rounds):
        m = make_model(model_kind, y)
        m.fit(X, y)
        if len(remaining) == 0:
            break
        p = m.predict_proba(Xu[remaining])[:, 1]
        take = (p >= conf) | (p <= 1 - conf)
        if not take.any():
            break
        X = np.vstack([X, Xu[remaining[take]]])
        y = np.concatenate([y, (p[take] >= 0.5).astype(int)])
        remaining = remaining[~take]
    m = make_model(model_kind, y)
    m.fit(X, y)
    return m


def e2(df, X, kit_labels, n_rep, tau, model_kind="xgb"):
    y = df["y"].to_numpy()
    free = df["free_hosted"].to_numpy() == 1
    groups = np.where(kit_labels >= 0, "k" + kit_labels.astype(str), "g" + df["group"].astype(str))
    offline = pd.to_numeric(df.get("meta_offline", 0), errors="coerce").fillna(0).to_numpy() == 1
    F = matrix(df, (FEATURE_SETS_OFFLINE if offline.any() else FEATURE_SETS)["OURS"])
    rows = []
    for rep in range(n_rep):
        rng = np.random.default_rng(rep)
        sgk = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=rep)
        tr, te = next(sgk.split(F, y, groups))
        for p in FRACTIONS:
            tr_ph = tr[y[tr] == 1]
            tr_lg = tr[y[tr] == 0]
            seeds = rng.choice(tr_ph, max(1, int(round(p * len(tr_ph)))), replace=False)
            lg_rev = rng.choice(tr_lg, len(tr_lg) // 2, replace=False)
            unl = np.setdiff1d(tr, np.concatenate([seeds, lg_rev]))
            sp = np.zeros(len(y), bool); sp[seeds] = True
            sl = np.zeros(len(y), bool); sl[lg_rev] = True
            un = np.zeros(len(y), bool); un[unl] = True
            prop = propagate(X, kit_labels, sp, sl, un, tau=tau)
            pidx = np.flatnonzero(prop.labels == 1)
            prop_prec = float(y[pidx].mean()) if len(pidx) else float("nan")
            base_idx = np.concatenate([seeds, lg_rev])
            base_y = y[base_idx]
            variants = {
                "seeds_only": (base_idx, base_y),
                "propagation": (np.concatenate([base_idx, pidx]),
                                np.concatenate([base_y, np.ones(len(pidx), int)])),
                "oracle": (tr, y[tr]),
            }
            for name, (ix, yy) in variants.items():
                if len(np.unique(yy)) < 2:
                    continue
                m = make_model(model_kind, yy)
                m.fit(F[ix], yy)
                s = m.predict_proba(F[te])[:, 1]
                for sub, mask in (("all", np.ones(len(te), bool)), ("free_hosted", free[te])):
                    if mask.sum() >= 10:
                        rows.append({"rep": rep, "frac": p, "method": name, "subset": sub,
                                     "n_train_phish": int(yy.sum()), "prop_precision": prop_prec
                                     if name == "propagation" else np.nan,
                                     **compute_metrics(y[te][mask], scores=s[mask])})
            st = self_training(F[base_idx], base_y, F[unl], model_kind)
            s = st.predict_proba(F[te])[:, 1]
            for sub, mask in (("all", np.ones(len(te), bool)), ("free_hosted", free[te])):
                if mask.sum() >= 10:
                    rows.append({"rep": rep, "frac": p, "method": "self_training", "subset": sub,
                                 "n_train_phish": np.nan, "prop_precision": np.nan,
                                 **compute_metrics(y[te][mask], scores=s[mask])})
            print(f"  rep {rep} p={p:>5.0%}  seeds={len(seeds):>4}  propagated={len(pidx):>5} "
                  f"(precision {prop_prec:.3f})")
    return pd.DataFrame(rows)


def e3(df, kit_labels, X, max_dist):
    t = df["time"]
    ph = (df["y"].to_numpy() == 1) & t.notna().to_numpy() & (kit_labels >= 0)
    rows = []
    for c in np.unique(kit_labels[ph]):
        idx = np.flatnonzero(ph & (kit_labels == c))
        if len(idx) < 2:
            continue
        idx = idx[np.argsort(t.iloc[idx].to_numpy())]
        first_t = t.iloc[idx[0]]
        for k in range(1, len(idx)):
            prev = idx[:k]
            sim = (X[idx[k]] @ X[prev].T).toarray().ravel()
            j = prev[int(np.argmax(sim))]
            if 1 - sim.max() <= max_dist:
                rows.append({"cluster": int(c), "url": df.url.iloc[idx[k]],
                             "matched_url": df.url.iloc[j],
                             "lead_hours": (t.iloc[idx[k]] - t.iloc[j]).total_seconds() / 3600,
                             "since_first_hours": (t.iloc[idx[k]] - first_t).total_seconds() / 3600,
                             "free_hosted": int(df.free_hosted.iloc[idx[k]])})
    out = pd.DataFrame(rows)
    n_ph_t = int(((df.y == 1) & df.time.notna()).sum())
    summary = {"phish_with_listing_time": n_ph_t, "matched_later_members": len(out),
               "share": len(out) / max(n_ph_t, 1)}
    if len(out):
        summary.update({"lead_hours_median": float(out.lead_hours.median()),
                        "lead_hours_p75": float(out.lead_hours.quantile(.75)),
                        "lead_hours_max": float(out.lead_hours.max()),
                        "share_lead_over_1h": float((out.lead_hours > 1).mean()),
                        "share_lead_over_24h": float((out.lead_hours > 24).mean())})
    return out, summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=str(ROOT / "data" / "store" / "scans.db"))
    ap.add_argument("--out", default=str(ROOT / "results"))
    ap.add_argument("--snapshots", default=str(ROOT / "data" / "snapshots"))
    ap.add_argument("--kit-eps", type=float, default=0.25)
    ap.add_argument("--tau", type=float, default=0.15)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--infra-cap", type=int, default=5000)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)

    df, _ = clean(load_store(args.store))
    html = load_html(df, args.snapshots)
    has_kit = df["_kit"].map(lambda k: isinstance(k, dict) and bool(k)).to_numpy() if "_kit" in df \
        else np.zeros(len(df), bool)
    have = np.array([bool(h) for h in html]) | has_kit
    print(f"  pages with saved HTML: {have.sum():,}/{len(df):,}")
    df = df[have].reset_index(drop=True)
    html = [h for h, k in zip(html, have) if k]
    X = kit_matrix(html, bags=kit_bags(df, html))
    kit_labels = kit_clusters(X, eps=args.kit_eps)

    print("\nE1 clustering quality")
    r1 = e1(df, html, X, args.kit_eps, args.infra_cap, rng)
    (out / "e1_clustering.json").write_text(json.dumps(r1, indent=2))

    print("\nE2 label efficiency")
    r2 = e2(df, X, kit_labels, args.reps, args.tau)
    r2.to_csv(out / "e2_label_efficiency.csv", index=False)
    summ = (r2.groupby(["subset", "frac", "method"])[["f1", "recall", "precision", "pr_auc", "prop_precision"]]
            .mean().round(4))
    summ.to_csv(out / "e2_summary.csv")
    print(summ.loc["all"].to_string())

    print("\nE3 kit-match lead time")
    r3, s3 = e3(df, kit_labels, X, args.tau)
    r3.to_csv(out / "e3_lead_time.csv", index=False)
    (out / "e3_summary.json").write_text(json.dumps(s3, indent=2))
    print(f"  {s3}")


if __name__ == "__main__":
    main()
