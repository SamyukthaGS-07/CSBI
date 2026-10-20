#!/usr/bin/env python3
"""
evaluation/make_report.py
=========================
Turns results/*.csv|json into figures (results/figures/*.png) and a single
results/REPORT.md with every number the paper and the conclave talk use.
Run after train.py and campaign_experiments.py.

    python evaluation/make_report.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import roc_curve  # noqa: E402

RES = ROOT / "results"
FIG = RES / "figures"

# Ours is the one highlighted hue; baselines are neutral steps so the eye goes
# to the comparison that matters. Labels carry identity, never colour alone.
OURS_C = "#2a78d6"
BASE_C = ["#b8b6ae", "#8f8d86", "#5f5e59"]
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e0"
NAMES = {"B1_url": "URL only", "B2_tbdf": "TBDF (Mishra & Varshney 2025)",
         "B3_url_html": "URL + HTML", "B4_csbi": "CSBI (layers 1-4)", "OURS": "CSBI-PA (ours)",
         "OURS_minus_platform": "ours − platform layer", "OURS_minus_csbi": "ours − CSBI layers",
         "OURS_minus_url": "ours − URL features", "TBDF_plus_platform": "TBDF + platform layer"}
MAIN = ["B2_tbdf", "B3_url_html", "B4_csbi", "OURS"]


def style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def color_for(key, i):
    return OURS_C if key == "OURS" else BASE_C[min(i, len(BASE_C) - 1)]


def fig_feature_sets(cv: pd.DataFrame, model="xgb", metric="recall"):
    d = cv[(cv.model == model) & cv.features.isin(MAIN)]
    subs = ["all", "self_hosted", "free_hosted"]
    labels = {"all": "All pages", "self_hosted": "Self-hosted", "free_hosted": "Free-hosted"}
    fig, ax = plt.subplots(figsize=(8, 4.2), dpi=160)
    w = 0.19
    for i, fs in enumerate(MAIN):
        vals = [d[(d.features == fs) & (d.subset == s)][metric].mean() for s in subs]
        xs = np.arange(len(subs)) + (i - 1.5) * (w + 0.015)
        ax.bar(xs, vals, w, color=color_for(fs, i), label=NAMES[fs], edgecolor="white", linewidth=1)
        if fs in ("OURS", "B2_tbdf"):
            for x, v in zip(xs, vals):
                ax.text(x, v + 0.01, f"{v:.2f}", ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_xticks(np.arange(len(subs)), [labels[s] for s in subs], color=INK)
    ax.set_ylim(0, 1.08)
    ax.set_ylabel(metric.replace("_", " ").title() + " at threshold 0.5", color=MUTED, fontsize=9)
    style(ax)
    ax.legend(frameon=False, fontsize=8, ncol=2, loc="lower left", bbox_to_anchor=(0, 1.0))
    fig.tight_layout()
    fig.savefig(FIG / f"fig1_{metric}_by_subset.png")
    plt.close(fig)


def fig_roc(oof: pd.DataFrame, subset="free_hosted"):
    m = oof["free_hosted"] == 1 if subset == "free_hosted" else np.ones(len(oof), bool)
    y = oof.loc[m, "y"]
    if y.nunique() < 2:
        return
    fig, ax = plt.subplots(figsize=(5.2, 4.4), dpi=160)
    for i, fs in enumerate(MAIN):
        col = f"{fs}|xgb"
        if col not in oof:
            continue
        fpr, tpr, _ = roc_curve(y, oof.loc[m, col])
        ax.plot(fpr, tpr, color=color_for(fs, i), lw=2, label=NAMES[fs])
    ax.set_xscale("log")
    ax.set_xlim(1e-3, 1)
    ax.set_ylim(0, 1.01)
    ax.axvline(0.01, color=GRID, lw=1, ls="--")
    ax.set_xlabel("False-positive rate (log scale)", color=MUTED, fontsize=9)
    ax.set_ylabel("Phishing detected (TPR)", color=MUTED, fontsize=9)
    style(ax)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    ax.set_title("Free-hosted pages" if subset == "free_hosted" else "All pages", color=INK, fontsize=10, loc="left")
    fig.tight_layout()
    fig.savefig(FIG / f"fig2_roc_{subset}.png")
    plt.close(fig)


def fig_label_efficiency(e2: pd.DataFrame, subset="all"):
    d = e2[e2.subset == subset].groupby(["frac", "method"])["f1"].agg(["mean", "std"]).reset_index()
    order = [("oracle", "All labels (upper bound)", BASE_C[0], ":"),
             ("seeds_only", "Seeds only", BASE_C[2], "-"),
             ("self_training", "Self-training", BASE_C[1], "--"),
             ("propagation", "Kit propagation (ours)", OURS_C, "-")]
    fig, ax = plt.subplots(figsize=(6.4, 4.2), dpi=160)
    for key, lab, c, ls in order:
        s = d[d.method == key].sort_values("frac")
        if s.empty:
            continue
        ax.plot(s.frac * 100, s["mean"], color=c, lw=2, ls=ls, marker="o", ms=4, label=lab)
        ax.fill_between(s.frac * 100, s["mean"] - s["std"].fillna(0), s["mean"] + s["std"].fillna(0),
                        color=c, alpha=0.12, lw=0)
    ax.set_xscale("log")
    ax.set_xticks([1, 2, 5, 10, 20, 50], ["1%", "2%", "5%", "10%", "20%", "50%"])
    ax.set_xlabel("Share of phishing training labels revealed", color=MUTED, fontsize=9)
    ax.set_ylabel("F1 on unseen campaigns", color=MUTED, fontsize=9)
    style(ax)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(FIG / f"fig3_label_efficiency_{subset}.png")
    plt.close(fig)


def fig_borrowed(df: pd.DataFrame):
    if "borrowed_credibility" not in df:
        return
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.6), dpi=160, sharey=True)
    for ax, (key, title) in zip(axes, (("C_apparent", "Apparent surface trust (T1, T2)"),
                                       ("C_earned", "Earned surface trust"))):
        groups = [("Legit, self-hosted", (df.y == 0) & (df.free_hosted == 0), BASE_C[0]),
                  ("Legit, free-hosted", (df.y == 0) & (df.free_hosted == 1), BASE_C[2]),
                  ("Phish, free-hosted", (df.y == 1) & (df.free_hosted == 1), OURS_C)]
        data = [pd.to_numeric(df.loc[m, key], errors="coerce").dropna() for _, m, _ in groups]
        bp = ax.boxplot(data, orientation="vertical", patch_artist=True, widths=0.55, showfliers=False,
                        medianprops={"color": INK})
        for patch, (_, _, c) in zip(bp["boxes"], groups):
            patch.set_facecolor(c)
            patch.set_edgecolor("white")
        ax.set_xticks([1, 2, 3], [g[0] for g in groups], fontsize=8, color=INK)
        ax.set_title(title, color=INK, fontsize=10, loc="left")
        style(ax)
    axes[0].set_ylabel("Score (0-1)", color=MUTED, fontsize=9)
    fig.tight_layout()
    fig.savefig(FIG / "fig4_borrowed_credibility.png")
    plt.close(fig)


def fig_shap(df: pd.DataFrame):
    try:
        import joblib
        import xgboost as xgb
        from module5_decision.features import matrix
        b = joblib.load(ROOT / "module5_decision" / "artifacts" / "csbi_model.joblib")
    except Exception:
        return None
    X = matrix(df, b["features"])
    phi = b["model"].get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[:, :-1]
    imp = pd.Series(np.abs(phi).mean(0), index=b["features"]).sort_values(ascending=False)
    top = imp.head(15)[::-1]
    fig, ax = plt.subplots(figsize=(6.4, 4.8), dpi=160)
    new = ("p5_", "T5", "borrowed_credibility", "C_earned", "C_apparent", "CSBI_PA", "free_hosted")
    cols = [OURS_C if n.startswith(new) else BASE_C[1] for n in top.index]
    ax.barh(top.index, top.values, color=cols, edgecolor="white")
    ax.set_xlabel("Mean |SHAP| (log-odds)", color=MUTED, fontsize=9)
    ax.tick_params(axis="y", labelsize=8, colors=INK)
    style(ax)
    ax.xaxis.grid(True, color=GRID)
    ax.yaxis.grid(False)
    ax.set_title("Blue = new platform-aware features", color=MUTED, fontsize=9, loc="left")
    fig.tight_layout()
    fig.savefig(FIG / "fig5_shap_importance.png")
    plt.close(fig)
    return imp


def table(df: pd.DataFrame, cols, fmt="{:.3f}") -> str:
    head = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
    rows = []
    for _, r in df.iterrows():
        rows.append("| " + " | ".join(fmt.format(r[c]) if isinstance(r[c], (float, np.floating)) else str(r[c])
                                      for c in cols) + " |")
    return head + "\n".join(rows) + "\n"


def main() -> None:
    import argparse
    global RES, FIG
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(RES))
    ap.add_argument("--store", default=str(ROOT / "data" / "store" / "scans.db"))
    args = ap.parse_args()
    RES, FIG = Path(args.results), Path(args.results) / "figures"
    FIG.mkdir(parents=True, exist_ok=True)
    md = ["# CSBI-PA — results\n",
          "_Generated by `evaluation/make_report.py` from the files in `results/`. "
          "Every number below comes from those files; nothing is typed in by hand._\n"]

    ds = json.loads((RES / "dataset_report.json").read_text())
    md.append("## Dataset\n")
    md.append(f"- **{ds['n']:,} pages** after cleaning: {ds['n_phish']:,} phishing, {ds['n_legit']:,} legitimate")
    md.append(f"- Free-hosted: {ds['n_free_hosted']:,} pages ({ds['free_hosted_phish']:,} phishing, "
              f"{ds['free_hosted_legit']:,} legitimate)")
    md.append(f"- {ds['n_groups']:,} campaign-disjoint groups used for cross-validation")
    md.append("- Cleaning steps: " + "; ".join(f"{s} → {n:,}" for s, n in ds["cleaning"]))
    md.append("- Phishing platforms: " + ", ".join(f"{p} ({n})" for p, n in ds["platforms_phish"][:8]))
    md.append("- Legit platforms: " + ", ".join(f"{p} ({n})" for p, n in ds["platforms_legit"][:8]) + "\n")

    cv = pd.read_csv(RES / "cv_results.csv")
    md.append("## Detection (campaign-disjoint 5-fold CV)\n")
    for sub in ("all", "free_hosted", "self_hosted"):
        d = cv[cv.subset == sub].copy()
        d["feature set"] = d.features.map(NAMES).fillna(d.features)
        d = d.sort_values(["features", "model"])
        md.append(f"### {sub.replace('_', ' ').title()}\n")
        md.append(table(d, ["feature set", "model", "n", "precision", "recall", "f1", "roc_auc",
                            "pr_auc", "tpr_at_1fpr", "fpr"]))
    for metric in ("recall", "f1", "tpr_at_1fpr"):
        fig_feature_sets(cv, metric=metric)

    best = cv[(cv.model == "xgb")].set_index(["features", "subset"])
    try:
        o, t = best.loc[("OURS", "free_hosted")], best.loc[("B2_tbdf", "free_hosted")]
        b4 = best.loc[("B4_csbi", "free_hosted")]
        md.append("### Headline (XGBoost, free-hosted pages)\n")
        md.append(f"- CSBI-PA recall {o.recall:.3f} vs TBDF {t.recall:.3f} vs original CSBI {b4.recall:.3f}")
        md.append(f"- CSBI-PA F1 {o.f1:.3f} vs TBDF {t.f1:.3f} vs original CSBI {b4.f1:.3f}")
        md.append(f"- Phishing caught at 1% false-positive rate: CSBI-PA {o.tpr_at_1fpr:.3f} vs TBDF "
                  f"{t.tpr_at_1fpr:.3f} vs original CSBI {b4.tpr_at_1fpr:.3f}\n")
    except KeyError:
        pass
    ci_path = RES / "confidence_intervals.json"
    if ci_path.exists():
        ci = json.loads(ci_path.read_text())
        md.append("95% bootstrap intervals: " + "; ".join(
            f"{k.replace('|', ' ')} [{v[0]:.3f}, {v[1]:.3f}]" for k, v in ci.items() if "|f1" in k) + "\n")

    tp = RES / "temporal_results.csv"
    if tp.exists():
        tm = pd.read_csv(tp)
        tm["feature set"] = tm.features.map(NAMES).fillna(tm.features)
        md.append("## Temporal split (train on earlier-listed phishing, test on later)\n")
        md.append(table(tm[(tm.model == "xgb") & tm.features.isin(MAIN)].sort_values(["subset", "features"]),
                        ["feature set", "subset", "n", "precision", "recall", "f1", "roc_auc", "tpr_at_1fpr"]))

    oof = pd.read_csv(RES / "oof_scores.csv")
    fig_roc(oof, "free_hosted")
    fig_roc(oof, "all")

    e1p = RES / "e1_clustering.json"
    if e1p.exists():
        e1 = json.loads(e1p.read_text())
        md.append("## E1 — Campaign clustering: infrastructure vs kit fingerprint\n")
        rows = []
        for meth, d in e1.items():
            for sub, s in d.items():
                rows.append({"method": meth, "subset": sub, **s})
        md.append(table(pd.DataFrame(rows).fillna(float("nan")),
                        ["method", "subset", "n_pages", "n_clusters", "phish_clustered", "purity",
                         "mixed_cluster_rate", "largest_cluster"]))

    e2p = RES / "e2_label_efficiency.csv"
    if e2p.exists():
        e2 = pd.read_csv(e2p)
        fig_label_efficiency(e2, "all")
        fig_label_efficiency(e2, "free_hosted")
        s = (e2[e2.subset == "all"].groupby(["frac", "method"])
             .agg(f1=("f1", "mean"), recall=("recall", "mean"), prop_precision=("prop_precision", "mean"))
             .reset_index())
        piv = s.pivot(index="frac", columns="method", values="f1").reset_index()
        pp = s[s.method == "propagation"].set_index("frac")["prop_precision"]
        piv["propagation precision"] = piv["frac"].map(pp)
        piv["frac"] = (piv["frac"] * 100).map(lambda v: f"{v:g}%")
        md.append("## E2 — Label efficiency (F1 on unseen campaigns, mean of repeats)\n")
        md.append(table(piv, [c for c in ["frac", "seeds_only", "self_training", "propagation", "oracle",
                                          "propagation precision"] if c in piv]))

    e3p = RES / "e3_summary.json"
    if e3p.exists():
        e3 = json.loads(e3p.read_text())
        md.append("## E3 — Kit-match lead time\n")
        md.append("```\n" + json.dumps(e3, indent=2) + "\n```\n")

    try:
        from module5_decision.dataset import clean, load_store
        df, _ = clean(load_store(args.store), verbose=False)
        fig_borrowed(df)
        imp = fig_shap(df)
        if imp is not None:
            md.append("## What the model relies on (mean |SHAP|, top 15)\n")
            md.append(table(imp.head(15).rename("mean_abs_shap").reset_index().rename(columns={"index": "feature"}),
                            ["feature", "mean_abs_shap"], "{:.4f}"))
    except Exception as e:  # noqa: BLE001
        md.append(f"_(store-based figures skipped: {e})_\n")

    try:
        from evaluation.cluster_viz import build as build_campaign_map
        cm = build_campaign_map(args.store, RES, 0.25, str(ROOT / "data" / "snapshots"))
        if cm:
            md.append("## Campaign clustering\n")
            md.append(f"- {cm['n_pages']:,} confirmed-phishing pages grouped into "
                      f"**{cm['n_campaigns']:,} campaigns** by shared phishing kit "
                      f"({cm['clustered_share']:.0%} of pages in a campaign; largest has "
                      f"{cm['largest']:,} pages)")
            top = ", ".join(f"{c['brand']} ({c['size']})" for c in cm['campaigns'][:6])
            md.append(f"- Largest campaigns: {top}\n")
    except Exception as e:  # noqa: BLE001
        md.append(f"_(campaign map skipped: {e})_\n")

    md.append("## Figures\n")
    for p in sorted(FIG.glob("*.png")):
        md.append(f"![{p.stem}](figures/{p.name})")
    (RES / "REPORT.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"wrote {RES / 'REPORT.md'} and {len(list(FIG.glob('*.png')))} figures")


if __name__ == "__main__":
    main()
