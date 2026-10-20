#!/usr/bin/env python3
"""
module5_decision/train.py
=========================
Trains and evaluates every feature set (B1-B4, OURS, ablations) with three
model families, under two splits, and saves the production model.

Splits
  cv        5-fold StratifiedGroupKFold, campaign-disjoint (see dataset.py)
  temporal  phishing listed in the latest 30% of the collection window is
            held out; legit pages are split 70/30 at random (they have no
            listing time)

Every result is reported on three subsets of the test pages:
  all            everything
  free_hosted    pages on a shared free-hosting platform (the target gap)
  self_hosted    the rest

Outputs (results/)
  cv_results.csv, temporal_results.csv   one row per set x model x subset
  oof_scores.csv                         out-of-fold scores, for figures
  dataset_report.json                    cleaning log + class / platform counts
and the production model in module5_decision/artifacts/.

    python module5_decision/train.py --store data/store/scans.db
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from evaluation.metrics import bootstrap_ci, compute_metrics  # noqa: E402
from module5_decision.dataset import clean, load_store  # noqa: E402
from module5_decision.features import ABLATIONS, FEATURE_SETS, matrix  # noqa: E402

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None

RESULTS = ROOT / "results"
ARTIFACTS = ROOT / "module5_decision" / "artifacts"
SEED = 42


def make_model(kind: str, y: np.ndarray):
    pos = max(int(y.sum()), 1)
    neg = max(int(len(y) - y.sum()), 1)
    if kind == "lr":
        return make_pipeline(StandardScaler(), LogisticRegression(
            max_iter=4000, C=1.0, class_weight="balanced"))
    if kind == "rf":
        return RandomForestClassifier(n_estimators=400, min_samples_leaf=2, n_jobs=-1,
                                      class_weight="balanced_subsample", random_state=SEED)
    if kind == "xgb":
        if XGBClassifier is None:
            raise RuntimeError("xgboost not installed")
        return XGBClassifier(n_estimators=500, max_depth=6, learning_rate=0.05,
                             subsample=0.85, colsample_bytree=0.8, min_child_weight=2,
                             reg_lambda=1.0, scale_pos_weight=neg / pos, n_jobs=-1,
                             eval_metric="logloss", random_state=SEED, tree_method="hist")
    raise ValueError(kind)


def subsets(df: pd.DataFrame) -> dict[str, np.ndarray]:
    free = df["free_hosted"].to_numpy() == 1
    return {"all": np.ones(len(df), bool), "free_hosted": free, "self_hosted": ~free}


def evaluate_scores(df, scores, set_name, model_name, split, rows):
    y = df["y"].to_numpy()
    for sub, mask in subsets(df).items():
        if mask.sum() < 10:
            continue
        m = compute_metrics(y[mask], scores=scores[mask])
        rows.append({"split": split, "features": set_name, "model": model_name, "subset": sub, **m})


def run_cv(df, sets, models, n_splits=5):
    y = df["y"].to_numpy()
    groups = df["group"].to_numpy()
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=SEED)
    folds = list(cv.split(np.zeros(len(y)), y, groups))
    rows, oof = [], {}
    for set_name, cols in sets.items():
        X = matrix(df, cols)
        for mk in models:
            t0 = time.time()
            scores = np.zeros(len(y))
            for tr, te in folds:
                m = make_model(mk, y[tr])
                m.fit(X[tr], y[tr])
                scores[te] = m.predict_proba(X[te])[:, 1]
            oof[f"{set_name}|{mk}"] = scores
            evaluate_scores(df, scores, set_name, mk, "cv", rows)
            r = [x for x in rows if x["features"] == set_name and x["model"] == mk]
            print(f"  cv  {set_name:<22}{mk:<4} " + "  ".join(
                f"{x['subset']}: F1={x['f1']:.3f} AUC={x['roc_auc']:.3f}" for x in r)
                + f"  ({time.time() - t0:.0f}s)")
    return pd.DataFrame(rows), pd.DataFrame(oof), folds


def run_temporal(df, sets, models, frac_test=0.3):
    phish = df[df.y == 1]
    if phish["time"].notna().sum() < 50:
        print("  temporal split skipped: phishing pages have no listing times")
        return pd.DataFrame()
    cut = phish["time"].dropna().quantile(1 - frac_test)
    rng = np.random.default_rng(SEED)
    test = np.zeros(len(df), bool)
    test[(df.y == 1) & (df["time"] > cut)] = True
    legit_idx = np.flatnonzero(df.y.to_numpy() == 0)
    test[rng.choice(legit_idx, int(len(legit_idx) * frac_test), replace=False)] = True
    # a campaign must not straddle the cut: drop training pages whose group is in test
    test_groups = set(df.loc[test, "group"])
    train = ~test & ~df["group"].isin(test_groups).to_numpy()
    print(f"  temporal: train {train.sum():,} (phish listed <= {cut:%Y-%m-%d %H:%M}), test {test.sum():,}")
    y = df["y"].to_numpy()
    rows = []
    for set_name, cols in sets.items():
        X = matrix(df, cols)
        for mk in models:
            m = make_model(mk, y[train])
            m.fit(X[train], y[train])
            s = np.full(len(df), np.nan)
            s[test] = m.predict_proba(X[test])[:, 1]
            sub = df[test].reset_index(drop=True)
            evaluate_scores(sub, s[test], set_name, mk, "temporal", rows)
    return pd.DataFrame(rows)


def fit_production(df, cols, kind="xgb"):
    y = df["y"].to_numpy()
    X = matrix(df, cols)
    model = make_model(kind, y)
    model.fit(X, y)
    return model


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=str(ROOT / "data" / "store" / "scans.db"))
    ap.add_argument("--models", default="lr,rf,xgb")
    ap.add_argument("--quick", action="store_true", help="xgb only, no ablations")
    ap.add_argument("--out", default=str(RESULTS))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)

    print("dataset")
    df, log = clean(load_store(args.store))
    if df.y.nunique() < 2 or len(df) < 50:
        sys.exit("not enough labelled pages to train — scan more first")
    models = ["xgb"] if args.quick else args.models.split(",")
    sets = dict(FEATURE_SETS) if args.quick else {**FEATURE_SETS, **ABLATIONS}

    report = {
        "cleaning": log,
        "n": len(df), "n_phish": int(df.y.sum()), "n_legit": int((1 - df.y).sum()),
        "n_free_hosted": int(df.free_hosted.sum()),
        "free_hosted_phish": int(((df.free_hosted == 1) & (df.y == 1)).sum()),
        "free_hosted_legit": int(((df.free_hosted == 1) & (df.y == 0)).sum()),
        "platforms_phish": Counter(df.loc[df.y == 1, "platform"].replace("", "(self-hosted)")).most_common(15),
        "platforms_legit": Counter(df.loc[df.y == 0, "platform"].replace("", "(self-hosted)")).most_common(15),
        "sources": Counter(df.get("meta_source", pd.Series(dtype=str)).fillna("?")).most_common(),
        "n_groups": int(df["group"].nunique()),
    }
    (out / "dataset_report.json").write_text(json.dumps(report, indent=2, default=str))

    print("\ncampaign-disjoint 5-fold CV")
    cv_df, oof, _ = run_cv(df, sets, models)
    cv_df.to_csv(out / "cv_results.csv", index=False)
    oof.insert(0, "url", df["url"])
    for c in ("y", "free_hosted", "platform", "group", "meta_source"):
        if c in df:
            oof[c] = df[c].values
    oof.to_csv(out / "oof_scores.csv", index=False)

    print("\ntemporal split")
    tm = run_temporal(df, sets, models)
    if len(tm):
        tm.to_csv(out / "temporal_results.csv", index=False)

    # headline CIs for the two models the paper compares most
    ci = {}
    for key in ("OURS|xgb", "B2_tbdf|xgb", "B4_csbi|xgb", "B3_url_html|xgb"):
        if key in oof:
            for sub, mask in subsets(df).items():
                ci[f"{key}|{sub}|f1"] = bootstrap_ci(df.y.to_numpy()[mask], oof[key].to_numpy()[mask], "f1")
                ci[f"{key}|{sub}|recall"] = bootstrap_ci(df.y.to_numpy()[mask], oof[key].to_numpy()[mask], "recall")
    (out / "confidence_intervals.json").write_text(json.dumps(ci, indent=2))

    print("\nproduction model (OURS, xgb, all data)")
    cols = FEATURE_SETS["OURS"]
    model = fit_production(df, cols, "xgb")
    oof_s = oof["OURS|xgb"].to_numpy() if "OURS|xgb" in oof else None
    thr = {"medium": 0.35, "high": 0.65}
    if oof_s is not None:
        legit = np.sort(oof_s[df.y.to_numpy() == 0])
        if len(legit) > 50:
            thr = {"medium": float(np.quantile(legit, 0.95)), "high": float(np.quantile(legit, 0.99))}
            thr["medium"] = min(thr["medium"], thr["high"])
    joblib.dump({"model": model, "features": cols, "thresholds": thr,
                 "trained_on": report, "version": time.strftime("%Y-%m-%d")},
                ARTIFACTS / "csbi_model.joblib")
    print(f"  saved {ARTIFACTS / 'csbi_model.joblib'}  thresholds={thr}")


if __name__ == "__main__":
    main()
