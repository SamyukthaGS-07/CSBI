"""
module5_decision.dataset
========================
Turns the scan store into the training / evaluation table, with the cleaning
rules stated explicitly so they can be reported in the paper.

Cleaning rules (applied in this order, counts are logged)
  R1  label is scam or legit
  R2  the page was actually fetched (fetch_ok = 1). Phishing pages that were
      already dead at scan time carry no page evidence for ANY page-based
      method, so they are excluded for every model alike.
  R3  pages that returned an error status (>= 400) are dropped for both classes
  R4  legit_login candidates are kept only if a password/credential field
      was actually found — otherwise they are just homepages again
  R5  exact duplicate pages (same URL host + same DOM hash + same label) keep one

Split keys
  group     campaign-disjoint grouping. Phishing pages sharing a DOM template
            hash (the same kit) are one group; otherwise pages are grouped by
            registrable domain. Prevents near-identical kit copies leaking
            across train/test. (Legit pages are not grouped by DOM hash:
            unrelated sites built on the same framework share empty-shell DOMs,
            which would create meaningless giant groups.)
  time      for phishing, when the feed listed it (meta_listed_at); used for the
            temporal split.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd

from common.hosting import host_of, platform_of, registrable_domain
from module5_decision.features import records_to_frame


def load_store(path: str | Path) -> pd.DataFrame:
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute("SELECT * FROM scans")]
    con.close()
    return records_to_frame(rows)


def clean(df: pd.DataFrame, verbose: bool = True) -> tuple[pd.DataFrame, list[tuple[str, int]]]:
    log = [("loaded", len(df))]
    df = df[df["ground_truth"].isin(["scam", "legit"])].copy()
    log.append(("R1 labelled", len(df)))
    df = df[pd.to_numeric(df.get("fetch_ok", 0), errors="coerce").fillna(0) == 1]
    log.append(("R2 page fetched", len(df)))
    st = pd.to_numeric(df.get("http_status", 200), errors="coerce").fillna(200)
    df = df[(st == 0) | (st < 400)]
    log.append(("R3 no error status", len(df)))
    src = df.get("meta_source", pd.Series("", index=df.index)).fillna("")
    is_login = src.str.startswith("legit_login")
    has_cred = pd.to_numeric(df.get("p5_cred_form", 0), errors="coerce").fillna(0) == 1
    df = df[~is_login | has_cred]
    log.append(("R4 login pages have a credential form", len(df)))
    df["host"] = df["url"].map(host_of)
    key = df["host"] + "|" + df["dom_tag_sequence_hash"].fillna("") + "|" + df["ground_truth"]
    df = df[~key.duplicated()].copy()
    log.append(("R5 deduplicated", len(df)))

    df["y"] = (df["ground_truth"] == "scam").astype(int)
    df["platform"] = df["host"].map(lambda h: platform_of(h) or "")
    df["free_hosted"] = (df["platform"] != "").astype(int)
    df["reg_domain"] = df["host"].map(registrable_domain)
    dom = df["dom_tag_sequence_hash"].fillna("")
    df["group"] = np.where((dom != "") & (df["y"] == 1), "dom:" + dom, "reg:" + df["reg_domain"])
    df["time"] = pd.to_datetime(df.get("meta_listed_at"), errors="coerce", utc=True)
    df = df.reset_index(drop=True)
    if verbose:
        for step, n in log:
            print(f"  {step:<42}{n:>8,}")
        print(f"  final: {len(df):,} pages  ({df.y.sum():,} phishing, {(1 - df.y).sum():,} legit; "
              f"{df.free_hosted.sum():,} free-hosted)")
    return df, log
