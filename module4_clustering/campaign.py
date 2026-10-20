"""
module4_clustering.campaign
===========================
Campaign discovery and cluster-based weak supervision.

Two clusterings are implemented over the same pages:

  infra_clusters()   Varshan's original method, vectorised so it scales:
                     DBSCAN over  d = sum_k w_k [field_k differs] + 2 * (1 - html_sim)
                     with fields ASN, provider, nameserver, SSL issuer, /24 block
                     and html_sim = cosine of tag-unigram TF-IDF (his weights,
                     his eps = 0.5, min_samples = 3).

  kit_clusters()     the kit-fingerprint method (kit_fingerprint.py), DBSCAN
                     with cosine distance on the kit TF-IDF vectors.

propagate() is the weak-supervision step: confirmed phishing labels spread to
unlabelled pages in the same kit cluster, but only when
  * the cluster contains no confirmed-legitimate page, and
  * the unlabelled page is within `tau` cosine distance of a confirmed
    phishing member (stricter than the clustering eps).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

from module4_clustering.kit_fingerprint import KitVectorizer, kit_tokens

INFRA_FIELDS = ("asn", "hosting_provider", "nameserver", "ssl_issuer", "ip_block")
INFRA_WEIGHTS = (1.0, 1.0, 1.0, 1.0, 1.0)
HTML_WEIGHT = 2.0


# --------------------------------------------------------------------------- #
def load_html(df: pd.DataFrame, snapshot_dir: str | Path | None = None) -> list[str]:
    out = []
    for p in df.get("snapshot_path", pd.Series([None] * len(df))):
        html = ""
        if isinstance(p, str) and p:
            path = Path(p)
            if not path.is_absolute() and snapshot_dir is not None and not path.exists():
                path = Path(snapshot_dir) / path.name
            try:
                html = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                html = ""
        out.append(html)
    return out


def kit_bags(df: pd.DataFrame, html: list[str]) -> list:
    """Kit token bag per page: the stored `_kit` bag when the record has one
    (computed at scan/import time), otherwise computed from the saved HTML."""
    from collections import Counter
    stored = df["_kit"] if "_kit" in df else pd.Series([None] * len(df))
    brands = df["_claimed_brand"].fillna("").tolist() if "_claimed_brand" in df else [""] * len(df)
    out = []
    for k, h, b in zip(stored, html, brands):
        if isinstance(k, dict) and k:
            out.append(Counter(k))
        else:
            out.append(kit_tokens(h, b))
    return out


def kit_matrix(html: list[str], brands: list[str] | None = None, return_vectorizer=False, bags=None):
    brands = brands or [""] * len(html)
    if bags is None:
        bags = [kit_tokens(h, b) for h, b in zip(html, brands)]
    kv = KitVectorizer()
    X = kv.fit_transform(bags)
    return (X, kv) if return_vectorizer else X


# --------------------------------------------------------------------------- #
def _tag_sequence(html: str) -> str:
    import re
    return " ".join(re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9]*)", html or "")).lower()


def infra_distance(df: pd.DataFrame, html: list[str]) -> np.ndarray:
    """Varshan's distance, computed with array operations instead of a double loop."""
    n = len(df)
    d = np.zeros((n, n), dtype=np.float32)
    for f, w in zip(INFRA_FIELDS, INFRA_WEIGHTS):
        vals = df.get(f, pd.Series([None] * n)).fillna("Unknown").astype(str).to_numpy()
        codes = pd.factorize(vals)[0]
        d += w * (codes[:, None] != codes[None, :])
    seqs = [_tag_sequence(h) for h in html]
    valid = np.array([bool(s) for s in seqs])
    sim = np.zeros((n, n), dtype=np.float32)
    if valid.sum() >= 2:
        vec = TfidfVectorizer(tokenizer=str.split, token_pattern=None, lowercase=False)
        M = vec.fit_transform([s for s, v in zip(seqs, valid) if v])
        idx = np.flatnonzero(valid)
        sim[np.ix_(idx, idx)] = (M @ M.T).toarray()
    d += HTML_WEIGHT * np.clip(1.0 - sim, 0, None)
    np.fill_diagonal(d, 0.0)
    return d


def infra_clusters(df, html, eps=0.5, min_samples=3) -> np.ndarray:
    return DBSCAN(eps=eps, min_samples=min_samples, metric="precomputed").fit_predict(
        infra_distance(df, html))


def kit_clusters(X, eps=0.25, min_samples=2) -> np.ndarray:
    return DBSCAN(eps=eps, min_samples=min_samples, metric="cosine",
                  algorithm="brute").fit_predict(X)


# --------------------------------------------------------------------------- #
@dataclass
class Propagation:
    labels: np.ndarray          # 1 = propagated phishing, 0 = untouched
    n_seeds: int
    n_propagated: int


def propagate(X, clusters: np.ndarray, seed_phish: np.ndarray, seed_legit: np.ndarray,
              unlabelled: np.ndarray, tau: float = 0.15) -> Propagation:
    """Spread confirmed phishing labels within kit clusters (see module doc)."""
    out = np.zeros(len(clusters), dtype=int)
    X = sparse.csr_matrix(X)
    for c in np.unique(clusters[clusters >= 0]):
        members = clusters == c
        if (members & seed_legit).any():
            continue
        seeds = np.flatnonzero(members & seed_phish)
        cand = np.flatnonzero(members & unlabelled)
        if len(seeds) == 0 or len(cand) == 0:
            continue
        sim = (X[cand] @ X[seeds].T).toarray().max(axis=1)
        out[cand[(1.0 - sim) <= tau]] = 1
    return Propagation(out, int(seed_phish.sum()), int(out.sum()))


# --------------------------------------------------------------------------- #
class KitIndex:
    """Nearest-known-kit lookup for live verdicts: 'this page is a copy of a
    confirmed phishing kit seen before'. Saved alongside the model."""

    def __init__(self, X, urls: list[str], cluster_ids: np.ndarray, vectorizer: KitVectorizer):
        from sklearn.preprocessing import normalize
        self.vectorizer = vectorizer
        self.X = normalize(sparse.csr_matrix(X))
        self.urls = list(urls)
        self.cluster_ids = np.asarray(cluster_ids)
        self.nn = NearestNeighbors(n_neighbors=1, metric="cosine", algorithm="brute").fit(self.X)

    def match_html(self, html: str, claimed_brand: str = "", max_dist: float = 0.15):
        return self.match(self.vectorizer.transform([kit_tokens(html, claimed_brand)]), max_dist)

    def match(self, x, max_dist: float = 0.15):
        if x.nnz == 0:
            return {"matched": False, "distance": 1.0}
        d, i = self.nn.kneighbors(sparse.csr_matrix(x), n_neighbors=1)
        d, i = float(d[0, 0]), int(i[0, 0])
        if d <= max_dist:
            return {"matched": True, "distance": round(d, 4), "url": self.urls[i],
                    "cluster_id": int(self.cluster_ids[i])}
        return {"matched": False, "distance": round(d, 4)}
