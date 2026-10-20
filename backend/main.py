"""
backend/main.py
===============
CSBI detection API (used by the browser extension and the dashboard).

    uvicorn backend.main:app --port 8000

Endpoints
  GET  /health              model + kit-index status
  POST /scan      {url}     server fetches the page and scores it
  POST /scan/page {url, html, final_url?, redirect_hosts?}
                            the browser supplies the rendered HTML (what the
                            user actually sees, including client-side-rendered
                            phishing pages a plain fetch would miss)
  GET  /campaigns           known phishing campaigns (kit clusters)

Results are cached for 30 minutes per URL so the extension can call on every
navigation without re-running WHOIS and TLS lookups.
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from common.hosting import host_of  # noqa: E402
from common.pipeline import _kit, scan_html, scan_url  # noqa: E402
from module5_decision.predict import load as load_model  # noqa: E402

app = FastAPI(title="CSBI Phishing Detection API", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

TTL = 30 * 60
MAX_HTML = 3_000_000
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()

# Popular domains are never sent through the model: a warning on google.com
# would destroy trust in the tool. Loaded from the legit top list if present.
_ALLOW: set[str] = set()
_top = ROOT / "data" / "labeled" / "legit_top.txt"
if _top.exists():
    _ALLOW = {host_of(u) for u in _top.read_text().splitlines()[:1000] if u.strip()}


class ScanReq(BaseModel):
    url: str


class PageReq(BaseModel):
    url: str
    html: str = Field(..., max_length=MAX_HTML)
    final_url: Optional[str] = None
    redirect_hosts: Optional[list[str]] = None


def _public(rec) -> dict:
    f = rec.features
    return {
        "url": rec.url,
        "risk_level": rec.risk_level,
        "scam_probability": rec.scam_probability,
        "reasons": rec.top3_reasons,
        "campaign": rec.cluster_label,
        "kit_match": f.get("_kit_match"),
        "free_hosted": bool(f.get("free_hosted")),
        "platform": f.get("platform") or None,
        "claimed_brand": f.get("_claimed_brand") or None,
        "scores": {"T1": rec.T1, "T2": rec.T2, "T3": rec.T3, "T4": rec.T4, "T5": f.get("T5"),
                   "CSBI": rec.CSBI, "CSBI_PA": f.get("CSBI_PA"),
                   "borrowed_credibility": f.get("borrowed_credibility"),
                   "C_apparent": f.get("C_apparent"), "C_earned": f.get("C_earned")},
        "drivers": f.get("_drivers", []),
        "stage1": f.get("_stage1"),
        "model": f.get("_model", "trained"),
    }


def _cached(key: str):
    with _lock:
        hit = _cache.get(key)
    if hit and time.time() - hit[0] < TTL:
        return hit[1]
    return None


def _store(key: str, val: dict) -> dict:
    with _lock:
        _cache[key] = (time.time(), val)
        if len(_cache) > 5000:
            for k in sorted(_cache, key=lambda k: _cache[k][0])[:1000]:
                _cache.pop(k, None)
    return val


def _allowlisted(url: str) -> Optional[dict]:
    h = host_of(url)
    parts = h.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in _ALLOW:
            return {"url": url, "risk_level": "LOW", "scam_probability": 0.0,
                    "reasons": ["Well-known popular site"], "allowlisted": True}
    return None


@app.get("/health")
def health():
    m = load_model()
    return {"ok": True, "model": bool(m), "model_version": (m or {}).get("version"),
            "thresholds": (m or {}).get("thresholds"), "kit_index": bool(_kit()),
            "allowlist": len(_ALLOW)}


@app.post("/scan")
def scan(req: ScanReq):
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must start with http:// or https://")
    if (a := _allowlisted(req.url)):
        return a
    if (c := _cached("u:" + req.url)):
        return c
    return _store("u:" + req.url, _public(scan_url(req.url)))


@app.post("/scan/page")
def scan_page(req: PageReq):
    if not req.url.startswith(("http://", "https://")):
        raise HTTPException(400, "url must start with http:// or https://")
    if (a := _allowlisted(req.final_url or req.url)):
        return a
    key = "p:" + hashlib.sha1((req.url + req.html[:200000]).encode("utf-8", "ignore")).hexdigest()
    if (c := _cached(key)):
        return c
    rec = scan_html(req.url, req.html, req.final_url, req.redirect_hosts)
    return _store(key, _public(rec))


@app.get("/stats")
def stats():
    """Running totals straight from the scan store (refreshes every call)."""
    import sqlite3
    db = ROOT / "data" / "store" / "scans.db"
    if not db.exists():
        return {"total": 0, "phishing": 0, "legit": 0, "phishing_last_24h": 0, "campaigns": 0}
    con = sqlite3.connect(str(db))
    q = lambda sql: con.execute(sql).fetchone()[0]  # noqa: E731
    out = {
        "total": q("SELECT COUNT(*) FROM scans"),
        "phishing": q("SELECT COUNT(*) FROM scans WHERE ground_truth='scam'"),
        "legit": q("SELECT COUNT(*) FROM scans WHERE ground_truth='legit'"),
        "phishing_last_24h": q("SELECT COUNT(*) FROM scans WHERE ground_truth='scam' "
                               "AND scan_timestamp >= datetime('now','-1 day')"),
        "campaigns": q("SELECT COUNT(DISTINCT cluster_id) FROM scans WHERE cluster_id IS NOT NULL"),
    }
    con.close()
    return out


@app.get("/campaigns")
def campaigns():
    p = ROOT / "results" / "campaigns.json"
    return json.loads(p.read_text()) if p.exists() else []


@app.get("/results/summary")
def results_summary():
    res = ROOT / "results"
    out = {"rows": [], "figures": [], "dataset": None}
    ds = res / "dataset_report.json"
    if ds.exists():
        out["dataset"] = json.loads(ds.read_text())
    cv = res / "cv_results.csv"
    if cv.exists():
        import csv
        with cv.open() as fh:
            rows = [r for r in csv.DictReader(fh) if r["model"] == "xgb"
                    and r["features"] in ("B1_url", "B2_tbdf", "B3_url_html", "B4_csbi", "OURS")]
        order = {"free_hosted": 0, "all": 1, "self_hosted": 2}
        out["rows"] = sorted(rows, key=lambda r: (order.get(r["subset"], 9), r["features"]))
    figs = res / "figures"
    if figs.exists():
        out["figures"] = sorted(p.name for p in figs.glob("*.png"))
    return out


(ROOT / "results" / "figures").mkdir(parents=True, exist_ok=True)
app.mount("/results/figures", StaticFiles(directory=str(ROOT / "results" / "figures")), name="figures")


@app.get("/")
def dashboard():
    return FileResponse(Path(__file__).resolve().parent / "static" / "index.html")
