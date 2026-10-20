"""
common.pipeline
===============
One call that runs the whole system on a URL (or on HTML the browser already
has), used by the API, the browser extension and the demo:

    scan_url(url)                  fetch -> features -> model -> kit match
    scan_html(url, html, ...)      same, but with page HTML supplied by the
                                   browser (no server-side fetch of the page;
                                   TLS / WHOIS / DNS are still looked up)

The Stage-1 routing decision (Module 2) is attached to the record for display
(`features["_stage1"]`); the verdict itself always comes from the trained
model, because Stage 1 alone cannot see page behaviour.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from common.schema import ScanRecord
from module3_behavioral.extraction import fetch as fetch_mod
from module3_behavioral.extraction.extractor import extract_features
from module5_decision import predict as predict_mod

KIT_INDEX = Path(__file__).resolve().parent.parent / "module4_clustering" / "artifacts" / "kit_index.joblib"


@lru_cache(maxsize=1)
def _kit():
    if not KIT_INDEX.exists():
        return None
    import joblib
    return joblib.load(KIT_INDEX)


def _finish(rec: ScanRecord, html: str) -> ScanRecord:
    from module2_screening.stage1_routing import stage1_routing
    rec.features["_stage1"] = stage1_routing(rec.url, rec.features)
    feats = dict(rec.features)
    feats.update({"T1": rec.T1, "T2": rec.T2, "T3": rec.T3, "T4": rec.T4, "CSBI": rec.CSBI})
    bundle = predict_mod.load()
    if bundle is not None:
        out = predict_mod.predict(feats, bundle)
        rec.scam_probability = out["scam_probability"]
        rec.risk_level = out["risk_level"]
        rec.top3_reasons = out["top3_reasons"]
        rec.features["_drivers"] = out["drivers"]
    else:                                         # no trained model yet
        from module5_decision.verdict_rules import verdict_and_reasons
        prob, risk, reasons = verdict_and_reasons(rec.to_dict())
        rec.scam_probability, rec.risk_level, rec.top3_reasons = prob, risk, reasons
        rec.features["_model"] = "rule-based fallback (no trained model found)"
    rec.trust_score = round(1 - (rec.scam_probability or 0), 4)

    kit = _kit()
    if kit is not None and html:
        m = kit["index"].match_html(html, rec.features.get("_claimed_brand", ""))
        rec.features["_kit_match"] = m
        if m.get("matched"):
            rec.cluster_id = m["cluster_id"]
            rec.cluster_label = kit["labels"].get(m["cluster_id"], f"campaign #{m['cluster_id']}")
            if rec.risk_level != "HIGH":
                rec.top3_reasons = ([f"Same phishing kit as a confirmed campaign ({rec.cluster_label})"]
                                    + rec.top3_reasons)[:3]
                rec.risk_level = "HIGH"
    return rec


def scan_url(url: str, save_snapshot: bool = False) -> ScanRecord:
    holder = {}

    def f(u, save=save_snapshot):
        fr = fetch_mod.fetch(u, save=save)
        holder["html"] = fr.html
        return fr
    rec = extract_features(url, fetch_fn=f, save_snapshot=save_snapshot)
    return _finish(rec, holder.get("html", ""))


def scan_html(url: str, html: str, final_url: Optional[str] = None,
              redirect_hosts: Optional[list[str]] = None) -> ScanRecord:
    """Score a page whose HTML the browser already rendered."""
    def f(u, save=False):
        fr = fetch_mod.FetchResult(url=u, final_url=final_url or u, status_code=200, ok=True, html=html)
        host = fetch_mod.url_host(final_url or u)
        fr.resolved_ip = fetch_mod.resolve_ip(host)
        fr.ssl_issuer, fr.ssl_not_before, fr.cert_names = fetch_mod.get_ssl_cert_full(host)
        try:
            from common.hosting import platform_of, registrable_domain
            wd = platform_of(host) or registrable_domain(host)
        except Exception:
            wd = host
        fr.whois_creation, fr.whois_expiration, fr.nameserver = fetch_mod.get_whois(wd)
        fr.redirect_hosts = redirect_hosts or [host]
        return fr
    rec = extract_features(url, fetch_fn=f, save_snapshot=False)
    return _finish(rec, html)
