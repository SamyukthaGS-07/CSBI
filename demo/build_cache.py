#!/usr/bin/env python3
"""
demo/build_cache.py
===================
Pre-computes the demo cache so the Streamlit app is instant and offline-capable.

It runs the REAL pipeline end to end:
  1. Module A  — your extract_features on each curated page (seeded fetch, so no
                 network needed, but every layer computes for real).
  2. Module B  — a rule-based verdict + top-3 reasons from the real feature values
                 (stand-in until the trained model lands; clearly labelled).
  3. Module C  — Varshan's real fingerprint -> similarity -> DBSCAN -> label ->
                 evaluate pipeline on the resulting records.

Output: demo/demo_cache.json  (everything the app needs, keyed by URL).

Run once:  python demo/build_cache.py
"""

import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "module_c"))

from csbi.extraction.extractor import extract_features
from csbi.extraction.fetch import FetchResult, ip_block
from demo.demo_sites import SITES

# Varshan's real Module C
from module_c.clustering.fingerprint import build_fingerprint
from module_c.clustering.html_similarity import compute_similarity_matrix
from module_c.clustering.distance_matrix import create_distance_matrix
from module_c.clustering.dbscan_cluster import perform_clustering
from module_c.clustering.label_cluster import label_clusters
from module_c.clustering.evaluation import ClusterEvaluator


# --------------------------------------------------------------------------- #
# Module A: run your real extractor with a seeded fetch                        #
# --------------------------------------------------------------------------- #
def seeded_fetch(site):
    def _f(url, save=True):
        return FetchResult(
            url=url, final_url=url, status_code=200, ok=True, html=site["html"],
            resolved_ip=site["ip"], ssl_issuer=site["ssl"], ssl_not_before=site["ssl_before"],
            whois_creation=site["created"], whois_expiration=site["expires"],
            nameserver=site["ns"], snapshot_path=None,
        )
    return _f


def seeded_asn(site):
    return lambda ip, timeout=6: (site["asn"], site["provider"])


# --------------------------------------------------------------------------- #
# Module B: rule-based verdict + top-3 reasons from REAL features              #
# --------------------------------------------------------------------------- #
REASON_RULES = [
    ("brand_mismatch", lambda f: f.get("brand_mismatch") == 1,
     lambda f: "Impersonates a known brand not reflected in the domain", 30),
    ("upi_field_presence", lambda f: f.get("upi_field_presence") == 1,
     lambda f: "Collects a UPI payment ID directly on the page", 25),
    ("fake_gov_qr", lambda f: f.get("fake_gov_qr_score", 0) >= 0.9,
     lambda f: "Displays a QR alongside fake government branding", 22),
    ("subsidy_bait", lambda f: f.get("subsidy_refund_language_score", 0) >= 0.5,
     lambda f: "Uses subsidy / refund / cashback bait language", 20),
    ("urgency", lambda f: f.get("urgency_language_score", 0) >= 0.5,
     lambda f: "Pressures the visitor with urgency / threat language", 18),
    ("young_domain", lambda f: 0 < f.get("domain_age_days", 9999) <= 30,
     lambda f: f"Domain registered only {int(f.get('domain_age_days',0))} days ago", 24),
    ("ext_scripts", lambda f: f.get("external_script_ratio", 0) >= 0.3,
     lambda f: "Loads a high ratio of third-party scripts", 10),
    ("no_https", lambda f: f.get("https") == 0,
     lambda f: "Served without HTTPS", 15),
]


def verdict_and_reasons(record):
    """Heuristic scam probability + risk + top-3 reasons from real features.
    Stands in for Module B's trained model; every input is a real measured value."""
    f = record["features"]
    csbi = record["CSBI"] or 0.0

    fired = [(w, msg(f)) for _, cond, msg, w in REASON_RULES if cond(f)]
    fired.sort(key=lambda x: -x[0])
    top3 = [msg for _, msg in fired[:3]]

    # probability: blend of behavioural evidence and the CSBI contradiction
    behaviour = min(sum(w for w, _ in fired) / 80.0, 1.0)
    prob = round(min(0.05 + 0.6 * behaviour + 0.35 * (csbi / 100.0), 0.99), 3)
    risk = "HIGH" if prob >= 0.66 else "MEDIUM" if prob >= 0.33 else "LOW"
    return prob, risk, (top3 or ["No strong scam signals detected"])


# --------------------------------------------------------------------------- #
def build():
    print("Module A — scanning 20 curated pages with the real extractor...")
    records = []          # for the app (rich, includes features + layer detail)
    c_input = []          # for Varshan's pipeline (his expected field names)

    import csbi.extraction.fetch as fetchmod
    for site in SITES:
        fetchmod.get_asn = seeded_asn(site)   # seed ASN for this site
        rec = extract_features(site["url"], store=None, fetch_fn=seeded_fetch(site))
        d = rec.to_dict()
        d["ground_truth"] = site["label"]
        d["campaign_true"] = site["campaign"]
        prob, risk, reasons = verdict_and_reasons(d)
        d["scam_probability"], d["risk_level"], d["top3_reasons"] = prob, risk, reasons
        # extra display data for the professional UI
        d["html_preview"] = site["html"]
        d["infra"] = {"ip": site["ip"], "asn": site["asn"], "provider": site["provider"],
                      "nameserver": site["ns"], "ssl_issuer": site["ssl"]}
        fx = d["features"]
        d["traditional_safe"] = bool(fx["https"] == 1 and fx["is_ip_domain"] == 0
                                     and fx["special_char_ratio"] <= 0.15
                                     and fx["subdomain_count"] <= 1)
        records.append(d)

        c_input.append({
            "url": site["url"],
            "hosting_provider": site["provider"],
            "asn": int(site["asn"].replace("AS", "")),
            "ip_address": site["ip"],
            "nameserver": site["ns"],
            "ssl_issuer": site["ssl"],
            "html_content": site["html"],
            "dom_hash": rec.dom_tag_sequence_hash,
        })

    print(f"  done — {len(records)} records scored.")

    print("Module C — running Varshan's real DBSCAN pipeline...")
    fingerprints = [{**r, **build_fingerprint(r)} for r in c_input]
    sim = compute_similarity_matrix([r["html_content"] for r in c_input])
    dist, _ = create_distance_matrix(fingerprints, sim)
    labels, info = perform_clustering(dist, eps=0.5, min_samples=3)
    cluster_id_to_label, updated = label_clusters(fingerprints, labels)

    true_labels = [s["campaign"] for s in SITES]
    ev = ClusterEvaluator()
    report = ev.generate_evaluation_report(dist, labels, true_labels, updated)
    print(f"  clusters={info}")

    # merge cluster results back into the app records
    for rec, lab, upd in zip(records, labels, updated):
        rec["cluster_id"] = int(lab)
        rec["cluster_label"] = (cluster_id_to_label.get(int(lab)) if int(lab) != -1
                                else "Unclustered (likely legitimate)")
        rec["ip_block"] = upd.get("IPBlock")
        rec["_fingerprint"] = {k: upd.get(k) for k in ("ASN", "Provider", "Nameserver", "SSL", "DOMHash", "IPBlock")}

    # cluster summary for the campaign tab
    clusters = {}
    for rec in records:
        cid = rec["cluster_id"]
        clusters.setdefault(cid, {"cluster_id": cid,
                                  "label": rec["cluster_label"],
                                  "members": [], "provider": rec["_fingerprint"]["Provider"]})
        clusters[cid]["members"].append(rec["url"])

    evaluation = {
        "silhouette_score": round(float(report.get("silhouette_score", 0.0)), 3),
        "purity_score": round(float(report.get("purity_score", 0.0)), 3),
        "n_clusters": info.get("n_clusters"),
        "n_noise": info.get("n_noise"),
        "n_total": len(records),
    }

    out = {
        "records": records,
        "clusters": list(clusters.values()),
        "evaluation": evaluation,
    }
    dest = ROOT / "demo" / "demo_cache.json"
    dest.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"\nwrote {dest}")

    # quick separation readout
    scams = [r["CSBI"] for r in records if r["ground_truth"] == "scam"]
    legit = [r["CSBI"] for r in records if r["ground_truth"] == "legit"]
    print(f"CSBI mean — scam={sum(scams)/len(scams):.1f}  legit={sum(legit)/len(legit):.1f}")
    print(f"clusters={evaluation['n_clusters']} noise={evaluation['n_noise']} "
          f"silhouette={evaluation['silhouette_score']} purity={evaluation['purity_score']}")


if __name__ == "__main__":
    build()
