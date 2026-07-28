#!/usr/bin/env python3
"""
module6_delivery/build_cache.py
================================
Orchestrator: pre-computes the demo cache by calling each module in the
pipeline, so the Streamlit app (Module 6) is instant and offline-capable.

Calls, in order:
  Module 3 (module3_behavioral) — CSBI feature extraction (seeded fetch here,
                                  real network fetch in production).
  Module 2 (module2_screening)  — Stage-1 infra routing decision.
  Module 5 (module5_decision)   — verdict + top reasons (rule-based stand-in
                                  until the trained classifier lands).
  Module 4 (module4_clustering) — Varshan's real campaign clustering.

Output: module6_delivery/demo_cache.json
Run once: python module6_delivery/build_cache.py
"""

import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "module4_clustering"))

from module3_behavioral.extraction.extractor import extract_features
from module3_behavioral.extraction.fetch import FetchResult, ip_block
from module6_delivery.demo_sites import SITES

# Varshan's real Module C
from module4_clustering.clustering.fingerprint import build_fingerprint
from module4_clustering.clustering.html_similarity import compute_similarity_matrix
from module4_clustering.clustering.distance_matrix import create_distance_matrix
from module4_clustering.clustering.dbscan_cluster import perform_clustering
from module4_clustering.clustering.label_cluster import label_clusters
from module4_clustering.clustering.evaluation import ClusterEvaluator


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
from module2_screening.stage1_routing import stage1_routing


from module5_decision.verdict_rules import verdict_and_reasons


# --------------------------------------------------------------------------- #
def build():
    print("Module A — scanning 20 curated pages with the real extractor...")
    records = []          # for the app (rich, includes features + layer detail)
    c_input = []          # for Varshan's pipeline (his expected field names)

    import module3_behavioral.extraction.fetch as fetchmod
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
        d.update(stage1_routing(site["url"], fx))
        if not d["routed_to_stage2"]:
            # Stage 1 resolved it directly — reflect that verdict in the demo
            d["risk_level"] = d["stage1_verdict"]
            d["scam_probability"] = 0.92 if d["stage1_verdict"] == "HIGH" else 0.03
            d["top3_reasons"] = [d["route_reason"]]
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
    dest = ROOT / "module6_delivery" / "demo_cache.json"
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
