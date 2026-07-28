"""
csbi.extraction.extractor
=========================
Module A's single entry point (Blueprint §2 steps 0-3, §4):

    extract_features(url) -> ScanRecord

It runs the whole analytical input half of the pipeline for one URL:
    fetch (HTTP + SSL + WHOIS + snapshot)
      -> Layer 1 structural   (from URL)
      -> Layer 2 temporal      (from fetch: WHOIS/SSL, incl. §10 fallback)
      -> Layer 3 behavioral    (from HTML)
      -> Layer 4 UPI           (from HTML)
      -> T1..T4                (§4.1)
      -> CSBI                  (§4.2)
    -> ScanRecord, written to the shared store.

Module B calls this and picks up from the ScanRecord (adds model output). The
`fetch_fn` argument is injectable so the pipeline can be unit-tested offline with
a canned FetchResult instead of hitting the network.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

from bs4 import BeautifulSoup

from csbi.common.schema import ScanRecord
from csbi.extraction import fetch as fetch_mod
from csbi.extraction import layer1_structural as l1
from csbi.extraction import layer2_temporal as l2
from csbi.extraction import layer3_behavioral as l3
from csbi.extraction import layer4_upi as l4
from csbi.scoring.trust_scores import all_trust_scores
from csbi.scoring.csbi import compute_csbi


def dom_tag_sequence_hash(html: str) -> Optional[str]:
    """A stable hash of the page's tag sequence — the structural DOM fingerprint
    Module C uses for template-similarity clustering. Written here (Module A owns
    the infrastructure fields per §3) so Varshan reads it straight from the store."""
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    seq = ">".join(t.name for t in soup.find_all(True))
    return hashlib.sha1(seq.encode("utf-8")).hexdigest()


def lookup_asn(ip: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(asn, hosting_provider) for an IP — the infrastructure fields Module C's
    fingerprint needs (§3). Delegates to fetch.get_asn (ip-api.com free endpoint,
    or ipinfo.io when IPINFO_TOKEN is set). Returns (None, None) on failure so a
    lookup outage never breaks a scan."""
    return fetch_mod.get_asn(ip)


def extract_features(
    url: str,
    store=None,
    fetch_fn: Optional[Callable] = None,
    save_snapshot: bool = True,
) -> ScanRecord:
    # Resolved at call time (not bound as a default) so the network layer can be
    # swapped for tests or offline replay.
    fetch_fn = fetch_fn or fetch_mod.fetch
    fr = fetch_fn(url, save=save_snapshot)

    # --- raw features from all four layers ---
    features: dict = {}
    features.update(l1.extract(url))
    features.update(l2.extract(fr))
    features.update(l3.extract(fr.html, url))
    features.update(l4.extract(fr.html, url))
    features["from_snapshot"] = int(fr.from_snapshot)   # §8.3 provenance flag
    # IP netblock — part of Module C's fingerprint (campaigns bulk-host in a /24).
    features["ip_block"] = fetch_mod.ip_block(fr.resolved_ip)

    # --- trust scores + CSBI ---
    trust = all_trust_scores(features)
    csbi = compute_csbi(**trust)

    # --- infrastructure fields (Module A writes; Module C reads) ---
    asn, hosting_provider = lookup_asn(fr.resolved_ip)

    record = ScanRecord(
        url=url,
        snapshot_path=fr.snapshot_path,
        resolved_ip=fr.resolved_ip,
        asn=asn,
        hosting_provider=hosting_provider,
        nameserver=fr.nameserver,
        ssl_issuer=fr.ssl_issuer,
        dom_tag_sequence_hash=dom_tag_sequence_hash(fr.html),
        features=features,
        T1=trust["T1"],
        T2=trust["T2"],
        T3=trust["T3"],
        T4=trust["T4"],
        CSBI=csbi,
    ).validate()

    if store is not None:
        store.write(record)
    return record
