from __future__ import annotations


def build_fingerprint(features: dict[str, object]) -> dict[str, object]:
    return {
        "asn": features.get("asn"),
        "ip_block": features.get("ip_block"),
        "ns": features.get("ns"),
        "ssl_issuer": features.get("ssl_issuer"),
        "dom_hash": features.get("dom_hash"),
    }
