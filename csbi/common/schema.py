"""
csbi.common.schema
==================

The ONE shared interface (Blueprint §3). Every URL the system scans becomes a
single ScanRecord. Ownership of each field group is fixed so the three modules
never step on each other:

    Identity ............ Module A (Samyuktha)   url, scan_timestamp, snapshot_path
    Infrastructure ...... Module A writes / Module C reads
                          resolved_ip, asn, hosting_provider, nameserver,
                          ssl_issuer, dom_tag_sequence_hash
    Features & scores ... Module A               features{...}, T1, T2, T3, T4, CSBI
    Model output ........ Module B (Shri Nithee)  scam_probability, trust_score,
                          risk_level, top3_reasons
    Cluster output ...... Module C (Varshan)      cluster_id, cluster_label
    Label ............... Dataset (shared)        ground_truth  (scam/legit/unknown)

This file is the contract. If a field changes here, it changes for everyone —
which is exactly the one thing the Day-1 kickoff locks and the mid-point sync
re-checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


VALID_GROUND_TRUTH = {"scam", "legit", "unknown"}
VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", None}


def utc_now_iso() -> str:
    """Timestamp used for scan_timestamp — ISO 8601, UTC, second precision."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ScanRecord:
    # ---- Identity (Module A) -------------------------------------------------
    url: str
    scan_timestamp: str = field(default_factory=utc_now_iso)
    snapshot_path: Optional[str] = None          # HTML/screenshot cache (§8.3)

    # ---- Infrastructure (Module A writes, Module C reads) --------------------
    resolved_ip: Optional[str] = None
    asn: Optional[str] = None
    hosting_provider: Optional[str] = None
    nameserver: Optional[str] = None
    ssl_issuer: Optional[str] = None
    dom_tag_sequence_hash: Optional[str] = None

    # ---- Features & scores (Module A) ---------------------------------------
    # `features` holds every raw layer feature keyed by name, e.g.
    # {"https": 1, "url_length_norm": 0.12, "subdomain_count": 1,
    #  "is_ip_domain": 0, "special_char_ratio": 0.03, "domain_age_days": 8, ...}
    features: dict[str, Any] = field(default_factory=dict)
    T1: Optional[float] = None                    # structural trust  (Layer 1)
    T2: Optional[float] = None                    # temporal trust    (Layer 2)
    T3: Optional[float] = None                    # behavioral trust  (Layer 3)
    T4: Optional[float] = None                    # UPI trust         (Layer 4)
    CSBI: Optional[float] = None                  # 100 * max(0, C - S)

    # ---- Model output (Module B) --------------------------------------------
    scam_probability: Optional[float] = None
    trust_score: Optional[float] = None
    risk_level: Optional[str] = None              # LOW / MEDIUM / HIGH
    top3_reasons: list[str] = field(default_factory=list)

    # ---- Cluster output (Module C) ------------------------------------------
    cluster_id: Optional[int] = None
    cluster_label: Optional[str] = None

    # ---- Label (shared dataset) ---------------------------------------------
    ground_truth: str = "unknown"                 # scam / legit / unknown

    # -------------------------------------------------------------------------
    def validate(self) -> "ScanRecord":
        """Raise ValueError if the record violates the §3 contract. Returns self
        so calls can be chained: store.write(rec.validate())."""
        if not self.url or not isinstance(self.url, str):
            raise ValueError("ScanRecord.url must be a non-empty string")
        if self.ground_truth not in VALID_GROUND_TRUTH:
            raise ValueError(
                f"ground_truth must be one of {sorted(VALID_GROUND_TRUTH)}, "
                f"got {self.ground_truth!r}"
            )
        if self.risk_level not in VALID_RISK_LEVELS:
            raise ValueError(
                f"risk_level must be one of {sorted(x for x in VALID_RISK_LEVELS if x)} "
                f"or None, got {self.risk_level!r}"
            )
        for name in ("T1", "T2", "T3", "T4"):
            v = getattr(self, name)
            if v is not None and not (0.0 <= float(v) <= 1.0):
                raise ValueError(f"{name} must be in [0, 1], got {v}")
        if self.CSBI is not None and not (0.0 <= float(self.CSBI) <= 100.0):
            raise ValueError(f"CSBI must be in [0, 100], got {self.CSBI}")
        if not isinstance(self.features, dict):
            raise ValueError("features must be a dict")
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanRecord":
        known = {f for f in cls.__dataclass_fields__}          # noqa: E1133
        return cls(**{k: v for k, v in d.items() if k in known})


# The infrastructure fields Module C is allowed to read. Kept here so the
# clustering side imports the contract instead of hard-coding field names.
INFRASTRUCTURE_FIELDS = (
    "url",
    "resolved_ip",
    "asn",
    "hosting_provider",
    "nameserver",
    "ssl_issuer",
    "dom_tag_sequence_hash",
)
