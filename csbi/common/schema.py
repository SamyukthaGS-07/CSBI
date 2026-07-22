from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4


@dataclass
class ScanRecord:
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    url: str = ""
    scanned_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    status: str = "unknown"
    trust_score: float | None = None
    csbi_score: float | None = None
    scam_probability: float | None = None
    risk_label: str | None = None
    cluster_id: str | None = None
    reasons: list[str] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanRecord":
        return cls(**payload)
