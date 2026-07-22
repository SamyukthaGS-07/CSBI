from __future__ import annotations

import re

UPI_VPA_PATTERN = re.compile(r"\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b")


def extract_upi_features(text: str) -> dict[str, object]:
    matches = UPI_VPA_PATTERN.findall(text)
    return {
        "upi_vpa_count": len(matches),
        "has_upi_vpa": bool(matches),
        "subsidy_score": 0,
        "has_qr_hint": "qr" in text.lower(),
    }
