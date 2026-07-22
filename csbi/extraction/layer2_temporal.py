from __future__ import annotations

from datetime import datetime, timezone


def extract_temporal_features() -> dict[str, object]:
    return {
        "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "whois_available": False,
        "ct_fallback_used": False,
    }
