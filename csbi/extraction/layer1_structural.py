from __future__ import annotations

from urllib.parse import urlparse


def extract_structural_features(url: str) -> dict[str, object]:
    parsed = urlparse(url)
    host = parsed.netloc
    return {
        "scheme": parsed.scheme,
        "host": host,
        "path_depth": len([part for part in parsed.path.split("/") if part]),
        "has_ip_host": host.replace(".", "").isdigit(),
    }
