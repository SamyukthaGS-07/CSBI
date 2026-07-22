from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import requests


@dataclass
class FetchResult:
    url: str
    html: str = ""
    final_url: str | None = None
    status_code: int | None = None


def fetch_url(url: str, timeout: int = 15) -> FetchResult:
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "CSBI/1.0"})
    return FetchResult(
        url=url,
        html=response.text,
        final_url=response.url,
        status_code=response.status_code,
    )


def save_snapshot(snapshot_dir: Path, url: str, html: str) -> Path:
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    snapshot_path = snapshot_dir / f"{abs(hash(url))}.html"
    snapshot_path.write_text(html, encoding="utf-8")
    return snapshot_path
