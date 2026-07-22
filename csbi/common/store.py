from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .schema import ScanRecord


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_records (
    scan_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL
)
"""


def _connect(store_path: Path) -> sqlite3.Connection:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(store_path)
    connection.execute(SCHEMA_SQL)
    connection.commit()
    return connection


def write_record(store_path: Path, record: ScanRecord) -> None:
    payload = json.dumps(record.to_dict())
    with _connect(store_path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO scan_records (scan_id, url, scanned_at, status, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (record.scan_id, record.url, record.scanned_at, record.status, payload),
        )
        connection.commit()


def read_record(store_path: Path, scan_id: str) -> ScanRecord | None:
    with _connect(store_path) as connection:
        row = connection.execute(
            "SELECT payload FROM scan_records WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
    if row is None:
        return None
    return ScanRecord.from_dict(json.loads(row[0]))


def query(store_path: Path, limit: int = 100) -> Iterable[dict[str, Any]]:
    with _connect(store_path) as connection:
        rows = connection.execute(
            "SELECT payload FROM scan_records ORDER BY scanned_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    for row in rows:
        yield json.loads(row[0])
