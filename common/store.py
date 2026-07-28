"""
csbi.common.store
=================

The shared scan-record store (Blueprint §3.1). Backed by SQLite so Module C can
query the infrastructure fields directly (WHERE asn = ...), while the per-URL
pipeline just writes whole records. Neither side calls the other live — they
meet only here.

Design choices:
  * Scalar + infrastructure fields are real columns  -> Varshan can query them.
  * `features` and `top3_reasons` are stored as JSON text blobs.
  * `url` is the primary key: re-scanning a URL upserts (last write wins),
    which matches the store semantics assumed by clustering.

Typical use
-----------
    from common.store import ScanStore
    from common.schema import ScanRecord

    store = ScanStore()                       # default path from config.settings
    store.write(ScanRecord(url="http://x").validate())
    rec = store.read("http://x")
    for r in store.query(ground_truth="scam"):
        ...
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from common.schema import ScanRecord

try:
    from config.settings import STORE_PATH as _DEFAULT_STORE_PATH
except Exception:  # config not importable in isolation — fall back to data/store
    _DEFAULT_STORE_PATH = Path("data/store/scans.db")


# Columns kept as real SQL columns (everything queryable / joinable).
_SCALAR_COLUMNS = (
    "url", "scan_timestamp", "snapshot_path",
    "resolved_ip", "asn", "hosting_provider", "nameserver",
    "ssl_issuer", "dom_tag_sequence_hash",
    "T1", "T2", "T3", "T4", "CSBI",
    "scam_probability", "trust_score", "risk_level",
    "cluster_id", "cluster_label",
    "ground_truth",
)
# Columns serialised as JSON text.
_JSON_COLUMNS = ("features", "top3_reasons")

_CREATE_SQL = f"""
CREATE TABLE IF NOT EXISTS scans (
    url                     TEXT PRIMARY KEY,
    scan_timestamp          TEXT,
    snapshot_path           TEXT,
    resolved_ip             TEXT,
    asn                     TEXT,
    hosting_provider        TEXT,
    nameserver              TEXT,
    ssl_issuer              TEXT,
    dom_tag_sequence_hash   TEXT,
    features                TEXT,      -- JSON
    T1                      REAL,
    T2                      REAL,
    T3                      REAL,
    T4                      REAL,
    CSBI                    REAL,
    scam_probability        REAL,
    trust_score             REAL,
    risk_level              TEXT,
    top3_reasons            TEXT,      -- JSON
    cluster_id              INTEGER,
    cluster_label           TEXT,
    ground_truth            TEXT DEFAULT 'unknown'
);
CREATE INDEX IF NOT EXISTS idx_scans_asn          ON scans(asn);
CREATE INDEX IF NOT EXISTS idx_scans_ground_truth ON scans(ground_truth);
CREATE INDEX IF NOT EXISTS idx_scans_cluster_id   ON scans(cluster_id);
"""


class ScanStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else Path(_DEFAULT_STORE_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # -- internals ------------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_CREATE_SQL)

    @staticmethod
    def _record_to_row(rec: ScanRecord) -> dict[str, Any]:
        d = rec.to_dict()
        row = {c: d.get(c) for c in _SCALAR_COLUMNS}
        for c in _JSON_COLUMNS:
            row[c] = json.dumps(d.get(c))
        return row

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        d = dict(row)
        for c in _JSON_COLUMNS:
            d[c] = json.loads(d[c]) if d.get(c) else ({} if c == "features" else [])
        return ScanRecord.from_dict(d)

    # -- public API -----------------------------------------------------------
    def write(self, record: ScanRecord) -> None:
        """Insert or update one record (upsert on url)."""
        row = self._record_to_row(record)
        cols = _SCALAR_COLUMNS + _JSON_COLUMNS
        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c != "url")
        sql = (
            f"INSERT INTO scans ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT(url) DO UPDATE SET {updates}"
        )
        with self._connect() as conn:
            conn.execute(sql, [row[c] for c in cols])

    def write_many(self, records: Iterable[ScanRecord]) -> int:
        n = 0
        for r in records:
            self.write(r)
            n += 1
        return n

    def read(self, url: str) -> Optional[ScanRecord]:
        with self._connect() as conn:
            cur = conn.execute("SELECT * FROM scans WHERE url = ?", (url,))
            row = cur.fetchone()
        return self._row_to_record(row) if row else None

    def query(self, **filters: Any) -> Iterator[ScanRecord]:
        """Yield records matching equality filters on scalar columns, e.g.
        query(ground_truth='scam') or query(asn='AS13335')."""
        bad = [k for k in filters if k not in _SCALAR_COLUMNS]
        if bad:
            raise ValueError(f"cannot filter on non-column field(s): {bad}")
        sql = "SELECT * FROM scans"
        params: list[Any] = []
        if filters:
            sql += " WHERE " + " AND ".join(f"{k} = ?" for k in filters)
            params = list(filters.values())
        with self._connect() as conn:
            for row in conn.execute(sql, params):
                yield self._row_to_record(row)

    def all(self) -> Iterator[ScanRecord]:
        yield from self.query()

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def update_cluster(self, url: str, cluster_id: int, cluster_label: str) -> None:
        """Convenience for Module C: write back only the cluster fields."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET cluster_id = ?, cluster_label = ? WHERE url = ?",
                (cluster_id, cluster_label, url),
            )
