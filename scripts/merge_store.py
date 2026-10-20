#!/usr/bin/env python3
"""
Merge another scan store (e.g. the scans.db from the PhreshPhish notebook's
csbi_results.zip, or a teammate's collection run) into this machine's store.
Existing URLs are kept unless --overwrite is given.

    python scripts/merge_store.py path/to/other/scans.db
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from common.store import ScanStore  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("other", help="scans.db to merge in")
    ap.add_argument("--into", default=str(ROOT / "data" / "store" / "scans.db"))
    ap.add_argument("--overwrite", action="store_true")
    args = ap.parse_args()
    ScanStore(args.into)                                  # make sure the schema exists
    con = sqlite3.connect(args.into)
    con.execute("ATTACH DATABASE ? AS other", (args.other,))
    cols = [r[1] for r in con.execute("PRAGMA table_info(scans)")]
    verb = "INSERT OR REPLACE" if args.overwrite else "INSERT OR IGNORE"
    before = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    con.execute(f"{verb} INTO scans ({', '.join(cols)}) SELECT {', '.join(cols)} FROM other.scans")
    con.commit()
    after = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    print(f"merged: {before:,} -> {after:,} records in {args.into}")


if __name__ == "__main__":
    main()
