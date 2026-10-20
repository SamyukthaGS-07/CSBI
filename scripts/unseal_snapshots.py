#!/usr/bin/env python3
"""
Unlock encrypted HTML archives produced by the GitHub Actions scanner into
data/snapshots/, so clustering / re-extraction work exactly as if the pages had
been scanned locally.

    python scripts/unseal_snapshots.py --key snapshots_private.pem downloads/*.sealed
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.sealed import unseal  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help="snapshots_private.pem (keep it out of the repo)")
    ap.add_argument("--out", default="data/snapshots")
    ap.add_argument("archives", nargs="+")
    args = ap.parse_args()
    key = Path(args.key).read_bytes()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    total = 0
    for a in args.archives:
        for p in sorted(Path().glob(a)) if any(c in a for c in "*?[") else [Path(a)]:
            files = unseal(p.read_bytes(), key)
            for name, data in files.items():
                (out / Path(name).name).write_bytes(data)
            total += len(files)
            print(f"{p.name}: {len(files)} pages")
    print(f"{total} pages written to {out}")


if __name__ == "__main__":
    main()
