from __future__ import annotations

import sys

from csbi.pipeline import run_pipeline


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit('Usage: python scripts/run_scan.py <url>')
    record = run_pipeline(sys.argv[1])
    print(record.to_dict())


if __name__ == '__main__':
    main()
