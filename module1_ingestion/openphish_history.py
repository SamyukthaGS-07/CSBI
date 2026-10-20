#!/usr/bin/env python3
"""
module1_ingestion/openphish_history.py
======================================
Builds a *timestamped* phishing dataset from the git history of OpenPhish's
public feed (github.com/openphish/public_feed). The feed is re-committed about
every 6 hours, so every URL's first and last appearance is recoverable.

Why this matters for the paper
------------------------------
Static phishing lists only tell you *that* a URL was phishing. The commit
history tells you *when* the feed first listed it. That is what makes two
experiments possible that most prior work cannot run:

  1. A temporal train/test split (train on older months, test on newer ones),
     which is far more honest than a random split.
  2. Early detection: for a campaign cluster, how many of its members could be
     flagged by propagation *before* OpenPhish listed them.

Usage
-----
    git clone --bare https://github.com/openphish/public_feed op.git
    python module1_ingestion/openphish_history.py op.git data/raw/openphish_history.csv

Output CSV columns: url, first_seen_utc, last_seen_utc, n_snapshots, host, free_hosted
"""
from __future__ import annotations

import csv
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.hosting import host_of, is_free_hosted  # noqa: E402

MARK = "@@COMMIT@@"


def _iter_diff(repo: str):
    """Yield (timestamp, added_lines) per commit, oldest first."""
    cmd = ["git", "-C", repo, "log", "--reverse", "-p", "--no-color",
           f"--format={MARK} %ct", "--", "feed.txt"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace")
    ts, added = None, []
    for line in proc.stdout:
        if line.startswith(MARK):
            if ts is not None:
                yield ts, added
            ts, added = int(line.split()[1]), []
        elif line.startswith("+") and not line.startswith("+++"):
            u = line[1:].strip()
            if u.startswith("http"):
                added.append(u)
    if ts is not None:
        yield ts, added
    proc.wait()


def build(repo: str) -> dict[str, dict]:
    seen: dict[str, dict] = {}
    for ts, added in _iter_diff(repo):
        for u in added:
            rec = seen.get(u)
            if rec is None:
                seen[u] = {"first": ts, "last": ts, "n": 1}
            else:
                rec["last"] = ts
                rec["n"] += 1
    return seen


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    repo, out = sys.argv[1], Path(sys.argv[2])
    seen = build(repo)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "first_seen_utc", "last_seen_utc", "n_snapshots", "host", "free_hosted"])
        for u, r in sorted(seen.items(), key=lambda kv: kv[1]["first"]):
            h = host_of(u)
            w.writerow([u, _iso(r["first"]), _iso(r["last"]), r["n"], h, int(is_free_hosted(h))])
    n_free = sum(is_free_hosted(host_of(u)) for u in seen)
    print(f"{len(seen):,} unique URLs -> {out}  ({n_free:,} free-hosted, "
          f"{100 * n_free / max(len(seen), 1):.1f}%)")


if __name__ == "__main__":
    main()
