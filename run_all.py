#!/usr/bin/env python3
"""
run_all.py — the whole CSBI-PA pipeline, step by step, from an empty store to
the results report. Works on Windows, macOS and Linux.

    python run_all.py setup          install deps + build URL lists
    python run_all.py legit          scan the legitimate lists (~1-2 h)
    python run_all.py collect 12     scan newly listed phishing for 12 hours
    python run_all.py results        train, run experiments, build index, report
    python run_all.py ctwatch        watch Certificate Transparency logs for zero-day lookalikes
    python run_all.py serve          start the API + dashboard on :8000 (this machine only)
    python run_all.py serve public   same, reachable at http://<server-ip>:8000 (cloud VM)
    python run_all.py status         what is in the store right now

`collect` is the step that needs time: phishing pages die within hours, so they
are scanned as they get listed. Run it for as long as you can (expect a few
hundred live phishing pages per day). Everything is resumable; Ctrl+C is safe.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def run(*args: str) -> None:
    print("\n$ " + " ".join(args), flush=True)
    r = subprocess.run(list(args), cwd=ROOT)
    if r.returncode != 0:
        sys.exit(f"step failed: {' '.join(args)}")


def setup() -> None:
    run(PY, "-m", "pip", "install", "-r", "requirements.txt")
    feed = ROOT / "data" / "raw" / "openphish_feed.git"
    if not feed.exists():
        run("git", "clone", "--bare", "https://github.com/openphish/public_feed", str(feed))
    else:
        run("git", "-C", str(feed), "fetch", "origin", "+refs/heads/*:refs/heads/*")
    run(PY, "module1_ingestion/openphish_history.py", str(feed), "data/raw/openphish_history.csv")
    run(PY, "module1_ingestion/build_legit.py", "--phish-history", "data/raw/openphish_history.csv")


def legit() -> None:
    for name in ("legit_free", "legit_login", "legit_top"):
        run(PY, "scripts/run_scan.py", "--file", f"data/labeled/{name}.txt", "--label", "legit",
            "--source", name, "--workers", "24")


def collect(hours: float) -> None:
    end = time.time() + hours * 3600
    print(f"collecting live phishing for {hours:g} h (until {time.strftime('%H:%M', time.localtime(end))})")
    while time.time() < end:
        run(PY, "scripts/collect_live.py", "--once", "--workers", "24", "--max-per-cycle", "800")
        wait = min(30 * 60, max(0, end - time.time()))
        if wait > 0:
            print(f"next pull in {wait / 60:.0f} min")
            time.sleep(wait)


def results() -> None:
    run(PY, "module5_decision/train.py")
    run(PY, "evaluation/campaign_experiments.py")
    run(PY, "module4_clustering/build_index.py")
    run(PY, "evaluation/make_report.py")
    print("\nDone. Open results/REPORT.md, or run:  python run_all.py serve")


def serve(public: bool = False) -> None:
    # public: listen on all interfaces so http://<server-ip>:8000 works (cloud VM)
    run(PY, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0" if public else "127.0.0.1",
        "--port", "8000")


def ctwatch() -> None:
    run(PY, "module1_ingestion/ct_monitor.py")


def status() -> None:
    run(PY, "scripts/run_scan.py", "--stats")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "setup":
        setup()
    elif cmd == "legit":
        legit()
    elif cmd == "collect":
        collect(float(sys.argv[2]) if len(sys.argv) > 2 else 12)
    elif cmd == "results":
        results()
    elif cmd == "ctwatch":
        ctwatch()
    elif cmd == "serve":
        serve(public=len(sys.argv) > 2 and sys.argv[2] == "public")
    elif cmd == "status":
        status()
    else:
        print(__doc__)
