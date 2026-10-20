#!/usr/bin/env python3
"""Cluster confirmed phishing into campaigns and build the kit index.
Thin wrapper around module4_clustering/build_index.py."""
import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent.parent / "module4_clustering" / "build_index.py"),
                   run_name="__main__")
