#!/usr/bin/env python3
"""
module1_ingestion/build_legit.py
================================
Builds the legitimate half of the dataset, in three parts, so the classifier
cannot win by learning shortcuts:

  legit_top.txt         homepages of popular domains (top-10k list mirror).
                        The usual "legit" class in prior work.
  legit_free.txt        legitimate pages on the SAME free-hosting platforms
                        phishers use (github.io, vercel.app, netlify.app,
                        pages.dev, ...), harvested from curated sources:
                        the links in ~675 "awesome" lists and npm package
                        homepages. Without this set the free-hosted subset
                        would be all-phishing and "is it on pages.dev?" would
                        look like a perfect detector.
  legit_login.txt       login / account pages of popular sites, so "has a
                        password field" is not a shortcut either.

Anything whose host ever appeared in the OpenPhish history is dropped.

    python module1_ingestion/build_legit.py --phish-history data/raw/openphish_history.csv
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

from common.hosting import host_of, platform_of  # noqa: E402

OUT = Path("data/labeled")
TOP_LIST = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-10000-domains"
AWESOME_ROOT = "https://raw.githubusercontent.com/sindresorhus/awesome/main/readme.md"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_TERMS = ("react vue svelte next nuxt astro ui component cli tool api sdk chart icon theme "
             "css tailwind docs blog portfolio template starter plugin vite webpack typescript "
             "node express auth form editor markdown game 3d animation hooks state test utils "
             "date color font map ai llm chat bot crypto web3 wallet image video audio pdf "
             "table data graph").split()
LOGIN_PATHS = ("/login", "/signin", "/account/login", "/users/sign_in", "/auth/login")
URL_RE = re.compile(r"https?://[^\s)<>\"'\]]+")


def _get(url: str, **kw) -> str:
    try:
        r = requests.get(url, timeout=30, **kw)
        return r.text if r.ok else ""
    except Exception:
        return ""


def _readme(repo_url: str) -> str:
    owner, name = repo_url.rstrip("/").split("/")[3:5]
    for br in ("main", "master"):
        for f in ("README.md", "readme.md", "Readme.md"):
            t = _get(f"https://raw.githubusercontent.com/{owner}/{name}/{br}/{f}")
            if t:
                return t
    return ""


def harvest_awesome(workers: int = 24) -> set[str]:
    root = _get(AWESOME_ROOT)
    repos = sorted(set(re.findall(r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", root)))
    print(f"awesome: {len(repos)} lists")
    urls: set[str] = set()
    with cf.ThreadPoolExecutor(workers) as ex:
        for text in ex.map(_readme, repos):
            urls.update(u.rstrip(").,;'\">]") for u in URL_RE.findall(text))
    return urls


def harvest_npm(workers: int = 12) -> set[str]:
    def page(job):
        q, off = job
        try:
            r = requests.get(NPM_SEARCH, params={"text": q, "size": 250, "from": off}, timeout=30)
            return [o["package"].get("links", {}).get("homepage") for o in r.json().get("objects", [])]
        except Exception:
            return []
    jobs = [(q, o) for q in NPM_TERMS for o in range(0, 5000, 250)]
    out: set[str] = set()
    with cf.ThreadPoolExecutor(workers) as ex:
        for hs in ex.map(page, jobs):
            out.update(h for h in hs if h and h.startswith("http"))
    print(f"npm: {len(out):,} homepages")
    return out


def one_per_host(urls) -> dict[str, str]:
    by: dict[str, str] = {}
    for u in sorted(urls, key=len):
        h = host_of(u)
        if h:
            by.setdefault(h, u)
    return by


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish-history", default="data/raw/openphish_history.csv")
    ap.add_argument("--top-n", type=int, default=3000)
    ap.add_argument("--login-n", type=int, default=800)
    ap.add_argument("--github-io-cap", type=int, default=600,
                    help="cap github.io so one platform does not dominate the legit class")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    random.seed(args.seed)
    OUT.mkdir(parents=True, exist_ok=True)

    bad_hosts: set[str] = set()
    p = Path(args.phish_history)
    if p.exists():
        import csv
        with p.open(encoding="utf-8") as fh:
            bad_hosts = {r["host"] for r in csv.DictReader(fh)}
    print(f"excluding {len(bad_hosts):,} hosts seen in phishing feeds")

    # --- popular homepages ---------------------------------------------------
    top = [d.strip() for d in _get(TOP_LIST).splitlines() if d.strip()][: args.top_n]
    top = [d for d in top if d not in bad_hosts and not platform_of(d)]
    (OUT / "legit_top.txt").write_text("\n".join(f"https://{d}/" for d in top) + "\n")
    print(f"legit_top.txt: {len(top):,}")

    # --- legit pages on free-hosting platforms ------------------------------
    cand = harvest_awesome() | harvest_npm()
    free = {h: u for h, u in one_per_host(cand).items() if platform_of(h) and h not in bad_hosts}
    by_plat = defaultdict(list)
    for h, u in free.items():
        by_plat[platform_of(h)].append(u)
    if len(by_plat.get("github.io", [])) > args.github_io_cap:
        by_plat["github.io"] = random.sample(by_plat["github.io"], args.github_io_cap)
    free_urls = sorted(u for us in by_plat.values() for u in us)
    (OUT / "legit_free.txt").write_text("\n".join(free_urls) + "\n")
    print(f"legit_free.txt: {len(free_urls):,}  "
          f"{Counter(platform_of(host_of(u)) for u in free_urls).most_common(10)}")

    # --- login pages of popular sites ---------------------------------------
    login = [f"https://{d}{random.choice(LOGIN_PATHS)}" for d in top[: args.login_n]]
    (OUT / "legit_login.txt").write_text("\n".join(login) + "\n")
    print(f"legit_login.txt: {len(login):,} candidates (non-login responses are dropped at training time)")


if __name__ == "__main__":
    main()
