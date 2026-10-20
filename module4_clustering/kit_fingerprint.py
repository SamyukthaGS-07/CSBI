"""
module4_clustering.kit_fingerprint
==================================
Phishing-KIT fingerprints: what the page is built from, not where it is hosted.

Why infrastructure clustering is not enough
-------------------------------------------
The original Module 4 clusters on ASN, provider, nameserver, SSL issuer and
/24 block. On a free-hosting platform every tenant shares all five
(e.g. every *.pages.dev page is Cloudflare / AS13335 / Google Trust Services),
so infrastructure distance collapses to zero and unrelated pages, phishing and
legitimate alike, merge into one giant "campaign". `evaluation/clustering_eval.py`
measures exactly this.

A kit fingerprint instead uses artefacts the phisher copies between
deployments of the same kit:
  * DOM structure  — tag 3-gram shingles
  * form schema    — input names / ids / types, form action paths
  * asset names    — script / stylesheet / image file names (not hosts)
  * CSS vocabulary — class names
  * exfil channel  — Telegram bot id hash, form-relay endpoint ids
  * page claim     — title tokens, claimed brand
All are combined as weighted bags of tokens and compared by cosine similarity.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from urllib.parse import urlparse

from bs4 import BeautifulSoup

_TG_BOT = re.compile(r"api\.telegram\.org/bot(\d{6,12}):", re.I)
_RELAY = re.compile(r"(formspree\.io/f/\w+|getform\.io/f/\w+|formsubmit\.co/[\w@.\-]+|"
                    r"script\.google\.com/macros/s/[\w\-]+|discord(?:app)?\.com/api/webhooks/\d+)", re.I)
_WORD = re.compile(r"[a-z]{3,}")

# token-family weights (applied by repeating the family prefix count times)
WEIGHTS = {"dom": 1, "form": 3, "asset": 2, "css": 1, "exfil": 6, "title": 1, "brand": 2}


def _h(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:10]


def kit_tokens(html: str, claimed_brand: str = "") -> Counter:
    """Bag of kit tokens for one page."""
    toks: Counter = Counter()
    if not html:
        return toks
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")

    tags = [t.name for t in soup.find_all(True)][:3000]
    for i in range(len(tags) - 2):
        toks[f"dom:{tags[i]}>{tags[i+1]}>{tags[i+2]}"] += WEIGHTS["dom"]

    for inp in soup.find_all(["input", "select", "textarea", "button"]):
        for a in ("name", "id", "type", "autocomplete"):
            v = str(inp.get(a, "")).strip().lower()
            if v:
                toks[f"form:{a}={v[:40]}"] += WEIGHTS["form"]
    for f in soup.find_all("form"):
        act = str(f.get("action", "")).strip().lower()
        if act:
            path = urlparse(act).path or act
            toks[f"form:action={path[-40:]}"] += WEIGHTS["form"]
        toks[f"form:method={str(f.get('method', 'get')).lower()}"] += 1

    for tag, attr in (("script", "src"), ("link", "href"), ("img", "src")):
        for el in soup.find_all(tag):
            v = str(el.get(attr, ""))
            if not v or v.startswith("data:"):
                if v.startswith("data:"):
                    toks[f"asset:inline-{tag}-{_h(v[:200])}"] += WEIGHTS["asset"]
                continue
            name = urlparse(v).path.rsplit("/", 1)[-1].lower()
            if name and len(name) < 80:
                toks[f"asset:{name}"] += WEIGHTS["asset"]

    for el in soup.find_all(class_=True, limit=2000):
        for c in el.get("class", [])[:6]:
            if 2 < len(c) < 40:
                toks[f"css:{c.lower()}"] += WEIGHTS["css"]

    low = html.lower()
    for m in _TG_BOT.finditer(low):
        toks[f"exfil:tg-{_h(m.group(1))}"] += WEIGHTS["exfil"]
    for m in _RELAY.finditer(low):
        toks[f"exfil:{_h(m.group(1))}"] += WEIGHTS["exfil"]

    title = soup.title.string.lower() if soup.title and soup.title.string else ""
    for w in _WORD.findall(title)[:20]:
        toks[f"title:{w}"] += WEIGHTS["title"]
    if claimed_brand:
        toks[f"brand:{claimed_brand}"] += WEIGHTS["brand"]
    return toks


class KitVectorizer:
    """Token bags -> L2-normalised TF-IDF sparse vectors (cosine-ready).
    Fit once on the corpus; transform() embeds new pages in the same space."""

    def __init__(self):
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.feature_extraction.text import TfidfTransformer
        self.dv = DictVectorizer(sparse=True)
        self.tf = TfidfTransformer(sublinear_tf=True)

    def fit_transform(self, bags: list[Counter]):
        return self.tf.fit_transform(self.dv.fit_transform([dict(b) for b in bags]))

    def transform(self, bags: list[Counter]):
        return self.tf.transform(self.dv.transform([dict(b) for b in bags]))


def vectorize(bags: list[Counter]):
    return KitVectorizer().fit_transform(bags)
