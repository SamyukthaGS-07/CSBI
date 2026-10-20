"""
module3_behavioral.extraction.layer_tbdf
========================================
Baseline B2 — "Tightly Bound Domain Features" (TBDF), reimplemented from
Mishra & Varshney (2025), arXiv:2503.06487 — CSBI's base paper.

Each feature compares one artefact of the page against the page's own domain
and is scored like the original: 1 = matches, -1 = mismatches, 0 = absent.

    tbdf_cn_info          TLS certificate CN/SAN covers the host
    tbdf_cookie_domain    cookies are set for the page's own domain
    tbdf_logo_domain      the logo image is served from the page's own domain
    tbdf_link_domain      the most common <a href> domain is the page's own
    tbdf_form_domain      every <form action> posts to the page's own domain

Reimplementation notes (state these in the paper):
  * Comparison is at registrable-domain level using the *private* Public
    Suffix List, so foo.pages.dev and bar.pages.dev are different domains, as
    they are different publishers.
  * The original paper's logo feature identifies the brand from the logo
    image; ours checks where the logo is served from. The rest follow the
    paper's definitions.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable
from urllib.parse import urljoin

from common.hosting import host_of, registrable_domain


def _same_site(a: str, b: str) -> bool:
    return bool(a) and bool(b) and registrable_domain(a) == registrable_domain(b)


def _cert_covers(host: str, names: Iterable[str]) -> bool:
    host = host.lower()
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count("."):
            return True
    return False


def _href_host(href: str, base: str) -> str:
    if not href:
        return ""
    href = href.strip()
    if href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
        return ""
    return host_of(urljoin(base, href))


def extract(soup, url: str, cert_names: list[str] | None = None,
            cookie_domains: list[str] | None = None) -> dict[str, int]:
    host = host_of(url)

    # 1. certificate CN / SAN
    if not cert_names:
        cn = 0
    else:
        cn = 1 if _cert_covers(host, cert_names) else -1

    # 2. cookie domain
    if not cookie_domains:
        ck = 0
    else:
        ck = 1 if all(_same_site(d, host) for d in cookie_domains) else -1

    if soup is None:
        return {"tbdf_cn_info": cn, "tbdf_cookie_domain": ck,
                "tbdf_logo_domain": 0, "tbdf_link_domain": 0, "tbdf_form_domain": 0}

    # 3. logo domain
    logo = 0
    for img in soup.find_all("img"):
        blob = " ".join(str(img.get(a, "")) for a in ("src", "alt", "class", "id")).lower()
        if "logo" in blob and img.get("src"):
            src = img.get("src")
            if src.startswith("data:"):
                logo = -1            # inlined logo: typical of copied kits
            else:
                logo = 1 if _same_site(_href_host(src, url) or host, host) else -1
            break

    # 4. most common link domain
    hosts = [_href_host(a.get("href", ""), url) for a in soup.find_all("a")]
    hosts = [h for h in hosts if h]
    if not hosts:
        link = 0
    else:
        top = Counter(registrable_domain(h) for h in hosts).most_common(1)[0][0]
        link = 1 if top == registrable_domain(host) else -1

    # 5. form action domain
    forms = soup.find_all("form")
    if not forms:
        form = 0
    else:
        form = 1
        for f in forms:
            act = (f.get("action") or "").strip()
            if not act or act.startswith("#"):
                continue            # posts to itself
            ah = _href_host(act, url)
            if ah and not _same_site(ah, host):
                form = -1
                break

    return {"tbdf_cn_info": cn, "tbdf_cookie_domain": ck, "tbdf_logo_domain": logo,
            "tbdf_link_domain": link, "tbdf_form_domain": form}
