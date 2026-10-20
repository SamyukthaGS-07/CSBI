"""
common.hosting
==============
One source of truth for "is this site on a shared free-hosting / site-builder
platform?" Every module (screening, features, evaluation subsets) imports this,
so the free-hosted subset in the paper is defined in exactly one place.

On these platforms the TLS certificate, IP, ASN and WHOIS all belong to the
*platform* (Cloudflare for pages.dev, Google for web.app, ...), not to whoever
published the page. Surface-credibility signals therefore look excellent for a
phishing page that costs nothing to publish. That is the gap CSBI targets.
"""
from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

try:
    import tldextract
    # Offline: use the bundled Public Suffix List snapshot, include private
    # suffixes (pages.dev, github.io, web.app, ... are listed there).
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
except Exception:          # pragma: no cover
    _EXTRACT = None

# Platform suffixes where anyone can publish a page for free under a shared
# parent domain. Grouped for readability; matching is by host suffix.
FREE_HOSTING_SUFFIXES: tuple[str, ...] = (
    # static / JAMstack hosts
    "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com",
    "github.io", "gitlab.io", "netlify.app", "vercel.app", "onrender.com",
    "surge.sh", "glitch.me", "replit.app", "repl.co", "fly.dev",
    "herokuapp.com", "azurewebsites.net", "azurestaticapps.net",
    "appspot.com", "cloudfront.net", "amplifyapp.com", "deno.dev",
    "railway.app", "koyeb.app", "ngrok-free.app", "ngrok.io", "trycloudflare.com",
    "codesandbox.io", "csb.app", "stackblitz.io", "framer.app", "framer.website",
    # site builders / page hosts
    "webflow.io", "wixsite.com", "weebly.com", "weeblysite.com", "square.site",
    "blogspot.com", "wordpress.com", "godaddysites.com", "mystrikingly.com",
    "jimdosite.com", "carrd.co", "000webhostapp.com", "000webhost.com",
    "sites.google.com", "notion.site", "gitbook.io", "typedream.app",
    "yolasite.com", "webnode.page", "site123.me", "tilda.ws", "ucraft.site",
    "firebasestorage.googleapis.com", "storage.googleapis.com", "ipfs.io",
    "dweb.link", "w3s.link", "linktr.ee", "bio.link", "tw1.ru",
)


def host_of(url: str) -> str:
    """Lower-cased host of a URL (no port, no credentials)."""
    if "//" not in url:
        url = "http://" + url
    netloc = urlparse(url).netloc
    return netloc.split("@")[-1].split(":")[0].strip("[]").lower().rstrip(".")


@lru_cache(maxsize=200_000)
def platform_of(host: str) -> str | None:
    """The free-hosting suffix this host sits under, or None."""
    host = host.lower().rstrip(".")
    for suf in FREE_HOSTING_SUFFIXES:
        if host == suf or host.endswith("." + suf):
            return suf
    return None


def is_free_hosted(host_or_url: str) -> bool:
    h = host_of(host_or_url) if "/" in host_or_url else host_or_url.lower()
    return platform_of(h) is not None


@lru_cache(maxsize=200_000)
def registrable_domain(host: str) -> str:
    """eTLD+1 using the private PSL, e.g. foo.pages.dev -> foo.pages.dev,
    login.sbi.co.in -> sbi.co.in. Falls back to the last two labels."""
    host = host.lower().rstrip(".")
    if _EXTRACT is not None:
        r = _EXTRACT(host)
        if r.domain and r.suffix:
            return f"{r.domain}.{r.suffix}"
        if r.domain:
            return r.domain
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def tenant_label(host: str) -> str:
    """The part of the host the *publisher* chose. On a free host that is the
    subdomain (sbi-kyc-update.pages.dev -> 'sbi-kyc-update'); elsewhere it is
    the registrable label (sbi-kyc-update.com -> 'sbi-kyc-update')."""
    host = host.lower().rstrip(".")
    plat = platform_of(host)
    if plat:
        return host[: -(len(plat) + 1)] if host != plat else ""
    reg = registrable_domain(host)
    return reg.split(".")[0]
