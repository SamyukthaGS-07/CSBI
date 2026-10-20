"""
csbi.extraction.fetch
=====================
All network I/O for a single scan, in one place (Blueprint §7 feature-extraction
tools + §8.3 snapshot strategy):

    HTTP GET  -> final URL, status, HTML          (requests)
    DNS       -> resolved IP                       (socket)
    TLS       -> SSL issuer + certificate notBefore(socket + ssl)
    WHOIS     -> creation / expiration / NS        (python-whois)
    Snapshot  -> cache HTML at scan-time so dead scam pages stay evaluable

Design: the *pure* parsing helpers (cert-date parsing, snapshot path, WHOIS
field coercion) are separated from the live network calls, so they unit-test
offline. The live calls (requests / socket / whois) run on a real machine — they
are wrapped so a failure degrades gracefully instead of raising, and every
failure is recorded on FetchResult.errors.

If the live GET fails but a snapshot exists, we serve the snapshot and set
from_snapshot=True — that is the §8.3 fallback for pages that go offline fast.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
except Exception:                     # requests optional at import time
    requests = None
try:
    import whois as _whois            # python-whois
except Exception:
    _whois = None

try:
    from config.settings import SNAPSHOT_DIR
except Exception:
    SNAPSHOT_DIR = Path("data/snapshots")

# A real browser UA: phishing kits routinely cloak (serve a blank/404 page) to
# anything that looks like a bot, which would silently empty Layers 3-5.
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
DEFAULT_TIMEOUT = 12
MAX_HTML_BYTES = 3_000_000


@dataclass
class FetchResult:
    url: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    ok: bool = False
    html: str = ""
    resolved_ip: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_not_before: Optional[dt.datetime] = None
    whois_creation: Optional[dt.datetime] = None
    whois_expiration: Optional[dt.datetime] = None
    nameserver: Optional[str] = None
    snapshot_path: Optional[str] = None
    from_snapshot: bool = False
    errors: list[str] = field(default_factory=list)
    # --- added for the TBDF baseline + platform-aware layer ---------------
    cert_names: list[str] = field(default_factory=list)   # subject CN + SANs
    cookie_domains: list[str] = field(default_factory=list)
    redirect_hosts: list[str] = field(default_factory=list)  # hosts in the redirect chain


# --------------------------------------------------------------------------- #
# Pure helpers (unit-testable offline)                                         #
# --------------------------------------------------------------------------- #
def url_host(url: str) -> str:
    netloc = urlparse(url).netloc or urlparse("//" + url).netloc
    return netloc.split("@")[-1].split(":")[0].strip("[]")


def snapshot_path_for(url: str, base: Path | str = SNAPSHOT_DIR) -> Path:
    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]
    return Path(base) / f"{digest}.html"


def parse_cert_datetime(value: str) -> Optional[dt.datetime]:
    """Parse an OpenSSL cert date like 'Jun  1 00:00:00 2025 GMT' -> UTC datetime."""
    if not value:
        return None
    cleaned = value.replace(" GMT", "").strip()
    try:
        return dt.datetime.strptime(cleaned, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def _coerce_whois_date(value) -> Optional[dt.datetime]:
    """python-whois returns datetime, list[datetime], or str — normalise to one."""
    if value is None:
        return None
    if isinstance(value, list):
        value = next((v for v in value if v), None)
    if isinstance(value, dt.datetime):
        return value
    if isinstance(value, str):
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return dt.datetime.strptime(value[:19], fmt)
            except ValueError:
                continue
    return None


# --------------------------------------------------------------------------- #
# Live network calls (best-effort; run on a real machine)                      #
# --------------------------------------------------------------------------- #
def resolve_ip(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def get_ssl_cert(host: str, port: int = 443, timeout: int = 6) -> tuple[Optional[str], Optional[dt.datetime]]:
    """Return (issuer_org, not_before) from the served certificate."""
    issuer, not_before, _ = get_ssl_cert_full(host, port, timeout)
    return issuer, not_before


def get_ssl_cert_full(host: str, port: int = 443, timeout: int = 6):
    """Return (issuer_org, not_before, names) where names = subject CN + DNS SANs."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName")
        not_before = parse_cert_datetime(cert.get("notBefore", ""))
        names = [v for k, v in (x[0] for x in cert.get("subject", ())) if k == "commonName"]
        names += [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        return issuer, not_before, sorted({n.lower() for n in names})
    except Exception:
        return None, None, []


_WHOIS_CACHE: dict[str, tuple] = {}


def get_whois(domain: str):
    """Return (creation, expiration, nameserver) best-effort, cached per domain
    (thousands of free-hosted pages share one platform WHOIS record)."""
    if domain in _WHOIS_CACHE:
        return _WHOIS_CACHE[domain]
    out = _get_whois_uncached(domain)
    _WHOIS_CACHE[domain] = out
    return out


def _get_whois_uncached(domain: str):
    if _whois is None:
        return None, None, None
    try:
        w = _whois.whois(domain)
        creation = _coerce_whois_date(w.creation_date)
        expiration = _coerce_whois_date(w.expiration_date)
        ns = w.name_servers
        if isinstance(ns, list):
            ns = ns[0] if ns else None
        ns = str(ns).lower() if ns else None
        return creation, expiration, ns
    except Exception:
        return None, None, None


# --------------------------------------------------------------------------- #
# ASN / IP-block lookup — infrastructure fields for Module C (§3)              #
# --------------------------------------------------------------------------- #
def ip_block(ip: Optional[str], prefix: int = 24) -> Optional[str]:
    """The /24 network an IPv4 address sits in, e.g. 203.0.113.7 -> 203.0.113.0/24.
    Computed locally (no network). Part of Module C's fingerprint: scam campaigns
    are frequently bulk-hosted inside one netblock."""
    if not ip:
        return None
    try:
        import ipaddress
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except Exception:
        return None


# Per-process cache: campaigns reuse hosts, so don't re-query the same IP.
_ASN_CACHE: dict[str, tuple[Optional[str], Optional[str]]] = {}

import threading as _threading
import time as _time

_ASN_LOCK = _threading.Lock()
_ASN_LAST = [0.0]
_ASN_MIN_INTERVAL = 1.4          # ip-api.com free tier: 45 requests / minute


def _asn_rate_limit() -> None:
    with _ASN_LOCK:
        wait = _ASN_LAST[0] + _ASN_MIN_INTERVAL - _time.monotonic()
        if wait > 0:
            _time.sleep(wait)
        _ASN_LAST[0] = _time.monotonic()


def get_asn(ip: Optional[str], timeout: int = 6) -> tuple[Optional[str], Optional[str]]:
    """Return (asn, hosting_provider) for an IP, e.g. ("AS13335", "Cloudflare, Inc.").

    Uses ip-api.com's free endpoint (no API key, ~45 requests/minute). If an
    IPINFO_TOKEN is set in the environment, ipinfo.io is tried first since it has
    a higher free allowance. Failures return (None, None) — never raises, because
    a missing ASN must not break a scan.
    """
    if not ip:
        return None, None
    if ip in _ASN_CACHE:
        return _ASN_CACHE[ip]
    if requests is None:
        return None, None

    asn = provider = None

    token = os.environ.get("IPINFO_TOKEN")
    if token:
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json",
                             params={"token": token}, timeout=timeout)
            if r.ok:
                d = r.json()
                org = d.get("org") or ""          # e.g. "AS13335 Cloudflare, Inc."
                if org.startswith("AS"):
                    asn, _, provider = org.partition(" ")
                    provider = provider or None
        except Exception:
            pass

    if asn is None:
        try:
            _asn_rate_limit()
            r = requests.get(f"http://ip-api.com/json/{ip}",
                             params={"fields": "status,as,asname,isp,org"}, timeout=timeout)
            if r.ok:
                d = r.json()
                if d.get("status") == "success":
                    as_field = d.get("as") or ""   # e.g. "AS13335 Cloudflare, Inc."
                    if as_field.startswith("AS"):
                        asn, _, rest = as_field.partition(" ")
                        provider = d.get("isp") or d.get("org") or rest or None
                    elif d.get("asname"):
                        asn = d["asname"]
                        provider = d.get("isp") or d.get("org")
        except Exception:
            pass

    _ASN_CACHE[ip] = (asn, provider)
    return asn, provider


# --------------------------------------------------------------------------- #
# Snapshot I/O (§8.3)                                                          #
# --------------------------------------------------------------------------- #
def save_snapshot(url: str, html: str, base: Path | str = SNAPSHOT_DIR) -> Optional[str]:
    if not html:
        return None
    path = snapshot_path_for(url, base)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        return str(path)
    except Exception:
        return None


def load_snapshot(url: str, base: Path | str = SNAPSHOT_DIR) -> Optional[str]:
    path = snapshot_path_for(url, base)
    if path.exists():
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return None
    return None


# --------------------------------------------------------------------------- #
# Orchestrator                                                                 #
# --------------------------------------------------------------------------- #
def fetch(url: str, timeout: int = DEFAULT_TIMEOUT, save: bool = True) -> FetchResult:
    """Fetch everything a scan needs for one URL. Never raises — failures are
    recorded on result.errors and the pipeline continues with what it has."""
    result = FetchResult(url=url)
    host = url_host(url)
    result.resolved_ip = resolve_ip(host)

    # --- HTTP (with §8.3 snapshot fallback) ---
    if requests is not None:
        try:
            resp = requests.get(
                url, timeout=timeout, allow_redirects=True, stream=True,
                headers={"User-Agent": USER_AGENT,
                         "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                         "Accept-Language": "en-IN,en;q=0.9"},
            )
            raw = resp.raw.read(MAX_HTML_BYTES, decode_content=True) or b""
            enc = resp.encoding or resp.apparent_encoding or "utf-8"
            result.status_code = resp.status_code
            result.final_url = resp.url
            result.html = raw.decode(enc, errors="replace")
            result.ok = resp.ok
            result.redirect_hosts = [url_host(r.url) for r in resp.history] + [url_host(resp.url)]
            result.cookie_domains = sorted({(c.domain or "").lstrip(".").lower()
                                            for c in resp.cookies if c.domain})
            resp.close()
            if save and result.html:
                result.snapshot_path = save_snapshot(url, result.html)
        except Exception as e:
            result.errors.append(f"http: {e}")
    else:
        result.errors.append("http: requests not installed")

    if not result.html:                          # live fetch failed -> snapshot
        cached = load_snapshot(url)
        if cached:
            result.html = cached
            result.from_snapshot = True
            result.snapshot_path = str(snapshot_path_for(url))
        else:
            result.errors.append("no live page and no snapshot available")

    # --- TLS + WHOIS (best-effort; independent of HTML) ---
    result.ssl_issuer, result.ssl_not_before, result.cert_names = get_ssl_cert_full(host)
    # WHOIS is keyed on the registrable domain (WHOIS servers do not know about
    # subdomains). For a free-hosted page that is the *platform* (pages.dev),
    # which is exactly the borrowed-credibility effect Layer 5 measures.
    try:
        from common.hosting import platform_of, registrable_domain
        whois_domain = platform_of(host) or registrable_domain(host)
    except Exception:
        whois_domain = host
    creation, expiration, ns = get_whois(whois_domain)
    result.whois_creation, result.whois_expiration, result.nameserver = creation, expiration, ns
    return result
