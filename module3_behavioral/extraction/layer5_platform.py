"""
module3_behavioral.extraction.layer5_platform
=============================================
Layer 5 — Platform-aware signals (new in the full build).

The problem
-----------
On a shared free-hosting platform (pages.dev, vercel.app, github.io, web.app,
webflow.io, ...) every surface signal that phishing detectors trust belongs to
the platform, not to the publisher:

    valid TLS cert      -> issued to *.pages.dev
    domain age          -> pages.dev's WHOIS record (years old)
    reputable ASN / IP  -> Cloudflare / Google / Vercel
    cert CN matches     -> wildcard covers every tenant

So TBDF-style "does the artefact match the domain?" features all pass, and the
page inherits credibility it never earned. We call this BORROWED CREDIBILITY.

What this layer measures
------------------------
1. Which surface signals are borrowed (owned by the platform) vs earned.
2. Behaviour that is *structurally* incompatible with a static host:
   a static site has no backend, so a credential form on it can only deliver
   what it collects to a third party (Telegram bot API, form relays, webhooks,
   Apps Script). That exfiltration path is visible in the HTML.
3. Brand impersonation judged against real brand ownership, including brands
   written into the publisher-chosen subdomain.

Generic HTML statistics (prefix `html_`) are also produced here; they form
Baseline B3 (URL + HTML content), the usual "content-based" detector family.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from common.brand_match import (brand_owns_host, brands_in_host_label,
                                brands_in_text)
from common.hosting import host_of, platform_of, registrable_domain

# Endpoints a static-hosted phishing kit uses to receive stolen data.
EXFIL_PATTERNS = tuple(re.compile(p, re.I) for p in (
    r"api\.telegram\.org/bot",
    r"formspree\.io", r"getform\.io", r"formsubmit\.co", r"submit-form\.com",
    r"formcarry\.com", r"basin\.usebasin\.com", r"usebasin\.com", r"web3forms\.com",
    r"emailjs\.com", r"api\.emailjs", r"smtpjs\.com",
    r"discord(app)?\.com/api/webhooks", r"hooks\.slack\.com",
    r"script\.google\.com/macros", r"docs\.google\.com/forms",
    r"firebaseio\.com", r"jsonbin\.io", r"api\.jsonbin", r"webhook\.site",
    r"requestbin", r"pipedream\.net", r"ngrok", r"herokuapp\.com/.*(send|post|log)",
    r"\.php\b",
))
_PWD_HINTS = ("password", "passwd", "passcode", "pin", "mpin")
_OTP_HINTS = ("otp", "one time", "verification code", "2fa", "sms code")
_CARD_HINTS = ("card number", "cardnumber", "cc-number", "cvv", "cvc", "expiry", "exp date")
_SEED_HINTS = ("seed phrase", "recovery phrase", "mnemonic", "12 words", "24 words", "private key")


def _attrs(tag) -> str:
    return " ".join(str(tag.get(a, "")) for a in
                    ("name", "id", "type", "placeholder", "aria-label", "autocomplete", "class")).lower()


def _prominent(soup) -> str:
    parts = []
    if soup.title and soup.title.string:
        parts.append(soup.title.string)
    for t in soup.find_all(["h1", "h2", "h3"], limit=12):
        parts.append(t.get_text(" ", strip=True))
    for img in soup.find_all("img", limit=40):
        parts.append(str(img.get("alt", "")))
        src = str(img.get("src", ""))
        if not src.startswith("data:"):
            parts.append(src.rsplit("/", 1)[-1].replace("-", " ").replace("_", " "))
    og = soup.find("meta", attrs={"property": "og:site_name"})
    if og and og.get("content"):
        parts.append(og["content"])
    return " ".join(parts)


def extract(soup, html: str, url: str, final_url: str | None = None,
            redirect_hosts: list[str] | None = None) -> dict:
    host = host_of(final_url or url)
    plat = platform_of(host)
    free = int(plat is not None)
    out: dict = {"free_hosted": free, "platform": plat or ""}

    if soup is None or not html:
        out.update({k: 0 for k in (
            "html_len", "html_n_forms", "html_n_inputs", "html_n_hidden", "html_n_links",
            "html_ext_link_ratio", "html_null_link_ratio", "html_n_scripts", "html_n_iframes",
            "html_n_img", "html_text_len", "html_has_title", "html_n_meta_refresh",
            "p5_brand_claimed", "p5_brand_impersonation", "p5_tenant_brand",
            "p5_cred_form", "p5_password_field", "p5_otp_field", "p5_card_field",
            "p5_seed_field", "p5_exfil_endpoint", "p5_static_cred_form",
            "p5_form_cross_site", "p5_cross_site_redirect", "p5_page_empty")})
        out["p5_page_empty"] = 1
        out["_claimed_brand"] = ""
        return out

    low = html.lower()
    forms = soup.find_all("form")
    inputs = soup.find_all(["input", "textarea", "select"])
    links = [a.get("href", "") or "" for a in soup.find_all("a")]
    ext_links = null_links = 0
    for h in links:
        h = h.strip()
        if not h or h == "#" or h.startswith(("javascript:", "#")):
            null_links += 1
            continue
        lh = host_of(urljoin(url, h))
        if lh and registrable_domain(lh) != registrable_domain(host):
            ext_links += 1
    text = soup.get_text(" ", strip=True)

    out.update({
        "html_len": len(html),
        "html_n_forms": len(forms),
        "html_n_inputs": len(inputs),
        "html_n_hidden": sum(1 for i in inputs if str(i.get("type", "")).lower() == "hidden"),
        "html_n_links": len(links),
        "html_ext_link_ratio": round(ext_links / len(links), 4) if links else 0.0,
        "html_null_link_ratio": round(null_links / len(links), 4) if links else 0.0,
        "html_n_scripts": len(soup.find_all("script")),
        "html_n_iframes": len(soup.find_all("iframe")),
        "html_n_img": len(soup.find_all("img")),
        "html_text_len": len(text),
        "html_has_title": int(bool(soup.title and soup.title.string and soup.title.string.strip())),
        "html_n_meta_refresh": len(soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})),
    })

    # --- brand claim vs real ownership --------------------------------------
    claimed = brands_in_text(_prominent(soup))
    top = claimed[0] if claimed else ""
    out["_claimed_brand"] = top
    out["p5_brand_claimed"] = int(bool(top))
    out["p5_brand_impersonation"] = int(bool(top) and not any(brand_owns_host(b, host) for b in claimed))
    host_brands = brands_in_host_label(host)
    out["p5_tenant_brand"] = int(any(not brand_owns_host(b, host) for b in host_brands))

    # --- what the page asks for ---------------------------------------------
    blob = " ".join(_attrs(i) for i in inputs) + " " + text.lower()[:20000]
    pwd = int(any(str(i.get("type", "")).lower() == "password" for i in inputs)
              or any(h in _attrs(i) for i in inputs for h in _PWD_HINTS))
    otp = int(any(h in blob for h in _OTP_HINTS))
    card = int(any(h in blob for h in _CARD_HINTS))
    seed = int(any(h in blob for h in _SEED_HINTS))
    emailish = any(("email" in _attrs(i) or "user" in _attrs(i) or "login" in _attrs(i)) for i in inputs)
    cred = int(bool(pwd or otp or card or seed or (emailish and inputs)))
    out.update({"p5_password_field": pwd, "p5_otp_field": otp, "p5_card_field": card,
                "p5_seed_field": seed, "p5_cred_form": cred})

    # --- where it goes ------------------------------------------------------
    exfil = int(any(p.search(low) for p in EXFIL_PATTERNS[:-1]))
    # A .php form target is only exfiltration on a static host (it cannot run PHP).
    if free and EXFIL_PATTERNS[-1].search(" ".join(str(f.get("action", "")) for f in forms)):
        exfil = 1
    out["p5_exfil_endpoint"] = exfil
    out["p5_static_cred_form"] = int(free and cred)
    cross = 0
    for f in forms:
        act = (f.get("action") or "").strip()
        if act and not act.startswith("#"):
            ah = host_of(urljoin(url, act))
            if ah and registrable_domain(ah) != registrable_domain(host):
                cross = 1
                break
    out["p5_form_cross_site"] = cross
    rh = [h for h in (redirect_hosts or []) if h]
    out["p5_cross_site_redirect"] = int(len({registrable_domain(h) for h in rh}) > 1)
    out["p5_page_empty"] = int(len(text) < 40 and not inputs)
    return out
