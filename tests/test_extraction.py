"""
tests.test_extraction
=====================
All of Module A's extraction, end to end, plus the §5 worked example that
reproduces CSBI ~= 65:

    Layer 1 structural · fetch pure-helpers · Layer 2 temporal (+ §10 fallback)
    · Layers 3/4 behavioral+UPI · extract_features() -> ScanRecord -> store
    · the §5 trace: real URL -> T1..T4 -> CSBI ~= 65.

Live network calls (requests/socket/whois) run on a real machine; here we drive
the pipeline with canned FetchResult fixtures.
"""

import datetime as dt

import pytest

from csbi.extraction import layer1_structural as l1
from csbi.extraction import layer2_temporal as l2
from csbi.extraction import layer3_behavioral as l3
from csbi.extraction import layer4_upi as l4
from csbi.extraction import fetch
from csbi.extraction.fetch import FetchResult
from csbi.extraction.extractor import extract_features, dom_tag_sequence_hash
from csbi.scoring import trust_scores as ts
from csbi.scoring.csbi import compute_csbi
from csbi.common.store import ScanStore

NOW = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)

# --- HTML fixtures -----------------------------------------------------------
SCAM_URL = "https://gov-subsidy-refund.netlify.app"
SCAM_HTML = """
<html><head><title>SBI Subsidy Refund Portal</title></head>
<body>
  <img src="/emblem.png" alt="National Emblem - Government of India">
  <h1>State Bank of India — Instant Subsidy Refund</h1>
  <p>Your account will be blocked. Act now and verify now within 24 hours
     to claim your government subsidy and cashback.</p>
  <img src="qr-code.png" alt="Scan QR to pay">
  <form><input name="vpa" placeholder="Enter your UPI ID"></form>
  <p>Send to refund@oksbi to receive your instant refund.</p>
  <script src="https://evil-cdn.ru/a.js"></script>
  <script src="https://tracker.xyz/b.js"></script>
  <script>var x=1;</script><script>var y=2;</script><script>var z=3;</script>
</body></html>
"""
LEGIT_URL = "https://www.onlinesbi.sbi/"
LEGIT_HTML = """
<html><head><title>State Bank of India - Personal Banking</title></head>
<body><h1>Welcome to SBI Online</h1>
  <p>Access your accounts and manage payments securely.</p>
  <script src="/static/app.js"></script></body></html>
"""


# =========================== Layer 1 — structural ============================
def test_l1_https_and_ip():
    assert l1.extract("https://sbi.co.in/login")["https"] == 1
    assert l1.extract("http://192.168.10.5/pay")["is_ip_domain"] == 1


def test_l1_subdomain_and_length():
    f = l1.extract("http://secure.login.sbi-verify.com/kyc")
    assert f["subdomain_count"] >= 2
    assert l1.extract("http://a.io/" + "x" * 200)["url_length_norm"] == 1.0


def test_l1_feeds_t1():
    assert 0.0 <= ts.t1_structural(l1.extract("https://www.sbi.co.in/")) <= 1.0


# =========================== fetch — pure helpers ============================
def test_parse_cert_datetime():
    assert fetch.parse_cert_datetime("Jun  1 00:00:00 2025 GMT") == dt.datetime(2025, 6, 1)
    assert fetch.parse_cert_datetime("garbage") is None


def test_coerce_whois_date_variants():
    assert fetch._coerce_whois_date([dt.datetime(2020, 1, 1), None]) == dt.datetime(2020, 1, 1)
    assert fetch._coerce_whois_date("2020-01-01 12:00:00") == dt.datetime(2020, 1, 1, 12, 0, 0)
    assert fetch._coerce_whois_date(None) is None


def test_snapshot_path_deterministic():
    assert fetch.snapshot_path_for("http://x.com") == fetch.snapshot_path_for("http://x.com")


# =========================== Layer 2 — temporal ==============================
def test_l2_ages_from_whois():
    fr = FetchResult(url="http://old.example",
                     whois_creation=dt.datetime(2016, 7, 22),
                     whois_expiration=dt.datetime(2027, 7, 22),
                     ssl_not_before=NOW - dt.timedelta(days=181))
    f = l2.extract(fr, now=NOW)
    assert f["domain_age_days"] > 3600
    assert 175 <= f["ssl_age_days"] <= 185
    assert f["registration_years"] > 10
    assert f["whois_fallback_used"] == 0


def test_l2_whois_privacy_fallback_to_cert():
    # §10: no WHOIS date -> use cert issuance as proxy, flag fallback.
    fr = FetchResult(url="http://private.example",
                     whois_creation=None, ssl_not_before=NOW - dt.timedelta(days=51))
    f = l2.extract(fr, now=NOW)
    assert f["whois_fallback_used"] == 1
    assert f["domain_age_days"] == f["ssl_age_days"]
    assert 45 <= f["domain_age_days"] <= 55


def test_l2_no_data_zero_trust():
    f = l2.extract(FetchResult(url="http://dead.example"), now=NOW)
    assert ts.t2_temporal(f) == 0.0


def test_l2_handles_timezone_aware_whois_dates():
    # Regression: live python-whois returns tz-aware datetimes; must not crash.
    aware = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    fr = FetchResult(url="https://example.com", whois_creation=aware,
                     whois_expiration=dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc),
                     ssl_not_before=aware)
    f = l2.extract(fr, now=NOW)
    assert f["domain_age_days"] > 0
    assert f["registration_years"] == pytest.approx(10.0, abs=0.1)


# =========================== Layers 3 & 4 ====================================
def test_l3_scam_flags():
    f = l3.extract(SCAM_HTML, SCAM_URL)
    assert f["brand_mismatch"] == 1
    assert f["urgency_language_score"] >= 0.5
    assert f["external_script_ratio"] == pytest.approx(0.4, abs=0.01)
    assert ts.t3_behavioral(f) < 0.35


def test_l3_legit_clean():
    f = l3.extract(LEGIT_HTML, LEGIT_URL)
    assert f["brand_mismatch"] == 0
    assert ts.t3_behavioral(f) == pytest.approx(1.0)


def test_l4_scam_flags():
    f = l4.extract(SCAM_HTML, SCAM_URL)
    assert f["upi_field_presence"] == 1
    assert f["subsidy_refund_language_score"] >= 0.5
    assert f["fake_gov_qr_score"] == 1.0
    assert ts.t4_upi(f) < 0.2


def test_l4_legit_clean():
    f = l4.extract(LEGIT_HTML, LEGIT_URL)
    assert f["upi_field_presence"] == 0
    assert ts.t4_upi(f) == pytest.approx(1.0)


def test_l4_upi_regex_excludes_emails_catches_vpa():
    assert l4.extract("<p>mail me at support@gmail.com</p>")["upi_field_presence"] == 0
    assert l4.extract("<p>pay merchant@paytm now</p>")["upi_field_presence"] == 1


# =========================== extractor end-to-end ============================
def _fake_fetch(html, *, creation=None, ssl_before=None):
    def _f(url, save=True):
        return FetchResult(url=url, ok=True, html=html, resolved_ip="203.0.113.7",
                           ssl_issuer="Let's Encrypt", ssl_not_before=ssl_before,
                           whois_creation=creation, nameserver="ns1.netlify.com",
                           snapshot_path="data/snapshots/x.html")
    return _f


def test_extract_features_scam(tmp_path):
    store = ScanStore(tmp_path / "scans.db")
    rec = extract_features(SCAM_URL, store=store,
                           fetch_fn=_fake_fetch(SCAM_HTML,
                                                creation=NOW - dt.timedelta(days=400),
                                                ssl_before=NOW - dt.timedelta(days=51)))
    assert rec.T1 == pytest.approx(0.85, abs=0.01)
    assert rec.T3 == pytest.approx(0.15, abs=0.01)
    assert rec.T4 == pytest.approx(0.0, abs=0.01)
    assert rec.CSBI > 40
    assert rec.resolved_ip == "203.0.113.7" and rec.dom_tag_sequence_hash is not None
    assert rec.scam_probability is None and rec.risk_level is None  # Module B's job
    assert store.read(SCAM_URL).CSBI == rec.CSBI


def test_extract_features_legit(tmp_path):
    store = ScanStore(tmp_path / "scans.db")
    rec = extract_features(LEGIT_URL, store=store,
                           fetch_fn=_fake_fetch(LEGIT_HTML,
                                                creation=NOW - dt.timedelta(days=4000),
                                                ssl_before=NOW - dt.timedelta(days=200)))
    assert rec.T3 == pytest.approx(1.0) and rec.T4 == pytest.approx(1.0)
    assert rec.CSBI < 15


def test_dom_hash_stable_and_differs():
    assert dom_tag_sequence_hash(SCAM_HTML) == dom_tag_sequence_hash(SCAM_HTML)
    assert dom_tag_sequence_hash(SCAM_HTML) != dom_tag_sequence_hash(LEGIT_HTML)
    assert dom_tag_sequence_hash("") is None


# =================== infrastructure fields for Module C ======================
def test_ip_block_derivation():
    assert fetch.ip_block("203.0.113.7") == "203.0.113.0/24"
    assert fetch.ip_block("172.66.147.243") == "172.66.147.0/24"
    assert fetch.ip_block(None) is None
    assert fetch.ip_block("not-an-ip") is None


def test_asn_lookup_populates_record(monkeypatch):
    """extract_features must fill asn/hosting_provider/ip_block for Module C."""
    monkeypatch.setattr("csbi.extraction.fetch.get_asn",
                        lambda ip, timeout=6: ("AS13335", "Cloudflare, Inc."))
    rec = extract_features(LEGIT_URL, fetch_fn=_fake_fetch(LEGIT_HTML))
    assert rec.asn == "AS13335"
    assert rec.hosting_provider == "Cloudflare, Inc."
    assert rec.features["ip_block"] == "203.0.113.0/24"


def test_asn_failure_does_not_break_scan(monkeypatch):
    monkeypatch.setattr("csbi.extraction.fetch.get_asn",
                        lambda ip, timeout=6: (None, None))
    rec = extract_features(LEGIT_URL, fetch_fn=_fake_fetch(LEGIT_HTML))
    assert rec.asn is None and rec.CSBI is not None   # scan still completes


# =========================== §5 worked example ===============================
def test_worked_example_end_to_end_csbi_65():
    """Real URL -> T1 from the formula; T2..T4 from representative raw values
    that reproduce §5's per-layer scores -> CSBI ~= 65 (the DoD anchor)."""
    f = l1.extract(SCAM_URL)
    f.update({"domain_age_days": 365, "ssl_age_days": 52, "registration_years": 6,
              "brand_mismatch": 1, "urgency_language_score": 1.0, "external_script_ratio": 0.40,
              "upi_field_presence": 1, "subsidy_refund_language_score": 1.0, "fake_gov_qr_score": 0.60})
    T = ts.all_trust_scores(f)
    assert T["T1"] == pytest.approx(0.85, abs=0.01)
    assert T["T2"] == pytest.approx(0.70, abs=0.01)
    assert T["T3"] == pytest.approx(0.15, abs=0.01)
    assert T["T4"] == pytest.approx(0.10, abs=0.01)
    assert compute_csbi(**T) == pytest.approx(65.0, abs=0.6)
