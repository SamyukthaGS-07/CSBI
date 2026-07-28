"""
demo/demo_sites.py
==================
The 20 curated sites for the review demo. Each has REAL HTML (so Layers 1/3/4
genuinely compute) and realistic infrastructure + WHOIS/SSL values (so Layer 2
and Varshan's clustering have real inputs).

Three scam campaigns share a DOM template + infrastructure block on purpose, so
Module C's DBSCAN recovers them as clusters. The 9 legit sites are deliberately
varied (different providers, templates, ages) so they fall out as noise.

Nothing here is fetched live — these are constructed test pages modeled on real
reported UPI/phishing campaigns. Layer computations on them are real; only the
network fetch is pre-seeded (equivalent to the §8.3 snapshot cache).
"""

import datetime as dt

NOW = dt.datetime.now()


def _days(n):
    return NOW - dt.timedelta(days=n)


# --- shared DOM templates (identical structure within a campaign) ------------
def _upi_cashback_page(brand, amount):
    return f"""<!DOCTYPE html><html><head><title>{brand} Instant Cashback Offer</title></head>
<body><div class="wrap"><header><img src="/logo.png" alt="{brand} Official"></header>
<main><h1>{brand} — Claim Your Instant Cashback</h1>
<p>Congratulations! You have won a cashback reward. Act now, this offer expires today.
Verify now within 24 hours to receive your instant refund and cashback.</p>
<img src="/qr.png" alt="Scan QR to receive Government of India verified cashback">
<form><label>Enter your UPI ID</label>
<input type="text" name="vpa" placeholder="yourname@upi">
<button>Claim ₹{amount} Now</button></form>
<p>Send a ₹1 verification to reward@oksbi to unlock your cashback instantly.</p>
</main></div>
<script src="https://track-metrics-cdn.ru/collect.js"></script>
<script src="https://analytics-pixel.xyz/p.js"></script>
<script>var _c=1;</script></body></html>"""


def _subsidy_page(scheme, dept):
    return f"""<!DOCTYPE html><html><head><title>{scheme} Subsidy Portal</title></head>
<body><div class="wrap"><header><img src="/emblem.png" alt="National Emblem Government of India"></header>
<main><h1>{dept} — {scheme} Subsidy Disbursement</h1>
<p>Your government subsidy under {scheme} is pending. Failure to verify KYC will
result in your account being blocked. Update KYC immediately to claim your subsidy.</p>
<img src="/govt-qr.png" alt="Official portal QR - Ministry of Finance">
<form><label>UPI ID for subsidy transfer</label>
<input type="text" name="upi_id" placeholder="Enter UPI ID">
<button>Receive Subsidy</button></form>
<p>Pay processing fee to subsidy@ybl to activate your yojana benefit.</p>
</main></div>
<script src="https://track-metrics-cdn.ru/collect.js"></script>
<script src="https://ads-redirect.top/r.js"></script>
<script>var _s=1;</script></body></html>"""


def _kyc_page(bank):
    return f"""<!DOCTYPE html><html><head><title>{bank} KYC Verification</title></head>
<body><div class="kyc"><h2>{bank} NetBanking — Urgent KYC Update</h2>
<p>Dear customer, your {bank} account will be suspended today. Your KYC has expired.
Verify now to avoid suspension. This is your final notice.</p>
<form><input name="username" placeholder="User ID">
<input name="password" type="password" placeholder="Password">
<input name="upi" placeholder="Linked UPI ID">
<button>Verify Account</button></form></div></body></html>"""


# --- legit pages (varied structure, clean content) --------------------------
def _legit_bank():
    return """<!DOCTYPE html><html><head><title>State Bank of India - Personal Banking</title></head>
<body><nav>Home Accounts Loans Cards</nav><section><h1>Welcome to SBI Online</h1>
<p>Securely manage your accounts, pay bills, and transfer funds. Your security is our priority.</p>
</section><footer>Contact us at your nearest branch.</footer></body></html>"""


def _legit_govt():
    return """<!DOCTYPE html><html><head><title>Reserve Bank of India</title></head>
<body><header><h1>Reserve Bank of India</h1></header><article>
<p>The central bank of India. Notifications, press releases, and regulatory guidelines.</p>
</article></body></html>"""


def _legit_ecom():
    return """<!DOCTYPE html><html><head><title>Amazon.in Shopping</title></head>
<body><div id="nav"><span>All</span><span>Deals</span></div>
<div id="grid"><p>Shop electronics, fashion, and more with fast delivery across India.</p></div>
</body></html>"""


def _legit_generic(title, body):
    return f"""<!DOCTYPE html><html><head><title>{title}</title></head>
<body><main><h1>{title}</h1><p>{body}</p></main></body></html>"""


# --- the 20 records ---------------------------------------------------------
# ssl_before / whois_creation / whois_expiration are datetimes; the rest are the
# infrastructure fields Module C fingerprints on.

SITES = [
    # ===== Campaign 1: Fake UPI Cashback (Cloudflare / Let's Encrypt) =====
    dict(url="https://instant-reward-claim.pages.dev/", label="scam",
         campaign="Fake UPI Cashback", html=_upi_cashback_page("SBI", "5000"),
         ip="104.21.5.11", asn="AS13335", provider="Cloudflare, Inc.",
         ns="ns1.cloudflare.com", ssl="Let's Encrypt",
         ssl_before=_days(40), created=_days(280), expires=_days(-450)),
    dict(url="https://festive-cashback-portal.pages.dev/", label="scam",
         campaign="Fake UPI Cashback", html=_upi_cashback_page("Paytm", "3000"),
         ip="104.21.5.42", asn="AS13335", provider="Cloudflare, Inc.",
         ns="ns1.cloudflare.com", ssl="Let's Encrypt",
         ssl_before=_days(35), created=_days(240), expires=_days(-480)),
    dict(url="https://mega-reward-2026.pages.dev/", label="scam",
         campaign="Fake UPI Cashback", html=_upi_cashback_page("PhonePe", "2500"),
         ip="104.21.5.88", asn="AS13335", provider="Cloudflare, Inc.",
         ns="ns1.cloudflare.com", ssl="Let's Encrypt",
         ssl_before=_days(50), created=_days(300), expires=_days(-420)),
    dict(url="https://claim-your-bonus.pages.dev/", label="scam",
         campaign="Fake UPI Cashback", html=_upi_cashback_page("Google Pay", "4000"),
         ip="104.21.5.130", asn="AS13335", provider="Cloudflare, Inc.",
         ns="ns1.cloudflare.com", ssl="Let's Encrypt",
         ssl_before=_days(28), created=_days(260), expires=_days(-460)),

    # ===== Campaign 2: Government Subsidy Scam (Google infra) =====
    dict(url="https://subsidy-disbursement.web.app/", label="scam",
         campaign="Government Subsidy Scam", html=_subsidy_page("PM-KISAN", "Ministry of Agriculture"),
         ip="142.250.4.20", asn="AS15169", provider="Google LLC",
         ns="ns-cloud-a1.googledomains.com", ssl="Google Trust Services",
         ssl_before=_days(45), created=_days(190), expires=_days(-540)),
    dict(url="https://benefit-transfer-portal.web.app/", label="scam",
         campaign="Government Subsidy Scam", html=_subsidy_page("LPG Gas", "Ministry of Petroleum"),
         ip="142.250.4.55", asn="AS15169", provider="Google LLC",
         ns="ns-cloud-a1.googledomains.com", ssl="Google Trust Services",
         ssl_before=_days(38), created=_days(210), expires=_days(-520)),
    dict(url="https://yojana-verify-portal.web.app/", label="scam",
         campaign="Government Subsidy Scam", html=_subsidy_page("Scholarship", "Ministry of Education"),
         ip="142.250.4.90", asn="AS15169", provider="Google LLC",
         ns="ns-cloud-a1.googledomains.com", ssl="Google Trust Services",
         ssl_before=_days(52), created=_days(175), expires=_days(-555)),
    dict(url="https://housing-benefit-claim.web.app/", label="scam",
         campaign="Government Subsidy Scam", html=_subsidy_page("PM Awas", "Ministry of Housing"),
         ip="142.250.4.144", asn="AS15169", provider="Google LLC",
         ns="ns-cloud-a1.googledomains.com", ssl="Google Trust Services",
         ssl_before=_days(30), created=_days(200), expires=_days(-530)),

    # ===== Campaign 3: Bank KYC Phishing (AWS, freshly registered) =====
    dict(url="https://secure-account-verify.com/", label="scam",
         campaign="Bank KYC Phishing", html=_kyc_page("SBI"),
         ip="52.95.1.10", asn="AS16509", provider="Amazon.com, Inc.",
         ns="ns-101.awsdns-12.com", ssl="Amazon", ssl_before=_days(6),
         created=_days(8), expires=_days(-357)),
    dict(url="https://netbanking-secure-login.com/", label="scam",
         campaign="Bank KYC Phishing", html=_kyc_page("HDFC"),
         ip="52.95.1.44", asn="AS16509", provider="Amazon.com, Inc.",
         ns="ns-101.awsdns-12.com", ssl="Amazon", ssl_before=_days(4),
         created=_days(5), expires=_days(-360)),
    dict(url="https://account-safety-check.com/", label="scam",
         campaign="Bank KYC Phishing", html=_kyc_page("ICICI"),
         ip="52.95.1.77", asn="AS16509", provider="Amazon.com, Inc.",
         ns="ns-101.awsdns-12.com", ssl="Amazon", ssl_before=_days(9),
         created=_days(11), expires=_days(-354)),

    # ===== Legit sites (varied — should NOT cluster) =====
    dict(url="https://www.onlinesbi.sbi/", label="legit", campaign="Legitimate",
         html=_legit_bank(), ip="163.53.78.20", asn="AS9829", provider="BSNL",
         ns="ns1.sbi.co.in", ssl="DigiCert", ssl_before=_days(120),
         created=_days(7300), expires=_days(-400)),
    dict(url="https://www.rbi.org.in/", label="legit", campaign="Legitimate",
         html=_legit_govt(), ip="14.140.1.50", asn="AS4755", provider="TATA",
         ns="ns1.rbi.org.in", ssl="Sectigo", ssl_before=_days(200),
         created=_days(9000), expires=_days(-300)),
    dict(url="https://www.amazon.in/", label="legit", campaign="Legitimate",
         html=_legit_ecom(), ip="52.95.116.10", asn="AS16509", provider="Amazon.com, Inc.",
         ns="ns1.p31.dynect.net", ssl="DigiCert", ssl_before=_days(85),
         created=_days(5500), expires=_days(-500)),
    dict(url="https://www.phonepe.com/", label="legit", campaign="Legitimate",
         html=_legit_generic("PhonePe - Payments App",
                             "India's leading digital payments platform for UPI, bills, and recharges."),
         ip="13.234.1.5", asn="AS16509", provider="Amazon.com, Inc.",
         ns="ns-200.awsdns-25.com", ssl="Amazon", ssl_before=_days(70),
         created=_days(3200), expires=_days(-600)),
    dict(url="https://www.hdfcbank.com/", label="legit", campaign="Legitimate",
         html=_legit_generic("HDFC Bank - Personal Banking",
                             "Banking, loans, credit cards and investments for every need."),
         ip="103.86.1.20", asn="AS17439", provider="NxtGen", ns="ns1.hdfcbank.com",
         ssl="DigiCert", ssl_before=_days(150), created=_days(8200), expires=_days(-350)),
    dict(url="https://tech-blog-daily.github.io/", label="legit", campaign="Legitimate",
         html=_legit_generic("Tech Blog Daily",
                             "A personal blog about software engineering, gadgets and open source."),
         ip="185.199.108.153", asn="AS54113", provider="Fastly", ns="dns1.p05.nsone.net",
         ssl="Let's Encrypt", ssl_before=_days(60), created=_days(900), expires=_days(-305)),
    dict(url="https://www.thehindu.com/", label="legit", campaign="Legitimate",
         html=_legit_generic("The Hindu - News",
                             "Latest news, analysis and opinion from India and the world."),
         ip="192.229.1.8", asn="AS15133", provider="Edgecast", ns="ns1.thehindu.com",
         ssl="DigiCert", ssl_before=_days(95), created=_days(6800), expires=_days(-450)),
    dict(url="https://www.iitm.ac.in/", label="legit", campaign="Legitimate",
         html=_legit_generic("IIT Madras",
                             "Indian Institute of Technology Madras — education and research."),
         ip="103.5.134.10", asn="AS55824", provider="NKN", ns="ns1.iitm.ac.in",
         ssl="Sectigo", ssl_before=_days(180), created=_days(7000), expires=_days(-320)),
    dict(url="https://www.india.gov.in/", label="legit", campaign="Legitimate",
         html=_legit_generic("National Portal of India",
                             "The official portal of the Government of India for citizen services."),
         ip="164.100.1.30", asn="AS4758", provider="NIC", ns="ns1.nic.in",
         ssl="DigiCert", ssl_before=_days(210), created=_days(8500), expires=_days(-280)),
]
