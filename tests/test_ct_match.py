from common.ct_match import classify, is_candidate


def test_impersonation_flagged():
    assert is_candidate("paypal-verify.com")
    assert is_candidate("sbi-kyc-update.xyz")
    assert is_candidate("icloud-find.pages.dev")
    assert is_candidate("secure-hdfc-netbanking.web.app")
    assert is_candidate("coinbase-wallet-recover.vercel.app")


def test_legit_not_flagged():
    for d in ("www.paypal.com", "netflix.com", "google.com", "example.org",
              "myrandomsite.com", "applepie-bakery.com", "myappleid.com"):
        assert not is_candidate(d), d


def test_reason_shape():
    r = classify("login-microsoftonline.support")
    assert r and r["brands"] and r["reasons"]
    assert r["host"] == "login-microsoftonline.support"
