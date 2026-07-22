from csbi.scoring.csbi import compute_csbi


def test_compute_csbi_non_negative():
    assert compute_csbi(0.2, 0.4) >= 0
