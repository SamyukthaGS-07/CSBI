# CSBI — Research & Publication Plan

## Base paper (anchor)
Mishra, R., & Varshney, G. (2025). *A Study of Effectiveness of Brand Domain
Identification Features for Phishing Detection in 2025.* arXiv:2503.06487.
https://arxiv.org/pdf/2503.06487

- Their idea: "tightly bound domain features" (TBDF) — features that stay
  consistent for legit sites but break for phishing. (This is CSBI's core idea.)
- Their features (each scored 1 = match, -1 = mismatch, 0 = absent):
  CN Info (SSL cert name vs domain), Cookie Domain, Logo Domain,
  Most Common Link Domain, Form Action Domain.
- Their result: Random Forest, ~99.8% accuracy, dataset = 4,667 legit
  (from Alexa Top 1M) + 4,561 phishing (from PhishTank + PhishStats),
  collected Nov 2024 – Jan 2025, keeping only sites where >=3 features fetched.

## Our positioning (the contribution)
Do NOT compete on accuracy — that space is saturated (~99%). Compete on ANGLE:

1. Generalize their single-signal brand-domain inconsistency into a **multi-layer
   cross-signal inconsistency (CSBI)**: structural + temporal + behavioural + UPI.
2. Add a **temporal** dimension (domain/SSL age) they do not use.
3. Add a **UPI / Indian-payment-fraud** dimension (Layer 4) they do not have.
4. Add **campaign clustering** (Module C) — group related scams by shared
   infrastructure for early detection of a whole campaign from one hit.

One-line claim for the paper:
"Overall accuracy is comparable to prior brand-domain work, but CSBI improves
recall on the hard *free-hosted* phishing subset — sites with a clean surface
(valid HTTPS, reputable platform domain) that brand/URL features miss — while
infrastructure clustering recovers scam campaigns."

## The experiment that proves it (Module B — Shri Nithee)
This is Blueprint sec 9.2, and it is the heart of the paper.

1. Baseline model: Random Forest on standard features only (URL + temporal),
   **without CSBI**. Report accuracy / precision / recall / F1 / ROC-AUC.
2. +CSBI model: same, **with** the T1-T4 + CSBI features added. Report same.
3. Ablation table: baseline vs +CSBI, on (a) the full set, (b) the free-hosted
   subset specifically. Expect the biggest gain on the free-hosted subset.
4. SHAP feature importance -> top-3 reasons (Blueprint sec 6.1), and to report
   where CSBI ranks among features.

If CSBI does not help, that is still a valid (if quieter) finding. Report honestly.

## Dataset plan (be realistic)
Target size: ~2,000-4,000 scanned URLs, balanced. (The base paper used ~9,228;
2-4k is plenty for RF/XGBoost + a credible ablation. The bottleneck is scanning
time, not model training.)

Sources (mirror the base paper for comparability):
- Legit: Tranco or Alexa/Cisco top-sites list (download once, take top N).
- Phishing: PhishTank full dump (free API key) OR PhishStats OR accumulate
  OpenPhish over several days. Expect 30-50% of phishing URLs to be dead by
  scan time, so pull ~2x what you need.

Two-step pipeline (already built):
1. `scripts/pull_dataset.py`  -> writes URL lists to data/labeled/scam.txt,
   legit.txt   (addresses only)
2. `scripts/run_scan.py --file <list> --label <scam|legit>`  -> scans each URL
   through Module A and writes feature vectors to data/store/scans.db
   (THE STORE = the training dataset). Resumable; run overnight.

Module B reads feature vectors out of scans.db to train.

## UPI data — honest limitation
There is no public UPI-scam URL dataset, and live UPI scam pages die within
hours. So:
- Validate the METHOD on general phishing (thousands of samples).
- DEMONSTRATE the UPI layer on a small curated + constructed set (CERT-In /
  cybercrime.gov.in advisories, reported campaigns, plus modelled pages).
- State UPI data scarcity as an explicit limitation, not a hidden gap.

## Target venue
A solid Scopus-indexed conference/workshop in security or applied ML. Frame as
an applied empirical study with a clear novel angle + honest limitations, not a
new-SOTA-accuracy claim.
