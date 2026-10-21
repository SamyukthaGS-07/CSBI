# CSBI-PA: Platform-Aware Cross-Signal Inconsistency Detection for Free-Hosted Phishing

**Samyuktha G S, Shri Nithee, Varshan**
*Department of Computer Science and Engineering, PSG Institute of Technology and Applied Research (PSG iTech), Coimbatore, India*

> Draft manuscript. Author order, affiliations, corresponding-author details, and funding/acknowledgements to be finalised before submission.

---

## Abstract

Phishing-detection research has reached near-saturation accuracy on conventional benchmarks, yet a large and growing fraction of real-world attacks evades deployed detectors by hiding on free web-hosting platforms. Analysing two years of the OpenPhish feed (389,920 unique URLs), we find that **42.9%** of phishing pages are served from shared free-hosting platforms such as `pages.dev`, `vercel.app`, and `github.io`. On these pages the TLS certificate, IP address, hosting Autonomous System, and domain-registration age all belong to the platform rather than the attacker; consequently the brand-domain and certificate features that drive state-of-the-art detectors—including the Tightly-Bound Domain Features (TBDF) of Mishra and Varshney (2025)—lose discriminative power. We introduce **CSBI-PA**, a platform-aware extension of Cross-Signal Behavioural Inconsistency detection. CSBI-PA contributes (i) a *borrowed-credibility* decomposition that separates the trust a page *displays* from the trust it has *earned*; (ii) a platform-aware behavioural layer that detects credential collection and third-party data exfiltration on backend-less static hosts; and (iii) a phishing-kit fingerprinting scheme that groups pages by the toolkit from which they were built, enabling cluster-based weak supervision and early detection of reused kits. Under campaign-disjoint cross-validation on live-collected data, CSBI-PA improves F1 on the free-hosted subset from 0.650 (TBDF) to 0.942 and true-positive rate at a 1% false-positive operating point from 0.420 to 0.908. An ablation isolates a +0.14 TPR@1%FPR gain attributable to the platform-aware layer on free-hosted pages, with neutral effect on self-hosted pages. Kit fingerprinting recovered 616 campaigns with a median early-detection lead of four days. The method is realised as a real-time scanning service, a browser extension, and a Certificate-Transparency monitor for zero-day self-hosted domains.

**Keywords:** phishing detection, free-hosting abuse, certificate transparency, campaign clustering, weak supervision, browser security, UPI fraud.

---

## 1. Introduction

Phishing remains one of the most prevalent initial-access vectors in modern cyber-attacks. A decade of machine-learning research has produced detectors that report accuracies above 99% on standard corpora assembled from PhishTank, PhishStats, and the Alexa/Tranco top sites. These results, however, are obtained predominantly on *self-hosted* phishing: pages served from attacker-registered domains whose URL lexicon, young registration age, and brand-mismatched certificates provide strong discriminative signal.

The contemporary threat landscape has shifted. Attackers increasingly publish phishing pages on free, reputable hosting platforms—static-site hosts (`pages.dev`, `vercel.app`, `github.io`, `web.app`, `netlify.app`), site builders (`webflow.io`, `weebly.com`), and object stores—because doing so is free, instantaneous, resilient to takedown, and, critically, confers the platform's own reputation on the malicious page. A measurement over the OpenPhish public feed from October 2024 to October 2026 shows that **42.9% of 389,920 distinct phishing URLs** were hosted on such platforms.

For a page on a free-hosting platform, the signals that conventional detectors rely upon are no longer controlled by the attacker:

- the **TLS certificate** is a wildcard issued to the platform (e.g., `*.pages.dev`);
- the **IP address** and **Autonomous System** belong to the platform operator (e.g., Cloudflare, Google, Vercel);
- the **WHOIS registration age** is that of the platform's multi-year-old parent domain;
- **brand-domain binding** features see a certificate and domain that legitimately match, because they match the platform.

We term this effect **borrowed credibility**: a near-zero-cost page inherits trust it never earned. Detectors whose discriminative power rests on surface-credibility features therefore degrade precisely on the fastest-growing segment of phishing.

This paper makes the following contributions:

1. A measurement of free-hosted phishing prevalence from two years of feed history, and an analysis of why surface-credibility and brand-domain features fail on this subset.
2. **CSBI-PA**, a platform-aware detection method built on three components: a borrowed-credibility decomposition, a platform-aware behavioural feature layer, and kit-fingerprint campaign clustering with cluster-based weak supervision.
3. A reproducible evaluation against a reimplementation of the TBDF baseline and standard URL and content baselines, under campaign-disjoint and temporal splits, reported separately for free-hosted and self-hosted subsets and at operating points relevant to end-user deployment.
4. A deployed system comprising a real-time scoring API, a browser extension with a credential-entry safeguard, and a Certificate-Transparency monitor that screens newly issued certificates for brand impersonation.

## 2. Related Work

**URL- and content-based detection.** A large body of work classifies phishing from lexical URL features (length, entropy, token counts, suspicious keywords, risky TLDs) and from page content (form structure, link ratios, DOM statistics). These approaches are lightweight and widely deployed but are known to degrade on short, benign-looking URLs and on pages that borrow legitimate structure.

**Brand-domain and tightly-bound features.** Mishra and Varshney (2025) propose *Tightly-Bound Domain Features* (TBDF)—certificate common-name, cookie domain, logo domain, dominant link domain, and form-action domain—each scored by whether the artefact is bound to the page's own domain. They report Random-Forest accuracy near 99.8% on a balanced corpus of ~9,200 pages collected November 2024–January 2025. We adopt this work as our base paper and primary baseline, and we show that its mechanism is specifically weakened by free-hosting abuse, where artefacts are bound to the platform domain rather than the attacker.

**Phishing-kit and campaign analysis.** Prior studies cluster phishing by shared infrastructure (ASN, IP block, nameserver) to recover campaigns. On shared free-hosting platforms, however, infrastructure is common to all tenants, collapsing such clusters. We instead fingerprint the deployed *kit* (DOM structure, form schema, asset names, exfiltration endpoints), which remains discriminative across hosting platforms.

**Certificate Transparency monitoring.** CT logs publish every issued certificate and have been used to detect look-alike domains at registration time. We incorporate CT monitoring as a complementary early-warning channel for self-hosted zero-day domains, acknowledging that it does not observe free-hosted pages that reuse platform wildcard certificates.

## 3. Problem Formulation: Borrowed Credibility

Let a page be characterised by a surface-credibility component derived from structural and temporal signals, and a behavioural-substance component derived from page behaviour. Conventional detectors implicitly assume that high surface credibility is expensive to obtain and therefore informative of legitimacy.

On a free-hosting platform this assumption fails. We decompose apparent surface credibility *C* into an **earned** part and a **borrowed** part. The borrowed part comprises every surface signal controlled by the platform rather than the publisher: certificate validity, certificate age, registrable-domain age, and hosting reputation. Formally, for a page on a platform *p*, the earned surface credibility excludes platform-owned signals; the borrowed credibility is

&nbsp;&nbsp;&nbsp;&nbsp;*BC = C_apparent − C_earned*,

which is zero for self-hosted pages and strictly positive for free-hosted pages that present platform-provided assurances. A detection method aware of this decomposition can discount borrowed assurances and instead weight behaviour that the attacker genuinely controls.

## 4. Methodology

CSBI-PA extends Cross-Signal Behavioural Inconsistency (CSBI) detection, which quantifies the gap between how trustworthy a page appears on its surface and how it behaves. The system comprises data acquisition, multi-layer feature extraction, platform-aware scoring, supervised classification, campaign clustering with weak supervision, and two deployment channels.

### 4.1 Data Acquisition

Phishing URLs are drawn from live feeds (OpenPhish, PhishStats with a confidence threshold, CERT Polska, phishunt, and PhishTank where an API key is available) and scanned within hours of listing, because free-hosted and self-hosted phishing pages are frequently removed within hours of publication. Each page is fetched with a browser user-agent; the HTTP response, final URL and redirect chain, TLS certificate (issuer, validity dates, subject/SAN names), DNS resolution, Autonomous System, WHOIS record, and set-cookie domains are captured, and the rendered HTML is stored as a scan-time snapshot.

The legitimate class is assembled in three strata to prevent shortcut learning: (i) homepages of popular domains; (ii) **legitimate pages on the same free-hosting platforms** that phishing abuses, harvested from curated developer sources; and (iii) login pages of popular services, so that the mere presence of a credential form is not a shortcut. The free-hosted legitimate stratum is essential: without it, "is the page on a free host?" would be a trivial and misleading discriminator.

A public corpus of historical phishing and benign pages with saved HTML (PhreshPhish; ~498k training pages) is additionally imported to enlarge the content-based feature space; imported pages carry no live certificate or WHOIS evidence and are flagged accordingly so that models trained on the live subset never consume missing-by-design values.

### 4.2 Feature Extraction

Features are organised into additive layers so that contributions can be isolated by ablation:

- **Layer 0 — URL lexical.** Length, host and path composition, digit and hyphen counts, entropy, suspicious-token and risky-TLD indicators, punycode, and embedded-credential markers.
- **Layers 1–2 — Structural and temporal.** HTTPS, subdomain depth, IP-literal host, special-character ratio; domain age, certificate age, and registration length.
- **Layers 3–4 — Behavioural and payment.** Brand impersonation judged against the brand's true registrable domains; urgency and subsidy/refund language; external-script ratio; UPI virtual-payment-address and form fields; and a government-emblem-plus-QR heuristic targeting Indian payment fraud.
- **Layer 5 — Platform-aware (this work).** Indicators that a credential form is served from a backend-less static host and can therefore only deliver captured data to a third party; detection of third-party exfiltration endpoints (messaging-bot APIs, form relays, webhooks, serverless script endpoints) in page source; cross-site form targets; brand impersonation encoded in the publisher-chosen subdomain; and the free-hosting indicator itself.
- **TBDF baseline features.** The five tightly-bound domain features of the base paper are reimplemented for direct comparison; certificate-name and cookie-domain features are computed where live evidence is available.

### 4.3 Borrowed Credibility and CSBI-PA

Per-layer trust scores T1–T4 in [0,1] are computed as in CSBI, with higher values indicating greater legitimacy. We add a platform-aware trust score T5 that penalises impersonation, credential collection, third-party exfiltration, and cross-site form submission. Surface credibility is decomposed into apparent and earned components (Section 3), yielding the borrowed-credibility feature *BC*. The platform-aware inconsistency score is

&nbsp;&nbsp;&nbsp;&nbsp;*CSBI-PA = 100 · max(0, C − min(T3, T4, T5))*,

where weakest-link aggregation over behavioural layers prevents a single strong red flag from being averaged away by layers that observed nothing. The per-layer weights constitute a definitional rubric; the supervised classifier consumes the underlying raw features, so reported detection performance does not depend on the rubric weights.

### 4.4 Kit Fingerprinting and Campaign Clustering

Because infrastructure is shared across tenants of a free-hosting platform, campaigns are recovered by fingerprinting the deployed phishing kit rather than the hosting infrastructure. A kit fingerprint is a weighted bag of tokens over DOM tag 3-grams, form input schema and action paths, asset file names, CSS class vocabulary, exfiltration-endpoint identifiers, and page-title and claimed-brand tokens. Pages are embedded via TF-IDF and clustered with DBSCAN under cosine distance.

**Cluster-based weak supervision.** Within a kit cluster containing at least one confirmed phishing page and no confirmed-legitimate page, confirmed labels are propagated to unlabelled members that lie within a stricter cosine radius of a confirmed seed. This addresses the label-scarcity of free-hosted phishing, which public feeds systematically under-represent. A nearest-kit index additionally supports inference-time matching of a new page to a previously confirmed campaign.

### 4.5 Classification

Gradient-boosted decision trees (XGBoost), Random Forest, and regularised Logistic Regression are trained over nested feature sets—URL only; TBDF; URL+content; CSBI layers 1–4; and the full platform-aware set—enabling controlled ablation. Class imbalance is handled by class weighting. Per-page explanations are produced from the model's own TreeSHAP attributions and surfaced as the top contributing reasons.

### 4.6 Certificate-Transparency Zero-Day Monitor

A streaming monitor consumes the Certificate Transparency firehose and retains only domains that name a brand they do not own (brand token on a free host, brand with a phishing action word, or a standalone brand token in a non-brand domain). Surviving candidates are scored by the trained model, and high-risk domains are reported as zero-day candidates ahead of any feed listing. CT monitoring observes domains that obtain their own certificate and therefore targets self-hosted zero-days; free-hosted pages, which reuse platform wildcard certificates and create no new CT entry, are covered by the page-level model and kit matching.

### 4.7 Deployment

A scoring service exposes synchronous URL and page-level endpoints and serves a monitoring dashboard with live collection statistics, the model comparison, the campaign map, and the zero-day feed. A browser extension scores each visited page in the background, interposes a full-page warning on high-risk pages, and guards credential, OTP, card, and UPI fields against entry on flagged pages.

## 5. Experimental Setup

**Dataset.** Live scanning and historical import yield 9,629 phishing and 10,123 legitimate pages; after removing dead pages, error responses, non-credential login candidates, and near-duplicates, 16,367 pages remain. The subset with complete live certificate and WHOIS evidence comprises 3,927 pages and is used for the primary evaluation of surface-dependent features.

**Splits.** Models are evaluated with 5-fold **campaign-disjoint** cross-validation, in which pages sharing a kit fingerprint (or, failing that, a registrable domain) are constrained to the same fold, preventing near-identical kit copies from leaking across train and test. A **temporal** split—training on earlier-listed phishing and testing on later—is additionally reported.

**Metrics.** Precision, recall, F1, ROC-AUC, PR-AUC, and true-positive rate at 1% and 0.1% false-positive rate are reported, the last being most relevant to user-facing deployment where false alarms are costly. Results are reported separately for all pages, the free-hosted subset, and the self-hosted subset.

**Baselines.** TBDF (reimplemented from the base paper), URL-only, URL+content, and CSBI layers 1–4.

## 6. Results

### 6.1 Detection Performance

Table 1 reports XGBoost results under campaign-disjoint cross-validation on the live-evidence subset.

**Table 1. Detection performance (XGBoost, campaign-disjoint CV).**

| Subset | Method | Recall | F1 | ROC-AUC | TPR@1%FPR |
|---|---|---|---|---|---|
| Free-hosted | TBDF (base paper) | 0.848 | 0.650 | 0.858 | 0.420 |
| Free-hosted | URL + content | 0.707 | 0.778 | 0.970 | 0.629 |
| Free-hosted | CSBI layers 1–4 | 0.894 | 0.896 | 0.988 | 0.767 |
| Free-hosted | **CSBI-PA (ours)** | **0.940** | **0.942** | **0.995** | **0.908** |
| All | TBDF (base paper) | 0.846 | 0.704 | 0.846 | 0.231 |
| All | **CSBI-PA (ours)** | **0.964** | **0.968** | **0.998** | **0.962** |
| Self-hosted | TBDF (base paper) | 0.846 | 0.727 | 0.842 | 0.111 |
| Self-hosted | **CSBI-PA (ours)** | **0.973** | **0.978** | **0.999** | **0.983** |

On the free-hosted subset, CSBI-PA attains F1 0.942 and detects 90.8% of phishing at a 1% false-positive operating point, compared with 0.650 and 42.0% for the base-paper features. The gap is largest at the strict operating point relevant to deployment.

### 6.2 Ablation

**Table 2. Effect of the platform-aware layer (XGBoost, free-hosted subset).**

| Feature set | F1 | TPR@1%FPR |
|---|---|---|
| CSBI-PA without platform layer | 0.896 | 0.767 |
| **CSBI-PA (full)** | **0.942** | **0.908** |

Adding the platform-aware layer improves free-hosted F1 by 0.046 and TPR@1%FPR by 0.141. On the self-hosted subset the same addition is neutral (F1 0.978 vs 0.977; TPR@1%FPR 0.983 vs 0.984), consistent with borrowed credibility being, by construction, zero when no surface signal is platform-owned. The layer therefore contributes where the mechanism predicts and nowhere else.

### 6.3 Campaign Recovery and Early Detection

Kit fingerprinting grouped confirmed phishing pages into **616 campaigns**, with 60% of pages assigned to a campaign. Recovered campaigns include large kit families impersonating cryptocurrency-wallet, telecommunications, and major-platform brands across multiple free-hosting providers. Ordering campaign members by feed-listing time, a later member whose kit matches an earlier confirmed member could have been flagged in advance; the median such lead is four days, indicating substantial early-detection headroom from kit matching.

## 7. Discussion and Limitations

The primary surface-dependent evaluation is conducted on the live-evidence subset (3,927 pages) collected over a short window; the measurement of free-hosted prevalence, by contrast, spans two years of feed history. The UPI-specific layer is validated on the UPI phishing present in the collected feeds; no large public UPI phishing corpus exists, and the layer is accordingly demonstrated rather than benchmarked at scale. Certificate-Transparency monitoring observes only domains that obtain their own certificate and does not detect free-hosted pages that reuse platform wildcard certificates; these are addressed by the page-level model and kit matching. The per-layer trust weights are a definitional rubric; reported classification results depend only on the underlying raw features.

## 8. Conclusion and Future Work

Free-hosted phishing constitutes a large and growing fraction of real-world attacks on which brand-domain and certificate features lose discriminative power. CSBI-PA addresses this by decomposing borrowed credibility, adding platform-aware behavioural signals, and recovering campaigns through kit fingerprinting with cluster-based weak supervision. On live data it substantially outperforms a faithful reimplementation of the base-paper features on the free-hosted subset, with the gain localised—by ablation—to the platform-aware layer precisely where borrowed credibility exists. The method is deployed as a scoring service, a browser extension, and a Certificate-Transparency monitor. Future work includes scaling the live-evidence corpus, incorporating QR-code decoding for the payment-fraud layer, and longitudinal evaluation of campaign-level early detection.

## References

[1] R. Mishra and G. Varshney, "A Study of Effectiveness of Brand Domain Identification Features for Phishing Detection in 2025," arXiv:2503.06487, 2025.
[2] PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing Website Dataset and Benchmark, arXiv:2507.10854, 2025.
[3] OpenPhish community feed. https://openphish.com
[4] PhishTank. https://phishtank.org
[5] Certificate Transparency. https://certificate.transparency.dev

*Additional references on URL-based detection, phishing-kit analysis, and DBSCAN clustering to be added.*
