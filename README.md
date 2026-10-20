# CSBI-PA — Platform-Aware Phishing Detection

Cross-Signal Behavioural Inconsistency (CSBI) detection, extended for the part
of phishing that current detectors handle worst: pages published for free on
shared platforms such as `pages.dev`, `vercel.app`, `github.io`, `web.app` and
`webflow.io`. PSG iTech, CSE.

## The problem

In the OpenPhish public feed, **42.9% of the 389,920 unique phishing URLs listed
between Oct 2024 and Oct 2026 sit on a free-hosting platform**
(`module1_ingestion/openphish_history.py` reproduces the figure). On those pages
every surface signal a detector trusts belongs to the *platform*: the TLS
certificate (a wildcard for `*.pages.dev`), the IP and ASN (Cloudflare, Google,
Vercel), the WHOIS age (the platform's domain, years old). Certificate-name,
domain-age and infrastructure features therefore *pass* on a phishing page that
cost nothing to publish. We call this **borrowed credibility**.

## What is new here

1. **Borrowed-credibility decomposition.** Surface trust is split into apparent
   trust (what the page shows) and earned trust (only signals the publisher
   controls): `BC = C_apparent − C_earned`.
2. **Layer 5: platform-aware behaviour.** A static host has no backend, so a
   credential form on it can only deliver what it collects to a third party.
   The exfiltration path (Telegram bot API, form relays, webhooks, Apps
   Script) is visible in the HTML. Layer 5 also judges brand impersonation
   against the brand's *real* domains, including brand names written into
   the subdomain (`paypal-verify.pages.dev`).
3. **CSBI-PA** = `100 · max(0, C − min(T3, T4, T5))`. A single strong behavioural
   red flag is no longer averaged away by layers that saw nothing.
4. **Kit-fingerprint campaigns + weak supervision.** Infrastructure clustering
   collapses on shared hosts (every tenant has the same ASN, certificate issuer
   and nameservers). Pages are instead clustered on the phishing kit itself:
   DOM shingles, form schema, asset names, CSS vocabulary and exfil endpoint.
   One confirmed page then labels its kit cluster.
5. **Deployed as a browser extension** with a credential guard: on a high-risk
   page, the first keystroke into a password, OTP, card or UPI field asks
   before the user can type.

## Baselines we compare against (same data, same splits)

| Set | Features |
|---|---|
| B1 | URL-lexical (24 features) |
| B2 | **TBDF**, reimplemented from the base paper, Mishra & Varshney (2025), arXiv:2503.06487 |
| B3 | URL + generic HTML statistics |
| B4 | original CSBI (layers 1–4, T1–T4, CSBI) |
| OURS | B4 + Layer 5 + T5 + borrowed credibility + CSBI-PA |

Each set is trained as Logistic Regression, Random Forest and XGBoost, and
evaluated with campaign-disjoint 5-fold cross-validation and a temporal split.
Results are reported separately for free-hosted and self-hosted pages, plus
TPR at 1% FPR. A browser warning that fires on 5% of legitimate sites is
unusable, so that operating point matters more than accuracy.

## Running it

```bash
python run_all.py setup          # deps, OpenPhish history, legit URL lists
python run_all.py legit          # scan ~5k legitimate pages (resumable)
python run_all.py collect 24     # scan phishing as it is listed, for 24 h
python run_all.py results        # train, experiments, campaigns, results/REPORT.md
python run_all.py serve          # API + dashboard at http://localhost:8000
```

Phishing pages are taken down within hours of being listed, so they are scanned
live by `collect`. Old feed URLs are dead and carry no page to analyse. Every
step is resumable; Ctrl+C is safe.

**Browser extension:** open `chrome://extensions`, enable *Developer mode*,
click *Load unpacked* and choose the `extension/` folder. Keep `run_all.py serve`
running. For a remote server, set the API address in the extension's Settings.

### Training data from PhreshPhish (Kaggle or Colab, no local machine needed)

`notebooks/phreshphish_colab.ipynb` streams a balanced sample of
[PhreshPhish](https://huggingface.co/datasets/phreshphish/phreshphish)
(CC-BY-4.0, anti-phishing research only), runs the saved HTML through every
layer offline, trains all models and baselines, runs the campaign experiments,
and packages `csbi_results.zip`.

On Kaggle: *File → Import Notebook → GitHub* (`SamyukthaGS-07/CSBI`, branch
`full-build`), *Settings → Internet: On*, then *Save Version → Save & Run All*.
It runs in the background (~1.5–2.5 h for 16k pages). Download the zip from the
version's *Output* tab.

Offline pages carry no TLS / WHOIS / DNS evidence, so they are tagged
`meta_offline = 1` and training uses the offline feature sets
(`train.py --track offline|live|all`).

### Running on a cloud VM (Ubuntu, e.g. Azure for Students, B2s)

Open inbound TCP port 8000, then:

```bash
sudo apt update && sudo apt install -y python3-venv git tmux unzip
git clone -b full-build https://github.com/SamyukthaGS-07/CSBI.git && cd CSBI
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

tmux new -s scan     # then: python run_all.py setup && python run_all.py collect 60   (Ctrl+B D)
tmux new -s web      # then: python run_all.py serve public                              (Ctrl+B D)
tmux new -s legit    # then: python run_all.py legit                                     (Ctrl+B D)
```

The dashboard is at `http://<server-ip>:8000`. Scanner processes share the free
IP-lookup rate limit, so `collect` and `legit` can run at the same time.

To add the PhreshPhish results to the server's live scans and retrain:

```bash
unzip -o csbi_results.zip -d phresh
python scripts/merge_store.py phresh/data/store/scans.db
python run_all.py results          # then restart the web session
```

## Repository map

| Path | What it does |
|---|---|
| `module1_ingestion/` | OpenPhish history miner, legit lists (top sites, legit free-hosted pages from ~675 awesome-lists + npm homepages, login pages) |
| `module2_screening/` | Stage-1 routing (free host → full analysis) |
| `module3_behavioral/` | fetch + layers 0 (URL), 1–4 (CSBI), TBDF baseline, layer 5 (platform), trust scores, CSBI, CSBI-PA |
| `module4_clustering/` | Varshan's infrastructure clustering, kit fingerprints, campaign propagation, kit index |
| `module5_decision/` | dataset cleaning, feature sets, training, SHAP-based reasons, inference |
| `evaluation/` | metrics, campaign experiments (E1–E3), report + figures |
| `backend/` | FastAPI: `/scan`, `/scan/page`, `/campaigns`, dashboard at `/` |
| `extension/` | Chrome MV3 extension |
| `common/` | schema, SQLite store, hosting/brand helpers, concurrent scanner, end-to-end pipeline |
| `module6_delivery/` | the original Streamlit review demo (kept for reference) |

## Honest limitations

- T1–T5 weights are a definitional rubric, not learned. The classifier learns
  from the raw features underneath. Reasons shown to users come from the
  model's own TreeSHAP values.
- No public UPI phishing dataset exists. The UPI layer (T4) is validated on
  whatever UPI pages the live feeds contain, and the paper says so.
- Legitimate free-hosted pages come from curated lists (awesome-lists, npm),
  which skew towards developer sites.
- E3 lead time is an upper bound: it assumes a page is crawled as soon as it
  goes up.

## Team

Samyuktha G S (scanning, CSBI layers, platform layer, pipeline), Shri Nithee
(classification and delivery), Varshan (campaign clustering).
