# CSBI Safety Check — review demo

A polished, consumer-safety front-end over the real engine.

## Setup (once)
```bash
pip install -r requirements.txt
pip install -r demo/requirements.txt
```

## Run
```bash
streamlit run demo/app.py
```
Pre-scanned, so it's instant and works offline.

## Flow (Check a site tab)
Pick a site → "Check this site" → the page jumps to the top and the four layers
reveal ONE BY ONE (~1.4s each, auto-scrolling) → then the CSBI verdict, top-3
reasons, campaign tag, and an expander showing the actual captured page.

## Live scan
The "Scan live" box runs the REAL engine on any URL in real time — proof it isn't
faked. Best demoed on a real legitimate site (e.g. https://www.google.com): it
scores LOW, showing the engine works on real input. Live scanning depends on
WHOIS/SSL/network, so it can be slow or return partial data for some sites; that's
expected and handled gracefully, but don't gamble the demo on a live phishing URL.

## Two laptops
Both run `streamlit run demo/app.py` locally. One picks a scam, the other a legit
site — CSBI gauges side by side tell the story.

## Regenerate cache (only if you change demo sites or the engine)
```bash
python demo/build_cache.py
```

## What's real (say this if asked)
- Layer scores (T1-T4), CSBI, and the campaign clusters are computed by the real
  code (Module A extractor + Varshan's real DBSCAN).
- The verdict/probability is a rule-based stand-in until Module B's trained model
  lands; every input to it is a real measured feature.
- The demonstration pages model reported UPI/subsidy/KYC campaigns. Live UPI scam
  pages are ephemeral (they die within hours) and unsafe to redistribute, so the
  app shows each page's captured content for full transparency, and the live-scan
  box runs the engine on any real URL you enter.
