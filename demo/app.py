#!/usr/bin/env python3
"""
demo/app.py — CSBI Scam Detection (review demo, professional UI)
================================================================
A visual front-end over the REAL engine. Reads demo/demo_cache.json (pre-scanned,
so it's instant and offline). Typing a URL runs the real extractor live.

Run:  streamlit run demo/app.py
"""

import json
import sys
import time
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components
import plotly.graph_objects as go

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
CACHE_PATH = ROOT / "demo" / "demo_cache.json"

st.set_page_config(page_title="CSBI · Is this site safe?", page_icon="🛡️", layout="centered")

# real live phishing URLs pulled from OpenPhish (may expire — they're live samples)

# ------------------------------------------------------------------ style ----
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"] { font-family:'Inter',sans-serif; }
:root{ --bg:#f4f6fb; --card:#fff; --ink:#0f172a; --mut:#64748b; --line:#e6eaf2;
       --brand:#2563eb; --safe:#16a34a; --warn:#f59e0b; --danger:#e11d48; }

/* ---- HARD LIGHT-MODE LOCK (fixes white-on-white when OS is in dark mode) ---- */
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"], section.main,
[data-testid="stHeader"] { background:#f4f6fb !important; }
/* every piece of Streamlit-rendered text -> dark */
.stApp, .stApp p, .stApp li, .stApp span, .stApp label, .stApp h1, .stApp h2,
.stApp h3, .stApp h4, .stApp h5, .stApp h6,
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] *,
[data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] *,
[data-testid="stMetricValue"], [data-testid="stMetricLabel"],
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] * {
  color:#0f172a !important;
}
/* dropdown + text input: white field, dark text */
[data-baseweb="select"] > div, [data-baseweb="input"] > div,
.stTextInput input, .stSelectbox div[role="button"] {
  background:#ffffff !important; color:#0f172a !important; border-color:#e6eaf2 !important;
}
[data-baseweb="select"] *, .stTextInput input::placeholder { color:#334155 !important; }
/* tabs */
.stTabs [data-baseweb="tab"] { color:#475569 !important; }
.stTabs [aria-selected="true"] { color:#2563eb !important; }
/* info box readable */
[data-testid="stAlert"], [data-testid="stAlert"] * { color:#0f172a !important; }
/* expander header */
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color:#0f172a !important; }
</style>
<style>
.stApp { background:var(--bg); }
.block-container{ max-width:860px; padding-top:1.4rem; }
#MainMenu, footer, header { visibility:hidden; }
h1,h2,h3{ color:var(--ink); }
.brandbar{ display:flex; align-items:center; gap:10px; margin-bottom:2px; }
.brandbar .logo{ font-size:1.7rem; }
.brandbar .name{ font-weight:800; font-size:1.35rem; color:var(--ink); letter-spacing:-.02em;}
.tagline{ color:var(--mut); font-size:.95rem; margin-bottom:14px; }
.card{ background:var(--card); border:1px solid var(--line); border-radius:16px;
       padding:20px 22px; margin-bottom:14px; box-shadow:0 1px 3px rgba(15,23,42,.04); }
.result-hd{ display:flex; align-items:center; gap:18px; }
.badge{ border-radius:14px; padding:14px 18px; color:#fff !important; text-align:center; min-width:150px; }
.badge .r{ font-size:1.5rem; font-weight:800; line-height:1.1; color:#fff !important; }
.badge .p{ font-size:.85rem; opacity:.92; color:#fff !important; }
.dom{ font-family:ui-monospace,monospace; font-size:1.05rem; color:var(--ink); font-weight:600; word-break:break-all; }
.grid{ display:grid; grid-template-columns:1fr 1fr; gap:8px 22px; margin-top:14px; }
.cell .l{ font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; color:var(--mut); }
.cell .v{ font-size:.92rem; color:var(--ink); font-family:ui-monospace,monospace; word-break:break-all; }
.checks{ display:flex; flex-wrap:wrap; gap:8px; margin-top:6px; }
.chip{ font-size:.8rem; padding:5px 11px; border-radius:999px; border:1px solid var(--line); background:#fafbfe; }
.chip.ok{ color:var(--safe) !important; border-color:#bbf7d0; background:#f0fdf4;}
.chip.bad{ color:var(--danger) !important; border-color:#fecdd3; background:#fff1f3;}
.chip.na{ color:var(--mut) !important; }
.layer{ display:flex; gap:16px; align-items:flex-start; }
.lnum{ font-family:ui-monospace,monospace; font-size:1.5rem; font-weight:800; color:var(--brand) !important; opacity:.35; min-width:42px;}
.ltitle{ font-weight:700; color:var(--ink); font-size:1.05rem; }
.lsub{ color:var(--mut); font-size:.83rem; margin-bottom:10px; }
.frow{ display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px dashed #eef1f7; font-size:.9rem;}
.frow .k{ color:#334155;} .frow .v{ font-family:ui-monospace,monospace; color:var(--ink);}
.ok{color:var(--safe);} .bad{color:var(--danger);} .neu{color:var(--mut);} .warn{color:var(--warn);}
.tscore{ text-align:right; font-family:ui-monospace,monospace; font-weight:700; color:var(--brand) !important; margin-top:8px;}
.reason{ background:#fff7f7 !important; color:#0f172a !important; border-left:3px solid var(--danger); padding:8px 12px; border-radius:8px; margin:6px 0; font-size:.92rem;}
.working{ font-size:.8rem; color:var(--warn); font-style:italic; }
.tag{ font-family:ui-monospace,monospace; font-size:.82rem; background:#eef2fb !important; color:#334155 !important; padding:3px 9px; border-radius:7px;}
.preview{ background:#0f172a !important; color:#cbd5e1 !important; font-family:ui-monospace,monospace; font-size:.75rem;
          padding:14px; border-radius:10px; max-height:260px; overflow:auto; white-space:pre-wrap;}
.preview *{ color:#cbd5e1 !important; }
.small{ font-size:.82rem; color:var(--mut) !important;}
.stTabs [data-baseweb="tab"] { color:#334155 !important; }
.stTabs [aria-selected="true"] { color:var(--brand) !important; }
.cell .v{ color:#0f172a !important; }
.dom{ color:#0f172a !important; }
</style>
""", unsafe_allow_html=True)


def scroll_to_anchor(anchor_id="csbi_anchor"):
    """Smoothly bring the given anchor element into view (used to follow the
    layer reveal downward, one layer at a time)."""
    components.html(f"""<script>
      const d=window.parent.document;
      const el=d.getElementById('{anchor_id}');
      if(el) el.scrollIntoView({{behavior:'smooth', block:'center'}});
    </script>""", height=0)


# --------------------------------------------------------------- data --------
@st.cache_data
def load_cache():
    if not CACHE_PATH.exists():
        import subprocess
        subprocess.run([sys.executable, str(ROOT / "demo" / "build_cache.py")], check=True)
    return json.loads(CACHE_PATH.read_text(encoding="utf-8"))


def live_scan(url):
    from csbi.extraction.extractor import extract_features
    from demo.build_cache import verdict_and_reasons
    rec = extract_features(url, store=None)
    d = rec.to_dict()
    d["campaign_true"] = "Live scan"; d["ground_truth"] = "unknown"
    p, risk, reasons = verdict_and_reasons(d)
    d["scam_probability"], d["risk_level"], d["top3_reasons"] = p, risk, reasons
    fx = d["features"]
    d["infra"] = {"ip": d.get("resolved_ip"), "asn": d.get("asn"), "provider": d.get("hosting_provider"),
                  "nameserver": d.get("nameserver"), "ssl_issuer": d.get("ssl_issuer")}
    d["traditional_safe"] = bool(fx["https"] == 1 and fx["is_ip_domain"] == 0
                                 and fx["special_char_ratio"] <= 0.15 and fx["subdomain_count"] <= 1)
    d["html_preview"] = "(live page not stored)"
    d["cluster_id"] = -1; d["cluster_label"] = "n/a (single live scan)"
    return d


CACHE = load_cache()
RECORDS = {r["url"]: r for r in CACHE["records"]}
RISKC = {"HIGH": "#e11d48", "MEDIUM": "#f59e0b", "LOW": "#16a34a"}


# --------------------------------------------------------------- pieces ------
def gauge(v):
    c = "#e11d48" if v >= 40 else "#f59e0b" if v >= 15 else "#16a34a"
    fig = go.Figure(go.Indicator(mode="gauge+number", value=v, number={"font": {"size": 34}},
        gauge={"axis": {"range": [0, 100], "tickfont": {"size": 9}}, "bar": {"color": c},
               "borderwidth": 0,
               "steps": [{"range": [0, 15], "color": "#eafaf1"}, {"range": [15, 40], "color": "#fef4e5"},
                         {"range": [40, 100], "color": "#fdecef"}]}))
    fig.update_layout(height=170, margin=dict(l=16, r=16, t=8, b=4),
                      paper_bgcolor="#ffffff", plot_bgcolor="#ffffff",
                      font=dict(color="#0f172a"))
    return fig


def render_header(rec):
    risk = rec["risk_level"]; col = RISKC[risk]; f = rec["features"]; infra = rec.get("infra", {})
    age = f.get("domain_age_days", 0)
    age_str = f"{age} days" + ("  ⚠ very new" if 0 < age <= 30 else "")
    st.markdown(f"""<div class="card">
      <div class="result-hd">
        <div class="badge" style="background:{col}"><div class="r">{risk}</div>
          <div class="p">{int(rec['scam_probability']*100)}% likely scam</div></div>
        <div style="flex:1"><div class="small">Analysed site</div>
          <div class="dom">{rec['url']}</div></div>
      </div>
      <div class="grid">
        <div class="cell"><div class="l">IP address</div><div class="v">{infra.get('ip') or '—'}</div></div>
        <div class="cell"><div class="l">Hosting provider</div><div class="v">{infra.get('provider') or '—'}</div></div>
        <div class="cell"><div class="l">ASN</div><div class="v">{infra.get('asn') or '—'}</div></div>
        <div class="cell"><div class="l">Nameserver</div><div class="v">{infra.get('nameserver') or '—'}</div></div>
        <div class="cell"><div class="l">SSL issuer</div><div class="v">{infra.get('ssl_issuer') or '—'}</div></div>
        <div class="cell"><div class="l">Domain age</div><div class="v">{age_str}</div></div>
      </div></div>""", unsafe_allow_html=True)


def checks_row(f):
    def chip(label, good, na=False):
        cls = "na" if na else ("ok" if good else "bad")
        mark = "—" if na else ("✓" if good else "✕")
        return f'<span class="chip {cls}">{mark} {label}</span>'
    html = '<div class="card"><div class="small" style="margin-bottom:6px">Checked against</div><div class="checks">'
    html += chip("Valid HTTPS", f["https"] == 1)
    html += chip("Domain age", not (0 < f.get("domain_age_days", 9999) <= 30))
    html += chip("Brand authenticity", f["brand_mismatch"] == 0)
    html += chip("No urgency pressure", f["urgency_language_score"] < 0.5)
    html += chip("No UPI harvesting", f["upi_field_presence"] == 0)
    html += chip("No fake-gov QR", f.get("fake_gov_qr_score", 0) < 0.9)
    html += "</div></div>"
    st.markdown(html, unsafe_allow_html=True)


def frow(k, v, state="neu", note=""):
    icon = {"ok": "✓", "bad": "✕", "neu": "•", "warn": "!"}[state]
    n = f' <span class="working">{note}</span>' if note else ""
    return f'<div class="frow"><span class="k"><span class="{state}">{icon}</span> {k}{n}</span><span class="v">{v}</span></div>'


LAYER_META = [
    ("01", "Structural", "The address itself — HTTPS, length, subdomains, characters. No page needed."),
    ("02", "Temporal", "How old is it — domain registration age and SSL certificate age."),
    ("03", "Behavioural", "What the page says — brand impersonation, urgency, third-party scripts."),
    ("04", "UPI signals", "The novel layer — UPI IDs, subsidy/refund bait, fake-government QR."),
]


def render_layer(i, rec):
    f = rec["features"]; num, title, sub = LAYER_META[i]; t = rec[f"T{i+1}"]
    rows = ""
    if i == 0:
        rows += frow("HTTPS present", "yes" if f["https"] else "no", "ok" if f["https"] else "bad")
        rows += frow("URL length (norm)", f'{f["url_length_norm"]:.2f}', "neu")
        rows += frow("Subdomains", f["subdomain_count"], "bad" if f["subdomain_count"] >= 2 else "ok")
        rows += frow("Raw IP as domain", "yes" if f["is_ip_domain"] else "no", "bad" if f["is_ip_domain"] else "ok")
        rows += frow("Special-char ratio", f'{f["special_char_ratio"]:.2f}', "bad" if f["special_char_ratio"] > .15 else "ok")
    elif i == 1:
        age = f["domain_age_days"]
        rows += frow("Domain age (days)", age, "bad" if 0 < age <= 30 else "ok" if age > 180 else "warn")
        rows += frow("SSL cert age (days)", f["ssl_age_days"], "neu")
        rows += frow("Registration (years)", f["registration_years"], "neu")
        if f.get("whois_fallback_used"):
            rows += frow("WHOIS hidden → SSL date used", "fallback §10", "warn")
    elif i == 2:
        rows += frow("Brand impersonation", "detected" if f["brand_mismatch"] else "none", "bad" if f["brand_mismatch"] else "ok")
        terms = ", ".join(f.get("_urgency_terms", [])[:4])
        rows += frow("Urgency language", f'{f["urgency_language_score"]:.2f}', "bad" if f["urgency_language_score"] >= .5 else "ok", note=terms)
        rows += frow("External-script ratio", f'{f["external_script_ratio"]:.2f}', "bad" if f["external_script_ratio"] >= .3 else "ok")
    else:
        rows += frow("UPI payment field", "yes" if f["upi_field_presence"] else "no", "bad" if f["upi_field_presence"] else "ok")
        terms = ", ".join(f.get("_subsidy_terms", [])[:4])
        rows += frow("Subsidy / refund bait", f'{f["subsidy_refund_language_score"]:.2f}', "bad" if f["subsidy_refund_language_score"] >= .5 else "ok", note=terms)
        rows += frow("Fake-government QR", f'{f["fake_gov_qr_score"]:.2f}', "bad" if f.get("fake_gov_qr_score", 0) >= .9 else "ok")
    st.markdown(f"""<div class="card"><div class="layer">
      <div class="lnum">{num}</div>
      <div style="flex:1"><div class="ltitle">Layer {int(num)} · {title}</div>
        <div class="lsub">{sub}</div>{rows}
        <div class="tscore">T{i+1} = {t:.3f}</div></div></div></div>""", unsafe_allow_html=True)


def render_verdict(rec):
    f = rec["features"]
    c = (rec["T1"] + rec["T2"]) / 2; s = (rec["T3"] + rec["T4"]) / 2
    a, b = st.columns([1, 1])
    with a:
        st.markdown('<div class="card"><div class="small">Surface vs behaviour</div>', unsafe_allow_html=True)
        fig = go.Figure()
        fig.add_bar(y=["C · looks legit", "S · behaves legit"], x=[c, s], orientation="h",
                    marker_color=["#2563eb", "#e11d48"], text=[f"{c:.2f}", f"{s:.2f}"], textposition="outside")
        fig.update_layout(height=150, xaxis_range=[0, 1.05], margin=dict(l=6, r=24, t=6, b=6),
                          paper_bgcolor="#ffffff", plot_bgcolor="#ffffff",
                          font=dict(color="#0f172a"))
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)
    with b:
        st.markdown('<div class="card"><div class="small">CSBI = 100 × max(0, C − S)</div>', unsafe_allow_html=True)
        st.plotly_chart(gauge(rec["CSBI"]), use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    reasons = "".join(f'<div class="reason">{r}</div>' for r in rec["top3_reasons"])
    st.markdown(f'<div class="card"><div class="small">Why — top signals (Module B)</div>{reasons}</div>', unsafe_allow_html=True)

    if rec.get("traditional_safe") and rec["risk_level"] != "LOW":
        st.markdown('<div class="card" style="border-left:4px solid var(--warn)">'
                    '⚠️ <b>A traditional URL checker would rate this SAFE</b> — valid HTTPS, clean address. '
                    'CSBI catches it from the behaviour instead.</div>', unsafe_allow_html=True)

    if rec.get("cluster_id", -1) != -1:
        st.markdown(f'<div class="card">🕸️ <b>Campaign (Module C):</b> '
                    f'<span class="tag">{rec["cluster_label"]}</span> — grouped with sites sharing '
                    f'hosting and page template.</div>', unsafe_allow_html=True)

    prev = rec.get("html_preview", "")
    if prev and prev != "(live page not stored)":
        with st.expander("View the captured page (what the layers analysed)"):
            st.markdown(f'<div class="preview">{prev.replace("<","&lt;").replace(">","&gt;")}</div>', unsafe_allow_html=True)


# =============================================================== APP ==========
st.markdown('<div class="brandbar"><span class="logo">🛡️</span>'
            '<span class="name">CSBI Safety Check</span></div>'
            '<div class="tagline">Catches scam sites that <b>look trustworthy but behave maliciously</b> — '
            'the ones a padlock icon won\'t save you from.</div>', unsafe_allow_html=True)

tab_scan, tab_camp, tab_about = st.tabs(["🔍  Check a site", "🕸️  Campaigns", "💡  How it works"])

with tab_scan:
    by_camp = {}
    for u, r in RECORDS.items():
        by_camp.setdefault(r["campaign_true"], []).append(u)
    order = ["Fake UPI Cashback", "Government Subsidy Scam", "Bank KYC Phishing", "Legitimate"]
    options = [u for camp in order for u in by_camp.get(camp, [])]
    labelfn = lambda u: f"{'🔴' if RECORDS[u]['ground_truth']=='scam' else '🟢'}  {u}"

    choice = st.selectbox("Choose a site to check", options, format_func=labelfn)
    run = st.button("🔍  Check this site", type="primary", use_container_width=True)

    with st.expander("Advanced — scan any live URL in real time"):
        typed = st.text_input("Live URL", placeholder="https://example.com", label_visibility="collapsed")
        run_live = st.button("Scan this URL live", use_container_width=True)

    if run:
        st.session_state.update(rec=RECORDS[choice], step=0, analyzing=True)
    elif run_live and typed.strip():
        try:
            with st.spinner("Live-scanning… WHOIS/SSL can take a few seconds"):
                st.session_state.update(rec=live_scan(typed.strip()), step=0, analyzing=True)
        except Exception as e:
            st.error(f"Live scan couldn't complete: {e}")
            st.session_state["analyzing"] = False

    rec = st.session_state.get("rec")
    if not rec:
        st.info("Pick a site and press **Check this site**. The four detection layers run one by one, "
                "then combine into the CSBI verdict.")
    else:
        render_header(rec)
        checks_row(rec["features"])
        step = st.session_state.get("step", 4)
        shown = min(step, 4) if st.session_state.get("analyzing") else 4
        for i in range(shown):
            render_layer(i, rec)
        st.markdown('<div id="csbi_anchor"></div>', unsafe_allow_html=True)
        if st.session_state.get("analyzing") and step < 4:
            st.markdown(f'<div class="small working">Running Layer {step+1}…</div>', unsafe_allow_html=True)
            scroll_to_anchor("csbi_anchor")     # follow the reveal downward, gradually
            time.sleep(1.4)
            st.session_state["step"] = step + 1
            st.rerun()
        else:
            st.session_state["analyzing"] = False
            render_verdict(rec)

with tab_camp:
    ev = CACHE["evaluation"]
    st.markdown("#### Scam campaigns, grouped by shared infrastructure")
    st.markdown("<span class='small'>Scammers mass-produce sites from one template on one host. DBSCAN "
                "groups them by fingerprint (hosting · IP block · nameserver · SSL · DOM structure) — so "
                "flagging one exposes the whole campaign.</span>", unsafe_allow_html=True)
    m = st.columns(4)
    m[0].metric("Campaigns", ev["n_clusters"]); m[1].metric("Sites", ev["n_total"])
    m[2].metric("Legit (noise)", ev["n_noise"]); m[3].metric("Silhouette", ev["silhouette_score"])

    import math, random
    random.seed(7)
    clusters = CACHE["clusters"]; real = [c for c in clusters if c["cluster_id"] != -1]
    pal = ["#e11d48", "#f59e0b", "#7c3aed", "#2563eb", "#16a34a"]
    fig = go.Figure()
    for i, cd in enumerate(real):
        cx, cy = math.cos(2*math.pi*i/max(len(real), 1)), math.sin(2*math.pi*i/max(len(real), 1))
        xs = [cx+random.uniform(-.17, .17) for _ in cd["members"]]; ys = [cy+random.uniform(-.17, .17) for _ in cd["members"]]
        fig.add_trace(go.Scatter(x=xs, y=ys, mode="markers", name=f"{cd['label']} ({len(cd['members'])})",
                      marker=dict(size=17, color=pal[i % len(pal)], line=dict(width=1, color="#fff")),
                      text=cd["members"], hoverinfo="text"))
    noise = next((c for c in clusters if c["cluster_id"] == -1), None)
    if noise:
        xs = [random.uniform(-.28, .28) for _ in noise["members"]]; ys = [random.uniform(-.28, .28) for _ in noise["members"]]
        fig.add_trace(go.Scatter(x=xs, y=ys, mode="markers", name=f"Legitimate ({len(noise['members'])})",
                      marker=dict(size=11, color="#94a3b8", symbol="circle-open"), text=noise["members"], hoverinfo="text"))
    fig.update_layout(height=430, xaxis=dict(visible=False), yaxis=dict(visible=False),
                      margin=dict(l=6, r=6, t=6, b=6), legend=dict(orientation="h", y=-0.05),
                      paper_bgcolor="#ffffff", plot_bgcolor="#ffffff",
                      font=dict(color="#0f172a"))
    st.plotly_chart(fig, use_container_width=True)
    for cd in real:
        with st.expander(f"🔴 {cd['label']} — {len(cd['members'])} sites · {cd['provider']}"):
            for u in cd["members"]:
                st.markdown(f"- <span class='tag'>{u}</span>", unsafe_allow_html=True)

with tab_about:
    st.markdown("""
#### The idea
Old scam detectors check the **suit**: bad URL, no HTTPS, junk domain. But scammers now host on free
platforms (Cloudflare, Google, `pages.dev`) that hand them valid HTTPS and a reputable domain. The suit
is perfect, so old detectors wave them through.

**CSBI checks whether the suit matches the pitch.**
- **C — surface credibility** (Layers 1+2): does it *look* legit?
- **S — behavioural substance** (Layers 3+4): does it *behave* legit?

Big gap → polished surface, malicious behaviour → the scam signal free hosting hides.
""")
    st.latex(r"\mathrm{CSBI} = 100 \times \max(0,\; C - S)")
    st.markdown("""
**Three modules, one shared record store:** **A** measures the site (four layers → CSBI) · **B** gives the
verdict and reasons · **C** groups related scams into campaigns.
""")
    st.caption("Layer scores and CSBI are computed by the real engine; clusters by real DBSCAN. The verdict "
               "is a rule-based stand-in until the trained model lands. Demonstration pages model reported "
               "UPI campaigns — live UPI scams are ephemeral and unsafe to redistribute; the live-scan box "
               "runs the real engine on any URL you enter.")
