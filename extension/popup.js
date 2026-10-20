// Popup: shows the verdict for the current tab.

function el(tag, attrs = {}, children = []) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") e.textContent = v;
    else if (k === "style") e.style.cssText = v;
    else e.setAttribute(k, v);
  }
  children.forEach((c) => c && e.appendChild(c));
  return e;
}

function bar(label, value, color, max = 1) {
  const v = Math.max(0, Math.min(max, Number(value) || 0));
  return [
    el("span", { text: label }),
    el("div", { class: "track" }, [el("div", { class: "fill", style: `width:${(100 * v) / max}%;background:${color}` })]),
    el("span", { class: "num", text: max === 1 ? v.toFixed(2) : String(Math.round(v)) }),
  ];
}

function render(v, tabUrl) {
  const root = document.getElementById("root");
  root.replaceChildren();
  let host = "";
  try { host = new URL(tabUrl).hostname; } catch {}
  if (!v) {
    root.append(el("p", { class: "muted", text: /^https?:/.test(tabUrl || "") ? "No verdict yet — try Re-check." : "Nothing to check on this page." }));
    return;
  }
  if (v.risk_level === "ERROR") {
    root.append(el("p", { class: "err", text: "Could not reach the CSBI API." }),
      el("p", { class: "muted", text: "Start it with:  uvicorn backend.main:app --port 8000  (or change the address in Settings)." }));
    return;
  }
  const label = { HIGH: "Likely phishing", MEDIUM: "Suspicious", LOW: "Looks safe" }[v.risk_level] || v.risk_level;
  root.append(
    el("div", { class: "verdict" }, [
      el("span", { class: `level ${v.risk_level}`, text: label }),
      el("span", { class: "prob", text: `${Math.round((v.scam_probability || 0) * 100)}% phishing` }),
    ]),
    el("div", { class: "host", text: host }),
  );
  if (v.allowlisted) {
    root.append(el("p", { class: "muted", text: "Well-known popular site — not analysed." }));
    return;
  }
  root.append(el("h2", { text: "Why" }), el("ul", {}, (v.reasons || []).map((r) => el("li", { text: r }))));

  const s = v.scores || {};
  root.append(el("h2", { text: "Trust it shows vs trust it earned" }));
  root.append(el("div", { class: "bars" }, [
    ...bar("Apparent", s.C_apparent, "var(--borrowed)"),
    ...bar("Earned", s.C_earned, "var(--earned)"),
    ...bar("Behaviour", Math.min(s.T3 ?? 1, s.T4 ?? 1, s.T5 ?? 1), "#7A7A80"),
    ...bar("CSBI-PA", s.CSBI_PA, (s.CSBI_PA || 0) >= 50 ? "var(--high)" : "var(--med)", 100),
  ]));
  if (v.free_hosted && (s.borrowed_credibility || 0) > 0.2) {
    root.append(el("div", { class: "note",
      text: `Hosted on ${v.platform || "a free platform"}: the padlock and domain age belong to the platform, so they say nothing about this page.` }));
  }
  if (v.campaign) {
    root.append(el("div", { class: "campaign", text: `Known campaign: ${v.campaign}` }));
  }
}

async function main() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  const load = () => chrome.runtime.sendMessage({ type: "getVerdict", tabId: tab.id }, (v) => render(v, tab.url));
  load();
  document.getElementById("rescan").onclick = () => {
    document.getElementById("root").replaceChildren(el("p", { class: "muted", text: "Checking this page…" }));
    chrome.runtime.sendMessage({ type: "rescan", tabId: tab.id });
    setTimeout(load, 2500);
  };
}
main();
