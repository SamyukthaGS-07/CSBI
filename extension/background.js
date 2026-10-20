// CSBI Phishing Shield — background service worker.
// Receives page snapshots from content.js, asks the CSBI API for a verdict,
// keeps one verdict per tab, and drives the toolbar badge.

const DEFAULTS = { apiBase: "http://localhost:8000", enabled: true, warnMedium: true };
const verdicts = new Map();          // tabId -> verdict
const redirectChains = new Map();    // tabId -> [hosts]

async function settings() {
  const s = await chrome.storage.sync.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

function hostOf(u) {
  try { return new URL(u).hostname; } catch { return ""; }
}

function badge(tabId, v) {
  const map = {
    HIGH: { text: "!", color: "#C62828" },
    MEDIUM: { text: "?", color: "#E08A00" },
    LOW: { text: "", color: "#2E7D32" },
    ERROR: { text: "·", color: "#757575" },
  };
  const b = map[v?.risk_level] || map.ERROR;
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

// Track the redirect chain of each top-level navigation (cross-site hops are a feature).
chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, frameId, url }) => {
  if (frameId === 0) redirectChains.set(tabId, [hostOf(url)]);
});
chrome.webNavigation.onCommitted.addListener(({ tabId, frameId, url, transitionQualifiers }) => {
  if (frameId !== 0) return;
  const chain = redirectChains.get(tabId) || [];
  if ((transitionQualifiers || []).includes("server_redirect") || (transitionQualifiers || []).includes("client_redirect")) {
    chain.push(hostOf(url));
  } else if (!chain.length) {
    chain.push(hostOf(url));
  }
  redirectChains.set(tabId, chain);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  verdicts.delete(tabId);
  redirectChains.delete(tabId);
});

async function scanPage(tabId, payload) {
  const s = await settings();
  if (!s.enabled) return null;
  const body = {
    url: payload.url,
    html: payload.html,
    final_url: payload.url,
    redirect_hosts: redirectChains.get(tabId) || [hostOf(payload.url)],
  };
  try {
    const r = await fetch(`${s.apiBase}/scan/page`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`API ${r.status}`);
    const v = await r.json();
    v.checkedAt = Date.now();
    verdicts.set(tabId, v);
    badge(tabId, v);
    return v;
  } catch (e) {
    const v = { risk_level: "ERROR", error: String(e), url: payload.url };
    verdicts.set(tabId, v);
    badge(tabId, v);
    return v;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "page" && sender.tab) {
    scanPage(sender.tab.id, msg).then(async (v) => {
      const s = await settings();
      sendResponse({ verdict: v, warnMedium: s.warnMedium });
    });
    return true; // async response
  }
  if (msg.type === "getVerdict") {
    sendResponse(verdicts.get(msg.tabId) || null);
    return false;
  }
  if (msg.type === "rescan") {
    chrome.tabs.sendMessage(msg.tabId, { type: "resend" });
    sendResponse(true);
    return false;
  }
  return false;
});
