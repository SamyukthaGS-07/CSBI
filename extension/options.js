const DEFAULTS = { apiBase: "http://localhost:8000", enabled: true, warnMedium: true };
const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(DEFAULTS, (s) => {
  $("apiBase").value = s.apiBase;
  $("enabled").checked = s.enabled;
  $("warnMedium").checked = s.warnMedium;
});

$("save").onclick = async () => {
  const apiBase = $("apiBase").value.trim().replace(/\/+$/, "") || DEFAULTS.apiBase;
  try {
    const origin = new URL(apiBase).origin + "/*";
    if (!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/\*$/.test(origin)) {
      const ok = await chrome.permissions.request({ origins: [origin] });
      if (!ok) { $("status").textContent = "Permission for that address was not granted."; return; }
    }
  } catch {
    $("status").textContent = "That is not a valid address."; return;
  }
  chrome.storage.sync.set({ apiBase, enabled: $("enabled").checked, warnMedium: $("warnMedium").checked },
    () => { $("status").textContent = "Saved."; });
};

$("test").onclick = async () => {
  const base = $("apiBase").value.trim().replace(/\/+$/, "") || DEFAULTS.apiBase;
  $("status").textContent = "Testing…";
  try {
    const r = await fetch(`${base}/health`);
    const h = await r.json();
    $("status").textContent = h.model ? `Connected — model ${h.model_version}, kit index ${h.kit_index ? "loaded" : "missing"}.`
      : "Connected, but no trained model is loaded (rule-based fallback).";
  } catch (e) {
    $("status").textContent = `Could not connect: ${e}`;
  }
};
