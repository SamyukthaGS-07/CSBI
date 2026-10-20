// CSBI Phishing Shield — content script.
// Sends the rendered page to the background worker, then shows a warning
// interstitial (HIGH) or a banner (MEDIUM). On HIGH-risk pages it also guards
// credential fields: typing into a password / OTP / card field asks first.

(() => {
  if (window.top !== window) return;               // top frame only
  const MAX_HTML = 2_500_000;
  let verdict = null;
  let guardArmed = false;
  let userDismissed = false;

  function snapshot() {
    let html = document.documentElement ? document.documentElement.outerHTML : "";
    if (html.length > MAX_HTML) html = html.slice(0, MAX_HTML);
    return { type: "page", url: location.href, html };
  }

  function send() {
    chrome.runtime.sendMessage(snapshot(), (res) => {
      if (chrome.runtime.lastError || !res) return;
      verdict = res.verdict;
      if (!verdict || userDismissed) return;
      if (verdict.risk_level === "HIGH") {
        showInterstitial(verdict);
        armGuard();
      } else if (verdict.risk_level === "MEDIUM" && res.warnMedium) {
        showBanner(verdict);
      }
    });
  }

  function el(tag, attrs = {}, children = []) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "text") e.textContent = v;
      else e.setAttribute(k, v);
    }
    children.forEach((c) => e.appendChild(c));
    return e;
  }

  function reasonsList(v) {
    return el("ul", { class: "csbi-reasons" }, (v.reasons || []).map((r) => el("li", { text: r })));
  }

  function showInterstitial(v) {
    if (document.getElementById("csbi-overlay")) return;
    const pct = Math.round((v.scam_probability || 0) * 100);
    const host = location.hostname;
    const box = el("div", { class: "csbi-box", role: "alertdialog", "aria-labelledby": "csbi-title" }, [
      el("div", { class: "csbi-icon", text: "⚠" }),
      el("h1", { id: "csbi-title", text: "This page looks like phishing" }),
      el("p", { class: "csbi-host", text: host }),
      el("p", { class: "csbi-lead",
        text: `CSBI rates this page ${pct}% likely to be phishing. Do not enter passwords, OTPs, card details or UPI PINs here.` }),
      reasonsList(v),
    ]);
    if (v.free_hosted && v.scores && v.scores.borrowed_credibility > 0.2) {
      box.appendChild(el("p", { class: "csbi-note",
        text: `The padlock and domain age you see belong to ${v.platform || "the hosting platform"}, not to whoever published this page.` }));
    }
    if (v.campaign) {
      box.appendChild(el("p", { class: "csbi-note", text: `Matches a known phishing campaign: ${v.campaign}` }));
    }
    const back = el("button", { class: "csbi-btn csbi-primary", text: "Go back to safety" });
    back.onclick = () => { history.length > 1 ? history.back() : (location.href = "about:blank"); };
    const stay = el("button", { class: "csbi-btn csbi-link", text: "I understand the risk, continue" });
    stay.onclick = () => { userDismissed = true; overlay.remove(); };
    box.appendChild(el("div", { class: "csbi-actions" }, [back, stay]));
    const overlay = el("div", { id: "csbi-overlay" }, [box]);
    document.documentElement.appendChild(overlay);
    back.focus();
  }

  function showBanner(v) {
    if (document.getElementById("csbi-banner")) return;
    const close = el("button", { class: "csbi-x", "aria-label": "Dismiss", text: "×" });
    const bar = el("div", { id: "csbi-banner", role: "status" }, [
      el("strong", { text: "Be careful: " }),
      el("span", { text: (v.reasons && v.reasons[0]) || "This page shows some phishing signals." }),
      close,
    ]);
    close.onclick = () => bar.remove();
    document.documentElement.appendChild(bar);
  }

  // Credential guard: on HIGH pages, intercept the first keystroke into a
  // sensitive field and confirm before letting the user type.
  function sensitive(t) {
    if (!(t instanceof HTMLInputElement)) return false;
    const a = `${t.type} ${t.name} ${t.id} ${t.autocomplete} ${t.placeholder}`.toLowerCase();
    return t.type === "password" || /otp|pin|cvv|cvc|card|upi|vpa|passcode|seed|mnemonic/.test(a);
  }
  function armGuard() {
    if (guardArmed) return;
    guardArmed = true;
    let allowed = false;
    document.addEventListener("keydown", (e) => {
      if (allowed || !verdict || verdict.risk_level !== "HIGH" || !sensitive(e.target)) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      allowed = window.confirm(
        "CSBI Phishing Shield\n\nThis page was flagged as likely phishing. " +
        "Anything you type here may be sent to scammers.\n\nType into this field anyway?");
    }, true);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "resend") { userDismissed = false; send(); }
  });

  send();
  // Single-page apps and kits that render the form late: re-check once after
  // the DOM settles if a credential field appears that was not there before.
  const hadPwd = !!document.querySelector("input[type=password]");
  setTimeout(() => {
    if (!hadPwd && document.querySelector("input[type=password]")) send();
  }, 3000);
})();
