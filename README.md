<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard — Phishing Email Analysis</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;1,8..60,500&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root{
    --paper:#E7E3D8;
    --ink:#211F1B;
    --line:#B9B2A0;
    --accent:#A32B1F;
    --safe:#2F6844;
    --amber:#B9720A;
    --paper-raised:#EFEBE0;
  }
  *{box-sizing:border-box;}
  html,body{margin:0;padding:0;}
  body{
    background:var(--paper);
    color:var(--ink);
    font-family:'IBM Plex Mono', monospace;
    line-height:1.5;
    -webkit-font-smoothing:antialiased;
  }
  ::selection{background:var(--ink);color:var(--paper);}

  a{color:inherit;}

  .wrap{
    max-width:1040px;
    margin:0 auto;
    padding:48px 28px 80px;
  }

  header{
    border-bottom:1px solid var(--line);
    padding-bottom:28px;
    margin-bottom:36px;
    display:flex;
    justify-content:space-between;
    align-items:flex-end;
    flex-wrap:wrap;
    gap:16px;
  }
  header .title{
    font-family:'Source Serif 4', serif;
    font-weight:600;
    font-size:42px;
    letter-spacing:-0.01em;
  }
  header .title em{
    font-style:italic;
    font-weight:500;
    color:var(--accent);
  }
  header .tagline{
    max-width:320px;
    font-size:13px;
    color:#54514A;
    text-align:right;
  }

  .grid{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:0;
    border:1px solid var(--line);
  }
  @media (max-width:820px){
    .grid{grid-template-columns:1fr;}
  }

  .panel{
    padding:32px;
  }
  .panel + .panel{
    border-left:1px solid var(--line);
  }
  @media (max-width:820px){
    .panel + .panel{border-left:none;border-top:1px solid var(--line);}
  }

  .panel-label{
    font-size:11px;
    letter-spacing:0.04em;
    color:#7A7568;
    margin-bottom:18px;
  }

  label{
    display:block;
    font-size:12px;
    color:#54514A;
    margin-bottom:6px;
    margin-top:18px;
  }
  label:first-of-type{margin-top:0;}

  input[type=text], textarea{
    width:100%;
    background:var(--paper-raised);
    border:1px solid var(--line);
    color:var(--ink);
    font-family:'IBM Plex Mono', monospace;
    font-size:13px;
    padding:10px 12px;
    resize:vertical;
  }
  input[type=text]:focus, textarea:focus{
    outline:2px solid var(--ink);
    outline-offset:-1px;
  }
  textarea{min-height:120px;}

  .field-hint{font-size:11px;color:#8A8578;margin-top:4px;}

  .actions{
    margin-top:26px;
    display:flex;
    gap:10px;
    flex-wrap:wrap;
  }

  button{
    font-family:'IBM Plex Mono', monospace;
    font-size:13px;
    border:1px solid var(--ink);
    background:var(--ink);
    color:var(--paper);
    padding:11px 20px;
    cursor:pointer;
    transition:transform 0.08s ease, background 0.15s ease;
  }
  button:hover{background:#3A362F;}
  button:active{transform:translateY(1px);}

  button.secondary{
    background:transparent;
    color:var(--ink);
  }
  button.secondary:hover{background:rgba(0,0,0,0.05);}

  /* --- Report panel --- */
  .report-empty{
    color:#8A8578;
    font-size:13px;
    border:1px dashed var(--line);
    padding:24px;
    text-align:center;
  }

  .score-row{
    display:flex;
    align-items:baseline;
    gap:14px;
    margin-bottom:6px;
  }
  .score-num{
    font-family:'Source Serif 4', serif;
    font-weight:600;
    font-size:56px;
    line-height:1;
  }
  .score-den{
    font-size:14px;
    color:#7A7568;
  }

  .meter{
    height:6px;
    background:var(--line);
    margin:14px 0 18px;
    position:relative;
    overflow:hidden;
  }
  .meter-fill{
    height:100%;
    width:0%;
    transition:width 0.5s ease;
  }

  .stamp{
    display:inline-block;
    border:2px solid currentColor;
    padding:6px 16px;
    font-size:13px;
    letter-spacing:0.06em;
    transform:rotate(-3deg);
    margin-bottom:22px;
  }

  .flags-title{
    font-size:12px;
    color:#54514A;
    border-top:1px solid var(--line);
    padding-top:16px;
    margin-bottom:12px;
  }

  .flag{
    border-left:2px solid var(--line);
    padding:8px 0 8px 12px;
    margin-bottom:10px;
    font-size:12.5px;
  }
  .flag .cat{
    color:#7A7568;
    font-size:10.5px;
    display:block;
    margin-bottom:2px;
  }
  .flag .weight{
    color:var(--accent);
  }

  .no-flags{
    font-size:13px;
    color:var(--safe);
    border-left:2px solid var(--safe);
    padding-left:12px;
  }

  footer{
    margin-top:28px;
    font-size:11px;
    color:#8A8578;
    text-align:center;
  }
</style>
</head>
<body>

<div class="wrap">

  <header>
    <div class="title">Phish<em>Guard</em></div>
    <div class="tagline">Paste in a suspicious email and get a heuristic read on how likely it is to be phishing.</div>
  </header>

  <div class="grid">

    <!-- INPUT PANEL -->
    <div class="panel">
      <div class="panel-label">— email under review</div>

      <label for="sender">From header</label>
      <input type="text" id="sender" placeholder='"PayPal Security" &lt;alert@paypa1-support.xyz&gt;'>

      <label for="subject">Subject line</label>
      <input type="text" id="subject" placeholder="Urgent: verify your account">

      <label for="body">Body (HTML or plain text)</label>
      <textarea id="body" placeholder="Paste the email body here. HTML anchor tags are supported for link-mismatch detection."></textarea>
      <div class="field-hint">Tip: include &lt;a href="..."&gt;visible text&lt;/a&gt; tags to test link-mismatch detection.</div>

      <label for="links">Links found in email (one per line)</label>
      <textarea id="links" style="min-height:60px" placeholder="http://192.168.1.4/login&#10;https://bit.ly/3xample"></textarea>

      <label for="attachments">Attachment filenames (one per line)</label>
      <textarea id="attachments" style="min-height:52px" placeholder="invoice.docm"></textarea>

      <div class="actions">
        <button id="scanBtn">Scan email</button>
        <button class="secondary" id="sampleBtn" type="button">Load phishing sample</button>
        <button class="secondary" id="cleanBtn" type="button">Load clean sample</button>
      </div>
    </div>

    <!-- REPORT PANEL -->
    <div class="panel">
      <div class="panel-label">— scan report</div>
      <div id="report">
        <div class="report-empty">Run a scan to see the risk breakdown here.</div>
      </div>
    </div>

  </div>

  <footer>Rule-based heuristics only — not a substitute for email security infrastructure (SPF / DKIM / DMARC).</footer>
</div>

<script>
// ---------------------------------------------------------------
// PhishGuard detection engine (JS port of the Python / Java version)
// ---------------------------------------------------------------

const URGENCY_WORDS = [
  "urgent", "immediately", "verify your account", "act now", "suspended",
  "unauthorized access", "click here", "limited time", "final notice",
  "your account will be closed", "confirm your identity", "password expires",
  "unusual activity", "security alert", "restricted", "reactivate"
];

const FINANCIAL_WORDS = [
  "bank account", "credit card", "ssn", "social security", "payment failed",
  "invoice attached", "wire transfer", "gift card", "refund", "tax refund",
  "billing information"
];

const GENERIC_GREETINGS = [
  "dear customer", "dear user", "dear valued customer", "dear account holder",
  "dear sir/madam", "hello user"
];

const SUSPICIOUS_SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"
];

const COMMONLY_SPOOFED_BRANDS = [
  "paypal", "amazon", "apple", "microsoft", "google", "netflix",
  "bankofamerica", "chase", "wellsfargo", "irs", "dhl", "fedex",
  "linkedin", "facebook"
];

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".zip", ".click", ".gq", ".tk", ".ml", ".cf", ".work", ".loan"
];

const SUSPICIOUS_ATTACHMENT_EXTS = [
  ".exe", ".scr", ".js", ".vbs", ".bat", ".jar", ".hta", ".docm", ".xlsm"
];

function hostOf(url) {
  try { return new URL(url).host.toLowerCase(); }
  catch (e) { return ""; }
}

function scanEmail({ sender, subject, body, links, attachments }) {
  const flags = [];
  const add = (reason, weight, category) => flags.push({ reason, weight, category });

  const text = `${subject || ""}\n${body || ""}`.toLowerCase();

  // Urgency language
  const urgencyHits = URGENCY_WORDS.filter(w => text.includes(w));
  if (urgencyHits.length) {
    add(`Urgency/pressure language found: ${urgencyHits.slice(0, 3).join(", ")}`,
        Math.min(8 * urgencyHits.length, 25), "Language");
  }

  // Financial bait
  const financialHits = FINANCIAL_WORDS.filter(w => text.includes(w));
  if (financialHits.length) {
    add(`Financial/sensitive-data bait found: ${financialHits.slice(0, 3).join(", ")}`,
        Math.min(7 * financialHits.length, 20), "Language");
  }

  // Generic greeting
  if (GENERIC_GREETINGS.some(g => text.includes(g))) {
    add("Generic greeting instead of personalized name", 8, "Language");
  }

  // Sender spoofing
  if (sender) {
    const m = sender.match(/"?([^"<]*)"?\s*<([^>]+)>/);
    const displayName = (m ? m[1] : sender).trim().toLowerCase();
    const emailAddr = (m ? m[2] : sender).trim().toLowerCase();
    const domain = emailAddr.includes("@") ? emailAddr.split("@").pop() : "";

    const spoofedBrand = COMMONLY_SPOOFED_BRANDS.find(
      b => displayName.includes(b) && !domain.includes(b)
    );
    if (spoofedBrand) {
      add(`Display name mentions '${spoofedBrand}' but sending domain ('${domain}') doesn't match`,
          25, "Sender");
    }

    const domainPrefix = domain.includes(".") ? domain.split(".")[0] : domain;
    const hasDigit = /\d/.test(domainPrefix);
    const mentionsBrand = COMMONLY_SPOOFED_BRANDS.some(b => domain.includes(b));
    if (hasDigit && mentionsBrand) {
      add(`Sending domain '${domain}' contains digits mimicking a brand name`, 15, "Sender");
    }

    if (SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld))) {
      add(`Sender domain uses a high-risk TLD ('${domain}')`, 10, "Sender");
    }
  }

  // Links
  (links || []).forEach(link => {
    const host = hostOf(link);
    if (!host) return;

    if (SUSPICIOUS_SHORTENERS.some(s => host.includes(s))) {
      add(`Shortened URL hides real destination: ${link}`, 15, "Links");
    }
    if (SUSPICIOUS_TLDS.some(tld => host.endsWith(tld))) {
      add(`Link points to high-risk TLD domain: ${host}`, 12, "Links");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      add(`Link uses a raw IP address instead of a domain: ${host}`, 20, "Links");
    }
    const brand = COMMONLY_SPOOFED_BRANDS.find(b => text.includes(b) && !host.includes(b));
    if (brand) {
      add(`Email mentions '${brand}' but link goes to unrelated domain '${host}'`, 18, "Links");
    }
  });

  // Mismatched anchor text vs href
  if (body) {
    const anchorRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let am;
    while ((am = anchorRe.exec(body)) !== null) {
      const href = am[1];
      const visible = am[2].replace(/<[^>]+>/g, "").trim().toLowerCase();
      if (visible.startsWith("http") || visible.includes(".")) {
        const realDomain = hostOf(href);
        const shownDomain = visible.replace("http://", "").replace("https://", "").split("/")[0];
        if (shownDomain && realDomain && !shownDomain.includes(realDomain) && !realDomain.includes(shownDomain)) {
          add(`Displayed link text '${shownDomain}' does not match actual destination '${realDomain}'`,
              25, "Links");
        }
      }
    }
  }

  // Attachments
  (attachments || []).forEach(att => {
    const lower = att.toLowerCase();
    if (SUSPICIOUS_ATTACHMENT_EXTS.some(ext => lower.endsWith(ext))) {
      add(`Potentially dangerous attachment type: ${att}`, 20, "Attachments");
    }
  });

  const score = Math.min(flags.reduce((sum, f) => sum + f.weight, 0), 100);
  let riskLevel, color;
  if (score >= 60) { riskLevel = "HIGH RISK"; color = "var(--accent)"; }
  else if (score >= 30) { riskLevel = "MEDIUM RISK"; color = "var(--amber)"; }
  else if (score > 0) { riskLevel = "LOW RISK"; color = "var(--amber)"; }
  else { riskLevel = "CLEAN"; color = "var(--safe)"; }

  return { score, riskLevel, color, flags };
}

// ---------------------------------------------------------------
// UI wiring
// ---------------------------------------------------------------

function renderReport(result) {
  const el = document.getElementById("report");
  const flagsHtml = result.flags.length
    ? result.flags.map(f => `
        <div class="flag" style="border-color:${f.category === 'Sender' ? 'var(--accent)' : 'var(--line)'}">
          <span class="cat">${f.category}</span>
          <span class="weight">+${f.weight}</span> ${f.reason}
        </div>`).join("")
    : `<div class="no-flags">No red flags detected.</div>`;

  el.innerHTML = `
    <div class="score-row">
      <div class="score-num" style="color:${result.color}">${result.score}</div>
      <div class="score-den">/ 100</div>
    </div>
    <div class="meter"><div class="meter-fill" style="width:${result.score}%;background:${result.color}"></div></div>
    <div class="stamp" style="color:${result.color}">${result.riskLevel}</div>
    <div class="flags-title">— ${result.flags.length} flag${result.flags.length === 1 ? "" : "s"} raised</div>
    ${flagsHtml}
  `;
}

function currentInput() {
  return {
    sender: document.getElementById("sender").value,
    subject: document.getElementById("subject").value,
    body: document.getElementById("body").value,
    links: document.getElementById("links").value.split("\n").map(s => s.trim()).filter(Boolean),
    attachments: document.getElementById("attachments").value.split("\n").map(s => s.trim()).filter(Boolean),
  };
}

document.getElementById("scanBtn").addEventListener("click", () => {
  const result = scanEmail(currentInput());
  renderReport(result);
});

document.getElementById("sampleBtn").addEventListener("click", () => {
  document.getElementById("sender").value = '"PayPal Security" <alert@paypa1-support.xyz>';
  document.getElementById("subject").value = "URGENT: Your account will be suspended";
  document.getElementById("body").value =
`Dear valued customer,

We noticed unusual activity on your account. You must verify your identity immediately or your account will be suspended within 24 hours.

<a href="http://192.168.55.21/login">https://paypal.com/verify</a>

Please confirm your billing information and password to avoid interruption of service.`;
  document.getElementById("links").value = "http://192.168.55.21/login\nhttps://bit.ly/3xAmpLe";
  document.getElementById("attachments").value = "invoice_details.docm";
});

document.getElementById("cleanBtn").addEventListener("click", () => {
  document.getElementById("sender").value = '"Priya Shah" <priya.shah@your-company.com>';
  document.getElementById("subject").value = "Notes from today's planning meeting";
  document.getElementById("body").value =
`Hi team,

Attaching my notes from this afternoon's sprint planning. Let me know if I missed anything before I share it with the wider group tomorrow.

Thanks,
Priya`;
  document.getElementById("links").value = "";
  document.getElementById("attachments").value = "sprint_notes.pdf";
});
</script>

</body>
</html>
