/**
 * scanner.js — VulnRadar Frontend Logic
 * Handles scan initiation, progress simulation, result rendering,
 * filtering, and report download.
 */

"use strict";

// ── State ──────────────────────────────────────────────────────────────────
let allFindings = [];
let activeFilter = "all";

// ── URL validation ─────────────────────────────────────────────────────────
const urlInput    = document.getElementById("target-url");
const urlIndicator = document.getElementById("url-indicator");

urlInput.addEventListener("input", () => {
  const val = urlInput.value.trim();
  try {
    new URL(val);
    urlIndicator.className = "url-indicator valid";
  } catch {
    urlIndicator.className = val ? "url-indicator invalid" : "url-indicator";
  }
});

// Quick target setter
function setUrl(url) {
  urlInput.value = url;
  urlInput.dispatchEvent(new Event("input"));
}

// ── Logging ────────────────────────────────────────────────────────────────
function log(message, type = "info") {
  const logEl = document.getElementById("log-output");
  const line  = document.createElement("div");
  line.className = `log-line log-${type}`;

  const ts = new Date().toLocaleTimeString("en-GB", { hour12: false });
  line.textContent = `[${ts}] ${message}`;

  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

// ── Progress helpers ────────────────────────────────────────────────────────
const STEPS = ["step-crawl", "step-sqli", "step-xss", "step-auth", "step-traversal", "step-report"];
const STEP_LABELS = [
  "Crawling forms…",
  "Testing SQL Injection…",
  "Testing XSS…",
  "Testing Authentication…",
  "Testing Directory Traversal…",
  "Generating report…",
];
const STEP_PCT = [10, 30, 50, 68, 84, 95];

function setProgress(stepIndex) {
  STEPS.forEach((id, i) => {
    const el = document.getElementById(id);
    if (i < stepIndex)       el.className = "scan-step done";
    else if (i === stepIndex) el.className = "scan-step active";
    else                      el.className = "scan-step";
  });

  const pct = STEP_PCT[stepIndex] ?? 100;
  document.getElementById("progress-bar").style.width = pct + "%";
  document.getElementById("progress-pct").textContent  = pct + "%";
  document.getElementById("progress-label").textContent = STEP_LABELS[stepIndex] ?? "Finishing…";
}

function completeProgress() {
  STEPS.forEach(id => document.getElementById(id).className = "scan-step done");
  document.getElementById("progress-bar").style.width = "100%";
  document.getElementById("progress-pct").textContent  = "100%";
  document.getElementById("progress-label").textContent = "Scan complete!";
}

// Fake progress ticker that advances while we wait for the real result
function startProgressTicker() {
  let step = 0;
  setProgress(0);

  return setInterval(() => {
    if (step < STEPS.length - 1) {
      step++;
      setProgress(step);
      const labels = ["Crawling forms", "Testing SQL Injection", "Testing XSS", "Testing Auth", "Testing Directory Traversal"];
      if (labels[step - 1]) log(labels[step - 1] + "…", "step");
    }
  }, 2200); // advance roughly every 2.2 s
}

// ── Main scan function ─────────────────────────────────────────────────────
async function startScan() {
  const url = urlInput.value.trim();
  if (!url) {
    log("Please enter a target URL.", "error");
    return;
  }

  try { new URL(url); } catch {
    log("Invalid URL format. Example: http://localhost:3000", "error");
    return;
  }

  // UI state: scanning
  const scanBtn = document.getElementById("scan-btn");
  scanBtn.disabled = true;
  scanBtn.querySelector(".scan-btn-text").textContent = "Scanning";
  scanBtn.classList.add("scanning");

  document.getElementById("report-btn").style.display = "none";
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("results-container").style.display = "none";
  document.getElementById("progress-section").style.display = "block";
  document.getElementById("stats-panel").style.display = "none";

  allFindings = [];
  document.getElementById("findings-list").innerHTML = "";
  document.getElementById("log-output").innerHTML = "";

  log(`Scan started → ${url}`, "success");
  log("Connecting to target…", "info");

  const ticker = startProgressTicker();

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        modules: {
          sqli: document.getElementById("module-sqli").checked,
          xss: document.getElementById("module-xss").checked,
          traversal: document.getElementById("module-traversal").checked,
          auth: document.getElementById("module-auth").checked,
        },
      }),
    });

    clearInterval(ticker);

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || "Server error");
    }

    const data = await response.json();
    allFindings = data.findings || [];

    completeProgress();
    log(`Scan complete — ${allFindings.length} finding(s) detected.`, "success");

    renderStats(allFindings);
    renderFindings(allFindings, activeFilter);

    document.getElementById("results-container").style.display = "flex";
    document.getElementById("stats-panel").style.display = "block";

    document.getElementById("report-btn").style.display = "flex";
    log("HTML report ready for download.", "info");

  } catch (err) {
    clearInterval(ticker);
    log(`Error: ${err.message}`, "error");
    document.getElementById("empty-state").style.display = "flex";
    document.getElementById("progress-section").style.display = "none";
  } finally {
    // Restore button
    scanBtn.disabled = false;
    scanBtn.querySelector(".scan-btn-text").textContent = "Launch Scan";
    scanBtn.classList.remove("scanning");
  }
}

// ── Network scanning ──────────────────────────────────────────────────────
async function startNetworkScan(scanType) {
  const target = document.getElementById("network-target").value.trim();
  if (!target) {
    log("Please enter an authorised IP address or hostname.", "error");
    return;
  }

  const halfBtn = document.getElementById("half-open-btn");
  const aggressiveBtn = document.getElementById("aggressive-btn");
  halfBtn.disabled = true;
  aggressiveBtn.disabled = true;

  prepareResultsArea();
  const label = scanType === "half_open" ? "Half-Open Scan" : "Aggressive Scan";
  log(`${label} started → ${target}`, "success");

  try {
    const response = await fetch("/network-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, scan_type: scanType }),
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Network scan failed");

    allFindings = data.findings || [];
    log(`${label} complete — ${allFindings.length} network finding(s).`, "success");
    if (data.result) renderNetworkDetails(data.result);
    showFindings(allFindings);
  } catch (err) {
    log(`Network scan error: ${err.message}`, "error");
    document.getElementById("empty-state").style.display = "flex";
  } finally {
    halfBtn.disabled = false;
    aggressiveBtn.disabled = false;
  }
}

// ── HTTP log analysis ─────────────────────────────────────────────────────
async function startLogAnalysis() {
  const fileInput = document.getElementById("log-file");
  const logText = document.getElementById("log-text").value.trim();
  const button = document.getElementById("log-analyze-btn");

  if (!fileInput.files.length && !logText) {
    log("Paste HTTP log text or upload a log file.", "error");
    return;
  }

  button.disabled = true;
  prepareResultsArea();
  log("HTTP log analysis started.", "success");

  try {
    const options = { method: "POST" };
    if (fileInput.files.length) {
      const body = new FormData();
      body.append("log_file", fileInput.files[0]);
      options.body = body;
    } else {
      options.headers = { "Content-Type": "application/json" };
      options.body = JSON.stringify({ log_text: logText });
    }

    const response = await fetch("/analyze-logs", options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Log analysis failed");

    allFindings = data.findings || [];
    log(`HTTP log analysis complete — ${allFindings.length} suspicious request(s).`, "success");
    showFindings(allFindings);
  } catch (err) {
    log(`Log analysis error: ${err.message}`, "error");
    document.getElementById("empty-state").style.display = "flex";
  } finally {
    button.disabled = false;
  }
}

function prepareResultsArea() {
  document.getElementById("report-btn").style.display = "none";
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("results-container").style.display = "none";
  document.getElementById("progress-section").style.display = "none";
  document.getElementById("stats-panel").style.display = "none";
  document.getElementById("findings-list").innerHTML = "";
  allFindings = [];
}

function showFindings(findings) {
  renderStats(findings);
  renderFindings(findings, activeFilter);
  document.getElementById("results-container").style.display = "flex";
  document.getElementById("stats-panel").style.display = "block";
  document.getElementById("report-btn").style.display = "flex";
  log("HTML report ready for download.", "info");
}

function renderNetworkDetails(result) {
  const hosts = result.hosts || [];
  hosts.forEach(host => {
    const openPorts = (host.ports || []).filter(p => p.state === "open");
    if (openPorts.length) {
      const summary = openPorts.map(p => `${p.port}/${p.protocol} ${p.service || "unknown"}`).join(", ");
      log(`Open ports on ${host.host}: ${summary}`, "step");
    } else {
      log(`No open ports returned for ${host.host}.`, "info");
    }
  });
}

// ── Stats ──────────────────────────────────────────────────────────────────
function renderStats(findings) {
  const counts = { High: 0, Medium: 0, Low: 0 };
  findings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  document.getElementById("stat-high").textContent   = counts.High;
  document.getElementById("stat-medium").textContent = counts.Medium;
  document.getElementById("stat-low").textContent    = counts.Low;
  document.getElementById("stat-total").textContent  = findings.length;
}

// ── Results rendering ──────────────────────────────────────────────────────
function renderFindings(findings, filter) {
  const list = document.getElementById("findings-list");
  list.innerHTML = "";

  const filtered = filter === "all"
    ? findings
    : findings.filter(f => f.severity === filter);

  if (filtered.length === 0) {
    list.innerHTML = `<div class="no-findings-msg">
      ${filter === "all"
        ? "✅ No vulnerabilities detected. The target may be well-protected (or not vulnerable to the tested payloads)."
        : `No ${filter} severity findings.`}
    </div>`;
    return;
  }

  // Sort: High → Medium → Low
  const ORDER = { High: 0, Medium: 1, Low: 2, Info: 3 };
  filtered
    .sort((a, b) => (ORDER[a.severity] ?? 4) - (ORDER[b.severity] ?? 4))
    .forEach((f, i) => {
      const card = buildFindingCard(f, i + 1);
      list.appendChild(card);
    });
}

function buildFindingCard(finding, num) {
  const severity = finding.severity || "Info";
  const sevClass = severity.toLowerCase();
  const source = finding.source || "Web Scanner";
  const targetUrl = finding.url || finding.target || "—";

  const card = document.createElement("div");
  card.className = `finding-card sev-${sevClass}`;
  card.dataset.severity = severity;

  // Truncate URL for display
  const displayUrl = targetUrl.length > 60
    ? targetUrl.slice(0, 57) + "…"
    : targetUrl;

  card.innerHTML = `
    <div class="finding-top" onclick="toggleCard(this)">
      <span class="sev-pill ${sevClass}">${escHtml(severity)}</span>
      <div>
        <div class="finding-name">${escHtml(finding.type)}</div>
        <div class="finding-url">${escHtml(source)} · ${escHtml(displayUrl)}</div>
      </div>
      <span class="expand-icon">▶</span>
    </div>
    <div class="finding-body">
      <div class="detail-row">
        <span class="detail-key">Source</span>
        <span class="detail-val">${escHtml(source)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-key">Target</span>
        <span class="detail-val">${escHtml(targetUrl)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-key">Field</span>
        <span class="detail-val">${escHtml(finding.field || "—")}</span>
      </div>
      <div class="detail-row">
        <span class="detail-key">Payload</span>
        <span class="detail-val"><code>${escHtml(finding.payload || "—")}</code></span>
      </div>
      <div class="detail-row">
        <span class="detail-key">Evidence</span>
        <span class="detail-val">${escHtml(finding.evidence || "—")}</span>
      </div>
      <div class="detail-row">
        <span class="detail-key">Impact</span>
        <span class="detail-val">${escHtml(finding.impact || "—")}</span>
      </div>
      <div class="detail-row">
        <span class="detail-key">Mitigation</span>
        <span class="detail-val fix-val">${escHtml(finding.mitigation || finding.fix || "—")}</span>
      </div>
    </div>`;

  return card;
}

function toggleCard(headerEl) {
  const card = headerEl.closest(".finding-card");
  card.classList.toggle("expanded");
}

// ── Filter pills ───────────────────────────────────────────────────────────
function filterResults(severity) {
  activeFilter = severity;

  document.querySelectorAll(".filter-pill").forEach(btn => btn.classList.remove("active"));

  const pillMap = { all: 0, High: 1, Medium: 2, Low: 3 };
  const pills = document.querySelectorAll(".filter-pill");
  pills[pillMap[severity]]?.classList.add("active");

  renderFindings(allFindings, severity);
}

// ── Report download ────────────────────────────────────────────────────────
function downloadReport() {
  log("Downloading report…", "info");
  window.location.href = "/download-report";
}

// ── Utility ────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Allow Enter key in URL input to trigger scan
urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});
