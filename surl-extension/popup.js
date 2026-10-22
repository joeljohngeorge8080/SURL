/**
 * SURL — Sentinel URL Security Scanner
 * Popup Controller Logic (Dual Backend: Localhost & sentinelurl.site)
 */

document.addEventListener("DOMContentLoaded", async () => {
  // ── Elements ───────────────────────────────────────────────
  const serverStatus = document.getElementById("serverStatus");
  const openSettingsBtn = document.getElementById("openSettingsBtn");
  const viewLogsLink = document.getElementById("viewLogsLink");

  const envLocalBtn = document.getElementById("envLocalBtn");
  const envCloudBtn = document.getElementById("envCloudBtn");
  const envAutoBtn = document.getElementById("envAutoBtn");

  const inputSection = document.getElementById("inputSection");
  const scanningSection = document.getElementById("scanningSection");
  const errorSection = document.getElementById("errorSection");
  const resultSection = document.getElementById("resultSection");

  const urlInput = document.getElementById("urlInput");
  const clearInputBtn = document.getElementById("clearInputBtn");
  const useCurrentTabBtn = document.getElementById("useCurrentTabBtn");
  const startScanBtn = document.getElementById("startScanBtn");
  const cancelScanBtn = document.getElementById("cancelScanBtn");

  const scanProgressBar = document.getElementById("scanProgressBar");
  const terminalLog = document.getElementById("terminalLog");

  const errorMessage = document.getElementById("errorMessage");
  const retryScanBtn = document.getElementById("retryScanBtn");
  const openOptionsErrorBtn = document.getElementById("openOptionsErrorBtn");

  // Results
  const scoreCircle = document.getElementById("scoreCircle");
  const scoreValue = document.getElementById("scoreValue");
  const severityBadge = document.getElementById("severityBadge");
  const resultUrl = document.getElementById("resultUrl");
  const phishingRiskBar = document.getElementById("phishingRiskBar");
  const phishingRiskVal = document.getElementById("phishingRiskVal");
  const transportRiskBar = document.getElementById("transportRiskBar");
  const transportRiskVal = document.getElementById("transportRiskVal");
  const confidenceBar = document.getElementById("confidenceBar");
  const confidenceVal = document.getElementById("confidenceVal");
  const pbhFingerprintVal = document.getElementById("pbhFingerprintVal");
  const copyFingerprintBtn = document.getElementById("copyFingerprintBtn");
  const executiveSummaryText = document.getElementById("executiveSummaryText");
  const toggleIndicatorsBtn = document.getElementById("toggleIndicatorsBtn");
  const indicatorsArrow = document.getElementById("indicatorsArrow");
  const indicatorCount = document.getElementById("indicatorCount");
  const indicatorsList = document.getElementById("indicatorsList");

  const viewInDashboardBtn = document.getElementById("viewInDashboardBtn");
  const copyJsonBtn = document.getElementById("copyJsonBtn");
  const resetScanBtn = document.getElementById("resetScanBtn");

  // State
  let currentSettings = { surlApiUrl: "auto", scanMode: "static" };
  let activeBackendMode = "auto"; // 'local', 'cloud', 'auto'
  let activeResolvedUrl = "http://localhost:8000";
  let currentScanResult = null;
  let scanAnimationTimer = null;
  let activeAbortController = null;

  // ── 1. Settings & Server Resolution ────────────────────────
  async function loadSettings() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({
        surlApiUrl: "auto",
        scanMode: "static"
      }, (data) => {
        currentSettings = data;

        if (data.surlApiUrl.includes("localhost") || data.surlApiUrl.includes("127.0.0.1")) {
          activeBackendMode = "local";
        } else if (data.surlApiUrl.includes("sentinelurl.site")) {
          activeBackendMode = "cloud";
        } else {
          activeBackendMode = "auto";
        }

        updateEnvButtonsUI();

        const modeRadio = document.querySelector(`input[name="scanMode"][value="${data.scanMode}"]`);
        if (modeRadio) modeRadio.checked = true;

        resolve(data);
      });
    });
  }

  function updateEnvButtonsUI() {
    [envLocalBtn, envCloudBtn, envAutoBtn].forEach(b => b?.classList.remove("active"));
    if (activeBackendMode === "local") envLocalBtn?.classList.add("active");
    else if (activeBackendMode === "cloud") envCloudBtn?.classList.add("active");
    else envAutoBtn?.classList.add("active");
  }

  async function resolveBackendUrl() {
    if (activeBackendMode === "local") {
      activeResolvedUrl = "http://localhost:8000";
      return activeResolvedUrl;
    }
    if (activeBackendMode === "cloud") {
      activeResolvedUrl = "https://sentinelurl.site";
      return activeResolvedUrl;
    }

    // Auto Mode: check localhost first
    try {
      const res = await fetch("http://localhost:8000/health", { method: "GET", signal: AbortSignal.timeout(1200) });
      if (res.ok) {
        activeResolvedUrl = "http://localhost:8000";
        return activeResolvedUrl;
      }
    } catch (_) {}

    activeResolvedUrl = "https://sentinelurl.site";
    return activeResolvedUrl;
  }

  async function checkServer() {
    setServerPill("checking", "Connecting...");
    try {
      const target = await resolveBackendUrl();
      const base = target.replace(/\/+$/, "");

      let isUp = false;
      let label = "Online";

      try {
        const res = await fetch(`${base}/health`, { method: "GET", signal: AbortSignal.timeout(2500) });
        if (res.ok) {
          const json = await res.json();
          isUp = true;
          label = `Online (${base.includes("localhost") ? "Local" : "Cloud"})`;
        }
      } catch (_) {}

      if (!isUp && base.includes("sentinelurl.site")) {
        try {
          await fetch(base, { method: "GET", mode: "no-cors", signal: AbortSignal.timeout(2500) });
          isUp = true;
          label = "Online (Cloud)";
        } catch (_) {}
      }

      if (isUp) {
        setServerPill("online", label);
      } else {
        setServerPill("offline", base.includes("localhost") ? "Local Offline" : "Cloud Offline");
      }
    } catch (e) {
      setServerPill("offline", "Offline");
    }
  }

  function setServerPill(type, label) {
    serverStatus.className = `status-pill status-${type}`;
    serverStatus.querySelector(".status-label").textContent = label;
  }

  serverStatus.addEventListener("click", checkServer);

  // Backend environment button clicks
  envLocalBtn?.addEventListener("click", () => {
    activeBackendMode = "local";
    updateEnvButtonsUI();
    currentSettings.surlApiUrl = "http://localhost:8000";
    chrome.storage.sync.set({ surlApiUrl: "http://localhost:8000" });
    checkServer();
  });

  envCloudBtn?.addEventListener("click", () => {
    activeBackendMode = "cloud";
    updateEnvButtonsUI();
    currentSettings.surlApiUrl = "https://sentinelurl.site";
    chrome.storage.sync.set({ surlApiUrl: "https://sentinelurl.site" });
    checkServer();
  });

  envAutoBtn?.addEventListener("click", () => {
    activeBackendMode = "auto";
    updateEnvButtonsUI();
    currentSettings.surlApiUrl = "auto";
    chrome.storage.sync.set({ surlApiUrl: "auto" });
    checkServer();
  });

  // ── 2. Tab URL Detection ────────────────────────────────────
  async function populateCurrentTabUrl() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url && !tab.url.startsWith("chrome://") && !tab.url.startsWith("edge://") && !tab.url.startsWith("about:")) {
        urlInput.value = tab.url;
        clearInputBtn.style.display = "inline";
      }
    } catch (err) {
      console.warn("Could not query tab:", err);
    }
  }

  useCurrentTabBtn.addEventListener("click", populateCurrentTabUrl);

  urlInput.addEventListener("input", () => {
    clearInputBtn.style.display = urlInput.value ? "inline" : "none";
  });

  clearInputBtn.addEventListener("click", () => {
    urlInput.value = "";
    clearInputBtn.style.display = "none";
    urlInput.focus();
  });

  // ── 3. Scan Pipeline Execution ──────────────────────────────
  const terminalSteps = [
    "[+] Initializing SURL analysis engine...",
    "[+] Validating URL & resolving DNS...",
    "[+] Inspecting SSL/TLS & Lexical Heuristics...",
    "[+] Querying Threat Intelligence Feeds...",
    "[+] Checking Brand Impersonation Signatures...",
    "[+] Computing Weighted Risk Score...",
    "[+] Synthesizing PBH Fingerprint...",
    "[✓] Threat analysis successfully completed."
  ];

  function startScanningAnimation() {
    terminalLog.innerHTML = "";
    let stepIndex = 0;
    scanProgressBar.style.width = "10%";

    function advanceStep() {
      if (stepIndex < terminalSteps.length) {
        const line = document.createElement("div");
        line.className = `log-line ${stepIndex === terminalSteps.length - 1 ? "active" : ""}`;
        line.textContent = terminalSteps[stepIndex];
        terminalLog.appendChild(line);
        terminalLog.scrollTop = terminalLog.scrollHeight;

        const progressPercent = Math.min(95, Math.round(((stepIndex + 1) / terminalSteps.length) * 100));
        scanProgressBar.style.width = `${progressPercent}%`;

        stepIndex++;
        scanAnimationTimer = setTimeout(advanceStep, 550);
      }
    }

    advanceStep();
  }

  function stopScanningAnimation() {
    if (scanAnimationTimer) {
      clearTimeout(scanAnimationTimer);
      scanAnimationTimer = null;
    }
  }

  async function executeScan() {
    let targetUrl = urlInput.value.trim();
    if (!targetUrl) {
      showError("Please enter a valid URL to scan.");
      return;
    }

    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = "https://" + targetUrl;
      urlInput.value = targetUrl;
    }

    const selectedMode = document.querySelector('input[name="scanMode"]:checked')?.value || "static";

    // Switch views
    inputSection.style.display = "none";
    errorSection.style.display = "none";
    resultSection.style.display = "none";
    scanningSection.style.display = "block";

    startScanningAnimation();

    activeAbortController = new AbortController();
    const timeoutMs = selectedMode === "dynamic" ? 50000 : 25000;
    const timeoutId = setTimeout(() => activeAbortController.abort(), timeoutMs);

    try {
      const targetHost = await resolveBackendUrl();
      const base = targetHost.replace(/\/+$/, "");
      const endpoint = selectedMode === "dynamic" ? `${base}/scan-dynamic` : `${base}/scan`;

      let response;
      try {
        response = await fetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          body: JSON.stringify({ url: targetUrl }),
          signal: activeAbortController.signal
        });
      } catch (firstErr) {
        // If in auto mode and localhost failed, try cloud as fallback!
        if (activeBackendMode === "auto" && base.includes("localhost")) {
          const fallbackEndpoint = selectedMode === "dynamic" ? "https://sentinelurl.site/scan-dynamic" : "https://sentinelurl.site/scan";
          response = await fetch(fallbackEndpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Accept": "application/json"
            },
            body: JSON.stringify({ url: targetUrl }),
            signal: activeAbortController.signal
          });
        } else {
          throw firstErr;
        }
      }

      clearTimeout(timeoutId);
      stopScanningAnimation();

      if (!response.ok) {
        const errText = await response.text();
        let message = `Server returned HTTP ${response.status}`;
        try {
          const parsed = JSON.parse(errText);
          message = parsed.detail || parsed.error || message;
        } catch (_) {}
        throw new Error(message);
      }

      const data = await response.json();
      currentScanResult = data;

      scanProgressBar.style.width = "100%";

      chrome.storage.local.set({
        lastScanResult: data,
        lastScannedUrl: targetUrl,
        lastScanTimestamp: Date.now()
      });

      const score = data.risk_score ?? data.dynamic_risk_score ?? 0;
      const severity = data.severity || (score >= 70 ? "High" : score >= 30 ? "Suspicious" : "Low");
      chrome.runtime.sendMessage({
        action: "UPDATE_BADGE",
        score: score,
        severity: severity
      });

      setTimeout(() => {
        renderResults(data, targetUrl);
      }, 400);

    } catch (err) {
      clearTimeout(timeoutId);
      stopScanningAnimation();
      console.error("Scan error:", err);

      let msg = err.message;
      if (err.name === "AbortError") {
        msg = "Scan timed out. Server or dynamic sandbox took too long to respond.";
      } else if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError")) {
        msg = `Cannot reach backend (${activeResolvedUrl}). Switch to Cloud (sentinelurl.site) or run 'uvicorn app.main:app --port 8000' for Localhost.`;
      }

      showError(msg);
    }
  }

  cancelScanBtn.addEventListener("click", () => {
    if (activeAbortController) {
      activeAbortController.abort();
    }
    stopScanningAnimation();
    scanningSection.style.display = "none";
    inputSection.style.display = "block";
  });

  startScanBtn.addEventListener("click", executeScan);
  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") executeScan();
  });

  // ── 4. Rendering Results ────────────────────────────────────
  function renderResults(data, url) {
    scanningSection.style.display = "none";
    inputSection.style.display = "none";
    errorSection.style.display = "none";
    resultSection.style.display = "block";

    const score = data.risk_score ?? data.dynamic_risk_score ?? 0;
    const severity = data.severity || (score >= 70 ? "High" : score >= 30 ? "Suspicious" : "Low");

    scoreValue.textContent = score;
    resultUrl.textContent = url || data.url || "";
    resultUrl.title = url || data.url || "";

    severityBadge.className = "severity-badge";
    scoreCircle.style.boxShadow = "";

    if (score >= 70 || severity === "High" || severity === "Malicious") {
      severityBadge.classList.add("badge-malicious");
      severityBadge.textContent = "MALICIOUS / HIGH";
      scoreCircle.style.borderColor = "var(--color-danger)";
      scoreCircle.style.boxShadow = "0 0 16px rgba(239, 68, 68, 0.5)";
      scoreValue.style.color = "var(--color-danger)";
    } else if (score >= 30 || severity === "Suspicious" || severity === "Medium") {
      severityBadge.classList.add("badge-suspicious");
      severityBadge.textContent = "SUSPICIOUS";
      scoreCircle.style.borderColor = "var(--color-warn)";
      scoreCircle.style.boxShadow = "0 0 16px rgba(245, 158, 11, 0.4)";
      scoreValue.style.color = "var(--color-warn)";
    } else {
      severityBadge.classList.add("badge-safe");
      severityBadge.textContent = "SAFE / LOW RISK";
      scoreCircle.style.borderColor = "var(--color-safe)";
      scoreCircle.style.boxShadow = "0 0 16px rgba(16, 185, 129, 0.4)";
      scoreValue.style.color = "var(--color-safe)";
    }

    const phishingVal = data.phishing_risk ?? 0;
    phishingRiskBar.style.width = `${phishingVal}%`;
    phishingRiskVal.textContent = `${phishingVal}%`;

    const transportVal = data.transport_risk ?? 0;
    transportRiskBar.style.width = `${transportVal}%`;
    transportRiskVal.textContent = `${transportVal}%`;

    const confVal = data.confidence_score ?? 85;
    confidenceBar.style.width = `${confVal}%`;
    confidenceVal.textContent = `${confVal}%`;

    const pbh = data.pbh_fingerprint || "PBH-CLEAN-0000";
    pbhFingerprintVal.textContent = pbh;

    executiveSummaryText.textContent = data.executive_summary ||
      (data.dynamic_analysis ? "Dynamic sandbox analysis complete." : "Analysis successfully performed by SURL engine.");

    const indicators = data.detailed_analysis || [];
    indicatorCount.textContent = indicators.length;
    indicatorsList.innerHTML = "";

    if (indicators.length === 0) {
      indicatorsList.innerHTML = `<div class="indicator-card"><div class="ind-desc" style="color: #64748b;">No abnormal threat indicators detected.</div></div>`;
    } else {
      indicators.forEach((ind) => {
        const item = document.createElement("div");
        item.className = "indicator-card";

        const sevClass = (ind.severity || "").toLowerCase().includes("high")
          ? "ind-sev-high"
          : (ind.severity || "").toLowerCase().includes("suspicious")
          ? "ind-sev-suspicious"
          : "ind-sev-low";

        item.innerHTML = `
          <div class="ind-head">
            <span class="ind-name">${escapeHtml(ind.indicator || "Indicator")}</span>
            <span class="ind-sev ${sevClass}">${escapeHtml(ind.severity || "Info")}</span>
          </div>
          <div class="ind-desc">${escapeHtml(ind.report_paragraph || ind.remediation_strategy || "")}</div>
        `;
        indicatorsList.appendChild(item);
      });
    }
  }

  // Toggle indicators accordion
  toggleIndicatorsBtn.addEventListener("click", () => {
    const isHidden = indicatorsList.style.display === "none";
    indicatorsList.style.display = isHidden ? "flex" : "none";
    indicatorsArrow.classList.toggle("open", isHidden);
  });

  // Copy Fingerprint
  copyFingerprintBtn.addEventListener("click", () => {
    navigator.clipboard.writeText(pbhFingerprintVal.textContent).then(() => {
      copyFingerprintBtn.textContent = "Copied!";
      setTimeout(() => { copyFingerprintBtn.textContent = "Copy"; }, 1500);
    });
  });

  // Copy Full JSON
  copyJsonBtn.addEventListener("click", () => {
    if (!currentScanResult) return;
    navigator.clipboard.writeText(JSON.stringify(currentScanResult, null, 2)).then(() => {
      copyJsonBtn.textContent = "✓ Copied";
      setTimeout(() => { copyJsonBtn.textContent = "📋 Copy JSON"; }, 1500);
    });
  });

  // Open in SURL Dashboard
  viewInDashboardBtn.addEventListener("click", async () => {
    const base = activeResolvedUrl.replace(/\/+$/, "");
    const resultsPageUrl = base.includes("localhost") ? `${base}/results` : base;

    const newTab = await chrome.tabs.create({ url: resultsPageUrl });

    if (currentScanResult && newTab.id && base.includes("localhost")) {
      chrome.scripting?.executeScript({
        target: { tabId: newTab.id },
        func: (scanData) => {
          try {
            localStorage.setItem("scanResult", JSON.stringify(scanData));
            window.location.reload();
          } catch (e) {
            console.error("Failed to inject scanResult:", e);
          }
        },
        args: [currentScanResult]
      }).catch(() => {});
    }
  });

  // Reset to new scan
  resetScanBtn.addEventListener("click", () => {
    resultSection.style.display = "none";
    errorSection.style.display = "none";
    scanningSection.style.display = "none";
    inputSection.style.display = "block";
    populateCurrentTabUrl();
  });

  // ── 5. Error Handling ───────────────────────────────────────
  function showError(msg) {
    stopScanningAnimation();
    scanningSection.style.display = "none";
    inputSection.style.display = "none";
    resultSection.style.display = "none";
    errorSection.style.display = "block";
    errorMessage.textContent = msg;
  }

  retryScanBtn.addEventListener("click", () => {
    errorSection.style.display = "none";
    inputSection.style.display = "block";
  });

  openOptionsErrorBtn.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  openSettingsBtn.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  viewLogsLink.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: activeResolvedUrl });
  });

  // ── 6. Restore Cached Result If Any ─────────────────────────
  chrome.storage.local.get(["lastScanResult", "lastScannedUrl"], (res) => {
    if (res.lastScanResult) {
      currentScanResult = res.lastScanResult;
      if (!urlInput.value) {
        urlInput.value = res.lastScannedUrl || "";
      }
    }
  });

  // Initialize
  await loadSettings();
  await checkServer();
  await populateCurrentTabUrl();
});

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
