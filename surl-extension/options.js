/**
 * SURL Extension — Options / Settings Controller
 */

const DEFAULT_SETTINGS = {
  surlApiUrl: "auto", // 'auto', 'http://localhost:8000', or 'https://sentinelurl.site'
  scanMode: "static",
  alertThreshold: 70,
  enableInPageBanner: true,
  enableContextMenu: true
};

document.addEventListener("DOMContentLoaded", () => {
  const apiUrlInput = document.getElementById("apiUrlInput");
  const testConnectionBtn = document.getElementById("testConnectionBtn");
  const connectionResult = document.getElementById("connectionResult");
  const alertThresholdInput = document.getElementById("alertThresholdInput");
  const thresholdValDisplay = document.getElementById("thresholdValDisplay");
  const enableContextMenuCheckbox = document.getElementById("enableContextMenuCheckbox");
  const enableBannerCheckbox = document.getElementById("enableBannerCheckbox");
  const saveBtn = document.getElementById("saveBtn");
  const resetDefaultsBtn = document.getElementById("resetDefaultsBtn");
  const saveStatus = document.getElementById("saveStatus");

  const presetLocalBtn = document.getElementById("presetLocalBtn");
  const presetCloudBtn = document.getElementById("presetCloudBtn");
  const presetAutoBtn = document.getElementById("presetAutoBtn");

  // Load current settings
  chrome.storage.sync.get(DEFAULT_SETTINGS, (settings) => {
    apiUrlInput.value = settings.surlApiUrl;
    alertThresholdInput.value = settings.alertThreshold;
    thresholdValDisplay.textContent = settings.alertThreshold;
    enableContextMenuCheckbox.checked = settings.enableContextMenu;
    enableBannerCheckbox.checked = settings.enableInPageBanner;

    const modeRadio = document.querySelector(`input[name="defaultMode"][value="${settings.scanMode}"]`);
    if (modeRadio) modeRadio.checked = true;
  });

  // Preset button handlers
  presetLocalBtn?.addEventListener("click", () => {
    apiUrlInput.value = "http://localhost:8000";
    testConnectionBtn.click();
  });

  presetCloudBtn?.addEventListener("click", () => {
    apiUrlInput.value = "https://sentinelurl.site";
    testConnectionBtn.click();
  });

  presetAutoBtn?.addEventListener("click", () => {
    apiUrlInput.value = "auto";
    testConnectionBtn.click();
  });

  // Slider change
  alertThresholdInput.addEventListener("input", () => {
    thresholdValDisplay.textContent = alertThresholdInput.value;
  });

  // Test Connection
  testConnectionBtn.addEventListener("click", async () => {
    connectionResult.style.display = "block";
    connectionResult.className = "connection-status";
    connectionResult.textContent = "Testing connection...";
    testConnectionBtn.disabled = true;

    const rawInput = apiUrlInput.value.trim();

    try {
      if (rawInput === "auto" || !rawInput) {
        // Test both
        let localStatus = "Offline";
        let cloudStatus = "Offline";

        try {
          const lRes = await fetch("http://localhost:8000/health", { method: "GET", signal: AbortSignal.timeout(2000) });
          if (lRes.ok) localStatus = "Online (v1.0)";
        } catch (_) {}

        try {
          const cRes = await fetch("https://sentinelurl.site", { method: "GET", mode: "no-cors", signal: AbortSignal.timeout(3000) });
          cloudStatus = "Online (Reachable)";
        } catch (_) {}

        connectionResult.className = "connection-status conn-success";
        connectionResult.innerHTML = `✓ Auto-Detect Mode Configured:<br>• <strong>Localhost (8000)</strong>: ${localStatus}<br>• <strong>Cloud (sentinelurl.site)</strong>: ${cloudStatus}`;
        return;
      }

      const base = rawInput.replace(/\/+$/, "");
      const start = performance.now();

      // Check health endpoint
      let ok = false;
      let info = "";

      try {
        const res = await fetch(`${base}/health`, { method: "GET", signal: AbortSignal.timeout(3500) });
        if (res.ok) {
          const data = await res.json();
          ok = true;
          info = `SURL Engine ${data.version || "v1.0"}`;
        }
      } catch (_) {}

      // Fallback check root if /health is 404 or blocked (e.g. cloudfront static frontend)
      if (!ok) {
        try {
          const resRoot = await fetch(base, { method: "GET", mode: "no-cors", signal: AbortSignal.timeout(3500) });
          ok = true;
          info = "Cloud Host Reachable";
        } catch (e) {
          throw e;
        }
      }

      const latency = Math.round(performance.now() - start);
      if (ok) {
        connectionResult.className = "connection-status conn-success";
        connectionResult.innerHTML = `✓ Connection Successful! ${info} (${latency}ms latency).`;
      } else {
        connectionResult.className = "connection-status conn-error";
        connectionResult.textContent = `✗ Could not verify connection to ${base}.`;
      }

    } catch (err) {
      connectionResult.className = "connection-status conn-error";
      connectionResult.textContent = `✗ Connection failed: ${err.message}. Make sure server is online.`;
    } finally {
      testConnectionBtn.disabled = false;
    }
  });

  // Save Settings
  saveBtn.addEventListener("click", () => {
    const newSettings = {
      surlApiUrl: apiUrlInput.value.trim() || DEFAULT_SETTINGS.surlApiUrl,
      scanMode: document.querySelector('input[name="defaultMode"]:checked')?.value || "static",
      alertThreshold: parseInt(alertThresholdInput.value, 10) || 70,
      enableContextMenu: enableContextMenuCheckbox.checked,
      enableInPageBanner: enableBannerCheckbox.checked
    };

    chrome.storage.sync.set(newSettings, () => {
      chrome.runtime.sendMessage({
        action: "UPDATE_SETTINGS",
        settings: newSettings
      });

      saveStatus.textContent = "Settings saved successfully!";
      setTimeout(() => { saveStatus.textContent = ""; }, 2500);
    });
  });

  // Reset Defaults
  resetDefaultsBtn.addEventListener("click", () => {
    if (confirm("Reset all settings to default values?")) {
      chrome.storage.sync.set(DEFAULT_SETTINGS, () => {
        apiUrlInput.value = DEFAULT_SETTINGS.surlApiUrl;
        alertThresholdInput.value = DEFAULT_SETTINGS.alertThreshold;
        thresholdValDisplay.textContent = DEFAULT_SETTINGS.alertThreshold;
        enableContextMenuCheckbox.checked = DEFAULT_SETTINGS.enableContextMenu;
        enableBannerCheckbox.checked = DEFAULT_SETTINGS.enableInPageBanner;
        const modeRadio = document.querySelector(`input[name="defaultMode"][value="${DEFAULT_SETTINGS.scanMode}"]`);
        if (modeRadio) modeRadio.checked = true;

        saveStatus.textContent = "Reset to defaults!";
        setTimeout(() => { saveStatus.textContent = ""; }, 2000);
      });
    }
  });
});
