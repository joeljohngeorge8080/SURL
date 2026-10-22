/**
 * SURL — Sentinel URL Security Scanner
 * Background Service Worker (Manifest V3)
 * Supports dual backend: Localhost & sentinelurl.site
 */

const DEFAULT_SETTINGS = {
  surlApiUrl: "auto", // 'auto', 'http://localhost:8000', or 'https://sentinelurl.site'
  scanMode: "static", // 'static' or 'dynamic'
  alertThreshold: 70,
  enableInPageBanner: true,
  enableContextMenu: true,
  autoScanSuspiciousTabs: false
};

// ── Initialization ───────────────────────────────────────────
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[SURL Background] Initializing extension service worker...");

  chrome.storage.sync.get(DEFAULT_SETTINGS, (settings) => {
    chrome.storage.sync.set(settings);
    setupContextMenus(settings.enableContextMenu);
  });
});

// ── Context Menus ─────────────────────────────────────────────
function setupContextMenus(enabled = true) {
  chrome.contextMenus.removeAll(() => {
    if (!enabled) return;

    chrome.contextMenus.create({
      id: "surl_scan_link",
      title: "🛡️ Scan Link with SURL",
      contexts: ["link"]
    });

    chrome.contextMenus.create({
      id: "surl_scan_page",
      title: "🛡️ Scan Current Page with SURL",
      contexts: ["page"]
    });
  });
}

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const settings = await getSettings();
  let targetUrl = "";

  if (info.menuItemId === "surl_scan_link" && info.linkUrl) {
    targetUrl = info.linkUrl;
  } else if (info.menuItemId === "surl_scan_page" && tab?.url) {
    targetUrl = tab.url;
  }

  if (!targetUrl || targetUrl.startsWith("chrome://") || targetUrl.startsWith("edge://")) {
    showNotification("SURL Warning", "Cannot scan internal browser pages.", "info");
    return;
  }

  showNotification("SURL Scanning...", `Analyzing: ${truncateUrl(targetUrl)}`, "info");

  try {
    const result = await performScan(targetUrl, settings.surlApiUrl, settings.scanMode);

    if (result.error) {
      showNotification("SURL Scan Error", result.error, "error");
      return;
    }

    const score = result.risk_score ?? 0;
    const severity = result.severity || "Unknown";
    updateBadge(tab?.id, score, severity);

    const title = `SURL: ${severity.toUpperCase()} (Score: ${score}/100)`;
    const message = result.executive_summary || `Scan finished for ${truncateUrl(targetUrl)}`;
    showNotification(title, message, score >= settings.alertThreshold ? "alert" : "info");

    chrome.storage.local.set({
      lastScanResult: result,
      lastScannedUrl: targetUrl,
      lastScanTimestamp: Date.now()
    });

    if (tab?.id && score >= settings.alertThreshold && settings.enableInPageBanner) {
      chrome.tabs.sendMessage(tab.id, {
        action: "SHOW_THREAT_BANNER",
        data: result
      }).catch(() => {});
    }

  } catch (err) {
    console.error("[SURL Background] Scan failed:", err);
    showNotification("SURL Scan Failed", `Could not connect to SURL server (${settings.surlApiUrl}). ${err.message}`, "error");
  }
});

// ── Message Listener ──────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SCAN_URL") {
    getSettings().then(async (settings) => {
      try {
        const result = await performScan(
          request.url,
          request.apiUrl || settings.surlApiUrl,
          request.mode || settings.scanMode
        );

        if (sender.tab?.id) {
          updateBadge(sender.tab.id, result.risk_score, result.severity);
        }

        chrome.storage.local.set({
          lastScanResult: result,
          lastScannedUrl: request.url,
          lastScanTimestamp: Date.now()
        });

        sendResponse({ success: true, data: result });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    });
    return true;
  }

  if (request.action === "CHECK_SERVER") {
    const targetUrl = request.apiUrl || "auto";
    checkServerHealth(targetUrl)
      .then((status) => sendResponse(status))
      .catch((err) => sendResponse({ online: false, error: err.message }));
    return true;
  }

  if (request.action === "UPDATE_BADGE") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    updateBadge(tabId, request.score, request.severity);
    sendResponse({ success: true });
    return false;
  }

  if (request.action === "UPDATE_SETTINGS") {
    if (typeof request.settings?.enableContextMenu !== "undefined") {
      setupContextMenus(request.settings.enableContextMenu);
    }
    sendResponse({ success: true });
    return false;
  }
});

// ── API Helpers ───────────────────────────────────────────────
async function resolveApiUrl(preferred = "auto") {
  if (preferred && preferred !== "auto") return preferred.replace(/\/+$/, "");

  // Auto mode: test localhost first
  try {
    const res = await fetch("http://localhost:8000/health", { method: "GET", signal: AbortSignal.timeout(1200) });
    if (res.ok) return "http://localhost:8000";
  } catch (_) {}

  return "https://sentinelurl.site";
}

async function performScan(url, apiUrl, mode = "static") {
  const base = await resolveApiUrl(apiUrl);
  const endpoint = mode === "dynamic" ? `${base}/scan-dynamic` : `${base}/scan`;

  const controller = new AbortController();
  const timeoutMs = mode === "dynamic" ? 45000 : 20000;
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let response;
    try {
      response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify({ url: url.trim() }),
        signal: controller.signal
      });
    } catch (fetchErr) {
      // If localhost failed in auto mode, try cloud fallback
      if (base.includes("localhost") && (apiUrl === "auto" || !apiUrl)) {
        const fallbackEndpoint = mode === "dynamic" ? "https://sentinelurl.site/scan-dynamic" : "https://sentinelurl.site/scan";
        response = await fetch(fallbackEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
          },
          body: JSON.stringify({ url: url.trim() }),
          signal: controller.signal
        });
      } else {
        throw fetchErr;
      }
    }

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errorText = await response.text();
      let errorMsg = `Server returned HTTP ${response.status}`;
      try {
        const errorJson = JSON.parse(errorText);
        if (errorJson.detail) errorMsg = errorJson.detail;
        else if (errorJson.error) errorMsg = errorJson.error;
      } catch (e) {
        if (errorText) errorMsg += `: ${errorText.substring(0, 100)}`;
      }
      throw new Error(errorMsg);
    }

    const data = await response.json();
    return data;
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      throw new Error(`Scan timed out after ${timeoutMs / 1000}s. Server took too long.`);
    }
    throw err;
  }
}

async function checkServerHealth(apiUrl) {
  const base = await resolveApiUrl(apiUrl);
  const start = performance.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3500);

  try {
    let isUp = false;
    let version = "1.0.0";

    try {
      const response = await fetch(`${base}/health`, {
        method: "GET",
        signal: controller.signal
      });
      if (response.ok) {
        const data = await response.json();
        isUp = true;
        version = data.version || "1.0.0";
      }
    } catch (_) {}

    if (!isUp && base.includes("sentinelurl.site")) {
      try {
        await fetch(base, { method: "GET", mode: "no-cors", signal: controller.signal });
        isUp = true;
      } catch (_) {}
    }

    clearTimeout(timeoutId);
    const latency = Math.round(performance.now() - start);

    if (isUp) {
      return { online: true, version: version, latencyMs: latency, endpoint: base };
    }
    return { online: false, error: "Unreachable", latencyMs: latency, endpoint: base };
  } catch (err) {
    clearTimeout(timeoutId);
    return { online: false, error: err.message || "Connection refused" };
  }
}

function updateBadge(tabId, score, severity) {
  if (score === undefined || score === null) {
    chrome.action.setBadgeText({ text: "", tabId: tabId || undefined });
    return;
  }

  let badgeText = `${score}`;
  let badgeColor = "#10b981";

  if (score >= 70 || severity === "High" || severity === "Malicious") {
    badgeColor = "#ef4444";
    badgeText = `${score}`;
  } else if (score >= 30 || severity === "Suspicious" || severity === "Medium") {
    badgeColor = "#f59e0b";
    badgeText = `${score}`;
  } else {
    badgeColor = "#10b981";
    badgeText = "OK";
  }

  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId: tabId || undefined });
  chrome.action.setBadgeText({ text: badgeText, tabId: tabId || undefined });
}

function showNotification(title, message, type = "info") {
  const iconUrl = chrome.runtime.getURL("icons/icon128.png");
  chrome.notifications.create({
    type: "basic",
    iconUrl: iconUrl,
    title: title,
    message: message || "Operation completed.",
    priority: type === "alert" ? 2 : 1
  });
}

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULT_SETTINGS, (settings) => {
      resolve(settings);
    });
  });
}

function truncateUrl(url, maxLen = 45) {
  if (!url) return "";
  return url.length > maxLen ? url.substring(0, maxLen) + "..." : url;
}
