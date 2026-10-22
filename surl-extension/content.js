/**
 * SURL — Sentinel URL Security Scanner
 * In-Page Content Script
 */

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SHOW_THREAT_BANNER") {
    displayThreatBanner(request.data);
    sendResponse({ received: true });
  }
});

function displayThreatBanner(data) {
  // Check if banner already exists
  let existing = document.getElementById("surl-security-banner-root");
  if (existing) existing.remove();

  const score = data.risk_score ?? data.dynamic_risk_score ?? 0;
  const severity = (data.severity || "HIGH THREAT").toUpperCase();
  const summary = data.executive_summary || "This page has been flagged for deceptive or suspicious patterns.";

  const banner = document.createElement("div");
  banner.id = "surl-security-banner-root";
  banner.className = "surl-banner-active";

  banner.innerHTML = `
    <div class="surl-banner-content">
      <div class="surl-banner-left">
        <div class="surl-banner-icon">⚠️</div>
        <div class="surl-banner-info">
          <div class="surl-banner-headline">
            <span class="surl-tag">${severity}</span>
            <strong>SURL Security Alert: Potential Threat Detected (Score: ${score}/100)</strong>
          </div>
          <div class="surl-banner-desc">${escapeHtml(summary)}</div>
        </div>
      </div>
      <div class="surl-banner-actions">
        <button id="surl-banner-close" class="surl-btn-dismiss">Dismiss</button>
      </div>
    </div>
  `;

  document.body.prepend(banner);

  document.getElementById("surl-banner-close")?.addEventListener("click", () => {
    banner.classList.add("surl-banner-hiding");
    setTimeout(() => banner.remove(), 300);
  });
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
