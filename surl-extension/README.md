# 🛡️ SURL — Sentinel URL Security Extension

A high-performance Chrome & Chromium browser extension providing real-time AI threat intelligence, lexical heuristic analysis, and dynamic sandbox threat scanning powered by the **SURL (Sentinel URL)** backend.

---

## 🚀 Key Features

- **⚡ Instant 1-Click Scan**: Auto-detects the active browser tab's URL and performs deep threat analysis.
- **🛡️ Dual-Mode Threat Pipeline**:
  - **Static Heuristics (`/scan`)**: Real-time DNS, WHOIS domain age, SSL/TLS certificate inspection, lexical patterns, and brand impersonation detection (~1–2 seconds).
  - **Dynamic Sandbox (`/scan-dynamic`)**: Headless Chromium execution monitoring DOM mutations, JavaScript evasion, and network exfiltration.
- **📊 Cyber Risk Intelligence Dashboard**:
  - Visual 0–100 Risk Score Meter.
  - Severity Badging (`SAFE`, `SUSPICIOUS`, `MALICIOUS / HIGH`).
  - Phishing Risk, Transport Risk, and Confidence metrics.
  - **PBH Fingerprint** (Protocol-Behavior-Heuristic 16-bit binary signature) with 1-click copy.
  - Actionable indicator breakdown with remediation and verification advice.
- **🖱️ Right-Click Context Menus**: Right-click any link or page to scan instantly without leaving the webpage.
- **🚨 In-Page Threat Warning Banner**: Displays an alert banner on flagged malicious pages before credentials can be entered.
- **⚙️ Configurable Backend**: Connect to local dev (`http://localhost:8000`) or production API with live connection latency testing.

---

## 📂 Extension Folder Structure

All future edits for the browser extension should be made in this folder: `c:\Users\jishn\SURL\surl-extension\`

```
surl-extension/
├── manifest.json         # Chrome Manifest V3 configuration
├── popup.html            # Main extension popup interface
├── popup.css             # Cyberpunk/dark theme styles for the popup
├── popup.js              # Popup controller, tab detection & API caller
├── background.js         # Service worker, context menus & badge alerts
├── content.js            # In-page threat banner injection
├── content.css           # Styling for in-page threat banner
├── options.html          # Extension settings & API configuration UI
├── options.css           # Styling for options page
├── options.js            # Settings logic & server latency tester
├── generate_icons.py     # Standalone Python icon generator (stdlib only)
├── icons/                # High-res extension icons (16, 32, 48, 128, svg)
│   ├── icon.svg
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── README.md             # This file
```

---

## 🛠️ How to Install & Load in Your Browser

This extension works on **Google Chrome**, **Microsoft Edge**, **Brave**, **Opera**, and any Chromium-based browser.

### 1. Open Browser Extension Manager
- In **Chrome**: Navigate to `chrome://extensions/`
- In **Edge**: Navigate to `edge://extensions/`
- In **Brave**: Navigate to `brave://extensions/`

### 2. Enable Developer Mode
- Toggle the **Developer mode** switch in the top-right corner of the Extensions page.

### 3. Load the Extension
1. Click the **"Load unpacked"** button in the top-left corner.
2. Browse to and select the `surl-extension` folder:
   ```
   c:\Users\jishn\SURL\surl-extension
   ```
3. The **SURL — Sentinel URL Security Scanner** card will appear in your extension list!
4. Pin the SURL icon to your browser toolbar for quick access.

---

## 🔌 Dual Backend Connection (Localhost & sentinelurl.site)

The extension now includes a seamless **Backend Environment Switcher** right in the popup header:
- **💻 Local**: Connects directly to `http://localhost:8000` (ideal for active development & testing).
- **☁️ Cloud**: Connects to the live cloud production domain `https://sentinelurl.site`.
- **⚡ Auto (Recommended)**: Checks `http://localhost:8000` first. If your local server is offline, it automatically falls back to `https://sentinelurl.site`!

### Quick Start:
1. Make sure your Python virtual environment is activated and dependencies are installed.
2. Start the FastAPI backend:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
3. Open the SURL extension popup in your browser.
4. Select **Local**, **Cloud**, or **Auto** using the quick toggles.
5. The status pill displays live connection state (e.g. `Online (Local)` or `Online (Cloud)`).
6. Click **"Current Tab"** and hit **"EXECUTE THREAT SCAN"** to analyze any website!

---

## 📝 Making Future Edits

- **Popup UI & Styling**: Modify `popup.html` and `popup.css`.
- **Scanning Logic & API Calls**: Modify `popup.js` and `background.js`.
- **In-Page Warnings**: Modify `content.js` and `content.css`.
- **Settings & Config**: Modify `options.html` and `options.js`.
- **Icons**: Edit `icons/icon.svg` or run `python generate_icons.py` to regenerate PNGs.
- **Reloading changes**: After modifying any file in `surl-extension/`, simply click the **Reload (🔄)** icon on the SURL extension card in `chrome://extensions/`.
