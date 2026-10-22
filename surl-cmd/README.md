# 🛡️ SURL CMD — Command-Line Threat Intelligence Tool

Access the Sentinel URL (SURL) security scanner directly through Windows Command Prompt (`cmd.exe`). Simply provide any URL to CMD, view immediate threat breakdown, and automatically redirect to the interactive web dashboard.

---

## 🌐 Dual Backend Architecture

SURL CMD fully supports **both Localhost and Cloud (`sentinelurl.site`)** environments:

| Environment | Endpoint | Purpose |
|---|---|---|
| **Localhost** | `http://localhost:8000` | Local FastAPI backend engine with real-time dynamic analysis & dev environment |
| **Cloud** | `https://sentinelurl.site` | Cloud portal & official production deployment |
| **Auto (Default)** | Localhost ➔ Cloud | Automatically connects to Localhost if online; smoothly falls back to Cloud |

---

## ⚡ Quick Start

### 1. From the Project Directory
Open `cmd` in `C:\Users\jishn\SURL`:

```cmd
surl https://github.com
```

Or run without arguments to enter interactive mode:

```cmd
surl
```

---

## 📋 Commands & Options

| Command | Description |
|---|---|
| `surl <URL>` | **Auto Mode**: Uses Localhost if active, falls back to `sentinelurl.site` |
| `surl <URL> --local` (or `-l`) | Force **Localhost** backend (`http://localhost:8000`) & auto-starts local server if needed |
| `surl <URL> --cloud` (or `-c`) | Force **Cloud** backend (`https://sentinelurl.site`) |
| `surl <URL> --both` | Redirects to **both** Localhost and `sentinelurl.site` in browser |
| `surl <URL> --site` (or `-s`) | Scans and also directly opens destination website if verified safe |
| `surl <URL> --no-browser` (or `-n`) | Runs scan in CMD without opening the browser |
| `surl <URL> --server <URL>` | Uses a custom backend server URL |
| `scan <URL>` | Convenience shortcut alias for `surl` |

---

## 🌐 Making `surl` Accessible from ANY CMD Window

To run `surl` from any folder or path on your computer (e.g., `C:\Users\jishn>`, Desktop, Downloads):

1. Double-click or run:
   ```cmd
   install_to_path.bat
   ```
2. Open a **new** Command Prompt (`cmd.exe`).
3. Now type `surl <URL>` from anywhere!

```cmd
C:\Users\jishn> surl https://google.com
```
