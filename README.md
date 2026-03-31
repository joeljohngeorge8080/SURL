<div align="center">

<h1>🛡️ SURL — Sentinel URL</h1>

<p><strong>An advanced, open-source URL threat intelligence and phishing detection engine.</strong></p>
<p>
  <!-- Badges -->
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/FastAPI-0.111-009485?style=flat-square&logo=fastapi" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/Playwright-headless-green?style=flat-square&logo=playwright" alt="Playwright"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" alt="Status"/>
</p>
<p><em>Combines static heuristics, a live browser sandbox, threat intelligence feeds, and a multi-layer correlation engine — all behind a single REST API.</em></p>

</div>

---

## Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
  - [Running the Application](#running-the-application)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [Tests](#-tests)
- [Deployment](#-deployment)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔭 Overview

**SURL (Sentinel URL)** is a production-grade URL threat analysis platform. It goes far beyond simple blocklist lookups — it actively opens a URL in a sandboxed headless browser, simulates real human interaction (typing, clicking, form-filling), monitors network traffic, and correlates all signals through a multi-layer intelligence engine to deliver a rich, explainable risk report.

It is designed for:
- 🔐 **Security analysts** who need rapid, explainable URL verdicts.
- 🧑‍💻 **Developers** who need a drop-in URL safety API.
- 🏛️ **Researchers** studying phishing, credential harvesting, and web-based threats.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      CLIENT / UI                        │
└────────────────────────┬────────────────────────────────┘
                         │  REST API (FastAPI)
┌────────────────────────▼────────────────────────────────┐
│               SCAN ORCHESTRATOR                         │
│  ┌─────────────┐   ┌───────────────┐   ┌─────────────┐ │
│  │   Static    │   │   Dynamic     │   │  Threat     │ │
│  │  Analysis   │   │   Sandbox     │   │  Intel      │ │
│  │  Engine     │   │ (Playwright)  │   │  Feeds      │ │
│  └──────┬──────┘   └──────┬────────┘   └──────┬──────┘ │
│         │                 │                   │         │
│  ┌──────▼─────────────────▼───────────────────▼──────┐  │
│  │            CORRELATION ENGINE                      │  │
│  │    (Strict 3-Layer: Static + Dynamic + Intel)      │  │
│  └──────────────────────────┬─────────────────────── ┘  │
│                             │                           │
│  ┌──────────────────────────▼────────────────────────┐  │
│  │            SCORING ENGINE                         │  │
│  │   Risk Score | Severity | PBH Fingerprint         │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Core Processing Pipeline

| Stage | Module | What Happens |
|---|---|---|
| **1. Normalization** | `static_analysis/url_normalizer.py` | URL is cleaned, private IPs are blocked |
| **2. Static Analysis** | `static_analysis/` | DNS, WHOIS, TLS, brand detection, lexical heuristics, HTML scan |
| **3. Dynamic Sandbox** | `app/dynamic_analysis/` | URL is opened in Playwright; human interaction is simulated |
| **4. Threat Intel** | `threat_intel/` | VirusTotal, URLhaus, Google Safe Browsing lookups |
| **5. Correlation** | `app/intelligence/correlation_engine.py` | All signals are cross-correlated via a strict 3-layer model |
| **6. Scoring & Report** | `scoring_engine/` | Risk score (0–100), severity, PBH fingerprint, and explanation |

---

## ✨ Features

### 🔬 Static Analysis
- **Lexical Analysis** — suspicious patterns, keyword matching, character entropy
- **DNS Inspection** — A/MX/NS record analysis
- **WHOIS Lookup** — newly registered domains, registrar details
- **TLS/SSL Verification** — certificate validity, protocol strength
- **HTML Scanner** — hidden forms, suspicious iframes, obfuscated scripts
- **Brand Detector** — detects impersonation of popular brands
- **OCR Image Scanning** — extract URLs from screenshots (via Tesseract)

### 🧪 Dynamic Sandbox (Playwright)
- Headless Chromium browser with a realistic 1280×800 viewport
- **Humanized interaction engine** — simulates real user behaviour:
  - Random keystroke delays, mouse trajectories
  - Cookie/consent banner auto-dismissal
  - Safe button interaction (SSO buttons are excluded)
  - Intelligent form auto-filling with a fake persona
  - Auto-accepting JS dialog popups
- **Multi-stage labeled screenshots** (landing, post-consent, pre/post-click, form-fill, final state)
- **Network monitoring** — captures POST requests, JS payloads, external calls
- **Redirect chain analysis**

### 🧠 Intelligence Modules
- **Redirect Intelligence** — detects suspicious redirect hops
- **Keyword Intelligence** — phishing keyword heuristics in page text
- **JS Intelligence** — high/medium risk JavaScript pattern detection
- **Credential Intelligence** — detects credential harvesting forms
- **Network Exfiltration Detection** — identifies data exfiltration POST requests

### 🌐 Threat Intel Feeds
- **VirusTotal** API integration
- **URLhaus** API integration
- **Google Safe Browsing** (configurable)
- **PhishTank** (configurable)

### 📊 Scoring & Reporting
- **Risk Score**: 0–100 numerical risk score
- **Severity**: Low / Medium / High / Critical
- **PBH Fingerprint**: A unique behavioral hash for the URL
- **Binary Pattern**: Machine-readable threat signature
- **Executive Summary**: Plain-English explanation of the verdict
- **Detailed Analysis**: Per-signal breakdown of why the score was assigned

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **API Framework** | [FastAPI](https://fastapi.tiangolo.com/) + Uvicorn |
| **Browser Automation** | [Playwright](https://playwright.dev/python/) (Chromium) |
| **HTML Parsing** | BeautifulSoup4 |
| **DNS Resolution** | dnspython |
| **OCR** | Tesseract + pytesseract + Pillow |
| **WHOIS** | python-whois |
| **Worker Queue** | Celery + Redis |
| **Config Management** | pydantic-settings |
| **String Matching** | python-Levenshtein |

---

## 🚀 Getting Started

### Prerequisites

- **Python** 3.11+
- **Tesseract OCR** (for image URL extraction)
- **Redis** (optional, needed for Celery workers)

```bash
# Debian/Ubuntu
sudo apt-get install -y tesseract-ocr

# macOS
brew install tesseract
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-org/surl.git
cd surl

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Playwright browsers
playwright install chromium
playwright install-deps chromium
```

### Environment Variables

Copy the example `.env` and fill in your keys:

```bash
cp .env .env.local
```

Edit `.env` (or set environment variables directly in production):

```env
# ── Core ──────────────────────────────────────────────────────────
DEBUG=False
PROJECT_NAME="Sentinel URL (SURL)"

# ── Threat Intelligence APIs ───────────────────────────────────────
# Required for full threat intel coverage
VIRUSTOTAL_API_KEY=your_virustotal_key_here
URLHAUS_API_KEY=your_urlhaus_key_here

# ── Database (optional but recommended for production) ─────────────
# DATABASE_URL=postgresql://user:password@localhost:5432/surl

# ── S3 / Object Storage (for screenshots in multi-server setups) ───
# S3_ENDPOINT_URL=http://localhost:9000
# S3_ACCESS_KEY=admin
# S3_SECRET_KEY=admin123
# S3_BUCKET_NAME=surl-screenshots

# ── Celery / Redis (for async worker jobs) ─────────────────────────
# CELERY_BROKER_URL=redis://localhost:6379/0
# CELERY_RESULT_BACKEND=redis://localhost:6379/0
```

> **⚠️ Security Notice:** Never commit real API keys to version control. Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) in production.

### Running the Application

#### Development

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Production (recommended)

```bash
# Using Gunicorn with Uvicorn workers for production concurrency
pip install gunicorn
gunicorn app.main:app \
  -k uvicorn.workers.UvicornWorker \
  --workers 4 \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --access-logfile -
```

#### Celery Workers (async scan jobs)

```bash
# Start all workers (dynamic, static, scoring)
celery -A workers.celery_app worker --loglevel=info -Q default
```

The application will be available at: **http://localhost:8000**

---

## 📡 API Reference

All endpoints are served under the root prefix. Interactive API docs are available at:
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`

### `POST /scan`
Run a full static analysis scan on a URL.

**Request Body:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "timestamp": "2026-03-29T12:00:00Z",
  "engine_version": "1.0",
  "risk_score": 78,
  "severity": "High",
  "transport_risk": 25,
  "phishing_risk": 53,
  "confidence_score": 91,
  "pbh_fingerprint": "a3f9c1...",
  "binary_pattern": "10110010",
  "executive_summary": "...",
  "detailed_analysis": [...]
}
```

### `POST /scan-dynamic`
Run a full dynamic sandbox scan (slower; opens a real browser).

**Request Body:** Same as `/scan`.

**Response:** Adds `dynamic_analysis` and `dynamic_risk_score` fields.

### `POST /scan-image`
Extract URLs from a screenshot or image file using OCR, and preview risk for each.

**Request:** `multipart/form-data` with a `file` field (PNG/JPEG).

**Response:**
```json
{
  "detected_urls": [
    {
      "url": "https://...",
      "preview_score": 85,
      "preview_severity": "High",
      "preview_flags": ["suspicious_domain", "no_https", "brand_impersonation"]
    }
  ]
}
```

### `POST /scan-selected`
Alias for `/scan`. Designed for browser-extension initiated scans.

---

## 📁 Project Structure

```
SURL/
├── app/
│   ├── main.py                  # FastAPI app, CORS, routing, static files
│   ├── api/
│   │   ├── routes.py            # All API endpoint definitions
│   │   └── schemas.py           # Pydantic request/response models
│   ├── core/
│   │   ├── config.py            # Settings (pydantic-settings)
│   │   ├── logger.py            # Centralized logger setup
│   │   └── exceptions.py        # Global exception handler
│   ├── services/
│   │   └── scan_orchestrator.py # Main scan pipeline coordinator
│   ├── dynamic_analysis/
│   │   ├── sandbox_runner.py    # Playwright sandbox orchestration
│   │   ├── interaction_engine.py # Humanized browser interaction
│   │   ├── network_monitor.py   # POST request & exfiltration detection
│   │   └── screenshots.py       # Multi-stage screenshot session manager
│   ├── intelligence/
│   │   ├── correlation_engine.py # 3-layer signal correlation
│   │   ├── redirect_intelligence.py
│   │   ├── keyword_intelligence.py
│   │   ├── js_intelligence.py
│   │   └── credential_intelligence.py
│   └── templates/               # Jinja2 HTML templates (results pages)
│
├── static_analysis/
│   ├── static_runner.py         # Orchestrates all static checks
│   ├── dns_analyzer.py
│   ├── whois_checker.py
│   ├── tls_checker.py
│   ├── html_scanner.py
│   ├── lexical_analyzer.py
│   ├── brand_detector.py
│   ├── url_normalizer.py
│   └── image_url_extractor.py   # OCR via Tesseract
│
├── scoring_engine/
│   ├── score_calculator.py      # Risk score (0–100) computation
│   ├── explanation.py           # Human-readable analysis generation
│   └── pbh_fingerprint.py       # Behavioral hash / binary pattern
│
├── threat_intel/
│   ├── virustotal.py
│   ├── urlhaus.py
│   ├── google_safe_browsing.py
│   ├── phishtank.py
│   └── domain_reputation.py
│
├── workers/
│   ├── celery_app.py            # Celery configuration
│   ├── dynamic_worker.py
│   ├── static_worker.py
│   └── scoring_worker.py
│
├── tests/                       # Test suite
├── docker/                      # Docker & Docker Compose files
├── ci/                          # CI/CD pipeline definitions
├── requirements.txt
└── .env                         # Environment variable template
```

---

## ⚙️ Configuration

All settings are managed via environment variables and loaded by `app/core/config.py` using `pydantic-settings`. The application is fully configuration-driven — no hardcoded secrets.

| Variable | Description | Required |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for threat lookups | Recommended |
| `URLHAUS_API_KEY` | URLhaus API key | Recommended |
| `DATABASE_URL` | PostgreSQL connection string | Optional |
| `S3_ENDPOINT_URL` | S3/MinIO endpoint for screenshot storage | Optional |
| `CELERY_BROKER_URL` | Redis URL for Celery task queue | Optional |
| `DEBUG` | Enable debug mode (`True`/`False`) | No (default: `False`) |

---

## 🧪 Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=app --cov=static_analysis --cov=scoring_engine --cov-report=html
```

---

## ☁️ Deployment

### System Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disk | 10 GB | 20 GB |
| OS | Ubuntu 22.04+ | Ubuntu 22.04+ |

### Production Checklist

- [ ] Set `DEBUG=False` in environment
- [ ] Restrict `CORS` to your frontend domain (in `app/main.py`)
- [ ] Set real API keys via environment variables / secrets manager
- [ ] Run behind a reverse proxy (Nginx or Caddy) with HTTPS
- [ ] Configure `gunicorn` with appropriate worker count (`CPU * 2 + 1`)
- [ ] Set up Redis for Celery if using async workers
- [ ] Configure log aggregation (ELK, Datadog, etc.)
- [ ] Add a `/health` endpoint and configure your load balancer health checks

### Quick Deploy with Docker

> **Note:** Docker configuration is available in the `docker/` directory.

```bash
# Build and run
cd docker/
docker compose up --build -d
```

### Nginx Reverse Proxy (example snippet)

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;
    }
}
```

---

## 🗺️ Roadmap

- [ ] Redis caching layer for repeated URL scans
- [ ] WebSocket-based real-time scan progress stream
- [ ] Database-backed scan history and analytics dashboard
- [ ] Rate limiting middleware (`slowapi`)
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Sentry integration for production error tracking
- [ ] CLI tool (`surl scan <url>`) for developer workflows
- [ ] Browser extension for on-demand scanning from the browser

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

<div align="center">
  <sub>Built with 🛡️ for a safer internet.</sub>
</div>
