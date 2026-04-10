# SURL — Sentinel URL

A threat intelligence platform that scans URLs for phishing, malware, and suspicious behaviour. It combines static analysis (DNS, WHOIS, TLS, lexical heuristics) with a live dynamic sandbox powered by Playwright to detect what static checks miss.

---


## What it does

You drop in a URL — or an image containing a URL — SURL runs it through a multi-stage analysis pipeline:

1. **Static analysis** — DNS, WHOIS, TLS certificate, lexical patterns, brand impersonation detection
2. **Dynamic sandbox** — headless Chromium visit, humanised interaction, JS analysis, network exfiltration monitoring, multi-stage screenshots
3. **Scoring engine** — weighted risk score + PBH fingerprint for classification
4. **Threat intel** — VirusTotal and URLhaus checks (when API keys are configured)

Results come back as a structured JSON report with an executive summary and per-indicator remediation advice.

---

## Tech stack

| Layer | Technology |
|---|---|
| API | FastAPI + Uvicorn / Gunicorn |
| Sandbox | Playwright (Chromium headless) |
| OCR | Tesseract + Pillow |
| Config | pydantic-settings |
| Container | Docker (multi-stage) |
| CI/CD | GitHub Actions |

---

## Local setup

**Requirements:** Python 3.12+, Tesseract OCR installed on the host.

```bash
# 1 — Clone
git clone https://github.com/<your-org>/surl.git
cd surl

# 2 — Create and activate venv
python -m venv venv
source venv/bin/activate

# 3 — Install dependencies
pip install -r requirements.txt
playwright install chromium
playwright install-deps chromium

# 4 — Configure environment
cp .env.example .env
# Edit .env — at minimum add your VIRUSTOTAL_API_KEY

# 5 — Run
uvicorn app.main:app --reload --port 8000
```

The API will be live at `http://localhost:8000`.  
Interactive docs (Swagger) are only available when `DEBUG=True`.

---

## Environment variables

All configuration lives in `.env`. Copy `.env.example` to get started.

| Variable | Required | Description |
|---|---|---|
| `DEBUG` | No | Set to `True` only in development. Disables docs in production. |
| `VIRUSTOTAL_API_KEY` | Recommended | VirusTotal API v3 key |
| `URLHAUS_API_KEY` | Optional | URLhaus API key |
| `DATABASE_URL` | Optional | PostgreSQL connection string |
| `RATE_LIMIT_PER_MINUTE` | No | Max requests per minute per IP (default `30`, `0` to disable) |
| `CORS_ORIGINS` | No | Comma-separated allowed origins. Defaults to `*` if unset |
| `API_PORT` | No | Host port for docker-compose (default `8000`) |
| `S3_ENDPOINT_URL` | Optional | MinIO / S3 endpoint for screenshot uploads |
| `S3_ACCESS_KEY` | Optional | S3 access key |
| `S3_SECRET_KEY` | Optional | S3 secret key |
| `CELERY_BROKER_URL` | Optional | Redis broker URL for async workers |

---

## Running with Docker

```bash
# 1 — Copy and configure your .env
cp .env.example .env

# 2 — Build and start
docker compose up --build -d

# 3 — Check it's healthy
curl http://localhost:8000/health

# 4 — Tail logs
docker compose logs -f api

# 5 — Bring it down
docker compose down
```

The image is built in two stages — a builder stage that compiles dependencies, and a slim runtime stage. The container runs as a non-root user (`appuser`).

---

## CI/CD

Every push and pull request to `main` / `master` runs through three jobs in `.github/workflows/ci.yml`:

1. **Lint** — [Ruff](https://docs.astral.sh/ruff/) checks for code quality issues
2. **Test** — Installs all dependencies (including Playwright + Tesseract), then runs `pytest tests/`
3. **Docker build & push** — Only on pushes to `main` / `master`. Builds the image and pushes it to GitHub Container Registry (`ghcr.io`)

API keys expected in CI are stored as GitHub repository secrets (`VIRUSTOTAL_API_KEY`, `URLHAUS_API_KEY`). The Docker push uses the built-in `GITHUB_TOKEN` — no additional credentials needed.

---

## Project structure

```
surl/
├── app/                    # FastAPI application
│   ├── api/
│   │   ├── routes.py       # All API endpoints
│   │   └── schemas.py      # Pydantic request/response models
│   ├── core/
│   │   ├── config.py       # pydantic-settings — all env vars live here
│   │   ├── exceptions.py   # Global exception handler
│   │   ├── logger.py       # Structured JSON logger
│   │   └── middleware.py   # Rate limiting + security headers
│   ├── dynamic_analysis/   # Playwright sandbox, interaction engine, screenshots
│   ├── intelligence/       # Redirect chain, JS, credential, correlation engines
│   ├── services/
│   │   └── scan_orchestrator.py  # Main scan pipeline
│   ├── static/             # Frontend JS / CSS assets
│   ├── templates/          # Jinja2 HTML templates
│   └── main.py             # App factory — middleware wiring, mounts, health
│
├── static_analysis/        # DNS, WHOIS, TLS, lexical, brand detection modules
├── scoring_engine/         # Risk scoring, PBH fingerprint, explanation generator
├── threat_intel/           # VirusTotal, URLhaus, PhishTank integrations
├── workers/                # Optional Celery async workers
├── tests/                  # Test suite
│
├── Dockerfile              # Multi-stage production image
├── .dockerignore
├── docker-compose.yml
├── .env.example            # Environment variable template
├── requirements.txt        # Pinned Python dependencies
└── .github/
    └── workflows/
        └── ci.yml          # GitHub Actions CI/CD pipeline
```

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check (used by Docker + load balancers) |
| `POST` | `/scan` | Full static scan |
| `POST` | `/scan-dynamic` | Dynamic sandbox scan |
| `POST` | `/scan-image` | OCR a screenshot image and scan extracted URLs |
| `GET` | `/results` | Results page (HTML) |
| `GET` | `/dynamic-results` | Dynamic results page (HTML) |

---

## 🚀 Deployment (AWS EC2)

This project is containerized using Docker and can be deployed on AWS EC2 with minimal setup.

### Prerequisites

- AWS account
- An EC2 instance (Ubuntu recommended)
- Docker installed on the instance
- A domain name (optional but recommended)

---

### 1. Pull the Docker Image

```bash
docker pull joeljohngeorge8080/surl-api:latest
```

---

### 2. Run the Container

```bash
docker run -d \
  --name surl-api \
  -p 80:8000 \
  --restart always \
  joeljohngeorge8080/surl-api:latest
```

This maps port 80 on the EC2 instance to port 8000 inside the container.

---

### 3. Configure Environment Variables

```bash
docker run -d \
  --name surl-api \
  -p 80:8000 \
  --restart always \
  -e DEBUG=False \
  -e VIRUSTOTAL_API_KEY=your_key_here \
  joeljohngeorge8080/surl-api:latest
```

---

### 4. Access the Application

Once the container is running, open:

```
http://<your-ec2-public-ip>
```

Or if a domain is configured:

```
http://sentinelurl.site
```

---

### 5. (Optional) Domain Setup

If you have a domain (e.g., from Namecheap):

- Create an **A record** pointing to your EC2 public IP
- Wait for DNS propagation

---

### 6. (Optional) HTTPS Setup

For production use, configure HTTPS using:

- NGINX + Let's Encrypt (Certbot)
- or AWS Certificate Manager with an Application Load Balancer

---

### Notes

- The app exposes `/health` for health checks — ALB and monitoring tools can probe this
- View live logs with `docker logs -f surl-api`
- Ensure the EC2 security group allows inbound traffic on ports **80** (HTTP) and **22** (SSH)

---

### Future Improvements

- Move secrets to AWS Secrets Manager
- Use Amazon ECR instead of Docker Hub for the image registry
- Deploy with ECS/Fargate for auto-scaling
- Mount a persistent volume or use S3 for screenshot storage

---

## Notes

- The dynamic sandbox visits real URLs with a headless browser. Always run it in an isolated network environment.
- `DEBUG=False` is the default and should stay that way in production — it disables Swagger UI and enables stricter error handling.
- Screenshots saved during dynamic analysis are stored in the `screenshots/` volume mount. These are served at `/screenshots/<filename>`.
