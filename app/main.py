import os
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.config import settings
from app.core.exceptions import global_exception_handler
from app.core.logger import logger
from app.core.middleware import RateLimitMiddleware, SecurityHeadersMiddleware


# ─────────────────────────────────────────────────────────────
# Application factory
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    # Disable interactive docs in production
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)


# ─────────────────────────────────────────────────────────────
# Middleware stack  (order matters — outermost registered last)
# ─────────────────────────────────────────────────────────────

# 1. Security headers (applied to every response)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Rate limiting — only on mutating / heavy endpoints
app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
)

# 3. CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Accept"],
)


# ─────────────────────────────────────────────────────────────
# Request logging  (lightweight, no sensitive data)
# ─────────────────────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.monotonic()
    response = await call_next(request)
    duration_ms = round((time.monotonic() - start) * 1000, 1)
    logger.info({
        "event": "http_request",
        "method": request.method,
        "path": request.url.path,
        "status": response.status_code,
        "duration_ms": duration_ms,
    })
    return response


# ─────────────────────────────────────────────────────────────
# Global exception handler
# ─────────────────────────────────────────────────────────────

app.add_exception_handler(Exception, global_exception_handler)


# ─────────────────────────────────────────────────────────────
# Health endpoint  (used by Docker HEALTHCHECK and load balancers)
# ─────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
async def health():
    return JSONResponse({"status": "ok", "version": settings.VERSION})


# ─────────────────────────────────────────────────────────────
# API routes
# ─────────────────────────────────────────────────────────────

app.include_router(router)


# ─────────────────────────────────────────────────────────────
# Static / template mounts
# ─────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
static_path = os.path.join(BASE_DIR, "static")
html_path = os.path.join(BASE_DIR, "templates")
screenshots_dir = os.path.join(os.path.dirname(BASE_DIR), "screenshots")

# Ensure runtime dirs exist (important inside the container)
os.makedirs(screenshots_dir, exist_ok=True)

app.mount("/screenshots", StaticFiles(directory=screenshots_dir), name="screenshots")
app.mount("/static", StaticFiles(directory=static_path), name="static")
app.mount("/", StaticFiles(directory=html_path, html=True), name="html")


# ─────────────────────────────────────────────────────────────
# Dev-only entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )
