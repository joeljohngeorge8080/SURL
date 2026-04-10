import time
import hashlib
from collections import defaultdict
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.logger import logger


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter keyed by client IP.
    Only active when settings.RATE_LIMIT_PER_MINUTE > 0.
    """

    def __init__(self, app, requests_per_minute: int = 30):
        super().__init__(app)
        self._rpm = requests_per_minute
        self._window = 60  # seconds
        # {ip_hash: [timestamp, ...]}
        self._hits: dict[str, list[float]] = defaultdict(list)

    @staticmethod
    def _hash_ip(ip: str) -> str:
        """Hash the IP so we never store raw addresses in memory."""
        return hashlib.sha256(ip.encode()).hexdigest()[:16]

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if self._rpm == 0:
            return await call_next(request)

        ip_hash = self._hash_ip(self._client_ip(request))
        now = time.monotonic()

        # Prune expired entries
        self._hits[ip_hash] = [
            t for t in self._hits[ip_hash] if now - t < self._window
        ]

        if len(self._hits[ip_hash]) >= self._rpm:
            logger.warning({"event": "rate_limit_exceeded", "ip_hash": ip_hash})
            return JSONResponse(
                status_code=429,
                content={"error": "Too many requests. Please wait and try again."},
                headers={"Retry-After": str(self._window)},
            )

        self._hits[ip_hash].append(now)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject production-grade security headers on every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        # Remove server fingerprint
        try:
            del response.headers["server"]
        except KeyError:
            pass
        return response
