from pydantic_settings import BaseSettings
from pydantic import Field
from pydantic import ConfigDict
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Application ────────────────────────────────────────────────────────
    PROJECT_NAME: str = "Sentinel URL (SURL)"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Port used by docker-compose on the host side (not used by the app itself)
    API_PORT: int = 8000

    # Comma-separated list of allowed CORS origins.
    CORS_ORIGINS: str = ""

    # ── Rate Limiting ──────────────────────────────────────────────────────
    RATE_LIMIT_PER_MINUTE: int = Field(default=30, ge=0)

    # ── Threat Intelligence APIs ───────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str | None = None
    URLHAUS_API_KEY: str | None = None

    # ── Storage ────────────────────────────────────────────────────────────
    DATABASE_URL: str | None = None

    # ── Object Storage (S3 / MinIO) ────────────────────────────────────────
    S3_ENDPOINT_URL: str | None = None
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_BUCKET_NAME: str = "surl-screenshots"

    # ── Async Workers ──────────────────────────────────────────────────────
    CELERY_BROKER_URL: str | None = None
    CELERY_RESULT_BACKEND: str | None = None

    # ── Computed helpers ───────────────────────────────────────────────────
    @property
    def cors_origin_list(self) -> List[str]:
        """Return CORS_ORIGINS as a Python list, or ['*'] if unset/empty."""
        if not self.CORS_ORIGINS or self.CORS_ORIGINS.strip() == "":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache()
def get_settings() -> Settings:
    return Settings()


# Global singleton
settings = get_settings()
