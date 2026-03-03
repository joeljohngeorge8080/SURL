import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Application Config
    PROJECT_NAME: str = "Sentinel URL (SURL)"
    VERSION: str = "1.0.0"
    DEBUG: bool = False

    # External APIs (Threat Intelligence)
    VIRUSTOTAL_API_KEY: str | None = None
    URLHAUS_API_KEY: str | None = None
    # Add Google Safe Browsing and others here as needed

    # Storage Config
    DATABASE_URL: str | None = None
    # S3 / MinIO Settings
    S3_ENDPOINT_URL: str | None = None
    S3_ACCESS_KEY: str | None = None
    S3_SECRET_KEY: str | None = None
    S3_BUCKET_NAME: str = "surl-screenshots"

    # Worker Config (Celery)
    CELERY_BROKER_URL: str | None = None
    CELERY_RESULT_BACKEND: str | None = None

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

# Global settings instance
settings = Settings()
