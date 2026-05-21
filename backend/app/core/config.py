from functools import lru_cache
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "KindMelody Security Scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    API_V1_PREFIX: str = "/api/v1"
    API_V1_STR: str = "/api/v1"

    SECRET_KEY: str = "change-me-in-production-kindmelody-2026"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    DATABASE_URL: str = "postgresql+asyncpg://kindmelody:kindmelody@postgres:5432/kindmelody"
    REDIS_URL: str = "redis://redis:6379/0"

    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    SCAN_TIMEOUT_SECONDS: int = 300
    SCANNER_TIMEOUT_SECONDS: int = 30
    MAX_SCANNERS_CONCURRENT: int = 7

    RATE_LIMIT_PER_MINUTE: int = 10
    RATE_LIMIT_PER_HOUR: int = 100

    BLOCKED_IP_RANGES: List[str] = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]

    ALLOWED_SCHEMES: List[str] = ["http", "https"]

    PROMETHEUS_MULTIPROC_DIR: Optional[str] = None

    OTEL_EXPORTER_OTLP_ENDPOINT: Optional[str] = None
    OTEL_SERVICE_NAME: str = "kindmelody-backend"

    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    CORS_ORIGINS: List[str] = ["http://localhost:3000", "https://kindmelody.dev"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
