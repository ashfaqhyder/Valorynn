"""Application configuration sourced only from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(value: str | None, default: bool = False) -> bool:
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    secret_key: str
    database_path: Path
    cookie_secure: bool
    environment: str
    scan_timeout_seconds: float
    max_source_bytes: int

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


def get_settings() -> Settings:
    environment = os.getenv("VALORYNN_ENV", "development")
    secret = os.getenv("VALORYNN_SECRET_KEY", "")
    if not secret:
        if environment.lower() == "production":
            raise RuntimeError("VALORYNN_SECRET_KEY must be set in production.")
        secret = "development-only-change-before-deployment"
    return Settings(
        secret_key=secret,
        database_path=Path(os.getenv("VALORYNN_DATABASE_PATH", "data/valorynn.sqlite3")),
        cookie_secure=_bool(os.getenv("VALORYNN_COOKIE_SECURE"), environment.lower() == "production"),
        environment=environment,
        scan_timeout_seconds=float(os.getenv("VALORYNN_SCAN_TIMEOUT_SECONDS", "12")),
        max_source_bytes=int(os.getenv("VALORYNN_MAX_SOURCE_BYTES", str(5 * 1024 * 1024))),
    )


settings = get_settings()
