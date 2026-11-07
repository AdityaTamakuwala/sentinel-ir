"""Environment-driven settings and strict production startup validation."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

FORBIDDEN_PROD_MARKERS = (
    "change_me",
    "changeme",
    "default",
    "demo",
    "example",
    "insecure",
    "password",
    "mdeymzq1",  # base64 prefix of "012345..."
)


class ProductionSafetyError(RuntimeError):
    """Raised when production mode detects unsafe configuration or demo artifacts."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Core
    APP_ENV: Literal["development", "testing", "production"] = "development"
    APP_NAME: str = "SENTINEL IR"
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"

    # Secrets
    SECRET_KEY: str = Field(default="dev_only_fallback_secret_key_do_not_use_in_prod_0123456789")
    ENCRYPTION_KEY: str = Field(default="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    METRICS_BEARER_TOKEN: str = Field(default="dev_metrics_token_0123456789")

    # Auth & Cookies
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    COOKIE_SECURE: bool = False
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "sentinel_ir"
    POSTGRES_USER: str = "sentinel_owner"
    POSTGRES_PASSWORD: str = "dev_owner_pw"
    APP_DB_USER: str = "sentinel_app"
    APP_DB_PASSWORD: str = "dev_app_pw"

    MIGRATION_DATABASE_URL: str = (
        "postgresql+asyncpg://sentinel_owner:dev_owner_pw@localhost:5432/sentinel_ir"
    )
    DATABASE_URL: str = (
        "postgresql+asyncpg://sentinel_app:dev_app_pw@localhost:5432/sentinel_ir"
    )
    SYNC_DATABASE_URL: str = (
        "postgresql+psycopg://sentinel_app:dev_app_pw@localhost:5432/sentinel_ir"
    )

    # Redis & Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # Seeding
    SEED_DEMO_DATA: bool = False
    DEMO_USER_PASSWORD: str = "SentinelDemo!2026#SOC"

    # Ingestion & Deduplication
    DEDUPLICATION_WINDOW_MINUTES: int = 10
    WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS: int = 300
    WEBHOOK_MAX_PAYLOAD_BYTES: int = 1_048_576

    # Evidence storage
    EVIDENCE_STORAGE_DIR: str = str(Path(__file__).resolve().parents[3] / "storage" / "evidence")
    MAX_UPLOAD_BYTES: int = 26_214_400
    CLAMAV_ENABLED: bool = False
    CLAMAV_HOST: str = "clamav"
    CLAMAV_PORT: int = 3310

    # Threat Intelligence Providers
    ENRICHMENT_USE_MOCK_WHEN_UNCONFIGURED: bool = True
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_BASE_URL: str = "https://www.virustotal.com/api/v3"
    VIRUSTOTAL_RATE_LIMIT_PER_MIN: int = 4
    VIRUSTOTAL_CACHE_TTL_SECONDS: int = 3600

    ABUSEIPDB_API_KEY: str = ""
    ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"
    ABUSEIPDB_RATE_LIMIT_PER_MIN: int = 30
    ABUSEIPDB_CACHE_TTL_SECONDS: int = 3600

    OTX_API_KEY: str = ""
    OTX_BASE_URL: str = "https://otx.alienvault.com/api/v1"
    OTX_RATE_LIMIT_PER_MIN: int = 30
    OTX_CACHE_TTL_SECONDS: int = 3600

    # Notifications
    SLACK_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL: str = ""
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "sentinel-ir@example.org"

    # Optional LLM Draft Summary (Tier 3)
    LLM_ENABLED: bool = False
    LLM_PROVIDER: str = "openai_compatible"
    LLM_BASE_URL: str = "https://api.openai.com/v1"
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_API_KEY: str = ""

    # Paths for bundled playbooks and offline MITRE STIX data
    PLAYBOOKS_DIR: str = str(Path(__file__).resolve().parents[3] / "playbooks")
    DATA_DIR: str = str(Path(__file__).resolve().parents[3] / "data")

    @property
    def resolved_playbooks_dir(self) -> Path:
        docker_path = Path("/app/playbooks")
        if docker_path.exists():
            return docker_path
        return Path(self.PLAYBOOKS_DIR)

    @property
    def resolved_data_dir(self) -> Path:
        docker_path = Path("/app/data")
        if docker_path.exists():
            return docker_path
        return Path(self.DATA_DIR)

    @property
    def effective_cookie_secure(self) -> bool:
        return True if self.APP_ENV == "production" else self.COOKIE_SECURE

    def validate_startup_safety(self) -> None:
        """Enforce cryptographic validity in all environments and strict safety in production."""
        try:
            Fernet(self.ENCRYPTION_KEY.encode("utf-8"))
        except Exception as exc:
            raise ProductionSafetyError(
                "ENCRYPTION_KEY must be a valid 32-byte URL-safe base64-encoded Fernet key."
            ) from exc

        if self.APP_ENV != "production":
            return

        violations: list[str] = []

        if not self.SECRET_KEY or len(self.SECRET_KEY.strip()) < 32:
            violations.append("SECRET_KEY is missing or shorter than 32 characters.")
        elif any(marker in self.SECRET_KEY.lower() for marker in FORBIDDEN_PROD_MARKERS) or (
            "dev_only" in self.SECRET_KEY.lower()
        ):
            violations.append("SECRET_KEY contains default, demo, or placeholder markers.")

        if any(marker in self.ENCRYPTION_KEY.lower() for marker in FORBIDDEN_PROD_MARKERS):
            violations.append("ENCRYPTION_KEY uses a default, placeholder, or test key.")

        if self.SEED_DEMO_DATA:
            violations.append("SEED_DEMO_DATA=true is strictly forbidden in production mode.")

        if not self.COOKIE_SECURE:
            violations.append("COOKIE_SECURE must be true in production mode.")

        if not self.METRICS_BEARER_TOKEN or len(self.METRICS_BEARER_TOKEN.strip()) < 24 or (
            any(marker in self.METRICS_BEARER_TOKEN.lower() for marker in FORBIDDEN_PROD_MARKERS)
            or "dev_" in self.METRICS_BEARER_TOKEN.lower()
        ):
            violations.append("METRICS_BEARER_TOKEN is missing, short, or uses a dev placeholder.")

        for db_label, url_val in (
            ("DATABASE_URL", self.DATABASE_URL),
            ("MIGRATION_DATABASE_URL", self.MIGRATION_DATABASE_URL),
        ):
            lowered = url_val.lower()
            if any(m in lowered for m in ("change_me", "dev_owner_pw", "dev_app_pw", ":postgres@")):
                violations.append(f"{db_label} contains default or placeholder credentials.")

        if violations:
            joined = " | ".join(violations)
            raise ProductionSafetyError(
                f"SENTINEL IR refused to start in production due to unsafe configuration: {joined}"
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

