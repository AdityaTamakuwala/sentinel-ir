"""Milestone 0 tests: production safety refusal, structured logging redaction, health & metrics."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient

from app.core.config import ProductionSafetyError, Settings
from app.core.logging import redact_mapping
from app.main import create_app


def test_production_refuses_demo_or_default_secrets() -> None:
    """Section 2 & 5: Production mode must refuse to start with demo flags or placeholder secrets."""
    valid_fernet = Fernet.generate_key().decode("ascii")

    # 1. Default secret key must fail in production
    s_default_secret = Settings(
        APP_ENV="production",
        SECRET_KEY="dev_only_fallback_secret_key_do_not_use_in_prod_0123456789",
        ENCRYPTION_KEY=valid_fernet,
        METRICS_BEARER_TOKEN="prod_metrics_strong_token_998877665544",
        COOKIE_SECURE=True,
        SEED_DEMO_DATA=False,
        DATABASE_URL="postgresql+asyncpg://sentinel_app:StrongProdPw99!@postgres:5432/sentinel_ir",
        MIGRATION_DATABASE_URL="postgresql+asyncpg://sentinel_owner:StrongOwnerPw99!@postgres:5432/sentinel_ir",
    )
    with pytest.raises(ProductionSafetyError, match="SECRET_KEY"):
        s_default_secret.validate_startup_safety()

    # 2. SEED_DEMO_DATA=True must fail in production
    s_demo_enabled = Settings(
        APP_ENV="production",
        SECRET_KEY="xK9#vM2$pL8@qR5!wZ1^nB4&tY7*uJ0_hG3+fD6=sA9",
        ENCRYPTION_KEY=valid_fernet,
        METRICS_BEARER_TOKEN="prod_metrics_strong_token_998877665544",
        COOKIE_SECURE=True,
        SEED_DEMO_DATA=True,
        DATABASE_URL="postgresql+asyncpg://sentinel_app:StrongProdPw99!@postgres:5432/sentinel_ir",
        MIGRATION_DATABASE_URL="postgresql+asyncpg://sentinel_owner:StrongOwnerPw99!@postgres:5432/sentinel_ir",
    )
    with pytest.raises(ProductionSafetyError, match="SEED_DEMO_DATA"):
        s_demo_enabled.validate_startup_safety()

    # 3. Valid hardened production config must pass
    s_valid_prod = Settings(
        APP_ENV="production",
        SECRET_KEY="xK9#vM2$pL8@qR5!wZ1^nB4&tY7*uJ0_hG3+fD6=sA9",
        ENCRYPTION_KEY=valid_fernet,
        METRICS_BEARER_TOKEN="prod_metrics_strong_token_998877665544",
        COOKIE_SECURE=True,
        SEED_DEMO_DATA=False,
        DATABASE_URL="postgresql+asyncpg://sentinel_app:StrongProdPw99!@postgres:5432/sentinel_ir",
        MIGRATION_DATABASE_URL="postgresql+asyncpg://sentinel_owner:StrongOwnerPw99!@postgres:5432/sentinel_ir",
    )
    s_valid_prod.validate_startup_safety()


def test_structured_logging_redacts_secrets() -> None:
    raw = {
        "username": "analyst_l1",
        "password": "SuperSecretPassword!",
        "nested": {
            "virustotal_api_key": "vt_live_12345",
            "safe_field": "INC-2026-0001",
        },
    }
    redacted = redact_mapping(raw)
    assert redacted["username"] == "analyst_l1"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["virustotal_api_key"] == "[REDACTED]"
    assert redacted["nested"]["safe_field"] == "INC-2026-0001"


@pytest.mark.asyncio
async def test_liveness_security_headers_and_metrics_auth() -> None:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/health/live", headers={"X-Request-ID": "req-m0-check-001"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "alive"
        assert resp.headers["X-Request-ID"] == "req-m0-check-001"
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"

        # /metrics without token must be rejected with 401
        unauth_metrics = await client.get("/metrics")
        assert unauth_metrics.status_code == 401
        assert unauth_metrics.json()["error"]["correlation_id"]

