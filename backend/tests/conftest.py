"""Shared pytest fixtures for real PostgreSQL + Redis integration and security tests."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import AsyncGenerator
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.db.session import get_redis_client, get_session_factory, reset_connections
from app.main import create_app
from scripts.seed_dev_data import seed_demo_environment

TEST_DB_NAME = "sentinel_ir_test"


def _normalize_local_host(url: str) -> str:
    """When running pytest on the host outside Docker, map compose service names to 127.0.0.1."""
    if Path("/.dockerenv").exists():
        return url
    parsed = urlparse(url)
    if parsed.hostname in ("postgres", "redis"):
        netloc = parsed.netloc.replace(parsed.hostname, "127.0.0.1")
        return urlunparse(parsed._replace(netloc=netloc))
    return url


def _swap_db_name(url: str, db_name: str) -> str:
    parsed = urlparse(_normalize_local_host(url))
    return urlunparse(parsed._replace(path=f"/{db_name}"))


def _to_psycopg_conninfo(sqlalchemy_url: str, db_name: str) -> str:
    cleaned = sqlalchemy_url.replace("postgresql+asyncpg://", "postgresql://").replace(
        "postgresql+psycopg://", "postgresql://"
    )
    return _swap_db_name(cleaned, db_name)


@pytest.fixture(scope="session")
def migrated_test_db() -> str:
    """Provision a clean `sentinel_ir_test` DB, grant `sentinel_app` ACLs, and test Alembic downgrade/upgrade."""
    base_settings = Settings()

    admin_conninfo = _to_psycopg_conninfo(base_settings.MIGRATION_DATABASE_URL, "postgres")
    test_owner_conninfo = _to_psycopg_conninfo(base_settings.MIGRATION_DATABASE_URL, TEST_DB_NAME)

    with psycopg.connect(admin_conninfo, autocommit=True) as conn:
        conn.execute(f"DROP DATABASE IF EXISTS {TEST_DB_NAME} WITH (FORCE);")
        conn.execute(f"CREATE DATABASE {TEST_DB_NAME} OWNER {base_settings.POSTGRES_USER};")

    app_user = base_settings.APP_DB_USER
    owner_user = base_settings.POSTGRES_USER
    with psycopg.connect(test_owner_conninfo, autocommit=True) as conn:
        conn.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        conn.execute(f"GRANT CONNECT ON DATABASE {TEST_DB_NAME} TO {app_user};")
        conn.execute(f"GRANT USAGE ON SCHEMA public TO {app_user};")
        conn.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner_user} IN SCHEMA public "
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {app_user};"
        )
        conn.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {owner_user} IN SCHEMA public "
            f"GRANT USAGE, SELECT ON SEQUENCES TO {app_user};"
        )

    test_mig_url = _swap_db_name(base_settings.MIGRATION_DATABASE_URL, TEST_DB_NAME)
    test_app_url = _swap_db_name(base_settings.DATABASE_URL, TEST_DB_NAME)
    test_sync_url = _swap_db_name(base_settings.SYNC_DATABASE_URL, TEST_DB_NAME)

    parsed_redis = urlparse(_normalize_local_host(base_settings.REDIS_URL))
    test_redis_url = urlunparse(parsed_redis._replace(path="/15"))

    backend_dir = Path(__file__).resolve().parents[1]
    test_evidence_dir = backend_dir.parent / "storage" / "test_evidence"
    test_evidence_dir.mkdir(parents=True, exist_ok=True)

    os.environ["APP_ENV"] = "testing"
    os.environ["MIGRATION_DATABASE_URL"] = test_mig_url
    os.environ["DATABASE_URL"] = test_app_url
    os.environ["SYNC_DATABASE_URL"] = test_sync_url
    os.environ["REDIS_URL"] = test_redis_url
    os.environ["COOKIE_SECURE"] = "false"
    os.environ["EVIDENCE_STORAGE_DIR"] = str(test_evidence_dir)
    get_settings.cache_clear()
    alembic_ini = backend_dir / "alembic.ini"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(backend_dir)

    # Gate requirement: verify clean upgrade -> downgrade -> upgrade cycle
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(alembic_ini), "upgrade", "head"],
        cwd=str(backend_dir),
        env=env,
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(alembic_ini), "downgrade", "base"],
        cwd=str(backend_dir),
        env=env,
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(alembic_ini), "upgrade", "head"],
        cwd=str(backend_dir),
        env=env,
        check=True,
    )
    return test_app_url


@pytest_asyncio.fixture
async def db_session(migrated_test_db: str) -> AsyncGenerator[AsyncSession, None]:
    get_settings.cache_clear()
    await reset_connections()
    redis = get_redis_client()
    await redis.flushdb()

    factory = get_session_factory()
    async with factory() as session:
        await seed_demo_environment(session)

    async with factory() as session:
        yield session

    await reset_connections()


@pytest_asyncio.fixture
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


async def login_as(
    client: AsyncClient,
    username: str,
    password: str | None = None,
) -> tuple[dict[str, str], str]:
    """Authenticate via `/api/v1/auth/login` and return `(cookies_dict, csrf_token)`."""
    pw = password or get_settings().DEMO_USER_PASSWORD
    client.cookies.clear()
    resp = await client.post(
        "/api/v1/auth/login",
        json={"identifier": username, "password": pw},
    )
    assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
    data = resp.json()
    csrf = data["csrf_token"]
    cookies = {k: v for k, v in client.cookies.items()}
    return cookies, csrf
