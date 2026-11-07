"""SQLAlchemy 2.x async engine/session factory and Redis client management."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None
_redis_client: aioredis.Redis | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            echo=False,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory()
    async with factory() as session:
        yield session


def get_redis_client() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def reset_connections() -> None:
    """Dispose cached engine/Redis pools (useful in test fixtures and shutdown)."""
    global _engine, _session_factory, _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.aclose()  # type: ignore[attr-defined]
        except Exception:  # noqa: S110
            pass
        _redis_client = None
    if _engine is not None:
        try:
            await _engine.dispose()
        except Exception:  # noqa: S110
            pass
        _engine = None
    _session_factory = None


async def check_database_ready() -> tuple[bool, str]:
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True, "ok"
    except Exception as exc:
        return False, type(exc).__name__


async def check_redis_ready() -> tuple[bool, str]:
    try:
        client = get_redis_client()
        pong = await client.ping()
        return bool(pong), "ok" if pong else "ping_false"
    except Exception as exc:
        return False, type(exc).__name__

