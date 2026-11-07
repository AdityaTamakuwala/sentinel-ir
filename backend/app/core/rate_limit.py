"""Redis-backed sliding/fixed window rate limiting and token bucket primitives."""

from __future__ import annotations

import time

from fastapi import status

from app.core.errors import AppError
from app.db.session import get_redis_client


async def enforce_rate_limit(
    bucket_key: str,
    *,
    max_requests: int,
    window_seconds: int,
) -> None:
    """Increment Redis window counter and raise 429 AppError if limit exceeded."""
    redis = get_redis_client()
    now_window = int(time.time() // window_seconds)
    redis_key = f"sentinel:rl:{bucket_key}:{now_window}"

    current = await redis.incr(redis_key)
    if current == 1:
        await redis.expire(redis_key, window_seconds + 2)

    if current > max_requests:
        raise AppError(
            code="RATE_LIMIT_EXCEEDED",
            message=f"Rate limit exceeded ({max_requests} requests per {window_seconds}s). Retry shortly.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details={"retry_after_seconds": window_seconds},
        )


async def try_acquire_provider_token(
    provider_slug: str,
    *,
    rate_limit_per_minute: int,
) -> bool:
    """Non-throwing Redis rate-limit token check for external Threat Intel providers."""
    if rate_limit_per_minute <= 0:
        return False
    redis = get_redis_client()
    minute_bucket = int(time.time() // 60)
    redis_key = f"sentinel:provider_rl:{provider_slug}:{minute_bucket}"
    current = await redis.incr(redis_key)
    if current == 1:
        await redis.expire(redis_key, 65)
    return int(current) <= rate_limit_per_minute

