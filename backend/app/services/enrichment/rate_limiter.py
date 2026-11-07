"""Redis sliding-window rate limiter for external threat intelligence providers."""

from __future__ import annotations

import time

from redis.asyncio import Redis


async def check_provider_rate_limit(
    redis: Redis,
    provider_name: str,
    max_requests: int,
    window_seconds: int = 60,
) -> bool:
    """Check if a request to `provider_name` is within rate limit quotas.

    Uses a Redis sorted set sliding window.
    Returns True if permitted (and registers the request timestamp), False if rate-limited.
    """
    key = f"sentinel:ratelimit:{provider_name}"
    now = time.time()
    cutoff = now - window_seconds

    pipe = redis.pipeline()
    # Remove records older than current window
    pipe.zremrangebyscore(key, "-inf", cutoff)
    # Count requests in window
    pipe.zcard(key)
    # Expire the key after window
    pipe.expire(key, window_seconds * 2)
    results = await pipe.execute()

    current_count = int(results[1])
    if current_count >= max_requests:
        return False

    # Record current timestamp
    await redis.zadd(key, {f"{now}:{current_count}": now})
    return True

