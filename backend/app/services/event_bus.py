"""Redis Pub/Sub real-time event fan-out with monotonic IDs and Last-Event-ID replay buffer."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.db.session import get_redis_client

logger = logging.getLogger("sentinel.events")

SSE_CHANNEL = "sentinel:sse:broadcast"
SSE_SEQ_KEY = "sentinel:sse:seq"
SSE_HISTORY_KEY = "sentinel:sse:history"
SSE_HISTORY_MAX_LEN = 250


async def publish_realtime_event(
    event_type: str,
    payload: dict[str, Any],
    *,
    required_permission: str = "dashboard:view",
    target_user_id: str | None = None,
) -> int | None:
    """Publish a structured event to Redis Pub/Sub and retain in bounded replay history."""
    try:
        redis = get_redis_client()
        event_id = int(await redis.incr(SSE_SEQ_KEY))
        envelope = {
            "id": event_id,
            "type": event_type,
            "timestamp": datetime.now(UTC).isoformat(),
            "required_permission": required_permission,
            "target_user_id": target_user_id,
            "data": payload,
        }
        serialized = json.dumps(envelope, default=str)
        await redis.rpush(SSE_HISTORY_KEY, serialized)
        await redis.ltrim(SSE_HISTORY_KEY, -SSE_HISTORY_MAX_LEN, -1)
        await redis.publish(SSE_CHANNEL, serialized)
        return event_id
    except Exception:
        # Never fail a core database write if Redis pub/sub has a transient hiccup
        logger.warning("Failed to publish SSE event", extra={"structured_data": {"type": event_type}})
        return None

