"""Authenticated Server-Sent Events (SSE) stream fanned out via Redis Pub/Sub (`/api/v1/events`)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import StreamingResponse

from app.core.rbac import PermissionCode, require_authenticated_user, role_has_permission
from app.db.session import get_redis_client
from app.models.user import User
from app.services.event_bus import SSE_CHANNEL, SSE_HISTORY_KEY

router = APIRouter(prefix="/events", tags=["Real-Time Telemetry Stream"])


def _user_can_receive_event(user_role: str, user_id_str: str, envelope: dict[str, Any]) -> bool:
    target_uid = envelope.get("target_user_id")
    if target_uid and str(target_uid) != user_id_str:
        return False

    req_perm = envelope.get("required_permission")
    if not req_perm:
        return True
    try:
        perm_enum = PermissionCode(str(req_perm))
    except ValueError:
        return False
    return role_has_permission(user_role, perm_enum)


def _format_sse_frame(envelope: dict[str, Any]) -> str:
    ev_id = envelope.get("id", 0)
    ev_type = envelope.get("type", "message")
    data_str = json.dumps(envelope, separators=(",", ":"), default=str)
    return f"id: {ev_id}\nevent: {ev_type}\ndata: {data_str}\n\n"


@router.get("/stream")
async def stream_realtime_events(
    request: Request,
    last_event_id_header: str | None = Header(default=None, alias="Last-Event-ID"),
    last_event_id_query: int | None = Query(default=None, alias="last_event_id", ge=0),
    once: bool = Query(
        default=False,
        description="Emit initial handshake + replay buffer and close immediately (used by automated tests).",
    ),
    user: User = Depends(require_authenticated_user()),
) -> StreamingResponse:
    user_role = user.role.name if user.role else "soc_l1"
    user_id_str = str(user.id)

    parsed_last_id: int | None = last_event_id_query
    if parsed_last_id is None and last_event_id_header:
        try:
            parsed_last_id = int(last_event_id_header.strip())
        except ValueError:
            parsed_last_id = None

    async def event_generator() -> AsyncGenerator[str, None]:
        redis = get_redis_client()
        yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'role': user_role})}\n\n"

        # Replay missed events from bounded Redis history when Last-Event-ID is supplied
        if parsed_last_id is not None:
            history_raw = await redis.lrange(SSE_HISTORY_KEY, 0, -1)
            for item_str in history_raw:
                try:
                    env = json.loads(item_str)
                except json.JSONDecodeError:
                    continue
                if int(env.get("id", 0)) > parsed_last_id and _user_can_receive_event(
                    user_role, user_id_str, env
                ):
                    yield _format_sse_frame(env)

        if once:
            return

        pubsub = redis.pubsub()
        await pubsub.subscribe(SSE_CHANNEL)
        try:
            while True:
                if await request.is_disconnected():
                    break
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
                if msg and msg.get("type") == "message":
                    raw_data = msg.get("data")
                    if isinstance(raw_data, str):
                        try:
                            env = json.loads(raw_data)
                        except json.JSONDecodeError:
                            continue
                        if _user_can_receive_event(user_role, user_id_str, env):
                            yield _format_sse_frame(env)
                else:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(0.05)
        finally:
            await pubsub.unsubscribe(SSE_CHANNEL)
            await pubsub.aclose()  # type: ignore[attr-defined]

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

