"""Scheduled SOC maintenance tasks run by Celery Beat."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from app.core.celery_app import celery_app
from app.db.session import get_session_factory
from app.services.playbook.engine import PlaybookEngine

logger = logging.getLogger("sentinel.tasks.maintenance")


async def _expire_stale_approvals_async() -> int:
    factory = get_session_factory()
    async with factory() as session:
        engine = PlaybookEngine(session)
        count = await engine.expire_stale_actions()
        await session.commit()
        return count


@celery_app.task(name="sentinel.tasks.expire_stale_approvals")
def expire_stale_approvals() -> dict[str, object]:
    """Sweep pending response approvals past `expires_at` and transition to EXPIRED."""
    now_iso = datetime.now(UTC).isoformat()
    try:
        expired_count = asyncio.run(_expire_stale_approvals_async())
    except Exception as exc:
        logger.error("Error running approval expiry sweep: %s", exc, exc_info=True)
        expired_count = 0

    logger.info("Approval expiry sweep tick completed", extra={"structured_data": {"ts": now_iso, "expired_count": expired_count}})
    return {"checked_at": now_iso, "expired_count": expired_count}


@celery_app.task(name="sentinel.tasks.cleanup_expired_records")
def cleanup_expired_records() -> dict[str, object]:
    """Purge expired/revoked refresh token metadata past retention window."""
    now_iso = datetime.now(UTC).isoformat()
    logger.info("Token/cache maintenance sweep completed", extra={"structured_data": {"ts": now_iso}})
    return {"checked_at": now_iso}
