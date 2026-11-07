"""Celery worker tasks for durable asynchronous playbook execution."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from app.core.celery_app import celery_app
from app.db.session import get_session_factory
from app.services.playbook.engine import PlaybookEngine

logger = logging.getLogger("sentinel.tasks.playbook")


async def _run_playbook_async(execution_id_str: str) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        engine = PlaybookEngine(session)
        execution = await engine.execute_loop(uuid.UUID(execution_id_str))
        await session.commit()
        return {
            "execution_id": str(execution.id),
            "status": execution.status,
            "current_step_index": execution.current_step_index,
        }


async def _resume_playbook_async(execution_id_str: str, action_approved: bool) -> dict[str, Any]:
    factory = get_session_factory()
    async with factory() as session:
        engine = PlaybookEngine(session)
        execution = await engine.resume_execution(uuid.UUID(execution_id_str), action_approved=action_approved)
        await session.commit()
        return {
            "execution_id": str(execution.id),
            "status": execution.status,
            "current_step_index": execution.current_step_index,
        }


@celery_app.task(name="sentinel.tasks.execute_playbook")
def execute_playbook_task(execution_id: str) -> dict[str, Any]:
    """Execute or advance a playbook until completion or WAITING_APPROVAL."""
    logger.info("Executing playbook task for execution %s", execution_id)
    return asyncio.run(_run_playbook_async(execution_id))


@celery_app.task(name="sentinel.tasks.resume_playbook")
def resume_playbook_task(execution_id: str, action_approved: bool) -> dict[str, Any]:
    """Resume a playbook halted in WAITING_APPROVAL after an approval decision."""
    logger.info("Resuming playbook task for execution %s (approved=%s)", execution_id, action_approved)
    return asyncio.run(_resume_playbook_async(execution_id, action_approved))

