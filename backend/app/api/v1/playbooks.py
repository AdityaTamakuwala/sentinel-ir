"""API router for Declarative Playbooks and Playbook Executions."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AppError
from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.automation import Playbook, PlaybookExecution
from app.models.base import utc_now
from app.models.user import User
from app.schemas.playbook import (
    PlaybookDetailOut,
    PlaybookExecuteRequest,
    PlaybookExecutionOut,
    PlaybookExecutionStepOut,
    PlaybookOut,
)
from app.services.audit_service import AuditService
from app.services.playbook.engine import PlaybookEngine
from app.services.playbook.loader import PlaybookLoader

router = APIRouter(prefix="/playbooks", tags=["playbooks"])


def _format_execution_out(execution: PlaybookExecution, users_map: dict[uuid.UUID, str] | None = None) -> PlaybookExecutionOut:
    users_map = users_map or {}
    steps_out: list[PlaybookExecutionStepOut] = [
        PlaybookExecutionStepOut(
            id=s.id,
            step_index=s.step_index,
            step_id=s.step_id,
            step_type=s.step_type,
            step_name=s.step_name,
            status=s.status,
            attempt_count=s.attempt_count,
            inputs_json=s.inputs_json or {},
            outputs_json=s.outputs_json or {},
            error_details=s.error_details,
            duration_ms=s.duration_ms,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in (execution.steps or [])
    ]
    steps_out.sort(key=lambda s: s.step_index)

    return PlaybookExecutionOut(
        id=execution.id,
        playbook_id=execution.playbook_id,
        playbook_slug=execution.playbook.slug if execution.playbook else "unknown",
        playbook_name=execution.playbook.name if execution.playbook else "Unknown Playbook",
        version_number=execution.version_number,
        incident_id=execution.incident_id,
        alert_id=execution.alert_id,
        triggered_by=execution.triggered_by,
        triggered_by_username=users_map.get(execution.triggered_by_user_id) if execution.triggered_by_user_id else None,
        is_dry_run=execution.is_dry_run,
        status=execution.status,
        current_step_index=execution.current_step_index,
        current_step_id=execution.current_step_id,
        waiting_response_action_id=execution.waiting_response_action_id,
        error_message=execution.error_message,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        created_at=execution.created_at,
        steps=steps_out,
    )


@router.get("", response_model=list[PlaybookOut])
async def list_playbooks(
    session: AsyncSession = Depends(get_db_session),
    _user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_VIEW)),
) -> list[PlaybookOut]:
    """List all registered playbooks."""
    stmt = (
        select(Playbook)
        .options(selectinload(Playbook.versions))
        .order_by(Playbook.name.asc())
    )
    result = await session.execute(stmt)
    playbooks = result.scalars().all()

    # If no playbooks exist in DB yet, auto-sync from filesystem
    if not playbooks:
        await PlaybookLoader.sync_builtin_playbooks(session)
        result = await session.execute(stmt)
        playbooks = result.scalars().all()

    out: list[PlaybookOut] = []
    for pb in playbooks:
        # Determine step count from active version
        active_v = next((v for v in pb.versions if v.version == pb.current_version), None)
        step_count = 0
        if active_v and isinstance(active_v.definition_json, dict):
            step_count = len(active_v.definition_json.get("steps", []))

        out.append(
            PlaybookOut(
                id=pb.id,
                slug=pb.slug,
                name=pb.name,
                description=pb.description,
                is_enabled=pb.is_enabled,
                auto_trigger_mode=pb.auto_trigger_mode,
                current_version=pb.current_version,
                is_builtin=pb.is_builtin,
                step_count=step_count,
                created_at=pb.created_at,
                updated_at=pb.updated_at,
            )
        )
    return out


@router.post("/sync", status_code=status.HTTP_200_OK)
async def sync_playbooks(
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_MANAGE)),
) -> dict[str, Any]:
    """Force synchronization of YAML playbooks from disk into database."""
    synced = await PlaybookLoader.sync_builtin_playbooks(session)
    await AuditService.record(
        session,
        action="playbook.sync_all",
        actor=user,
        target_type="playbooks",
        target_id=None,
        details={"synced_count": len(synced)},
    )
    await session.commit()
    return {"status": "success", "synced_count": len(synced), "playbooks": [p.slug for p in synced]}


@router.get("/executions", response_model=list[PlaybookExecutionOut])
async def list_executions(
    status_filter: str | None = Query(None, alias="status"),
    incident_id: uuid.UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
    _user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_VIEW)),
) -> list[PlaybookExecutionOut]:
    """List playbook executions with pagination and filtering."""
    query = (
        select(PlaybookExecution)
        .options(
            selectinload(PlaybookExecution.playbook),
            selectinload(PlaybookExecution.steps),
        )
        .order_by(desc(PlaybookExecution.created_at))
        .offset(offset)
        .limit(limit)
    )

    if status_filter:
        query = query.where(PlaybookExecution.status == status_filter)
    if incident_id:
        query = query.where(PlaybookExecution.incident_id == incident_id)

    res = await session.execute(query)
    executions = res.scalars().all()

    # Preload usernames
    user_ids = {e.triggered_by_user_id for e in executions if e.triggered_by_user_id}
    users_map: dict[uuid.UUID, str] = {}
    if user_ids:
        u_stmt = select(User.id, User.username).where(User.id.in_(user_ids))
        u_res = await session.execute(u_stmt)
        users_map = {row[0]: row[1] for row in u_res.all()}

    return [_format_execution_out(e, users_map) for e in executions]


@router.get("/executions/{id}", response_model=PlaybookExecutionOut)
async def get_execution(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    _user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_VIEW)),
) -> PlaybookExecutionOut:
    """Retrieve full execution state and step history."""
    stmt = (
        select(PlaybookExecution)
        .where(PlaybookExecution.id == id)
        .options(
            selectinload(PlaybookExecution.playbook),
            selectinload(PlaybookExecution.steps),
        )
    )
    res = await session.execute(stmt)
    execution = res.scalar_one_or_none()
    if not execution:
        raise AppError(code="NOT_FOUND", message="Playbook execution not found", status_code=404)

    users_map: dict[uuid.UUID, str] = {}
    if execution.triggered_by_user_id:
        u_stmt = select(User.username).where(User.id == execution.triggered_by_user_id)
        u_name = (await session.execute(u_stmt)).scalar_one_or_none()
        if u_name:
            users_map[execution.triggered_by_user_id] = u_name

    return _format_execution_out(execution, users_map)


@router.post("/executions/{id}/cancel", response_model=PlaybookExecutionOut)
async def cancel_execution(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_EXECUTE)),
) -> PlaybookExecutionOut:
    """Cancel an active or waiting playbook execution."""
    stmt = (
        select(PlaybookExecution)
        .where(PlaybookExecution.id == id)
        .options(
            selectinload(PlaybookExecution.playbook),
            selectinload(PlaybookExecution.steps),
        )
    )
    res = await session.execute(stmt)
    execution = res.scalar_one_or_none()
    if not execution:
        raise AppError(code="NOT_FOUND", message="Playbook execution not found", status_code=404)

    if execution.status in ("COMPLETED", "FAILED", "CANCELLED", "EXPIRED"):
        raise AppError(code="INVALID_STATE", message=f"Execution is already {execution.status}", status_code=400)

    execution.status = "CANCELLED"
    execution.completed_at = utc_now()
    execution.error_message = f"Cancelled by analyst {user.username}"

    await AuditService.record(
        session,
        action="playbook.execution.cancelled",
        actor=user,
        target_type="playbook_execution",
        target_id=str(execution.id),
        details={"previous_status": execution.status},
    )

    await session.commit()
    return _format_execution_out(execution, {user.id: user.username})


@router.get("/{id_or_slug}", response_model=PlaybookDetailOut)
async def get_playbook_detail(
    id_or_slug: str,
    session: AsyncSession = Depends(get_db_session),
    _user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_VIEW)),
) -> PlaybookDetailOut:
    """Retrieve detailed playbook definition with YAML and input schema."""
    is_uuid = False
    try:
        parsed_uuid = uuid.UUID(id_or_slug)
        is_uuid = True
    except ValueError:
        parsed_uuid = None

    if is_uuid:
        stmt = select(Playbook).where(Playbook.id == parsed_uuid).options(selectinload(Playbook.versions))
    else:
        stmt = select(Playbook).where(Playbook.slug == id_or_slug).options(selectinload(Playbook.versions))

    res = await session.execute(stmt)
    playbook = res.scalar_one_or_none()
    if not playbook:
        raise AppError(code="NOT_FOUND", message=f"Playbook '{id_or_slug}' not found", status_code=404)

    active_v = next((v for v in playbook.versions if v.version == playbook.current_version), None)
    if not active_v:
        raise AppError(code="NOT_FOUND", message="Active version definition not found", status_code=404)

    step_count = len(active_v.definition_json.get("steps", [])) if isinstance(active_v.definition_json, dict) else 0

    return PlaybookDetailOut(
        id=playbook.id,
        slug=playbook.slug,
        name=playbook.name,
        description=playbook.description,
        is_enabled=playbook.is_enabled,
        auto_trigger_mode=playbook.auto_trigger_mode,
        current_version=playbook.current_version,
        is_builtin=playbook.is_builtin,
        step_count=step_count,
        created_at=playbook.created_at,
        updated_at=playbook.updated_at,
        definition_yaml=active_v.definition_yaml,
        definition_json=active_v.definition_json,
        trigger_config=active_v.trigger_config,
        input_schema=active_v.input_schema,
    )


@router.post("/{id_or_slug}/execute", response_model=PlaybookExecutionOut)
async def execute_playbook(
    id_or_slug: str,
    payload: PlaybookExecuteRequest,
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(require_permission(PermissionCode.PLAYBOOKS_EXECUTE)),
) -> PlaybookExecutionOut:
    """Trigger playbook execution (runs automated steps and halts at approval checkpoints)."""
    engine = PlaybookEngine(session)

    execution = await engine.create_execution(
        playbook_id_or_slug=id_or_slug,
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        triggered_by="manual",
        triggered_by_user_id=user.id,
        parameters=payload.parameters,
        is_dry_run=payload.is_dry_run,
        idempotency_key=payload.idempotency_key,
    )

    # Run the execution loop
    execution = await engine.execute_loop(execution.id)
    await session.commit()

    return _format_execution_out(execution, {user.id: user.username})
