"""API router for Human-Approved Response Actions and Four-Eyes Governance."""

from __future__ import annotations

import datetime
import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AppError
from app.core.rbac import (
    ROLE_PERMISSION_MATRIX,
    PermissionCode,
    RoleName,
    require_permission,
)
from app.db.session import get_db_session
from app.models.automation import ResponseAction, ResponseApproval
from app.models.base import utc_now
from app.models.user import User
from app.schemas.playbook import (
    ResponseActionOut,
    ResponseActionProposeRequest,
    ResponseApprovalOut,
    ResponseApprovalRequest,
)
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event
from app.services.playbook.adapter import get_response_adapter
from app.services.playbook.engine import PlaybookEngine
from app.services.playbook.four_eyes import validate_response_approval

router = APIRouter(prefix="/responses", tags=["responses"])


def _format_action_out(action: ResponseAction, users_map: dict[uuid.UUID, str] | None = None) -> ResponseActionOut:
    users_map = users_map or {}
    req_username = users_map.get(action.requested_by_id) or (action.requested_by.username if action.requested_by else "unknown")
    appr_username = None
    if action.approved_by_id:
        appr_username = users_map.get(action.approved_by_id) or (action.approved_by.username if action.approved_by else None)

    approvals_out: list[ResponseApprovalOut] = []
    for app in (action.approvals or []):
        approver_name = users_map.get(app.approver_id) or (app.approver.username if getattr(app, "approver", None) else "unknown")
        approvals_out.append(
            ResponseApprovalOut(
                id=app.id,
                response_action_id=app.response_action_id,
                approver_id=app.approver_id,
                approver_username=approver_name,
                decision=app.decision,
                comment=app.comment,
                decided_at=app.decided_at,
            )
        )

    return ResponseActionOut(
        id=action.id,
        incident_id=action.incident_id,
        playbook_execution_id=action.playbook_execution_id,
        action_type=action.action_type,
        target_indicator=action.target_indicator,
        target_hostname=action.target_hostname,
        target_username=action.target_username,
        title=action.title,
        justification=action.justification,
        parameters_json=action.parameters_json or {},
        risk_impact=action.risk_impact,
        status=action.status,
        adapter_name=action.adapter_name,
        is_simulated=action.is_simulated,
        requested_by_id=action.requested_by_id,
        requested_by_username=req_username,
        approved_by_id=action.approved_by_id,
        approved_by_username=appr_username,
        expires_at=action.expires_at,
        executed_at=action.executed_at,
        execution_result=action.execution_result,
        failure_reason=action.failure_reason,
        created_at=action.created_at,
        approvals=approvals_out,
    )


@router.get("/actions", response_model=list[ResponseActionOut])
async def list_response_actions(
    status_filter: str | None = Query(None, alias="status"),
    incident_id: uuid.UUID | None = Query(None),
    risk_impact: str | None = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
    _user: User = Depends(require_permission(PermissionCode.INCIDENTS_VIEW)),
) -> list[ResponseActionOut]:
    """List response actions with status, incident, and risk impact filters."""
    query = (
        select(ResponseAction)
        .options(
            selectinload(ResponseAction.requested_by),
            selectinload(ResponseAction.approved_by),
            selectinload(ResponseAction.approvals).selectinload(ResponseApproval.approver),
        )
        .order_by(desc(ResponseAction.created_at))
        .offset(offset)
        .limit(limit)
    )

    if status_filter:
        query = query.where(ResponseAction.status == status_filter)
    if incident_id:
        query = query.where(ResponseAction.incident_id == incident_id)
    if risk_impact:
        query = query.where(ResponseAction.risk_impact == risk_impact)

    res = await session.execute(query)
    actions = res.scalars().all()

    # Preload user map for faster lookup
    user_ids: set[uuid.UUID] = set()
    for a in actions:
        user_ids.add(a.requested_by_id)
        if a.approved_by_id:
            user_ids.add(a.approved_by_id)
        for app in a.approvals:
            user_ids.add(app.approver_id)

    users_map: dict[uuid.UUID, str] = {}
    if user_ids:
        u_stmt = select(User.id, User.username).where(User.id.in_(user_ids))
        u_res = await session.execute(u_stmt)
        users_map = {row[0]: row[1] for row in u_res.all()}

    return [_format_action_out(a, users_map) for a in actions]


@router.get("/actions/{id}", response_model=ResponseActionOut)
async def get_response_action(
    id: uuid.UUID,
    session: AsyncSession = Depends(get_db_session),
    _user: User = Depends(require_permission(PermissionCode.INCIDENTS_VIEW)),
) -> ResponseActionOut:
    """Retrieve response action details, parameters, and full approval trail."""
    stmt = (
        select(ResponseAction)
        .where(ResponseAction.id == id)
        .options(
            selectinload(ResponseAction.requested_by),
            selectinload(ResponseAction.approved_by),
            selectinload(ResponseAction.approvals).selectinload(ResponseApproval.approver),
        )
    )
    res = await session.execute(stmt)
    action = res.scalar_one_or_none()
    if not action:
        raise AppError(code="NOT_FOUND", message="Response action not found", status_code=404)

    return _format_action_out(action)


@router.post("/actions", response_model=ResponseActionOut, status_code=status.HTTP_201_CREATED)
async def propose_response_action(
    payload: ResponseActionProposeRequest,
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(require_permission(PermissionCode.RESPONSE_PROPOSE)),
) -> ResponseActionOut:
    """Propose a manual containment action requiring human approval."""
    expires_at = utc_now() + datetime.timedelta(hours=payload.timeout_hours)

    action = ResponseAction(
        incident_id=payload.incident_id,
        action_type=payload.action_type,
        title=payload.title,
        justification=payload.justification,
        parameters_json=payload.parameters,
        risk_impact=payload.risk_impact,
        target_indicator=payload.target_indicator,
        target_hostname=payload.target_hostname,
        target_username=payload.target_username,
        status="PENDING_APPROVAL",
        adapter_name="simulated",
        is_simulated=True,
        requested_by_id=user.id,
        expires_at=expires_at,
    )
    session.add(action)
    await session.flush()

    await AuditService.record(
        session,
        action="response.action.proposed",
        actor=user,
        target_type="response_action",
        target_id=str(action.id),
        details={
            "action_type": action.action_type,
            "risk_impact": action.risk_impact,
            "incident_id": str(action.incident_id),
        },
    )

    await publish_realtime_event(
        "response.action.proposed",
        {
            "action_id": str(action.id),
            "incident_id": str(action.incident_id),
            "risk_impact": action.risk_impact,
        },
    )

    await session.commit()
    return await get_response_action(action.id, session=session, _user=user)


@router.post("/actions/{id}/approve", response_model=ResponseActionOut)
async def approve_response_action(
    id: uuid.UUID,
    payload: ResponseApprovalRequest,
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(require_permission(PermissionCode.RESPONSE_APPROVE_LOW)),
) -> ResponseActionOut:
    """Approve a proposed response action enforcing four-eyes validation and role authorization."""
    stmt = (
        select(ResponseAction)
        .where(ResponseAction.id == id)
        .options(
            selectinload(ResponseAction.requested_by),
            selectinload(ResponseAction.approved_by),
            selectinload(ResponseAction.approvals).selectinload(ResponseApproval.approver),
        )
    )
    res = await session.execute(stmt)
    action = res.scalar_one_or_none()
    if not action:
        raise AppError(code="NOT_FOUND", message="Response action not found", status_code=404)

    # Fetch approver user record with role
    u_stmt = select(User).where(User.id == user.id).options(selectinload(User.role))
    u_res = await session.execute(u_stmt)
    approver = u_res.scalar_one()

    # Determine approver permissions based on role
    role_key = RoleName(approver.role.name) if approver.role else RoleName.SOC_L1
    user_perms = ROLE_PERMISSION_MATRIX.get(role_key, frozenset())

    # FOUR-EYES AND RISK-TIER VERIFICATION
    validate_response_approval(action, approver, user_perms)

    # Immutable approval record
    approval = ResponseApproval(
        response_action_id=action.id,
        approver_id=approver.id,
        decision="approved",
        comment=payload.comment,
        decided_at=utc_now(),
    )
    session.add(approval)
    action.approvals.append(approval)

    action.status = "APPROVED"
    action.approved_by_id = approver.id
    await session.flush()

    await AuditService.record(
        session,
        action="response.action.approved",
        actor=approver,
        target_type="response_action",
        target_id=str(action.id),
        details={
            "action_type": action.action_type,
            "risk_impact": action.risk_impact,
            "requested_by_id": str(action.requested_by_id),
            "comment": payload.comment,
        },
    )

    # If this action is tied to a waiting PlaybookExecution, resume the playbook engine!
    if action.playbook_execution_id:
        engine = PlaybookEngine(session)
        await engine.resume_execution(action.playbook_execution_id, action_approved=True)
    else:
        # Standalone manual action: execute via adapter directly
        adapter = get_response_adapter(action.adapter_name)
        telemetry = await adapter.execute(action)
        action.status = "COMPLETED"
        action.executed_at = utc_now()
        action.execution_result = telemetry

    await session.commit()
    return await get_response_action(action.id, session=session, _user=user)


@router.post("/actions/{id}/reject", response_model=ResponseActionOut)
async def reject_response_action(
    id: uuid.UUID,
    payload: ResponseApprovalRequest,
    session: AsyncSession = Depends(get_db_session),
    user: User = Depends(require_permission(PermissionCode.RESPONSE_APPROVE_LOW)),
) -> ResponseActionOut:
    """Reject a proposed response action enforcing four-eyes validation."""
    stmt = (
        select(ResponseAction)
        .where(ResponseAction.id == id)
        .options(
            selectinload(ResponseAction.requested_by),
            selectinload(ResponseAction.approved_by),
            selectinload(ResponseAction.approvals).selectinload(ResponseApproval.approver),
        )
    )
    res = await session.execute(stmt)
    action = res.scalar_one_or_none()
    if not action:
        raise AppError(code="NOT_FOUND", message="Response action not found", status_code=404)

    u_stmt = select(User).where(User.id == user.id).options(selectinload(User.role))
    u_res = await session.execute(u_stmt)
    approver = u_res.scalar_one()

    role_key = RoleName(approver.role.name) if approver.role else RoleName.SOC_L1
    user_perms = ROLE_PERMISSION_MATRIX.get(role_key, frozenset())

    # FOUR-EYES AND RISK-TIER VERIFICATION
    validate_response_approval(action, approver, user_perms)

    # Immutable approval record
    approval = ResponseApproval(
        response_action_id=action.id,
        approver_id=approver.id,
        decision="rejected",
        comment=payload.comment,
        decided_at=utc_now(),
    )
    session.add(approval)
    action.approvals.append(approval)

    action.status = "REJECTED"
    action.approved_by_id = approver.id
    await session.flush()

    await AuditService.record(
        session,
        action="response.action.rejected",
        actor=approver,
        target_type="response_action",
        target_id=str(action.id),
        details={
            "action_type": action.action_type,
            "risk_impact": action.risk_impact,
            "requested_by_id": str(action.requested_by_id),
            "comment": payload.comment,
        },
    )

    # If tied to a waiting PlaybookExecution, resume with action_approved=False
    if action.playbook_execution_id:
        engine = PlaybookEngine(session)
        await engine.resume_execution(action.playbook_execution_id, action_approved=False)

    await session.commit()
    return await get_response_action(action.id, session=session, _user=user)
