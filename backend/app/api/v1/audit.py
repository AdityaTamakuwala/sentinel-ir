"""Tamper-Evident Audit Log Search, Cryptographic Chain Verification, and CSV/JSON Export."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.ops import AuditLog
from app.models.user import User
from app.schemas.audit import (
    AuditChainVerificationOut,
    AuditLogItemOut,
    PaginatedAuditLogsOut,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit & Compliance"])


@router.get("", response_model=PaginatedAuditLogsOut)
async def list_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=30, ge=1, le=200),
    actor_username: str | None = Query(default=None),
    action: str | None = Query(default=None),
    target_type: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    from_ts: datetime | None = Query(default=None),
    to_ts: datetime | None = Query(default=None),
    _actor: User = Depends(require_permission(PermissionCode.AUDIT_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedAuditLogsOut:
    filters: list[Any] = []
    if actor_username:
        filters.append(AuditLog.actor_username.ilike(f"%{actor_username.strip()}%"))
    if action:
        filters.append(AuditLog.action.ilike(f"%{action.strip()}%"))
    if target_type:
        filters.append(AuditLog.target_type == target_type.strip())
    if outcome:
        filters.append(AuditLog.outcome == outcome.strip().lower())
    if from_ts:
        filters.append(AuditLog.occurred_at >= from_ts)
    if to_ts:
        filters.append(AuditLog.occurred_at <= to_ts)
    if search and search.strip():
        q = f"%{search.strip()}%"
        filters.append(
            or_(
                AuditLog.action.ilike(q),
                AuditLog.actor_username.ilike(q),
                AuditLog.target_id.ilike(q),
                AuditLog.correlation_id.ilike(q),
            )
        )

    count_stmt = select(func.count(AuditLog.id))
    if filters:
        count_stmt = count_stmt.where(*filters)
    total = int((await db.execute(count_stmt)).scalar_one())

    stmt = (
        select(AuditLog)
        .where(*filters)
        .order_by(AuditLog.seq.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return PaginatedAuditLogsOut(
        items=[AuditLogItemOut.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/verify", response_model=AuditChainVerificationOut)
async def verify_audit_chain(
    _actor: User = Depends(require_permission(PermissionCode.AUDIT_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> AuditChainVerificationOut:
    result = await AuditService.verify_chain(db)
    return AuditChainVerificationOut(**result)


@router.get("/export")
async def export_audit_logs(
    request: Request,
    export_format: Literal["json", "csv"] = Query(default="json", alias="format"),
    limit: int = Query(default=1000, ge=1, le=5000),
    actor: User = Depends(require_permission(PermissionCode.AUDIT_EXPORT)),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    await AuditService.record(
        db,
        action="audit.exported",
        actor=actor,
        target_type="audit_logs",
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={"format": export_format, "limit": limit},
    )
    await db.commit()

    res = await db.execute(select(AuditLog).order_by(AuditLog.seq.desc()).limit(limit))
    rows = list(res.scalars().all())

    if export_format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "seq",
                "occurred_at",
                "actor_username",
                "actor_role",
                "action",
                "target_type",
                "target_id",
                "outcome",
                "source_ip",
                "correlation_id",
                "prev_hash",
                "entry_hash",
            ]
        )
        for r in rows:
            writer.writerow(
                [
                    r.seq,
                    r.occurred_at.isoformat(),
                    r.actor_username,
                    r.actor_role or "",
                    r.action,
                    r.target_type,
                    r.target_id or "",
                    r.outcome,
                    r.source_ip or "",
                    r.correlation_id,
                    r.prev_hash,
                    r.entry_hash,
                ]
            )
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="sentinel-ir-audit-logs.csv"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    payload = [AuditLogItemOut.model_validate(r).model_dump(mode="json") for r in rows]
    return Response(
        content=json.dumps(payload, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": 'attachment; filename="sentinel-ir-audit-logs.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )
