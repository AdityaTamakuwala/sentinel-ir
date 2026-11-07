"""Forensic Evidence API endpoints (`/api/v1/evidence`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.core.logging import get_correlation_id
from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.incident import Incident
from app.models.investigation import Evidence, EvidenceCustodyLog
from app.models.user import User
from app.schemas.evidence import (
    EvidenceCustodyLogOut,
    EvidenceDetailOut,
    EvidenceIntegrityVerifyOut,
    EvidenceVersionOut,
    EvidenceWithdrawRequest,
    PaginatedEvidenceOut,
)
from app.services.audit_service import AuditService
from app.services.evidence_service import EvidenceService

router = APIRouter(prefix="/evidence", tags=["Forensic Evidence & Custody"])


async def _serialize_evidence(db: AsyncSession, ev: Evidence) -> EvidenceDetailOut:
    inc_res = await db.execute(select(Incident.human_id).where(Incident.id == ev.incident_id))
    human_id = inc_res.scalar_one_or_none()
    latest = ev.versions[0] if ev.versions else None

    return EvidenceDetailOut(
        id=ev.id,
        incident_id=ev.incident_id,
        incident_human_id=human_id,
        title=ev.title,
        description=ev.description,
        evidence_type=ev.evidence_type,
        status=ev.status,
        withdrawn_reason=ev.withdrawn_reason,
        withdrawn_at=ev.withdrawn_at,
        current_version=ev.current_version,
        uploaded_by_username=ev.uploaded_by.username if ev.uploaded_by else "unknown",
        sha256_hash=latest.sha256_hash if latest else ("0" * 64),
        original_filename=latest.original_filename if latest else "unknown",
        detected_mime_type=latest.detected_mime_type if latest else "application/octet-stream",
        size_bytes=latest.size_bytes if latest else 0,
        is_simulated=ev.is_simulated,
        created_at=ev.created_at,
        updated_at=ev.updated_at,
        versions=[
            EvidenceVersionOut(
                id=v.id,
                version_number=v.version_number,
                original_filename=v.original_filename,
                detected_mime_type=v.detected_mime_type,
                size_bytes=v.size_bytes,
                sha256_hash=v.sha256_hash,
                av_scan_status=v.av_scan_status,
                uploaded_by_username=v.uploaded_by.username if v.uploaded_by else "unknown",
                notes=v.notes,
                created_at=v.created_at,
            )
            for v in ev.versions
        ],
        custody_logs=[EvidenceCustodyLogOut.model_validate(c) for c in ev.custody_logs],
    )


@router.get("", response_model=PaginatedEvidenceOut)
async def list_evidence(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    incident_id: uuid.UUID | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None, max_length=128),
    _actor: User = Depends(require_permission(PermissionCode.EVIDENCE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedEvidenceOut:
    filters = []
    if incident_id:
        filters.append(Evidence.incident_id == incident_id)
    if status_filter:
        filters.append(Evidence.status == status_filter.lower())
    if search and search.strip():
        q = f"%{search.strip()}%"
        filters.append(Evidence.title.ilike(q))

    count_stmt = select(func.count(Evidence.id))
    if filters:
        count_stmt = count_stmt.where(*filters)
    total = int((await db.execute(count_stmt)).scalar_one())

    stmt = (
        select(Evidence)
        .where(*filters)
        .order_by(Evidence.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    items = [await _serialize_evidence(db, r) for r in rows]
    return PaginatedEvidenceOut(items=items, total=total, page=page, page_size=page_size)


@router.post("", response_model=EvidenceDetailOut, status_code=status.HTTP_201_CREATED)
async def upload_evidence_artifact(
    request: Request,
    incident_id: uuid.UUID = Form(...),
    title: str = Form(..., min_length=3, max_length=255),
    description: str = Form(default="", max_length=2000),
    evidence_type: str = Form(default="file"),
    file: UploadFile = File(...),
    actor: User = Depends(require_permission(PermissionCode.EVIDENCE_UPLOAD)),
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceDetailOut:
    ev = await EvidenceService.upload_evidence(
        db,
        incident_id=incident_id,
        title=title,
        description=description,
        evidence_type=evidence_type,
        upload=file,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return await _serialize_evidence(db, ev)


@router.get("/{evidence_id}", response_model=EvidenceDetailOut)
async def get_evidence_detail(
    evidence_id: uuid.UUID,
    _actor: User = Depends(require_permission(PermissionCode.EVIDENCE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceDetailOut:
    res = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    ev = res.scalar_one_or_none()
    if ev is None:
        raise AppError("EVIDENCE_NOT_FOUND", "Evidence record not found.", 404)
    return await _serialize_evidence(db, ev)


@router.post("/{evidence_id}/versions", response_model=EvidenceDetailOut, status_code=status.HTTP_201_CREATED)
async def upload_evidence_version(
    evidence_id: uuid.UUID,
    request: Request,
    notes: str | None = Form(default=None, max_length=1000),
    file: UploadFile = File(...),
    actor: User = Depends(require_permission(PermissionCode.EVIDENCE_UPLOAD)),
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceDetailOut:
    ev = await EvidenceService.upload_new_version(
        db,
        evidence_id=evidence_id,
        upload=file,
        notes=notes,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return await _serialize_evidence(db, ev)


@router.post("/{evidence_id}/verify", response_model=EvidenceIntegrityVerifyOut)
async def verify_evidence_integrity(
    evidence_id: uuid.UUID,
    request: Request,
    version_number: int | None = Query(default=None, ge=1),
    actor: User = Depends(require_permission(PermissionCode.EVIDENCE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceIntegrityVerifyOut:
    res = await EvidenceService.verify_integrity(
        db,
        evidence_id=evidence_id,
        version_number=version_number,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return EvidenceIntegrityVerifyOut(**res)


@router.get("/{evidence_id}/download")
async def download_evidence_artifact(
    evidence_id: uuid.UUID,
    request: Request,
    version_number: int | None = Query(default=None, ge=1),
    actor: User = Depends(require_permission(PermissionCode.EVIDENCE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> FileResponse:
    res = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
    ev = res.scalar_one_or_none()
    if ev is None:
        raise AppError("EVIDENCE_NOT_FOUND", "Evidence record not found.", 404)

    target_ver_num = version_number or ev.current_version
    ver_obj = next((v for v in ev.versions if v.version_number == target_ver_num), None)
    if ver_obj is None:
        raise AppError("EVIDENCE_VERSION_NOT_FOUND", "Requested evidence version not found.", 404)

    path = EvidenceService.resolve_storage_path(ver_obj.storage_key)
    if not path.exists():
        raise AppError("EVIDENCE_FILE_MISSING", "Evidence storage blob missing on disk.", 404)

    now = datetime.now(UTC)
    source_ip = request.client.host if request.client else None
    db.add(
        EvidenceCustodyLog(
            id=uuid.uuid4(),
            evidence_id=ev.id,
            version_number=ver_obj.version_number,
            actor_id=actor.id,
            actor_label=actor.username,
            action="downloaded",
            sha256_recorded=ver_obj.sha256_hash,
            ip_address=source_ip,
            correlation_id=get_correlation_id(),
            details={"filename": ver_obj.original_filename},
            created_at=now,
        )
    )
    await AuditService.record(
        db,
        action="evidence.downloaded",
        actor=actor,
        target_type="evidence",
        target_id=str(ev.id),
        source_ip=source_ip,
        details={
            "version_number": ver_obj.version_number,
            "filename": ver_obj.original_filename,
            "sha256": ver_obj.sha256_hash,
        },
    )
    await db.commit()

    return FileResponse(
        path=str(path),
        media_type="application/octet-stream",
        filename=ver_obj.original_filename,
        headers={
            "Content-Disposition": f'attachment; filename="{ver_obj.original_filename}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
        },
    )


@router.post("/{evidence_id}/withdraw", response_model=EvidenceDetailOut)
async def withdraw_evidence_artifact(
    evidence_id: uuid.UUID,
    payload: EvidenceWithdrawRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.EVIDENCE_WITHDRAW)),
    db: AsyncSession = Depends(get_db_session),
) -> EvidenceDetailOut:
    ev = await EvidenceService.withdraw_evidence(
        db,
        evidence_id=evidence_id,
        reason=payload.reason,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return await _serialize_evidence(db, ev)

