"""Incident Reports API endpoints (`/api/v1/reports`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.user import User
from app.services.reporting.service import ReportingService

router = APIRouter(prefix="/reports", tags=["Incident Reporting Engine"])


class GenerateReportRequest(BaseModel):
    report_format: str = Field(
        default="pdf",
        description="Format of report: 'pdf', 'json', or 'stix'.",
    )
    tlp_classification: str = Field(
        default="TLP:AMBER",
        description="Traffic Light Protocol classification: 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', or 'TLP:RED'.",
    )


class IncidentReportOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    incident_version_snapshot: int
    report_format: str
    tlp_classification: str
    storage_key: str | None
    sha256_hash: str | None
    generated_by_id: uuid.UUID | None
    is_simulated: bool
    created_at: str


class IncidentReportDetailOut(IncidentReportOut):
    snapshot_json: dict[str, Any]


@router.get("", response_model=list[IncidentReportOut])
async def list_reports(
    incident_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _actor: User = Depends(require_permission(PermissionCode.REPORTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> list[IncidentReportOut]:
    """List generated incident reports with optional filtering by incident ID."""
    reports = await ReportingService.list_reports(
        db,
        incident_id=incident_id,
        limit=limit,
        offset=offset,
    )
    return [
        IncidentReportOut(
            id=r.id,
            incident_id=r.incident_id,
            incident_version_snapshot=r.incident_version_snapshot,
            report_format=r.report_format,
            tlp_classification=r.tlp_classification,
            storage_key=r.storage_key,
            sha256_hash=r.sha256_hash,
            generated_by_id=r.generated_by_id,
            is_simulated=r.is_simulated,
            created_at=r.created_at.isoformat(),
        )
        for r in reports
    ]


@router.post("/incidents/{incident_id}/generate", response_model=IncidentReportOut)
async def generate_incident_report(
    incident_id: uuid.UUID,
    payload: GenerateReportRequest,
    actor: User = Depends(require_permission(PermissionCode.REPORTS_GENERATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentReportOut:
    """Generate and persist an incident report in PDF, JSON, or STIX 2.1 format."""
    report = await ReportingService.generate_report(
        db,
        incident_id=incident_id,
        report_format=payload.report_format,
        tlp_classification=payload.tlp_classification,
        actor=actor,
    )
    return IncidentReportOut(
        id=report.id,
        incident_id=report.incident_id,
        incident_version_snapshot=report.incident_version_snapshot,
        report_format=report.report_format,
        tlp_classification=report.tlp_classification,
        storage_key=report.storage_key,
        sha256_hash=report.sha256_hash,
        generated_by_id=report.generated_by_id,
        is_simulated=report.is_simulated,
        created_at=report.created_at.isoformat(),
    )


@router.get("/{report_id}", response_model=IncidentReportDetailOut)
async def get_report(
    report_id: uuid.UUID,
    _actor: User = Depends(require_permission(PermissionCode.REPORTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentReportDetailOut:
    """Retrieve full metadata and JSON snapshot for a generated report."""
    report = await ReportingService.get_report(db, report_id)
    return IncidentReportDetailOut(
        id=report.id,
        incident_id=report.incident_id,
        incident_version_snapshot=report.incident_version_snapshot,
        report_format=report.report_format,
        tlp_classification=report.tlp_classification,
        storage_key=report.storage_key,
        sha256_hash=report.sha256_hash,
        generated_by_id=report.generated_by_id,
        is_simulated=report.is_simulated,
        created_at=report.created_at.isoformat(),
        snapshot_json=report.snapshot_json,
    )


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    _actor: User = Depends(require_permission(PermissionCode.REPORTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    """Stream download the generated report artifact (PDF, JSON, or STIX bundle)."""
    report, content_bytes, mime_type, filename = await ReportingService.get_report_file(
        db, report_id
    )
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": mime_type,
        "X-Content-Type-Options": "nosniff",
        "X-Report-SHA256": report.sha256_hash or "",
        "X-TLP-Classification": report.tlp_classification,
    }
    return Response(content=content_bytes, media_type=mime_type, headers=headers)

