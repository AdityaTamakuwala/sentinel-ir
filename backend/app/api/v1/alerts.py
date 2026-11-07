"""Alert Inbox, Manual/JSON Ingestion, Detail, and Triage Workbench endpoints (`/api/v1/alerts`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.models.investigation import Indicator, InvestigationNote
from app.models.user import User
from app.schemas.alert import (
    AlertDetailOut,
    AlertListItemOut,
    AlertOccurrenceOut,
    AlertTriageRequest,
    AssetSummaryOut,
    JsonBatchAlertImportRequest,
    ManualAlertCreateRequest,
    PaginatedAlertsOut,
)
from app.services.alert_service import AlertService, parse_wazuh_alert_payload

router = APIRouter(prefix="/alerts", tags=["Alerts & Triage Workbench"])


async def _fetch_linked_incidents_map(
    db: AsyncSession, alert_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[uuid.UUID, str]]:
    if not alert_ids:
        return {}
    res = await db.execute(
        select(IncidentAlert.alert_id, Incident.id, Incident.human_id)
        .join(Incident, Incident.id == IncidentAlert.incident_id)
        .where(IncidentAlert.alert_id.in_(alert_ids))
        .order_by(Incident.created_at.desc())
    )
    mapping: dict[uuid.UUID, tuple[uuid.UUID, str]] = {}
    for aid, inc_id, human_id in res.all():
        if aid not in mapping:
            mapping[aid] = (inc_id, human_id)
    return mapping


def _to_alert_list_item(
    alert: Alert,
    linked_map: dict[uuid.UUID, tuple[uuid.UUID, str]],
) -> AlertListItemOut:
    linked = linked_map.get(alert.id)
    return AlertListItemOut(
        id=alert.id,
        external_alert_id=alert.external_alert_id,
        source_system=alert.source_system,
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        event_category=alert.event_category,
        event_timestamp=alert.event_timestamp,
        ingested_at=alert.ingested_at,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        hostname=alert.hostname,
        username=alert.username,
        file_hash=alert.file_hash,
        domain=alert.domain,
        severity=alert.severity,
        triage_status=alert.triage_status,
        assigned_to_id=alert.assigned_to_id,
        assigned_to_username=alert.assigned_to.username if alert.assigned_to else None,
        occurrence_count=alert.occurrence_count,
        first_seen_at=alert.first_seen_at,
        last_seen_at=alert.last_seen_at,
        is_simulated=alert.is_simulated,
        linked_incident_id=linked[0] if linked else None,
        linked_incident_human_id=linked[1] if linked else None,
    )


@router.get("", response_model=PaginatedAlertsOut)
async def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    severity: str | None = Query(default=None),
    triage_status: str | None = Query(default=None),
    source_system: str | None = Query(default=None),
    assigned_to_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    _actor: User = Depends(require_permission(PermissionCode.ALERTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedAlertsOut:
    filters = []
    if severity:
        filters.append(Alert.severity == severity.lower())
    if triage_status:
        filters.append(Alert.triage_status == triage_status.lower())
    if source_system:
        filters.append(Alert.source_system == source_system.lower())
    if assigned_to_id:
        filters.append(Alert.assigned_to_id == assigned_to_id)
    if search and search.strip():
        q = f"%{search.strip()}%"
        filters.append(
            or_(
                Alert.rule_description.ilike(q),
                Alert.rule_id.ilike(q),
                Alert.hostname.ilike(q),
                Alert.username.ilike(q),
                Alert.src_ip.ilike(q),
                Alert.domain.ilike(q),
            )
        )

    count_stmt = select(func.count(Alert.id))
    if filters:
        count_stmt = count_stmt.where(*filters)
    total = int((await db.execute(count_stmt)).scalar_one())

    stmt = (
        select(Alert)
        .where(*filters)
        .order_by(Alert.last_seen_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    linked_map = await _fetch_linked_incidents_map(db, [r.id for r in rows])

    return PaginatedAlertsOut(
        items=[_to_alert_list_item(r, linked_map) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=AlertListItemOut, status_code=status.HTTP_201_CREATED)
async def create_manual_alert(
    payload: ManualAlertCreateRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.ALERTS_CREATE)),
    db: AsyncSession = Depends(get_db_session),
) -> AlertListItemOut:
    normalized: dict[str, Any] = {
        "source_system": payload.source_system,
        "rule_id": payload.rule_id,
        "rule_description": payload.rule_description,
        "event_category": payload.event_category,
        "severity": payload.severity,
        "event_timestamp": payload.event_timestamp,
        "src_ip": payload.src_ip,
        "dst_ip": payload.dst_ip,
        "hostname": payload.hostname,
        "username": payload.username,
        "file_hash": payload.file_hash,
        "domain": payload.domain,
        "mitre_mappings_raw": payload.mitre_techniques,
        "raw_payload": payload.raw_payload or payload.model_dump(mode="json"),
    }
    alert, _ = await AlertService.ingest_normalized_alert(
        db,
        normalized,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    linked_map = await _fetch_linked_incidents_map(db, [alert.id])
    return _to_alert_list_item(alert, linked_map)


@router.post("/import/json", response_model=list[AlertListItemOut], status_code=status.HTTP_201_CREATED)
async def import_json_alerts(
    payload: JsonBatchAlertImportRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.ALERTS_CREATE)),
    db: AsyncSession = Depends(get_db_session),
) -> list[AlertListItemOut]:
    ingested: list[Alert] = []
    client_ip = request.client.host if request.client else None
    for raw_item in payload.alerts:
        norm = (
            parse_wazuh_alert_payload(raw_item)
            if payload.format == "wazuh"
            else dict(raw_item)
        )
        alert, _ = await AlertService.ingest_normalized_alert(
            db,
            norm,
            actor=actor,
            source_ip=client_ip,
        )
        ingested.append(alert)
    linked_map = await _fetch_linked_incidents_map(db, [a.id for a in ingested])
    return [_to_alert_list_item(a, linked_map) for a in ingested]


@router.get("/{alert_id}", response_model=AlertDetailOut)
async def get_alert_detail(
    alert_id: uuid.UUID,
    _actor: User = Depends(require_permission(PermissionCode.ALERTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> AlertDetailOut:
    from sqlalchemy.orm import selectinload

    res = await db.execute(
        select(Alert)
        .options(selectinload(Alert.occurrences))
        .where(Alert.id == alert_id)
    )
    alert = res.scalar_one_or_none()
    if alert is None:
        raise AppError("ALERT_NOT_FOUND", "Alert not found.", status.HTTP_404_NOT_FOUND)

    # Related alerts sharing hostname, src_ip, or username
    rel_conds = []
    if alert.src_ip:
        rel_conds.append(Alert.src_ip == alert.src_ip)
    if alert.hostname:
        rel_conds.append(Alert.hostname == alert.hostname)
    if alert.username:
        rel_conds.append(Alert.username == alert.username)

    related_rows: list[Alert] = []
    if rel_conds:
        rel_res = await db.execute(
            select(Alert)
            .where(Alert.id != alert.id, or_(*rel_conds))
            .order_by(Alert.last_seen_at.desc())
            .limit(10)
        )
        related_rows = list(rel_res.scalars().all())

    all_ids = [alert.id] + [r.id for r in related_rows]
    linked_map = await _fetch_linked_incidents_map(db, all_ids)
    base_item = _to_alert_list_item(alert, linked_map)

    notes_res = await db.execute(
        select(InvestigationNote)
        .where(InvestigationNote.alert_id == alert.id, InvestigationNote.is_deleted.is_(False))
        .order_by(InvestigationNote.created_at.desc())
    )
    notes_list = [
        {
            "id": str(n.id),
            "author_username": n.author.username if n.author else "unknown",
            "content": n.current_content,
            "revision_count": n.revision_count,
            "created_at": n.created_at.isoformat(),
            "updated_at": n.updated_at.isoformat(),
        }
        for n in notes_res.scalars().all()
    ]

    # Pull any cached indicator enrichments matching this alert's indicators
    ioc_values = [v for v in (alert.src_ip, alert.domain, alert.file_hash) if v]
    enrichment_summary: list[dict[str, Any]] = []
    if ioc_values:
        ind_res = await db.execute(
            select(Indicator).where(Indicator.value.in_(ioc_values))
        )
        for ind in ind_res.scalars().all():
            enrichment_summary.append(
                {
                    "indicator_id": str(ind.id),
                    "ioc_type": ind.ioc_type,
                    "value": ind.value,
                    "is_internal": ind.is_internal,
                    "reputation": ind.reputation,
                    "confidence": ind.confidence,
                    "results": [
                        {
                            "provider": er.provider,
                            "status": er.status,
                            "reputation": er.reputation,
                            "confidence_score": er.confidence_score,
                            "malicious_count": er.malicious_count,
                            "total_engines": er.total_engines,
                            "summary": er.summary,
                            "is_mock": er.is_mock,
                            "looked_up_at": er.looked_up_at.isoformat(),
                        }
                        for er in ind.enrichments[:5]
                    ],
                }
            )

    return AlertDetailOut(
        **base_item.model_dump(),
        false_positive_reason=alert.false_positive_reason,
        triage_notes=alert.triage_notes,
        fingerprint=alert.fingerprint,
        raw_payload=alert.raw_payload,
        mitre_mappings_raw=alert.mitre_mappings_raw,
        recommended_steps=alert.recommended_steps,
        asset=AssetSummaryOut.model_validate(alert.asset) if alert.asset else None,
        occurrences=[AlertOccurrenceOut.model_validate(o) for o in alert.occurrences[:25]],
        related_alerts=[_to_alert_list_item(r, linked_map) for r in related_rows],
        notes=notes_list,
        enrichment_summary=enrichment_summary,
        version=alert.version,
    )


@router.patch("/{alert_id}/triage", response_model=AlertDetailOut)
async def triage_alert(
    alert_id: uuid.UUID,
    payload: AlertTriageRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.ALERTS_TRIAGE)),
    db: AsyncSession = Depends(get_db_session),
) -> AlertDetailOut:
    await AlertService.triage_alert(
        db,
        alert_id=alert_id,
        action=payload.action,
        actor=actor,
        reason=payload.reason,
        assigned_to_id=payload.assigned_to_id,
        note=payload.note,
        severity=payload.severity,
        source_ip=request.client.host if request.client else None,
    )
    return await get_alert_detail(alert_id=alert_id, _actor=actor, db=db)

