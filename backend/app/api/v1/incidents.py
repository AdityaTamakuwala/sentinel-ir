"""Incident Lifecycle, Risk Overrides, Assignment, Linking, Notes & Timeline endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AppError
from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.automation import ResponseAction
from app.models.incident import (
    Incident,
    IncidentLink,
    IncidentTimeline,
)
from app.models.investigation import (
    Evidence,
    IncidentIndicator,
    IncidentTechnique,
    InvestigationNote,
    NoteRevision,
)
from app.models.ops import Notification
from app.models.user import User
from app.schemas.incident import (
    IncidentAssignRequest,
    IncidentCreateRequest,
    IncidentDetailOut,
    IncidentLinkAlertRequest,
    IncidentLinkRelatedRequest,
    IncidentListItemOut,
    IncidentRiskOverrideRequest,
    IncidentTransitionRequest,
    IncidentUpdateFieldsRequest,
    NoteCreateRequest,
    NoteUpdateRequest,
    PaginatedIncidentsOut,
    TimelineEntryOut,
)
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event
from app.services.incident_service import (
    ALLOWED_INCIDENT_TRANSITIONS,
    IncidentService,
    compute_sla_state,
)

router = APIRouter(prefix="/incidents", tags=["Incidents & Investigation"])


def _to_incident_list_item(incident: Incident) -> IncidentListItemOut:
    sla = compute_sla_state(incident)
    return IncidentListItemOut(
        id=incident.id,
        human_id=incident.human_id,
        title=incident.title,
        category=incident.category,
        severity=incident.severity,
        priority=incident.priority,
        status=incident.status,
        risk_score=incident.risk_score,
        assigned_to_id=incident.assigned_to_id,
        assigned_to_username=incident.assigned_to.username if incident.assigned_to else None,
        alert_count=len(incident.alert_links),
        sla_status=sla["status"],
        sla_resolve_due_at=sla["resolve_due_at"],
        is_simulated=incident.is_simulated,
        version=incident.version,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


async def _resolve_incident_by_ref(db: AsyncSession, incident_ref: str) -> Incident:
    stmt = select(Incident).options(selectinload(Incident.timeline_entries))
    try:
        uid = uuid.UUID(incident_ref)
        stmt = stmt.where(Incident.id == uid)
    except ValueError:
        stmt = stmt.where(Incident.human_id == incident_ref.upper())

    res = await db.execute(stmt)
    incident = res.scalar_one_or_none()
    if incident is None:
        raise AppError("INCIDENT_NOT_FOUND", "Incident not found.", status.HTTP_404_NOT_FOUND)
    return incident


@router.get("", response_model=PaginatedIncidentsOut)
async def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = Query(default=None),
    assigned_to_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    _actor: User = Depends(require_permission(PermissionCode.INCIDENTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedIncidentsOut:
    filters = []
    if status_filter:
        filters.append(Incident.status == status_filter.upper())
    if severity:
        filters.append(Incident.severity == severity.lower())
    if assigned_to_id:
        filters.append(Incident.assigned_to_id == assigned_to_id)
    if search and search.strip():
        q = f"%{search.strip()}%"
        filters.append(
            or_(
                Incident.human_id.ilike(q),
                Incident.title.ilike(q),
                Incident.description.ilike(q),
                Incident.category.ilike(q),
            )
        )

    count_stmt = select(func.count(Incident.id))
    if filters:
        count_stmt = count_stmt.where(*filters)
    total = int((await db.execute(count_stmt)).scalar_one())

    stmt = (
        select(Incident)
        .where(*filters)
        .order_by(Incident.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = list((await db.execute(stmt)).scalars().all())
    return PaginatedIncidentsOut(
        items=[_to_incident_list_item(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("", response_model=IncidentDetailOut, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreateRequest,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key", max_length=128),
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_CREATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    incident = await IncidentService.create_incident(
        db,
        title=payload.title,
        description=payload.description,
        category=payload.category,
        base_severity=payload.base_severity,
        alert_ids=payload.alert_ids,
        assigned_to_id=payload.assigned_to_id,
        actor=actor,
        idempotency_key=idempotency_key,
        source_ip=request.client.host if request.client else None,
    )
    return await get_incident_detail(str(incident.id), _actor=actor, db=db)


@router.get("/{incident_ref}", response_model=IncidentDetailOut)
async def get_incident_detail(
    incident_ref: str,
    _actor: User = Depends(require_permission(PermissionCode.INCIDENTS_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    incident = await _resolve_incident_by_ref(db, incident_ref)
    base = _to_incident_list_item(incident)

    linked_alerts = []
    for link in incident.alert_links:
        a = link.alert
        if a:
            linked_alerts.append(
                {
                    "id": str(a.id),
                    "rule_id": a.rule_id,
                    "rule_description": a.rule_description,
                    "source_system": a.source_system,
                    "severity": a.severity,
                    "triage_status": a.triage_status,
                    "src_ip": a.src_ip,
                    "hostname": a.hostname,
                    "username": a.username,
                    "occurrence_count": a.occurrence_count,
                    "event_timestamp": a.event_timestamp.isoformat(),
                    "is_simulated": a.is_simulated,
                }
            )

    affected_assets = [
        {
            "id": str(al.asset.id),
            "hostname": al.asset.hostname,
            "ip_address": al.asset.ip_address,
            "asset_type": al.asset.asset_type,
            "criticality": al.asset.criticality,
            "owner": al.asset.owner,
            "department": al.asset.department,
        }
        for al in incident.asset_links
        if al.asset
    ]

    affected_users = [
        {
            "id": str(u.id),
            "username": u.username,
            "account_type": u.account_type,
            "is_privileged": u.is_privileged,
            "compromise_confirmed": u.compromise_confirmed,
            "notes": u.notes,
        }
        for u in incident.affected_users
    ]

    ind_res = await db.execute(
        select(IncidentIndicator).where(IncidentIndicator.incident_id == incident.id)
    )
    indicators = []
    for ii in ind_res.scalars().all():
        ind = ii.indicator
        if ind:
            indicators.append(
                {
                    "id": str(ind.id),
                    "ioc_type": ind.ioc_type,
                    "value": ind.value,
                    "is_internal": ind.is_internal,
                    "reputation": ind.reputation,
                    "confidence": ind.confidence,
                    "is_simulated": ind.is_simulated,
                    "enrichments": [
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

    tech_res = await db.execute(
        select(IncidentTechnique).where(IncidentTechnique.incident_id == incident.id)
    )
    mitre_techniques = [
        {
            "mapping_id": str(it.id),
            "technique_id": it.technique_id,
            "name": it.technique.name if it.technique else it.technique_id,
            "tactics": it.technique.tactics if it.technique else [],
            "source": it.source,
            "status": it.status,
            "rationale": it.rationale,
            "url": it.technique.url if it.technique else "",
            "confirmed_at": it.confirmed_at.isoformat() if it.confirmed_at else None,
        }
        for it in tech_res.scalars().all()
    ]

    notes_res = await db.execute(
        select(InvestigationNote)
        .where(
            InvestigationNote.incident_id == incident.id,
            InvestigationNote.is_deleted.is_(False),
        )
        .order_by(InvestigationNote.created_at.desc())
    )
    notes = [
        {
            "id": str(n.id),
            "author_username": n.author.username if n.author else "unknown",
            "content": n.current_content,
            "revision_count": n.revision_count,
            "created_at": n.created_at.isoformat(),
            "updated_at": n.updated_at.isoformat(),
            "revisions": [
                {
                    "revision_number": rev.revision_number,
                    "content": rev.content,
                    "edited_by": rev.edited_by.username if rev.edited_by else "unknown",
                    "created_at": rev.created_at.isoformat(),
                }
                for rev in n.revisions
            ],
        }
        for n in notes_res.scalars().all()
    ]

    ev_res = await db.execute(
        select(Evidence)
        .where(Evidence.incident_id == incident.id)
        .order_by(Evidence.created_at.desc())
    )
    evidence_items = []
    for ev in ev_res.scalars().all():
        latest_ver = ev.versions[0] if ev.versions else None
        evidence_items.append(
            {
                "id": str(ev.id),
                "title": ev.title,
                "description": ev.description,
                "evidence_type": ev.evidence_type,
                "status": ev.status,
                "withdrawn_reason": ev.withdrawn_reason,
                "current_version": ev.current_version,
                "uploaded_by": ev.uploaded_by.username if ev.uploaded_by else "unknown",
                "sha256_hash": latest_ver.sha256_hash if latest_ver else None,
                "original_filename": latest_ver.original_filename if latest_ver else None,
                "detected_mime_type": latest_ver.detected_mime_type if latest_ver else None,
                "size_bytes": latest_ver.size_bytes if latest_ver else 0,
                "is_simulated": ev.is_simulated,
                "created_at": ev.created_at.isoformat(),
            }
        )

    ra_res = await db.execute(
        select(ResponseAction)
        .where(ResponseAction.incident_id == incident.id)
        .order_by(ResponseAction.created_at.desc())
    )
    response_actions = [
        {
            "id": str(ra.id),
            "action_type": ra.action_type,
            "title": ra.title,
            "status": ra.status,
            "risk_impact": ra.risk_impact,
            "target_indicator": ra.target_indicator,
            "target_hostname": ra.target_hostname,
            "target_username": ra.target_username,
            "adapter_name": ra.adapter_name,
            "is_simulated": ra.is_simulated,
            "requested_by": ra.requested_by.username if ra.requested_by else "unknown",
            "approved_by": ra.approved_by.username if ra.approved_by else None,
            "expires_at": ra.expires_at.isoformat(),
            "executed_at": ra.executed_at.isoformat() if ra.executed_at else None,
            "execution_result": ra.execution_result,
            "created_at": ra.created_at.isoformat(),
        }
        for ra in ra_res.scalars().all()
    ]

    rel_inc_res = await db.execute(
        select(IncidentLink, Incident.human_id, Incident.title, Incident.status)
        .join(Incident, Incident.id == IncidentLink.target_incident_id)
        .where(IncidentLink.source_incident_id == incident.id)
    )
    related_incidents = [
        {
            "link_id": str(lnk.id),
            "target_incident_id": str(lnk.target_incident_id),
            "target_human_id": h_id,
            "target_title": t_title,
            "target_status": t_status,
            "link_type": lnk.link_type,
            "notes": lnk.notes,
        }
        for lnk, h_id, t_title, t_status in rel_inc_res.all()
    ]

    return IncidentDetailOut(
        **base.model_dump(),
        description=incident.description,
        risk_breakdown=incident.risk_breakdown,
        risk_override_severity=incident.risk_override_severity,
        risk_override_reason=incident.risk_override_reason,
        acknowledged_at=incident.acknowledged_at,
        contained_at=incident.contained_at,
        resolved_at=incident.resolved_at,
        closed_at=incident.closed_at,
        closure_category=incident.closure_category,
        closure_justification=incident.closure_justification,
        executive_summary=incident.executive_summary,
        root_cause=incident.root_cause,
        lessons_learned=incident.lessons_learned,
        recommendations_text=incident.recommendations_text,
        allowed_transitions=sorted(ALLOWED_INCIDENT_TRANSITIONS.get(incident.status, set())),
        linked_alerts=linked_alerts,
        affected_assets=affected_assets,
        affected_users=affected_users,
        indicators=indicators,
        mitre_techniques=mitre_techniques,
        notes=notes,
        evidence_items=evidence_items,
        response_actions=response_actions,
        related_incidents=related_incidents,
        timeline=[
            TimelineEntryOut(
                id=t.id,
                event_type=t.event_type,
                title=t.title,
                description=t.description,
                actor_id=t.actor_id,
                actor_label=t.actor_label,
                metadata_json=t.metadata_json,
                occurred_at=t.occurred_at,
            )
            for t in incident.timeline_entries
        ],
    )


@router.post("/{incident_id}/transition", response_model=IncidentDetailOut)
async def transition_incident_status(
    incident_id: uuid.UUID,
    payload: IncidentTransitionRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_UPDATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    await IncidentService.transition_status(
        db,
        incident_id=incident_id,
        target_status=payload.target_status,
        expected_version=payload.expected_version,
        actor=actor,
        reason=payload.reason,
        closure_category=payload.closure_category,
        closure_justification=payload.closure_justification,
        source_ip=request.client.host if request.client else None,
    )
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.post("/{incident_id}/assign", response_model=IncidentDetailOut)
async def assign_incident(
    incident_id: uuid.UUID,
    payload: IncidentAssignRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_ASSIGN)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if incident is None:
        raise AppError("INCIDENT_NOT_FOUND", "Incident not found.", 404)
    if incident.version != payload.expected_version:
        raise AppError(
            "OPTIMISTIC_LOCK_CONFLICT",
            "Incident was modified concurrently.",
            409,
            details={"current_version": incident.version},
        )

    assignee_username = "Unassigned"
    if payload.assigned_to_id is not None:
        u_res = await db.execute(select(User).where(User.id == payload.assigned_to_id))
        assignee = u_res.scalar_one_or_none()
        if assignee is None:
            raise AppError("ASSIGNEE_NOT_FOUND", "Assignee user not found.", 404)
        assignee_username = assignee.username

    now = datetime.now(UTC)
    incident.assigned_to_id = payload.assigned_to_id
    if payload.assigned_to_id and incident.acknowledged_at is None:
        incident.acknowledged_at = now
    incident.version += 1
    incident.updated_at = now

    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            event_type="analyst_assigned",
            title=f"Incident assigned to {assignee_username}",
            description=payload.note or f"Assigned by {actor.username}.",
            actor_id=actor.id,
            actor_label=actor.username,
            metadata_json={"assigned_to_id": str(payload.assigned_to_id) if payload.assigned_to_id else None},
            occurred_at=now,
        )
    )
    if payload.assigned_to_id is not None:
        db.add(
            Notification(
                user_id=payload.assigned_to_id,
                title=f"Assigned Case: {incident.human_id}",
                body=f"{actor.username} assigned '{incident.title[:160]}' to you.",
                severity="high" if incident.severity in ("critical", "high") else "info",
                event_type="incident.assigned",
                link_url=f"/incidents/{incident.human_id}",
                created_at=now,
            )
        )
    await AuditService.record(
        db,
        action="incident.assigned",
        actor=actor,
        target_type="incident",
        target_id=str(incident.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={"human_id": incident.human_id, "assigned_to": assignee_username},
    )
    await db.commit()
    await publish_realtime_event(
        "incident.assigned",
        {
            "incident_id": str(incident.id),
            "human_id": incident.human_id,
            "assigned_to": assignee_username,
        },
        required_permission="incidents:view",
    )
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.post("/{incident_id}/risk-override", response_model=IncidentDetailOut)
async def override_incident_risk(
    incident_id: uuid.UUID,
    payload: IncidentRiskOverrideRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_UPDATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if incident is None:
        raise AppError("INCIDENT_NOT_FOUND", "Incident not found.", 404)
    if incident.version != payload.expected_version:
        raise AppError(
            "OPTIMISTIC_LOCK_CONFLICT",
            "Incident was modified concurrently.",
            409,
            details={"current_version": incident.version},
        )

    prev_sev = incident.severity
    now = datetime.now(UTC)
    incident.severity = payload.override_severity
    incident.risk_override_severity = payload.override_severity
    incident.risk_override_reason = payload.justification.strip()
    incident.risk_overridden_by_id = actor.id
    incident.version += 1
    incident.updated_at = now

    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            event_type="severity_overridden",
            title=f"Severity overridden: {prev_sev.upper()} → {payload.override_severity.upper()}",
            description=payload.justification.strip(),
            actor_id=actor.id,
            actor_label=actor.username,
            metadata_json={"from_severity": prev_sev, "to_severity": payload.override_severity},
            occurred_at=now,
        )
    )
    await AuditService.record(
        db,
        action="incident.severity_overridden",
        actor=actor,
        target_type="incident",
        target_id=str(incident.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={
            "human_id": incident.human_id,
            "from_severity": prev_sev,
            "to_severity": payload.override_severity,
            "justification": payload.justification.strip(),
        },
    )
    await db.commit()
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.patch("/{incident_id}", response_model=IncidentDetailOut)
async def update_incident_fields(
    incident_id: uuid.UUID,
    payload: IncidentUpdateFieldsRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_UPDATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if incident is None:
        raise AppError("INCIDENT_NOT_FOUND", "Incident not found.", 404)
    if incident.version != payload.expected_version:
        raise AppError(
            "OPTIMISTIC_LOCK_CONFLICT",
            "Incident was modified concurrently.",
            409,
            details={"current_version": incident.version},
        )

    changed: list[str] = []
    for field_name in (
        "title",
        "description",
        "priority",
        "executive_summary",
        "root_cause",
        "lessons_learned",
        "recommendations_text",
    ):
        val = getattr(payload, field_name)
        if val is not None:
            setattr(incident, field_name, val.strip() if isinstance(val, str) else val)
            changed.append(field_name)

    incident.version += 1
    incident.updated_at = datetime.now(UTC)

    await AuditService.record(
        db,
        action="incident.fields_updated",
        actor=actor,
        target_type="incident",
        target_id=str(incident.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={"human_id": incident.human_id, "updated_fields": changed},
    )
    await db.commit()
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.post("/{incident_id}/alerts", response_model=IncidentDetailOut)
async def link_alert(
    incident_id: uuid.UUID,
    payload: IncidentLinkAlertRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_UPDATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    await IncidentService.link_alert_to_incident(
        db,
        incident_id=incident_id,
        alert_id=payload.alert_id,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.post("/{incident_id}/links", response_model=IncidentDetailOut)
async def link_related_incident(
    incident_id: uuid.UUID,
    payload: IncidentLinkRelatedRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.INCIDENTS_UPDATE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    await IncidentService.link_related_incidents(
        db,
        source_incident_id=incident_id,
        target_incident_id=payload.target_incident_id,
        link_type=payload.link_type,
        notes=payload.notes,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.post("/{incident_id}/notes", response_model=IncidentDetailOut, status_code=status.HTTP_201_CREATED)
async def add_incident_note(
    incident_id: uuid.UUID,
    payload: NoteCreateRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.NOTES_WRITE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    res = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = res.scalar_one_or_none()
    if incident is None:
        raise AppError("INCIDENT_NOT_FOUND", "Incident not found.", 404)

    now = datetime.now(UTC)
    cleaned = payload.content.strip()
    note = InvestigationNote(
        id=uuid.uuid4(),
        incident_id=incident.id,
        author_id=actor.id,
        current_content=cleaned,
        revision_count=1,
        created_at=now,
        updated_at=now,
    )
    db.add(note)
    db.add(
        NoteRevision(
            note_id=note.id,
            revision_number=1,
            content=cleaned,
            edited_by_id=actor.id,
            created_at=now,
        )
    )
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            event_type="note_added",
            title=f"Investigation note added by {actor.username}",
            description=cleaned[:240],
            actor_id=actor.id,
            actor_label=actor.username,
            metadata_json={"note_id": str(note.id)},
            occurred_at=now,
        )
    )
    await AuditService.record(
        db,
        action="incident.note_added",
        actor=actor,
        target_type="incident",
        target_id=str(incident.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={"note_id": str(note.id)},
    )
    await db.commit()
    await publish_realtime_event(
        "incident.timeline_updated",
        {"incident_id": str(incident.id), "event_type": "note_added"},
        required_permission="incidents:view",
    )
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)


@router.patch("/{incident_id}/notes/{note_id}", response_model=IncidentDetailOut)
async def edit_incident_note(
    incident_id: uuid.UUID,
    note_id: uuid.UUID,
    payload: NoteUpdateRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.NOTES_WRITE)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentDetailOut:
    res = await db.execute(
        select(InvestigationNote).where(
            InvestigationNote.id == note_id,
            InvestigationNote.incident_id == incident_id,
            InvestigationNote.is_deleted.is_(False),
        )
    )
    note = res.scalar_one_or_none()
    if note is None:
        raise AppError("NOTE_NOT_FOUND", "Investigation note not found.", 404)

    now = datetime.now(UTC)
    cleaned = payload.content.strip()
    next_rev = note.revision_count + 1
    note.current_content = cleaned
    note.revision_count = next_rev
    note.updated_at = now

    db.add(
        NoteRevision(
            note_id=note.id,
            revision_number=next_rev,
            content=cleaned,
            edited_by_id=actor.id,
            created_at=now,
        )
    )
    await AuditService.record(
        db,
        action="incident.note_revised",
        actor=actor,
        target_type="investigation_note",
        target_id=str(note.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={"incident_id": str(incident_id), "revision_number": next_rev},
    )
    await db.commit()
    return await get_incident_detail(str(incident_id), _actor=actor, db=db)
