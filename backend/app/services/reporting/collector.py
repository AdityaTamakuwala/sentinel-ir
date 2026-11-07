"""Comprehensive Incident Report Data Collector.

Aggregates complete, immutable incident snapshot data including core metadata,
timeline, IOCs, MITRE ATT&CK mappings, evidence with SHA-256 hashes, playbook traces,
four-eyes response approvals, and closure review notes.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AppError
from app.models.automation import PlaybookExecution, ResponseAction, ResponseApproval
from app.models.incident import (
    Incident,
    IncidentAlert,
    IncidentAsset,
)
from app.models.investigation import (
    Evidence,
    IncidentIndicator,
    IncidentTechnique,
    InvestigationNote,
)
from app.services.incident_service import compute_sla_state


class IncidentReportCollector:
    """Aggregates an exhaustive structured snapshot of an incident."""

    @classmethod
    async def collect_snapshot(
        cls,
        db: AsyncSession,
        incident_id: uuid.UUID,
    ) -> dict[str, Any]:
        stmt = (
            select(Incident)
            .where(Incident.id == incident_id)
            .options(
                selectinload(Incident.assigned_to),
                selectinload(Incident.created_by),
                selectinload(Incident.alert_links).selectinload(IncidentAlert.alert),
                selectinload(Incident.asset_links).selectinload(IncidentAsset.asset),
                selectinload(Incident.affected_users),
                selectinload(Incident.timeline_entries),
            )
        )
        res = await db.execute(stmt)
        incident = res.scalar_one_or_none()
        if not incident:
            raise AppError(
                code="INCIDENT_NOT_FOUND",
                message=f"Incident '{incident_id}' does not exist.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        now = datetime.now(UTC)

        # 1. Operational duration metrics
        mtta_min: float | None = None
        if incident.acknowledged_at and incident.acknowledged_at >= incident.created_at:
            mtta_min = round((incident.acknowledged_at - incident.created_at).total_seconds() / 60.0, 1)

        mttc_min: float | None = None
        if incident.contained_at and incident.contained_at >= incident.created_at:
            mttc_min = round((incident.contained_at - incident.created_at).total_seconds() / 60.0, 1)

        mttr_min: float | None = None
        end_ref = incident.resolved_at or incident.closed_at
        if end_ref and end_ref >= incident.created_at:
            mttr_min = round((end_ref - incident.created_at).total_seconds() / 60.0, 1)

        sla_state = compute_sla_state(incident, now=now)

        # 2. Response Actions and Four-Eyes Approvals
        actions_stmt = (
            select(ResponseAction)
            .where(ResponseAction.incident_id == incident.id)
            .options(
                selectinload(ResponseAction.requested_by),
                selectinload(ResponseAction.approvals).selectinload(ResponseApproval.approver),
            )
            .order_by(ResponseAction.created_at.asc())
        )
        actions_res = await db.execute(actions_stmt)
        actions = list(actions_res.scalars().all())

        response_actions_data: list[dict[str, Any]] = []
        for a in actions:
            target_val = a.target_indicator or a.target_hostname or a.target_username or "N/A"
            approvals_data = [
                {
                    "id": str(appr.id),
                    "decision": appr.decision,
                    "approver_username": appr.approver.username if appr.approver else "System",
                    "approver_role": appr.approver.role.name if appr.approver and appr.approver.role else "Unknown",
                    "comment": appr.comment,
                    "decided_at": appr.decided_at.isoformat(),
                }
                for appr in a.approvals
            ]
            response_actions_data.append(
                {
                    "id": str(a.id),
                    "action_type": a.action_type,
                    "target": target_val,
                    "parameters": a.parameters_json,
                    "risk_level": a.risk_impact,
                    "status": a.status,
                    "requires_four_eyes": True,
                    "proposed_by": a.requested_by.username if a.requested_by else "System",
                    "execution_output": a.execution_result,
                    "error_message": a.failure_reason,
                    "created_at": a.created_at.isoformat(),
                    "executed_at": a.executed_at.isoformat() if a.executed_at else None,
                    "approvals": approvals_data,
                }
            )

        # 3. Playbook Executions
        pb_stmt = (
            select(PlaybookExecution)
            .where(PlaybookExecution.incident_id == incident.id)
            .options(
                selectinload(PlaybookExecution.playbook),
                selectinload(PlaybookExecution.steps),
            )
            .order_by(PlaybookExecution.created_at.asc())
        )
        pb_res = await db.execute(pb_stmt)
        playbook_executions_data = [
            {
                "id": str(pe.id),
                "playbook_slug": pe.playbook.slug if pe.playbook else "unknown",
                "playbook_name": pe.playbook.name if pe.playbook else "Unknown Playbook",
                "version_number": pe.version_number,
                "status": pe.status,
                "triggered_by": pe.triggered_by,
                "is_dry_run": pe.is_dry_run,
                "started_at": pe.started_at.isoformat() if pe.started_at else None,
                "completed_at": pe.completed_at.isoformat() if pe.completed_at else None,
                "steps_completed": len(pe.steps),
            }
            for pe in pb_res.scalars().all()
        ]

        # 4. Indicators of Compromise
        ind_stmt = (
            select(IncidentIndicator)
            .where(IncidentIndicator.incident_id == incident.id)
            .options(selectinload(IncidentIndicator.indicator))
            .order_by(IncidentIndicator.created_at.asc())
        )
        ind_res = await db.execute(ind_stmt)
        indicators_data: list[dict[str, Any]] = []
        for link in ind_res.scalars().all():
            ind = link.indicator
            if ind:
                indicators_data.append(
                    {
                        "id": str(ind.id),
                        "ioc_type": ind.ioc_type,
                        "value": ind.value,
                        "reputation": ind.reputation,
                        "confidence": ind.confidence,
                        "is_internal": ind.is_internal,
                        "first_seen_at": ind.first_seen_at.isoformat(),
                        "last_seen_at": ind.last_seen_at.isoformat(),
                    }
                )

        # 5. MITRE ATT&CK Techniques
        tech_stmt = (
            select(IncidentTechnique)
            .where(IncidentTechnique.incident_id == incident.id)
            .options(selectinload(IncidentTechnique.technique))
            .order_by(IncidentTechnique.created_at.asc())
        )
        tech_res = await db.execute(tech_stmt)
        techniques_data: list[dict[str, Any]] = []
        for it in tech_res.scalars().all():
            tech = it.technique
            techniques_data.append(
                {
                    "id": str(it.id),
                    "technique_id": it.technique_id,
                    "name": tech.name if tech else it.technique_id,
                    "tactics": tech.tactics if tech else [],
                    "url": tech.url if tech else f"https://attack.mitre.org/techniques/{it.technique_id}",
                    "status": it.status,
                    "source": it.source,
                    "rationale": it.rationale,
                }
            )

        # 6. Forensic Evidence
        ev_stmt = (
            select(Evidence)
            .where(Evidence.incident_id == incident.id)
            .options(
                selectinload(Evidence.uploaded_by),
                selectinload(Evidence.versions),
                selectinload(Evidence.custody_logs),
            )
            .order_by(Evidence.created_at.asc())
        )
        ev_res = await db.execute(ev_stmt)
        evidence_data: list[dict[str, Any]] = []
        for ev in ev_res.scalars().all():
            latest_version = ev.versions[0] if ev.versions else None
            evidence_data.append(
                {
                    "id": str(ev.id),
                    "file_name": latest_version.original_filename if latest_version else ev.title,
                    "file_size_bytes": latest_version.size_bytes if latest_version else 0,
                    "sha256_hash": latest_version.sha256_hash if latest_version else "N/A",
                    "mime_type": latest_version.detected_mime_type if latest_version else "application/octet-stream",
                    "evidence_type": ev.evidence_type,
                    "version": ev.current_version,
                    "is_withdrawn": ev.status == "withdrawn",
                    "withdrawn_reason": ev.withdrawn_reason,
                    "uploaded_by": ev.uploaded_by.username if ev.uploaded_by else "System",
                    "created_at": ev.created_at.isoformat(),
                }
            )

        # 7. Timeline
        timeline_data = [
            {
                "id": str(t.id),
                "entry_type": t.event_type,
                "title": t.title,
                "description": t.description,
                "actor_username": t.actor_label or "System",
                "created_at": t.occurred_at.isoformat() if t.occurred_at else t.created_at.isoformat(),
            }
            for t in sorted(incident.timeline_entries, key=lambda x: x.occurred_at)
        ]

        # 8. Correlated Alerts
        alerts_data: list[dict[str, Any]] = []
        for lk in incident.alert_links:
            alt = lk.alert
            if alt:
                alerts_data.append(
                    {
                        "id": str(alt.id),
                        "rule_id": alt.rule_id,
                        "rule_description": alt.rule_description,
                        "source_system": alt.source_system,
                        "severity": alt.severity,
                        "event_category": alt.event_category,
                        "src_ip": alt.src_ip,
                        "dst_ip": alt.dst_ip,
                        "hostname": alt.hostname,
                        "username": alt.username,
                        "occurrence_count": alt.occurrence_count,
                        "ingested_at": alt.ingested_at.isoformat(),
                    }
                )

        # 9. Investigation Notes
        notes_stmt = (
            select(InvestigationNote)
            .where(
                InvestigationNote.incident_id == incident.id,
                InvestigationNote.is_deleted.is_(False),
            )
            .options(selectinload(InvestigationNote.author))
            .order_by(InvestigationNote.created_at.asc())
        )
        notes_res = await db.execute(notes_stmt)
        notes_data = [
            {
                "id": str(n.id),
                "author": n.author.username if n.author else "Analyst",
                "created_at": n.created_at.isoformat(),
                "content": n.current_content,
            }
            for n in notes_res.scalars().all()
        ]

        return {
            "snapshot_version": "1.0.0",
            "collected_at": now.isoformat(),
            "incident": {
                "id": str(incident.id),
                "human_id": incident.human_id,
                "title": incident.title,
                "description": incident.description,
                "category": incident.category,
                "severity": incident.severity,
                "priority": incident.priority,
                "status": incident.status,
                "risk_score": incident.risk_score,
                "risk_breakdown": incident.risk_breakdown,
                "created_at": incident.created_at.isoformat(),
                "acknowledged_at": incident.acknowledged_at.isoformat() if incident.acknowledged_at else None,
                "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
                "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
                "closure_category": incident.closure_category,
                "closure_justification": incident.closure_justification,
                "executive_summary": incident.executive_summary,
                "root_cause": incident.root_cause,
                "lessons_learned": incident.lessons_learned,
                "recommendations_text": incident.recommendations_text,
                "is_simulated": incident.is_simulated,
                "version": incident.version,
                "assigned_to": {
                    "username": incident.assigned_to.username,
                    "full_name": incident.assigned_to.full_name,
                    "email": incident.assigned_to.email,
                }
                if incident.assigned_to
                else None,
                "created_by": {
                    "username": incident.created_by.username,
                    "full_name": incident.created_by.full_name,
                }
                if incident.created_by
                else None,
            },
            "metrics": {
                "mtta_minutes": mtta_min,
                "mttc_minutes": mttc_min,
                "mttr_minutes": mttr_min,
                "sla_state": sla_state,
            },
            "timeline": timeline_data,
            "indicators": indicators_data,
            "mitre_techniques": techniques_data,
            "evidence": evidence_data,
            "response_actions": response_actions_data,
            "playbook_executions": playbook_executions_data,
            "alerts": alerts_data,
            "notes": notes_data,
        }