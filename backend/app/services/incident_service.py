"""Incident Management Service: State Machine, Explainable Risk Scoring, SLA, Optimistic Locking."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.core.rbac import PermissionCode, role_has_permission
from app.models.alert import Alert
from app.models.incident import (
    Incident,
    IncidentAffectedUser,
    IncidentAlert,
    IncidentAsset,
    IncidentLink,
    IncidentTimeline,
)
from app.models.investigation import (
    IncidentIndicator,
    IncidentTechnique,
    Indicator,
    MitreTechnique,
)
from app.models.ops import Notification, SlaPolicy
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event

# Explicit Allowed Incident Lifecycle State Machine
ALLOWED_INCIDENT_TRANSITIONS: dict[str, set[str]] = {
    "NEW": {"TRIAGED", "INVESTIGATING"},
    "TRIAGED": {"INVESTIGATING", "CONTAINMENT"},
    "INVESTIGATING": {"CONTAINMENT", "ERADICATION", "RESOLVED"},
    "CONTAINMENT": {"INVESTIGATING", "ERADICATION", "RECOVERY", "RESOLVED"},
    "ERADICATION": {"CONTAINMENT", "RECOVERY", "RESOLVED"},
    "RECOVERY": {"INVESTIGATING", "RESOLVED"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},
    "CLOSED": {"INVESTIGATING"},  # Reopening closed incident requires L2/Manager + mandatory reason
}

OPEN_INCIDENT_STATUSES = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT",
    "ERADICATION",
    "RECOVERY",
}

DEFAULT_SLA_MINUTES: dict[str, tuple[int, int]] = {
    "critical": (15, 240),     # 15m ack, 4h resolve
    "high": (60, 480),         # 1h ack, 8h resolve
    "medium": (240, 4320),     # 4h ack, 3d resolve
    "low": (1440, 10080),      # 24h ack, 7d resolve
}

BASE_SEVERITY_WEIGHTS = {
    "low": 15,
    "medium": 35,
    "high": 60,
    "critical": 80,
}

ASSET_CRITICALITY_WEIGHTS = {
    "low": 0,
    "medium": 5,
    "high": 12,
    "critical": 20,
}

PRIVILEGED_USERNAME_MARKERS = ("admin", "root", "svc_", "svc-", "domain_admin", "krbtgt", "system")


def is_internal_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        # Note: RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        # are treated as external simulated indicators in SENTINEL IR per Section 7!
        doc_nets = (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        )
        if any(addr in net for net in doc_nets):
            return False
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


def calculate_explainable_risk(
    *,
    base_severity: str,
    asset_criticality: str | None,
    threat_intel_confidence: int,
    correlated_alert_count: int,
    compromise_confirmed: bool,
    privileged_account_involved: bool,
) -> tuple[int, str, str, dict[str, Any]]:
    """Compute documented explainable risk score (0-100) + derived severity & priority.

    Formula (documented in docs/SEVERITY_SCORING.md):
      score = min(100, base_severity_weight
                     + asset_criticality_weight
                     + ti_confidence_points
                     + correlation_bonus
                     + compromise_bonus
                     + privileged_account_bonus)
    """
    base_w = BASE_SEVERITY_WEIGHTS.get(base_severity.lower(), 35)
    asset_w = ASSET_CRITICALITY_WEIGHTS.get((asset_criticality or "medium").lower(), 5)
    ti_points = round(min(max(threat_intel_confidence, 0), 100) * 0.15)
    corr_bonus = min(max(correlated_alert_count - 1, 0) * 4, 16)
    comp_bonus = 15 if compromise_confirmed else 0
    priv_bonus = 10 if privileged_account_involved else 0

    raw_total = base_w + asset_w + ti_points + corr_bonus + comp_bonus + priv_bonus
    final_score = min(100, raw_total)

    if final_score >= 80:
        derived_sev, priority = "critical", "p1"
    elif final_score >= 60:
        derived_sev, priority = "high", "p2"
    elif final_score >= 35:
        derived_sev, priority = "medium", "p3"
    else:
        derived_sev, priority = "low", "p4"

    breakdown: dict[str, Any] = {
        "formula_version": "1.0",
        "base_severity_weight": base_w,
        "asset_criticality_weight": asset_w,
        "threat_intel_points": ti_points,
        "correlated_alerts_bonus": corr_bonus,
        "compromise_evidence_bonus": comp_bonus,
        "privileged_account_bonus": priv_bonus,
        "raw_sum": raw_total,
        "final_score": final_score,
        "derived_severity": derived_sev,
        "factors": {
            "base_severity": base_severity,
            "asset_criticality": asset_criticality or "medium",
            "threat_intel_confidence": threat_intel_confidence,
            "correlated_alert_count": correlated_alert_count,
            "compromise_confirmed": compromise_confirmed,
            "privileged_account_involved": privileged_account_involved,
        },
    }
    return final_score, derived_sev, priority, breakdown


def compute_sla_state(incident: Incident, now: datetime | None = None) -> dict[str, Any]:
    ref_now = now or datetime.now(UTC)
    if incident.status in ("RESOLVED", "CLOSED"):
        resolved_ref = incident.resolved_at or incident.closed_at or ref_now
        breached = bool(
            incident.sla_resolve_due_at and resolved_ref > incident.sla_resolve_due_at
        )
        return {
            "status": "breached" if breached else "on_track",
            "ack_due_at": incident.sla_ack_due_at.isoformat() if incident.sla_ack_due_at else None,
            "resolve_due_at": (
                incident.sla_resolve_due_at.isoformat() if incident.sla_resolve_due_at else None
            ),
            "elapsed_ratio": 1.0 if breached else 0.5,
        }

    due = incident.sla_resolve_due_at
    if due is None:
        return {
            "status": "on_track",
            "ack_due_at": None,
            "resolve_due_at": None,
            "elapsed_ratio": 0.0,
        }

    total_window = max((due - incident.created_at).total_seconds(), 60.0)
    elapsed = max(
        (ref_now - incident.created_at).total_seconds() - incident.sla_paused_seconds,
        0.0,
    )
    ratio = round(elapsed / total_window, 4)

    ack_breached = bool(
        incident.acknowledged_at is None
        and incident.sla_ack_due_at is not None
        and ref_now > incident.sla_ack_due_at
    )
    if ref_now > due or ack_breached:
        sla_state = "breached"
    elif ratio >= 0.75:
        sla_state = "at_risk"
    else:
        sla_state = "on_track"

    return {
        "status": sla_state,
        "ack_due_at": incident.sla_ack_due_at.isoformat() if incident.sla_ack_due_at else None,
        "resolve_due_at": due.isoformat(),
        "elapsed_ratio": ratio,
    }


class IncidentService:
    @staticmethod
    async def _next_human_id(db: AsyncSession, year: int | None = None) -> str:
        seq_res = await db.execute(text("SELECT nextval('incident_human_id_seq')"))
        num = int(seq_res.scalar_one())
        yr = year or datetime.now(UTC).year
        return f"INC-{yr}-{num:04d}"

    @staticmethod
    async def _resolve_sla_deadlines(
        db: AsyncSession, severity: str, created_at: datetime
    ) -> tuple[datetime, datetime]:
        res = await db.execute(
            select(SlaPolicy).where(SlaPolicy.severity == severity.lower())
        )
        policy = res.scalar_one_or_none()
        if policy:
            ack_m, res_m = policy.ack_minutes, policy.resolve_minutes
        else:
            ack_m, res_m = DEFAULT_SLA_MINUTES.get(severity.lower(), (240, 4320))
        return (
            created_at + timedelta(minutes=ack_m),
            created_at + timedelta(minutes=res_m),
        )

    @staticmethod
    async def _sync_alert_entities_to_incident(
        db: AsyncSession, incident: Incident, alert: Alert, actor: User | None
    ) -> None:
        # 1. Link Asset if known
        if alert.asset_id:
            existing_asset = await db.execute(
                select(IncidentAsset).where(
                    IncidentAsset.incident_id == incident.id,
                    IncidentAsset.asset_id == alert.asset_id,
                )
            )
            if existing_asset.scalar_one_or_none() is None:
                db.add(IncidentAsset(incident_id=incident.id, asset_id=alert.asset_id))

        # 2. Link Affected User if present
        if alert.username:
            uname = alert.username.strip()
            existing_u = await db.execute(
                select(IncidentAffectedUser).where(
                    IncidentAffectedUser.incident_id == incident.id,
                    IncidentAffectedUser.username == uname,
                )
            )
            if existing_u.scalar_one_or_none() is None:
                is_priv = any(m in uname.lower() for m in PRIVILEGED_USERNAME_MARKERS)
                db.add(
                    IncidentAffectedUser(
                        incident_id=incident.id,
                        username=uname,
                        account_type="privileged" if is_priv else "standard",
                        is_privileged=is_priv,
                    )
                )

        # 3. Extract Indicators (IP, domain, SHA256)
        candidate_iocs: list[tuple[str, str]] = []
        if alert.src_ip:
            candidate_iocs.append(("ip", alert.src_ip))
        if alert.domain:
            candidate_iocs.append(("domain", alert.domain))
        if alert.file_hash and len(alert.file_hash) == 64:
            candidate_iocs.append(("sha256", alert.file_hash))

        for ioc_type, val in candidate_iocs:
            ind_res = await db.execute(
                select(Indicator).where(Indicator.ioc_type == ioc_type, Indicator.value == val)
            )
            indicator = ind_res.scalar_one_or_none()
            if indicator is None:
                internal_flag = is_internal_ip(val) if ioc_type == "ip" else val.endswith(".local")
                indicator = Indicator(
                    id=uuid.uuid4(),
                    ioc_type=ioc_type,
                    value=val,
                    is_internal=internal_flag,
                    reputation="internal" if internal_flag else "unknown",
                    is_simulated=alert.is_simulated,
                )
                db.add(indicator)
                await db.flush()
            else:
                indicator.last_seen_at = datetime.now(UTC)

            link_res = await db.execute(
                select(IncidentIndicator).where(
                    IncidentIndicator.incident_id == incident.id,
                    IncidentIndicator.indicator_id == indicator.id,
                )
            )
            if link_res.scalar_one_or_none() is None:
                db.add(
                    IncidentIndicator(
                        incident_id=incident.id,
                        indicator_id=indicator.id,
                        alert_id=alert.id,
                        added_by_id=actor.id if actor else None,
                    )
                )

        # 4. Suggest MITRE ATT&CK techniques carried on the alert
        for m in alert.mitre_mappings_raw or []:
            tech_id = str(m.get("id") or "").strip()
            if not tech_id:
                continue
            tech_res = await db.execute(
                select(MitreTechnique).where(MitreTechnique.id == tech_id)
            )
            tech = tech_res.scalar_one_or_none()
            if tech is None:
                # Ensure documented STIX stub exists if created before full STIX seed runs
                tech = MitreTechnique(
                    id=tech_id,
                    stix_id=f"attack-pattern--stub-{tech_id.lower()}",
                    name=str(m.get("name") or tech_id),
                    tactics=[str(m.get("tactic") or "execution")],
                    description="Mapped from alert detection rule metadata.",
                    url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                    is_subtechnique="." in tech_id,
                    parent_id=tech_id.split(".")[0] if "." in tech_id else None,
                )
                db.add(tech)
                await db.flush()

            it_res = await db.execute(
                select(IncidentTechnique).where(
                    IncidentTechnique.incident_id == incident.id,
                    IncidentTechnique.technique_id == tech.id,
                )
            )
            if it_res.scalar_one_or_none() is None:
                src = str(m.get("source") or "alert_metadata")
                if src not in ("alert_metadata", "enrichment", "playbook_rule", "analyst"):
                    src = "alert_metadata"
                db.add(
                    IncidentTechnique(
                        incident_id=incident.id,
                        technique_id=tech.id,
                        source=src,
                        status="suggested",
                        rationale=f"Derived from alert rule {alert.rule_id}: {alert.rule_description}",
                        linked_alert_id=alert.id,
                        created_by_id=actor.id if actor else None,
                    )
                )

    @staticmethod
    async def create_incident(
        db: AsyncSession,
        *,
        title: str,
        description: str,
        category: str = "general",
        base_severity: str = "medium",
        alert_ids: list[uuid.UUID] | None = None,
        assigned_to_id: uuid.UUID | None = None,
        actor: User | None = None,
        idempotency_key: str | None = None,
        source_ip: str | None = None,
        is_simulated: bool = False,
    ) -> Incident:
        if idempotency_key:
            idem_res = await db.execute(
                select(Incident).where(Incident.idempotency_key == idempotency_key)
            )
            existing_idem = idem_res.scalar_one_or_none()
            if existing_idem is not None:
                return existing_idem

        alerts: list[Alert] = []
        if alert_ids:
            a_res = await db.execute(select(Alert).where(Alert.id.in_(alert_ids)))
            alerts = list(a_res.scalars().all())
            if len(alerts) != len(set(alert_ids)):
                raise AppError(
                    code="ALERT_NOT_FOUND",
                    message="One or more specified alerts do not exist.",
                    status_code=status.HTTP_404_NOT_FOUND,
                )

            # Prevent duplicate open incidents from the same alert (Section 4 Module C & Section 18)
            open_link_res = await db.execute(
                select(Incident)
                .join(IncidentAlert, IncidentAlert.incident_id == Incident.id)
                .where(
                    IncidentAlert.alert_id.in_([a.id for a in alerts]),
                    Incident.status.in_(OPEN_INCIDENT_STATUSES),
                )
                .limit(1)
            )
            already_open = open_link_res.scalar_one_or_none()
            if already_open is not None:
                raise AppError(
                    code="ALERT_ALREADY_LINKED_TO_OPEN_INCIDENT",
                    message=(
                        f"Alert is already linked to open incident {already_open.human_id}. "
                        "Link additional context to the existing incident instead of creating a duplicate."
                    ),
                    status_code=status.HTTP_409_CONFLICT,
                    details={
                        "existing_incident_id": str(already_open.id),
                        "existing_human_id": already_open.human_id,
                    },
                )

        now = datetime.now(UTC)
        highest_sev = base_severity.lower()
        sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        asset_crit = "medium"
        priv_involved = False
        sim_flag = is_simulated

        for a in alerts:
            if sev_rank.get(a.severity, 2) > sev_rank.get(highest_sev, 2):
                highest_sev = a.severity
            if a.asset and sev_rank.get(a.asset.criticality, 2) > sev_rank.get(asset_crit, 2):
                asset_crit = a.asset.criticality
            if a.username and any(m in a.username.lower() for m in PRIVILEGED_USERNAME_MARKERS):
                priv_involved = True
            if a.is_simulated:
                sim_flag = True

        score, derived_sev, priority, breakdown = calculate_explainable_risk(
            base_severity=highest_sev,
            asset_criticality=asset_crit,
            threat_intel_confidence=0,
            correlated_alert_count=max(len(alerts), 1),
            compromise_confirmed=False,
            privileged_account_involved=priv_involved,
        )

        human_id = await IncidentService._next_human_id(db)
        ack_due, resolve_due = await IncidentService._resolve_sla_deadlines(db, derived_sev, now)

        incident = Incident(
            id=uuid.uuid4(),
            human_id=human_id,
            title=title.strip(),
            description=description.strip(),
            category=category.strip().lower(),
            severity=derived_sev,
            priority=priority,
            status="TRIAGED" if alerts else "NEW",
            assigned_to_id=assigned_to_id,
            created_by_id=actor.id if actor else None,
            acknowledged_at=now if assigned_to_id else None,
            sla_ack_due_at=ack_due,
            sla_resolve_due_at=resolve_due,
            risk_score=score,
            risk_breakdown=breakdown,
            idempotency_key=idempotency_key,
            is_simulated=sim_flag,
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(incident)
        await db.flush()

        actor_label = actor.username if actor else "SYSTEM"
        db.add(
            IncidentTimeline(
                incident_id=incident.id,
                event_type="incident_created",
                title=f"Incident {human_id} created ({derived_sev.upper()})",
                description=f"Case opened with risk score {score}/100 and status {incident.status}.",
                actor_id=actor.id if actor else None,
                actor_label=actor_label,
                metadata_json={"severity": derived_sev, "risk_score": score},
                occurred_at=now,
            )
        )

        for a in alerts:
            a.triage_status = "incident_created"
            a.version += 1
            db.add(
                IncidentAlert(
                    incident_id=incident.id,
                    alert_id=a.id,
                    linked_by_id=actor.id if actor else None,
                )
            )
            db.add(
                IncidentTimeline(
                    incident_id=incident.id,
                    event_type="alert_linked",
                    title=f"Alert [{a.rule_id}] linked: {a.rule_description[:90]}",
                    description=f"Source: {a.source_system} | Occurrences: {a.occurrence_count}",
                    actor_id=actor.id if actor else None,
                    actor_label=actor_label,
                    metadata_json={"alert_id": str(a.id), "rule_id": a.rule_id},
                    occurred_at=a.event_timestamp,
                )
            )
            await IncidentService._sync_alert_entities_to_incident(db, incident, a, actor)

        if assigned_to_id or derived_sev in ("high", "critical"):
            notif_sev = "critical" if derived_sev == "critical" else ("high" if derived_sev == "high" else "info")
            db.add(
                Notification(
                    user_id=assigned_to_id,
                    role_target=None if assigned_to_id else "soc_l2",
                    title=f"Incident Opened: {human_id} ({derived_sev.upper()})",
                    body=incident.title[:240],
                    severity=notif_sev,
                    event_type="incident.created",
                    link_url=f"/incidents/{human_id}",
                    created_at=now,
                )
            )

        await AuditService.record(
            db,
            action="incident.created",
            actor=actor,
            target_type="incident",
            target_id=str(incident.id),
            outcome="success",
            source_ip=source_ip,
            details={
                "human_id": human_id,
                "severity": derived_sev,
                "risk_score": score,
                "linked_alert_ids": [str(a.id) for a in alerts],
            },
        )
        await db.commit()
        await db.refresh(incident)

        await publish_realtime_event(
            "incident.created",
            {
                "incident_id": str(incident.id),
                "human_id": incident.human_id,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "is_simulated": incident.is_simulated,
            },
            required_permission="incidents:view",
        )
        return incident

    @staticmethod
    async def transition_status(
        db: AsyncSession,
        *,
        incident_id: uuid.UUID,
        target_status: str,
        expected_version: int,
        actor: User,
        reason: str | None = None,
        closure_category: str | None = None,
        closure_justification: str | None = None,
        source_ip: str | None = None,
    ) -> Incident:
        res = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = res.scalar_one_or_none()
        if incident is None:
            raise AppError(
                code="INCIDENT_NOT_FOUND",
                message="Incident not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        if incident.version != expected_version:
            raise AppError(
                code="OPTIMISTIC_LOCK_CONFLICT",
                message=(
                    f"Incident was modified concurrently (expected version {expected_version}, "
                    f"current version {incident.version}). Refresh and retry."
                ),
                status_code=status.HTTP_409_CONFLICT,
                details={"current_version": incident.version},
            )

        current = incident.status
        next_state = target_status.strip().upper()
        allowed = ALLOWED_INCIDENT_TRANSITIONS.get(current, set())

        if next_state not in allowed:
            await AuditService.record(
                db,
                action="incident.illegal_transition_rejected",
                actor=actor,
                target_type="incident",
                target_id=str(incident.id),
                outcome="denied",
                source_ip=source_ip,
                details={"from_status": current, "attempted_status": next_state},
            )
            await db.commit()
            raise AppError(
                code="ILLEGAL_STATE_TRANSITION",
                message=f"Transition from {current} to {next_state} is not permitted by the incident lifecycle state machine.",
                status_code=status.HTTP_409_CONFLICT,
                details={"current_status": current, "allowed_next": sorted(allowed)},
            )

        role_name = actor.role.name if actor.role else "soc_l1"

        # Reopening RESOLVED or CLOSED -> INVESTIGATING requires a mandatory reason;
        # reopening CLOSED specifically requires L2/Manager (`incidents:reopen_closed`).
        if current in ("RESOLVED", "CLOSED") and next_state == "INVESTIGATING":
            if not reason or len(reason.strip()) < 5:
                raise AppError(
                    code="REOPEN_REASON_REQUIRED",
                    message="Reopening an incident requires a written reason (minimum 5 characters).",
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
            if current == "CLOSED" and not role_has_permission(
                role_name, PermissionCode.INCIDENTS_REOPEN_CLOSED
            ):
                await AuditService.record(
                    db,
                    action="incident.reopen_closed_denied",
                    actor=actor,
                    target_type="incident",
                    target_id=str(incident.id),
                    outcome="denied",
                    source_ip=source_ip,
                )
                await db.commit()
                raise AppError(
                    code="REOPEN_CLOSED_FORBIDDEN",
                    message="Reopening a CLOSED incident requires SOC L2, SOC Manager, or Administrator authorization.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )

        # Closing requires closure category + written justification + `incidents:close`
        if next_state == "CLOSED":
            if not role_has_permission(role_name, PermissionCode.INCIDENTS_CLOSE):
                raise AppError(
                    code="CLOSE_INCIDENT_FORBIDDEN",
                    message="Closing an incident requires SOC L2 or higher authorization.",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            if not closure_category or not closure_justification or len(closure_justification.strip()) < 10:
                raise AppError(
                    code="CLOSURE_JUSTIFICATION_REQUIRED",
                    message="Closing an incident requires both a closure_category and a written closure_justification (minimum 10 characters).",
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
            incident.closure_category = closure_category.strip()
            incident.closure_justification = closure_justification.strip()

        now = datetime.now(UTC)
        if incident.acknowledged_at is None:
            incident.acknowledged_at = now
        if next_state == "CONTAINMENT" and incident.contained_at is None:
            incident.contained_at = now
        if next_state == "RESOLVED":
            incident.resolved_at = now
        if next_state == "CLOSED":
            incident.closed_at = now
        if current in ("RESOLVED", "CLOSED") and next_state == "INVESTIGATING":
            incident.resolved_at = None
            incident.closed_at = None

        incident.status = next_state
        incident.version += 1
        incident.updated_at = now

        db.add(
            IncidentTimeline(
                incident_id=incident.id,
                event_type="status_changed",
                title=f"Lifecycle transition: {current} → {next_state}",
                description=reason or closure_justification or f"Transitioned by {actor.username}.",
                actor_id=actor.id,
                actor_label=actor.username,
                metadata_json={
                    "from_status": current,
                    "to_status": next_state,
                    "closure_category": closure_category,
                },
                occurred_at=now,
            )
        )

        await AuditService.record(
            db,
            action="incident.status_changed",
            actor=actor,
            target_type="incident",
            target_id=str(incident.id),
            outcome="success",
            source_ip=source_ip,
            details={
                "human_id": incident.human_id,
                "from_status": current,
                "to_status": next_state,
                "reason": reason,
                "closure_category": closure_category,
                "new_version": incident.version,
            },
        )
        await db.commit()
        await db.refresh(incident)

        await publish_realtime_event(
            "incident.status_changed",
            {
                "incident_id": str(incident.id),
                "human_id": incident.human_id,
                "from_status": current,
                "to_status": next_state,
                "version": incident.version,
            },
            required_permission="incidents:view",
        )
        return incident

    @staticmethod
    async def link_alert_to_incident(
        db: AsyncSession,
        *,
        incident_id: uuid.UUID,
        alert_id: uuid.UUID,
        actor: User,
        source_ip: str | None = None,
    ) -> Incident:
        inc_res = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = inc_res.scalar_one_or_none()
        if incident is None:
            raise AppError("INCIDENT_NOT_FOUND", "Incident not found.", status.HTTP_404_NOT_FOUND)

        a_res = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = a_res.scalar_one_or_none()
        if alert is None:
            raise AppError("ALERT_NOT_FOUND", "Alert not found.", status.HTTP_404_NOT_FOUND)

        dup_res = await db.execute(
            select(IncidentAlert).where(
                IncidentAlert.incident_id == incident.id,
                IncidentAlert.alert_id == alert.id,
            )
        )
        if dup_res.scalar_one_or_none() is None:
            db.add(
                IncidentAlert(
                    incident_id=incident.id,
                    alert_id=alert.id,
                    linked_by_id=actor.id,
                )
            )
            alert.triage_status = "incident_created"
            alert.version += 1
            await IncidentService._sync_alert_entities_to_incident(db, incident, alert, actor)

            now = datetime.now(UTC)
            incident.version += 1
            incident.updated_at = now
            db.add(
                IncidentTimeline(
                    incident_id=incident.id,
                    event_type="alert_linked",
                    title=f"Alert [{alert.rule_id}] linked to {incident.human_id}",
                    description=alert.rule_description,
                    actor_id=actor.id,
                    actor_label=actor.username,
                    metadata_json={"alert_id": str(alert.id)},
                    occurred_at=now,
                )
            )
            await AuditService.record(
                db,
                action="incident.alert_linked",
                actor=actor,
                target_type="incident",
                target_id=str(incident.id),
                outcome="success",
                source_ip=source_ip,
                details={"alert_id": str(alert.id), "human_id": incident.human_id},
            )
            await db.commit()
            await db.refresh(incident)
        return incident

    @staticmethod
    async def link_related_incidents(
        db: AsyncSession,
        *,
        source_incident_id: uuid.UUID,
        target_incident_id: uuid.UUID,
        link_type: str,
        notes: str | None,
        actor: User,
        source_ip: str | None = None,
    ) -> IncidentLink:
        if source_incident_id == target_incident_id:
            raise AppError(
                "SELF_LINK_INVALID",
                "Cannot link an incident to itself.",
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        res = await db.execute(
            select(Incident.id).where(
                Incident.id.in_([source_incident_id, target_incident_id])
            )
        )
        if len(list(res.scalars().all())) != 2:
            raise AppError("INCIDENT_NOT_FOUND", "One or both incidents do not exist.", 404)

        link = IncidentLink(
            source_incident_id=source_incident_id,
            target_incident_id=target_incident_id,
            link_type=link_type,
            notes=notes,
            created_by_id=actor.id,
        )
        db.add(link)
        db.add(
            IncidentTimeline(
                incident_id=source_incident_id,
                event_type="incident_linked",
                title=f"Linked related incident ({link_type})",
                description=notes or "",
                actor_id=actor.id,
                actor_label=actor.username,
                metadata_json={"target_incident_id": str(target_incident_id), "link_type": link_type},
            )
        )
        await AuditService.record(
            db,
            action="incident.linked_related",
            actor=actor,
            target_type="incident",
            target_id=str(source_incident_id),
            outcome="success",
            source_ip=source_ip,
            details={"target_incident_id": str(target_incident_id), "link_type": link_type},
        )
        await db.commit()
        await db.refresh(link)
        return link
