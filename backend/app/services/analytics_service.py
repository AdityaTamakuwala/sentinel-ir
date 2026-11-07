"""Database-driven SOC Command Centre operational metrics (zero hardcoded figures)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.automation import PlaybookExecution, ResponseAction, ResponseApproval
from app.models.incident import Incident, IncidentTimeline
from app.models.investigation import IncidentTechnique, Indicator, MitreTechnique
from app.models.user import User
from app.services.incident_service import OPEN_INCIDENT_STATUSES, compute_sla_state


class AnalyticsService:
    @staticmethod
    async def get_command_center_metrics(
        db: AsyncSession,
        *,
        window_days: int = 30,
        severity: str | None = None,
        status_filter: str | None = None,
        source_system: str | None = None,
        assigned_to_id: uuid.UUID | None = None,
        include_simulated: bool = True,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=max(window_days, 1))

        # 1. Alert queries
        alert_stmt = select(Alert).where(Alert.ingested_at >= cutoff)
        if not include_simulated:
            alert_stmt = alert_stmt.where(Alert.is_simulated.is_(False))
        if severity:
            alert_stmt = alert_stmt.where(Alert.severity == severity.lower())
        if source_system:
            alert_stmt = alert_stmt.where(Alert.source_system == source_system.lower())
        if assigned_to_id:
            alert_stmt = alert_stmt.where(Alert.assigned_to_id == assigned_to_id)

        alerts_res = await db.execute(alert_stmt)
        alerts = list(alerts_res.scalars().all())

        # 2. Incident queries
        inc_stmt = select(Incident).where(Incident.created_at >= cutoff)
        if not include_simulated:
            inc_stmt = inc_stmt.where(Incident.is_simulated.is_(False))
        if severity:
            inc_stmt = inc_stmt.where(Incident.severity == severity.lower())
        if status_filter:
            inc_stmt = inc_stmt.where(Incident.status == status_filter.upper())
        if assigned_to_id:
            inc_stmt = inc_stmt.where(Incident.assigned_to_id == assigned_to_id)

        inc_res = await db.execute(inc_stmt.order_by(Incident.created_at.desc()))
        incidents = list(inc_res.scalars().all())

        open_incidents = [i for i in incidents if i.status in OPEN_INCIDENT_STATUSES]
        critical_open = [i for i in open_incidents if i.severity == "critical"]
        high_open = [i for i in open_incidents if i.severity == "high"]
        awaiting_action = [
            i for i in open_incidents if i.status == "NEW" or i.assigned_to_id is None
        ]
        under_investigation = [
            i
            for i in open_incidents
            if i.status in ("TRIAGED", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY")
        ]
        resolved_incidents = [i for i in incidents if i.status in ("RESOLVED", "CLOSED")]

        # MTTD = mean(ingested_at - event_timestamp) in minutes
        det_deltas_min: list[float] = []
        for a in alerts:
            if a.ingested_at >= a.event_timestamp:
                det_deltas_min.append((a.ingested_at - a.event_timestamp).total_seconds() / 60.0)
        mttd_minutes = round(sum(det_deltas_min) / len(det_deltas_min), 1) if det_deltas_min else None

        # MTTA = mean(acknowledged_at - created_at) in minutes
        ack_deltas_min: list[float] = []
        for i in incidents:
            if i.acknowledged_at and i.acknowledged_at >= i.created_at:
                ack_deltas_min.append((i.acknowledged_at - i.created_at).total_seconds() / 60.0)
        mtta_minutes = round(sum(ack_deltas_min) / len(ack_deltas_min), 1) if ack_deltas_min else None

        # MTTC = mean(contained_at - created_at) in minutes
        cont_deltas_min: list[float] = []
        for i in incidents:
            if i.contained_at and i.contained_at >= i.created_at:
                cont_deltas_min.append((i.contained_at - i.created_at).total_seconds() / 60.0)
        mttc_minutes = round(sum(cont_deltas_min) / len(cont_deltas_min), 1) if cont_deltas_min else None

        # MTTR = mean(resolved_at - created_at) in minutes for resolved incidents in window
        res_deltas_min: list[float] = []
        for i in resolved_incidents:
            end_ts = i.resolved_at or i.closed_at
            if end_ts and end_ts >= i.created_at:
                res_deltas_min.append((end_ts - i.created_at).total_seconds() / 60.0)
        mttr_minutes = round(sum(res_deltas_min) / len(res_deltas_min), 1) if res_deltas_min else None

        # SLA breakdown
        sla_counts = {"on_track": 0, "at_risk": 0, "breached": 0}
        sla_items: list[dict[str, Any]] = []
        for i in open_incidents[:15]:
            sla_info = compute_sla_state(i, now)
            sla_counts[sla_info["status"]] = sla_counts.get(sla_info["status"], 0) + 1
            sla_items.append(
                {
                    "incident_id": str(i.id),
                    "human_id": i.human_id,
                    "title": i.title,
                    "severity": i.severity,
                    "status": i.status,
                    "sla_status": sla_info["status"],
                    "elapsed_ratio": sla_info["elapsed_ratio"],
                    "resolve_due_at": sla_info["resolve_due_at"],
                    "is_simulated": i.is_simulated,
                }
            )
        for i in open_incidents[15:]:
            sla_info = compute_sla_state(i, now)
            sla_counts[sla_info["status"]] = sla_counts.get(sla_info["status"], 0) + 1

        # Severity distribution
        sev_dist_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for i in incidents:
            sev_dist_map[i.severity] = sev_dist_map.get(i.severity, 0) + 1
        severity_distribution = [
            {"severity": k, "count": v} for k, v in sev_dist_map.items()
        ]

        # Alert source distribution
        source_counts: dict[str, int] = {}
        for a in alerts:
            source_counts[a.source_system] = source_counts.get(a.source_system, 0) + 1
        alert_source_distribution = [
            {"source": k, "count": v}
            for k, v in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        # Daily trend series across last min(window_days, 14) days
        trend_days = min(max(window_days, 7), 30)
        trend_buckets: dict[str, dict[str, Any]] = {}
        for offset in range(trend_days - 1, -1, -1):
            day_str = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
            trend_buckets[day_str] = {"date": day_str, "alerts": 0, "incidents": 0}
        for a in alerts:
            d = a.ingested_at.astimezone(UTC).strftime("%Y-%m-%d")
            if d in trend_buckets:
                trend_buckets[d]["alerts"] += 1
        for i in incidents:
            d = i.created_at.astimezone(UTC).strftime("%Y-%m-%d")
            if d in trend_buckets:
                trend_buckets[d]["incidents"] += 1

        # Analyst workload
        users_res = await db.execute(select(User).where(User.is_active.is_(True)))
        users = list(users_res.scalars().all())
        workload: list[dict[str, Any]] = []
        for u in users:
            open_inc_count = sum(1 for i in open_incidents if i.assigned_to_id == u.id)
            open_alert_count = sum(
                1
                for a in alerts
                if a.assigned_to_id == u.id
                and a.triage_status in ("new", "in_review", "escalated")
            )
            workload.append(
                {
                    "user_id": str(u.id),
                    "username": u.username,
                    "full_name": u.full_name,
                    "role": u.role.name if u.role else "soc_l1",
                    "open_incidents": open_inc_count,
                    "active_alerts": open_alert_count,
                }
            )

        # Recent live activity feed from IncidentTimeline
        tl_res = await db.execute(
            select(IncidentTimeline, Incident.human_id, Incident.is_simulated)
            .join(Incident, Incident.id == IncidentTimeline.incident_id)
            .order_by(IncidentTimeline.occurred_at.desc())
            .limit(20)
        )
        activity_feed = [
            {
                "id": str(tl.id),
                "incident_id": str(tl.incident_id),
                "human_id": human_id,
                "event_type": tl.event_type,
                "title": tl.title,
                "description": tl.description,
                "actor_label": tl.actor_label,
                "occurred_at": tl.occurred_at.isoformat(),
                "is_simulated": is_sim,
            }
            for tl, human_id, is_sim in tl_res.all()
        ]

        # Total database counts (reconciliation metadata)
        total_alerts_all_time = int(
            (await db.execute(select(func.count(Alert.id)))).scalar_one()
        )
        total_incidents_all_time = int(
            (await db.execute(select(func.count(Incident.id)))).scalar_one()
        )

        return {
            "window_days": window_days,
            "generated_at": now.isoformat(),
            "kpis": {
                "total_alerts": len(alerts),
                "unreviewed_alerts": sum(1 for a in alerts if a.triage_status == "new"),
                "open_incidents": len(open_incidents),
                "critical_incidents": len(critical_open),
                "high_priority_incidents": len(high_open),
                "awaiting_analyst_action": len(awaiting_action),
                "under_investigation": len(under_investigation),
                "resolved_incidents": len(resolved_incidents),
                "mttd_minutes": mttd_minutes,
                "mtta_minutes": mtta_minutes,
                "mttc_minutes": mttc_minutes,
                "mttr_minutes": mttr_minutes,
                "total_alerts_all_time": total_alerts_all_time,
                "total_incidents_all_time": total_incidents_all_time,
            },
            "sla_summary": sla_counts,
            "sla_watchlist": sla_items,
            "severity_distribution": severity_distribution,
            "alert_source_distribution": alert_source_distribution,
            "trends": list(trend_buckets.values()),
            "analyst_workload": workload,
            "recent_activity": activity_feed,
        }

    @classmethod
    async def get_soc_overview(
        cls,
        db: AsyncSession,
        *,
        window_days: int = 30,
        include_simulated: bool = True,
    ) -> dict[str, Any]:
        """Aggregate executive-level SOC Command metrics, KPIs, and distributions."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=max(window_days, 1))

        # Incidents in window
        stmt = select(Incident).where(Incident.created_at >= cutoff)
        if not include_simulated:
            stmt = stmt.where(Incident.is_simulated.is_(False))
        res = await db.execute(stmt)
        incidents = list(res.scalars().all())

        # Alerts in window
        a_stmt = select(Alert).where(Alert.ingested_at >= cutoff)
        if not include_simulated:
            a_stmt = a_stmt.where(Alert.is_simulated.is_(False))
        a_res = await db.execute(a_stmt)
        alerts = list(a_res.scalars().all())

        # Playbook executions in window
        pb_stmt = select(PlaybookExecution).where(PlaybookExecution.created_at >= cutoff)
        pb_res = await db.execute(pb_stmt)
        pb_executions = list(pb_res.scalars().all())

        # MTTD, MTTA, MTTC, MTTR
        mttd_list: list[float] = [
            (a.ingested_at - a.event_timestamp).total_seconds() / 60.0
            for a in alerts
            if a.ingested_at >= a.event_timestamp
        ]
        mttd = round(sum(mttd_list) / len(mttd_list), 1) if mttd_list else 0.0

        mtta_list: list[float] = [
            (i.acknowledged_at - i.created_at).total_seconds() / 60.0
            for i in incidents
            if i.acknowledged_at and i.acknowledged_at >= i.created_at
        ]
        mtta = round(sum(mtta_list) / len(mtta_list), 1) if mtta_list else 0.0

        mttc_list: list[float] = [
            (i.contained_at - i.created_at).total_seconds() / 60.0
            for i in incidents
            if i.contained_at and i.contained_at >= i.created_at
        ]
        mttc = round(sum(mttc_list) / len(mttc_list), 1) if mttc_list else 0.0

        mttr_list: list[float] = []
        for i in incidents:
            end_ts = i.resolved_at or i.closed_at
            if end_ts and end_ts >= i.created_at:
                mttr_list.append((end_ts - i.created_at).total_seconds() / 60.0)
        mttr = round(sum(mttr_list) / len(mttr_list), 1) if mttr_list else 0.0

        # Status and category distributions
        status_map: dict[str, int] = {}
        category_map: dict[str, int] = {}
        sev_map: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        on_track_sla = 0
        for i in incidents:
            status_map[i.status] = status_map.get(i.status, 0) + 1
            category_map[i.category] = category_map.get(i.category, 0) + 1
            sev_map[i.severity] = sev_map.get(i.severity, 0) + 1
            sla = compute_sla_state(i, now)
            if sla["status"] == "on_track":
                on_track_sla += 1

        sla_rate = round((on_track_sla / len(incidents) * 100.0), 1) if incidents else 100.0

        completed_pb = sum(1 for p in pb_executions if p.status == "COMPLETED")
        pb_success_rate = (
            round((completed_pb / len(pb_executions) * 100.0), 1) if pb_executions else 100.0
        )

        return {
            "window_days": window_days,
            "generated_at": now.isoformat(),
            "kpis": {
                "mttd_minutes": mttd,
                "mtta_minutes": mtta,
                "mttc_minutes": mttc,
                "mttr_minutes": mttr,
                "total_incidents": len(incidents),
                "open_incidents": sum(1 for i in incidents if i.status in OPEN_INCIDENT_STATUSES),
                "critical_open": sum(1 for i in incidents if i.status in OPEN_INCIDENT_STATUSES and i.severity == "critical"),
                "high_open": sum(1 for i in incidents if i.status in OPEN_INCIDENT_STATUSES and i.severity == "high"),
                "total_alerts": len(alerts),
                "unreviewed_alerts": sum(1 for a in alerts if a.triage_status == "new"),
                "sla_compliance_rate": sla_rate,
                "playbook_success_rate": pb_success_rate,
                "total_playbook_runs": len(pb_executions),
            },
            "severity_distribution": [{"severity": k, "count": v} for k, v in sev_map.items()],
            "status_distribution": [{"status": k, "count": v} for k, v in status_map.items()],
            "category_distribution": [
                {"category": k, "count": v}
                for k, v in sorted(category_map.items(), key=lambda x: x[1], reverse=True)
            ],
        }

    @classmethod
    async def get_analytics_trends(
        cls,
        db: AsyncSession,
        *,
        window_days: int = 30,
        include_simulated: bool = True,
    ) -> dict[str, Any]:
        """Daily volume trends across alerts, incidents, and severities."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=max(window_days, 1))

        # Initialize date buckets
        buckets: dict[str, dict[str, Any]] = {}
        for offset in range(window_days - 1, -1, -1):
            day_str = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
            buckets[day_str] = {
                "date": day_str,
                "alerts": 0,
                "incidents": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }

        # Query alerts
        a_stmt = select(Alert.ingested_at).where(Alert.ingested_at >= cutoff)
        if not include_simulated:
            a_stmt = a_stmt.where(Alert.is_simulated.is_(False))
        a_res = await db.execute(a_stmt)
        for ingested_at in a_res.scalars().all():
            day = ingested_at.astimezone(UTC).strftime("%Y-%m-%d")
            if day in buckets:
                buckets[day]["alerts"] += 1

        # Query incidents
        i_stmt = select(Incident.created_at, Incident.severity).where(Incident.created_at >= cutoff)
        if not include_simulated:
            i_stmt = i_stmt.where(Incident.is_simulated.is_(False))
        i_res = await db.execute(i_stmt)
        for created_at, sev in i_res.all():
            day = created_at.astimezone(UTC).strftime("%Y-%m-%d")
            if day in buckets:
                buckets[day]["incidents"] += 1
                if sev in buckets[day]:
                    buckets[day][sev] += 1

        return {
            "window_days": window_days,
            "generated_at": now.isoformat(),
            "daily_trends": list(buckets.values()),
        }

    @classmethod
    async def get_analytics_performance(
        cls,
        db: AsyncSession,
        *,
        window_days: int = 30,
        include_simulated: bool = True,
    ) -> dict[str, Any]:
        """Automation performance, four-eyes approval metrics, and MITRE frequencies."""
        now = datetime.now(UTC)
        cutoff = now - timedelta(days=max(window_days, 1))

        # 1. Playbook execution status breakdown
        pb_stmt = select(PlaybookExecution.status, func.count(PlaybookExecution.id)).where(
            PlaybookExecution.created_at >= cutoff
        ).group_by(PlaybookExecution.status)
        pb_res = await db.execute(pb_stmt)
        pb_status_counts: dict[str, int] = {str(status): int(count) for status, count in pb_res.all()}
        total_pb = sum(pb_status_counts.values())

        # 2. Response Action & Approval statistics
        act_stmt = select(ResponseAction.status, func.count(ResponseAction.id)).where(
            ResponseAction.created_at >= cutoff
        ).group_by(ResponseAction.status)
        act_res = await db.execute(act_stmt)
        action_status_counts: dict[str, int] = {str(status): int(count) for status, count in act_res.all()}

        # Approvals decision breakdown
        appr_stmt = select(ResponseApproval.decision, func.count(ResponseApproval.id)).where(
            ResponseApproval.decided_at >= cutoff
        ).group_by(ResponseApproval.decision)
        appr_res = await db.execute(appr_stmt)
        approval_decisions: dict[str, int] = {str(decision): int(count) for decision, count in appr_res.all()}

        # 3. Top MITRE ATT&CK techniques mapped
        mitre_stmt = (
            select(IncidentTechnique.technique_id, func.count(IncidentTechnique.id).label("count"))
            .join(Incident, Incident.id == IncidentTechnique.incident_id)
            .where(Incident.created_at >= cutoff)
        )
        if not include_simulated:
            mitre_stmt = mitre_stmt.where(Incident.is_simulated.is_(False))
        mitre_stmt = mitre_stmt.group_by(IncidentTechnique.technique_id).order_by(
            func.count(IncidentTechnique.id).desc()
        ).limit(10)
        mitre_res = await db.execute(mitre_stmt)

        top_techniques: list[dict[str, Any]] = []
        for tech_id, count in mitre_res.all():
            t_info = await db.execute(select(MitreTechnique).where(MitreTechnique.id == tech_id))
            tech_obj = t_info.scalar_one_or_none()
            top_techniques.append(
                {
                    "technique_id": tech_id,
                    "name": tech_obj.name if tech_obj else tech_id,
                    "count": count,
                    "tactics": tech_obj.tactics if tech_obj else [],
                }
            )

        # 4. Indicators reputation distribution
        ind_stmt = select(Indicator.reputation, func.count(Indicator.id))
        if not include_simulated:
            ind_stmt = ind_stmt.where(Indicator.is_simulated.is_(False))
        ind_stmt = ind_stmt.group_by(Indicator.reputation)
        ind_res = await db.execute(ind_stmt)
        reputation_counts: dict[str, int] = {str(rep): int(count) for rep, count in ind_res.all()}

        return {
            "window_days": window_days,
            "generated_at": now.isoformat(),
            "playbooks": {
                "total_executions": total_pb,
                "by_status": pb_status_counts,
            },
            "response_actions": {
                "total_actions": sum(action_status_counts.values()),
                "by_status": action_status_counts,
                "approvals": approval_decisions,
            },
            "mitre_techniques": {
                "top_techniques": top_techniques,
            },
            "threat_intelligence": {
                "total_indicators": sum(reputation_counts.values()),
                "reputations": reputation_counts,
            },
        }
