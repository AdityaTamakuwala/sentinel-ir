"""Simulation Execution Engine.

Executes reproducible attack scenarios through the real alert ingestion pipeline,
links incidents, enriches indicators, maps MITRE techniques, triggers playbooks,
and tracks live execution progress.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import status
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.models.alert import Alert, AlertOccurrence
from app.models.automation import (
    IncidentReport,
    Playbook,
    PlaybookExecution,
    PlaybookExecutionStep,
    ResponseAction,
)
from app.models.base import utc_now
from app.models.incident import (
    Incident,
    IncidentAffectedUser,
    IncidentAlert,
    IncidentAsset,
    IncidentLink,
    IncidentTimeline,
)
from app.models.investigation import (
    Evidence,
    IncidentIndicator,
    IncidentTechnique,
    Indicator,
    InvestigationNote,
    MitreTechnique,
)
from app.models.simulation import SimulationExecution
from app.models.user import User
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event
from app.services.incident_service import IncidentService
from app.services.playbook.engine import PlaybookEngine
from app.services.simulation.scenarios import (
    get_scenario_definition,
    list_available_scenarios,
)

logger = logging.getLogger("sentinel.simulation")


class SimulationService:
    """Enterprise Scenario Execution Engine for realistic incident simulation."""

    @staticmethod
    def list_scenarios() -> list[dict[str, Any]]:
        """Return serialized list of all 7 simulation scenarios."""
        results: list[dict[str, Any]] = []
        for s in list_available_scenarios():
            results.append(
                {
                    "slug": s.slug,
                    "scenario_id": s.scenario_id,
                    "name": s.name,
                    "short_summary": s.short_summary,
                    "description": s.description,
                    "category": s.category,
                    "severity": s.severity,
                    "expected_mitre_techniques": s.expected_mitre_techniques,
                    "associated_playbook_slug": s.associated_playbook_slug,
                    "expected_response_actions": s.expected_response_actions,
                    "expected_investigation_path": s.expected_investigation_path,
                    "synthetic_indicators": [
                        {
                            "ioc_type": ind.ioc_type,
                            "value": ind.value,
                            "reputation": ind.reputation,
                            "confidence": ind.confidence,
                            "description": ind.description,
                        }
                        for ind in s.synthetic_indicators
                    ],
                    "alerts_count": len(s.alerts),
                }
            )
        return results

    @staticmethod
    def get_scenario(slug: str) -> dict[str, Any]:
        """Return full details for a scenario definition."""
        s = get_scenario_definition(slug)
        if not s:
            raise AppError(
                code="SCENARIO_NOT_FOUND",
                message=f"Simulation scenario '{slug}' does not exist.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return {
            "slug": s.slug,
            "scenario_id": s.scenario_id,
            "name": s.name,
            "short_summary": s.short_summary,
            "description": s.description,
            "category": s.category,
            "severity": s.severity,
            "expected_mitre_techniques": s.expected_mitre_techniques,
            "associated_playbook_slug": s.associated_playbook_slug,
            "expected_response_actions": s.expected_response_actions,
            "expected_investigation_path": s.expected_investigation_path,
            "alerts_count": len(s.alerts),
            "synthetic_indicators": [
                {
                    "ioc_type": ind.ioc_type,
                    "value": ind.value,
                    "reputation": ind.reputation,
                    "confidence": ind.confidence,
                    "description": ind.description,
                }
                for ind in s.synthetic_indicators
            ],
            "alerts": [
                {
                    "title": a.title,
                    "description": a.description,
                    "source_system": a.source_system,
                    "rule_id": a.rule_id,
                    "rule_description": a.rule_description,
                    "event_category": a.event_category,
                    "severity": a.severity,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "hostname": a.hostname,
                    "username": a.username,
                    "file_hash": a.file_hash,
                    "domain": a.domain,
                    "mitre_techniques": a.mitre_techniques,
                }
                for a in s.alerts
            ],
            "executive_summary_template": s.executive_summary_template,
        }

    @staticmethod
    async def launch_scenario(
        db: AsyncSession,
        *,
        slug: str,
        mode: str = "full_chain",
        actor: User,
        source_ip: str | None = None,
    ) -> SimulationExecution:
        """Execute a reproducible simulation scenario through the real ingestion and response pipeline."""
        if mode not in ("full_chain", "alerts_only", "incident_only"):
            raise AppError(
                code="INVALID_SIMULATION_MODE",
                message=f"Mode '{mode}' must be one of: 'full_chain', 'alerts_only', 'incident_only'.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        scenario = get_scenario_definition(slug)
        if not scenario:
            raise AppError(
                code="SCENARIO_NOT_FOUND",
                message=f"Simulation scenario '{slug}' does not exist.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        exec_id = uuid.uuid4()
        execution = SimulationExecution(
            id=exec_id,
            scenario_slug=slug,
            scenario_name=scenario.name,
            status="RUNNING",
            mode=mode,
            launched_by_id=actor.id,
            started_at=utc_now(),
            execution_log=[
                {
                    "timestamp": utc_now().isoformat(),
                    "level": "INFO",
                    "step": "INITIALIZATION",
                    "message": f"Scenario '{scenario.name}' ({scenario.scenario_id}) started by {actor.username} in {mode} mode.",
                }
            ],
            is_simulated=True,
        )
        db.add(execution)
        await db.flush()

        created_alerts: list[Alert] = []
        try:
            # 1. Ingest alert sequence through real AlertService
            for alert_spec in scenario.alerts:
                normalized_payload = {
                    "title": f"[SIMULATION] {alert_spec.title}",
                    "description": alert_spec.description,
                    "source_system": alert_spec.source_system,
                    "rule_id": alert_spec.rule_id,
                    "rule_description": alert_spec.rule_description,
                    "event_category": alert_spec.event_category,
                    "severity": alert_spec.severity,
                    "src_ip": alert_spec.src_ip,
                    "dst_ip": alert_spec.dst_ip,
                    "hostname": alert_spec.hostname,
                    "username": alert_spec.username,
                    "file_hash": alert_spec.file_hash,
                    "domain": alert_spec.domain,
                    "mitre_techniques": alert_spec.mitre_techniques,
                    "raw_payload": {
                        **alert_spec.raw_payload,
                        "simulation_scenario": slug,
                        "is_simulated": True,
                    },
                    "is_simulated": True,
                    "scenario_slug": slug,
                    "event_timestamp": utc_now(),
                }

                alert, _created = await AlertService.ingest_normalized_alert(
                    db,
                    normalized_payload,
                    actor=actor,
                    source_ip=source_ip,
                    deduplicate=False,
                )
                created_alerts.append(alert)

                execution.execution_log.append(
                    {
                        "timestamp": utc_now().isoformat(),
                        "level": "INFO",
                        "step": "ALERT_INGESTION",
                        "message": f"Ingested alert {alert.id} ({alert.rule_id}: {alert.rule_description})",
                    }
                )

            execution.alerts_count = len(created_alerts)

            # 2. Incident Creation (for full_chain and incident_only modes)
            incident: Incident | None = None
            if mode in ("full_chain", "incident_only") and created_alerts:
                alert_ids = [a.id for a in created_alerts]
                incident = await IncidentService.create_incident(
                    db,
                    title=f"[SIMULATION] {scenario.name}",
                    description=scenario.description,
                    category=scenario.category,
                    base_severity=scenario.severity,
                    alert_ids=alert_ids,
                    actor=actor,
                    source_ip=source_ip,
                    is_simulated=True,
                )
                incident.executive_summary = scenario.executive_summary_template
                execution.incident_id = incident.id

                # Upsert synthetic indicators and link to incident
                for ind_spec in scenario.synthetic_indicators:
                    ind_res = await db.execute(
                        select(Indicator).where(
                            Indicator.ioc_type == ind_spec.ioc_type,
                            Indicator.value == ind_spec.value,
                        )
                    )
                    indicator = ind_res.scalar_one_or_none()
                    if indicator is None:
                        indicator = Indicator(
                            id=uuid.uuid4(),
                            ioc_type=ind_spec.ioc_type,
                            value=ind_spec.value,
                            reputation=ind_spec.reputation,
                            confidence=ind_spec.confidence,
                            is_internal=ind_spec.reputation == "internal",
                            is_simulated=True,
                        )
                        db.add(indicator)
                        await db.flush()
                    else:
                        indicator.reputation = ind_spec.reputation
                        indicator.confidence = ind_spec.confidence
                        indicator.is_simulated = True
                        await db.flush()

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
                                added_by_id=actor.id,
                            )
                        )

                # Link expected MITRE ATT&CK techniques
                for tech_id in scenario.expected_mitre_techniques:
                    tech_res = await db.execute(
                        select(MitreTechnique).where(MitreTechnique.id == tech_id)
                    )
                    tech = tech_res.scalar_one_or_none()
                    if tech is None:
                        tech = MitreTechnique(
                            id=tech_id,
                            stix_id=f"attack-pattern--stub-{tech_id.lower()}",
                            name=tech_id,
                            tactics=["execution"],
                            description="Mapped from simulation scenario definition.",
                            url=f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                            is_subtechnique="." in tech_id,
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
                        db.add(
                            IncidentTechnique(
                                incident_id=incident.id,
                                technique_id=tech.id,
                                source="playbook_rule",
                                status="suggested",
                                rationale=f"Auto-suggested from simulation scenario '{scenario.name}'.",
                                created_by_id=actor.id,
                            )
                        )

                # Add timeline milestone
                db.add(
                    IncidentTimeline(
                        incident_id=incident.id,
                        event_type="simulation",
                        title=f"Simulation Drill: {scenario.name}",
                        description=(
                            f"Simulation scenario '{scenario.name}' ({scenario.scenario_id}) launched by "
                            f"{actor.username} with {len(created_alerts)} alerts and {len(scenario.synthetic_indicators)} indicators."
                        ),
                        actor_id=actor.id,
                        actor_label=actor.username,
                        metadata_json={"mode": mode, "scenario_slug": slug},
                        occurred_at=utc_now(),
                    )
                )

                execution.execution_log.append(
                    {
                        "timestamp": utc_now().isoformat(),
                        "level": "INFO",
                        "step": "INCIDENT_CREATION",
                        "message": f"Created Incident {incident.human_id} ({incident.title}) with status {incident.status}",
                    }
                )

            # 3. Playbook Execution (for full_chain mode)
            if mode == "full_chain" and incident and scenario.associated_playbook_slug:
                p_stmt = select(Playbook).where(Playbook.slug == scenario.associated_playbook_slug)
                p_res = await db.execute(p_stmt)
                playbook = p_res.scalar_one_or_none()

                if not playbook:
                    from app.services.playbook.loader import PlaybookLoader
                    await PlaybookLoader.sync_builtin_playbooks(db)
                    p_res = await db.execute(p_stmt)
                    playbook = p_res.scalar_one_or_none()

                if playbook and playbook.is_enabled:
                    engine = PlaybookEngine(db)
                    pb_exec = await engine.create_execution(
                        playbook_id_or_slug=playbook.slug,
                        incident_id=incident.id,
                        triggered_by="simulation",
                        triggered_by_user_id=actor.id,
                        is_dry_run=False,
                    )
                    pb_exec = await engine.execute_loop(pb_exec.id)
                    execution.playbook_execution_id = pb_exec.id

                    execution.execution_log.append(
                        {
                            "timestamp": utc_now().isoformat(),
                            "level": "INFO",
                            "step": "PLAYBOOK_EXECUTION",
                            "message": f"Triggered playbook {playbook.slug} (Execution ID: {pb_exec.id}, Status: {pb_exec.status})",
                        }
                    )

            # 4. Mark execution completed
            execution.status = "COMPLETED"
            execution.completed_at = utc_now()
            execution.execution_log.append(
                {
                    "timestamp": utc_now().isoformat(),
                    "level": "INFO",
                    "step": "COMPLETION",
                    "message": f"Simulation scenario '{scenario.name}' completed successfully.",
                }
            )

            await AuditService.record(
                db,
                action="simulation.launched",
                actor=actor,
                target_type="simulation_execution",
                target_id=str(execution.id),
                outcome="success",
                details={
                    "scenario_slug": slug,
                    "scenario_name": scenario.name,
                    "mode": mode,
                    "alerts_created": len(created_alerts),
                    "incident_id": str(incident.id) if incident else None,
                    "incident_human_id": incident.human_id if incident else None,
                    "playbook_execution_id": (
                        str(execution.playbook_execution_id) if execution.playbook_execution_id else None
                    ),
                },
            )

            await db.commit()

            # Publish real-time SSE notification
            await publish_realtime_event(
                "simulation.completed",
                {
                    "execution_id": str(execution.id),
                    "scenario_slug": slug,
                    "scenario_name": scenario.name,
                    "status": "COMPLETED",
                    "incident_id": str(incident.id) if incident else None,
                    "incident_human_id": incident.human_id if incident else None,
                    "alerts_count": len(created_alerts),
                },
            )

            return execution

        except Exception as exc:
            logger.exception("Simulation execution failed for %s", slug)
            await db.rollback()
            try:
                fail_exec = SimulationExecution(
                    id=exec_id,
                    scenario_slug=slug,
                    scenario_name=scenario.name,
                    status="FAILED",
                    mode=mode,
                    launched_by_id=actor.id,
                    started_at=utc_now(),
                    completed_at=utc_now(),
                    error_message=str(exc),
                    execution_log=[
                        {
                            "timestamp": utc_now().isoformat(),
                            "level": "ERROR",
                            "step": "FAILURE",
                            "message": f"Scenario execution failed: {exc}",
                        }
                    ],
                    is_simulated=True,
                )
                db.add(fail_exec)
                await db.commit()
            except Exception as persist_err:
                logger.warning("Could not persist failed simulation execution state: %s", persist_err)
            raise

    @staticmethod
    async def list_executions(
        db: AsyncSession,
        *,
        limit: int = 50,
        offset: int = 0,
        scenario_slug: str | None = None,
    ) -> list[SimulationExecution]:
        """List simulation execution history ordered newest first."""
        stmt = select(SimulationExecution).order_by(SimulationExecution.created_at.desc())
        if scenario_slug:
            stmt = stmt.where(SimulationExecution.scenario_slug == scenario_slug)
        stmt = stmt.limit(max(1, min(limit, 100))).offset(max(0, offset))
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @staticmethod
    async def get_execution(db: AsyncSession, execution_id: uuid.UUID) -> SimulationExecution:
        """Fetch simulation execution details by UUID."""
        stmt = select(SimulationExecution).where(SimulationExecution.id == execution_id)
        res = await db.execute(stmt)
        execution = res.scalar_one_or_none()
        if not execution:
            raise AppError(
                code="SIMULATION_EXECUTION_NOT_FOUND",
                message=f"Simulation execution '{execution_id}' does not exist.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return execution

    @staticmethod
    async def reset_simulation_data(db: AsyncSession, *, actor: User) -> dict[str, int]:
        """Strictly delete ONLY simulation-flagged records (is_simulated=True).

        Never modifies or removes non-simulated operational data.
        """
        # 1. Find all simulated incidents
        sim_inc_res = await db.execute(
            select(Incident.id).where(Incident.is_simulated.is_(True))
        )
        sim_inc_ids = list(sim_inc_res.scalars().all())

        # 2. Find all simulated alerts
        sim_alt_res = await db.execute(
            select(Alert.id).where(Alert.is_simulated.is_(True))
        )
        sim_alt_ids = list(sim_alt_res.scalars().all())

        # 3. Clean up relations for simulated incidents
        if sim_inc_ids:
            # Clean up simulated response actions
            action_ids_res = await db.execute(
                select(ResponseAction.id).where(ResponseAction.incident_id.in_(sim_inc_ids))
            )
            action_ids = list(action_ids_res.scalars().all())
            if action_ids:
                await db.execute(
                    delete(ResponseAction).where(ResponseAction.id.in_(action_ids))
                )

            # Playbook executions and steps
            pb_ids_res = await db.execute(
                select(PlaybookExecution.id).where(PlaybookExecution.incident_id.in_(sim_inc_ids))
            )
            pb_ids = list(pb_ids_res.scalars().all())
            if pb_ids:
                await db.execute(
                    delete(PlaybookExecutionStep).where(PlaybookExecutionStep.execution_id.in_(pb_ids))
                )
                await db.execute(
                    delete(PlaybookExecution).where(PlaybookExecution.id.in_(pb_ids))
                )

            # Incident reports
            await db.execute(
                delete(IncidentReport).where(IncidentReport.incident_id.in_(sim_inc_ids))
            )

            # Incident entity links
            await db.execute(
                delete(IncidentIndicator).where(IncidentIndicator.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(IncidentTechnique).where(IncidentTechnique.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(IncidentTimeline).where(IncidentTimeline.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(IncidentAlert).where(IncidentAlert.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(IncidentAsset).where(IncidentAsset.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(IncidentAffectedUser).where(IncidentAffectedUser.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(IncidentLink).where(
                    or_(
                        IncidentLink.source_incident_id.in_(sim_inc_ids),
                        IncidentLink.target_incident_id.in_(sim_inc_ids),
                    )
                )
            )
            await db.execute(
                delete(Evidence).where(Evidence.incident_id.in_(sim_inc_ids))
            )
            await db.execute(
                delete(InvestigationNote).where(InvestigationNote.incident_id.in_(sim_inc_ids))
            )

            # Delete the simulated incidents themselves
            await db.execute(
                delete(Incident).where(Incident.id.in_(sim_inc_ids))
            )

        # 4. Clean up simulated alerts and occurrences
        if sim_alt_ids:
            await db.execute(
                delete(AlertOccurrence).where(AlertOccurrence.alert_id.in_(sim_alt_ids))
            )
            await db.execute(
                delete(Alert).where(Alert.id.in_(sim_alt_ids))
            )

        # 5. Clean up simulated indicators
        ind_del = await db.execute(
            delete(Indicator).where(Indicator.is_simulated.is_(True))
        )
        deleted_indicators = ind_del.rowcount or 0

        # 6. Clean up simulation execution records
        exec_del = await db.execute(
            delete(SimulationExecution).where(SimulationExecution.is_simulated.is_(True))
        )
        deleted_executions = exec_del.rowcount or 0

        counts = {
            "deleted_incidents": len(sim_inc_ids),
            "deleted_alerts": len(sim_alt_ids),
            "deleted_indicators": deleted_indicators,
            "deleted_executions": deleted_executions,
        }

        await AuditService.record(
            db,
            action="simulation.reset",
            actor=actor,
            target_type="simulation",
            outcome="success",
            details=counts,
        )
        await db.commit()

        logger.info("Simulation data reset complete: %s", counts)
        return counts