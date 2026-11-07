"""Durable Declarative Playbook Execution Engine with Non-Blocking Checkpoints."""

from __future__ import annotations

import datetime
import logging
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.errors import AppError
from app.models.automation import (
    Playbook,
    PlaybookExecution,
    PlaybookExecutionStep,
    PlaybookVersion,
    ResponseAction,
)
from app.models.base import utc_now
from app.models.incident import Incident
from app.models.user import User
from app.schemas.playbook import PlaybookDefinition
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event
from app.services.playbook.adapter import get_response_adapter
from app.services.playbook.registry import step_registry
from app.services.playbook.templating import evaluate_condition, render_template

logger = logging.getLogger("sentinel.playbook.engine")


class PlaybookEngine:
    """Executes declarative playbooks step-by-step with durable database checkpoints."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create_execution(
        self,
        playbook_id_or_slug: str | uuid.UUID,
        incident_id: uuid.UUID | None = None,
        alert_id: uuid.UUID | None = None,
        triggered_by: str = "manual",
        triggered_by_user_id: uuid.UUID | None = None,
        parameters: dict[str, Any] | None = None,
        is_dry_run: bool = False,
        idempotency_key: str | None = None,
    ) -> PlaybookExecution:
        """Create and persist a new PlaybookExecution instance."""
        # 1. Check idempotency
        if idempotency_key:
            stmt = select(PlaybookExecution).where(PlaybookExecution.idempotency_key == idempotency_key)
            existing = (await self.session.execute(stmt)).scalar_one_or_none()
            if existing:
                return existing

        # 2. Resolve Playbook
        if isinstance(playbook_id_or_slug, uuid.UUID):
            p_stmt = select(Playbook).where(Playbook.id == playbook_id_or_slug)
        else:
            p_stmt = select(Playbook).where(Playbook.slug == str(playbook_id_or_slug))

        p_res = await self.session.execute(p_stmt)
        playbook = p_res.scalar_one_or_none()
        if not playbook:
            raise AppError(code="NOT_FOUND", message=f"Playbook '{playbook_id_or_slug}' not found", status_code=404)

        # 3. Resolve active PlaybookVersion
        v_stmt = select(PlaybookVersion).where(
            PlaybookVersion.playbook_id == playbook.id,
            PlaybookVersion.version == playbook.current_version,
        )
        v_res = await self.session.execute(v_stmt)
        version = v_res.scalar_one_or_none()
        if not version:
            raise AppError(
                code="NOT_FOUND",
                message=f"Active version {playbook.current_version} for playbook {playbook.slug} not found",
                status_code=404,
            )

        # 4. Resolve Incident Context if applicable
        incident_data: dict[str, Any] = {"parameters": parameters or {}, "human_id": "N/A"}
        if incident_id:
            inc_stmt = select(Incident).where(Incident.id == incident_id)
            inc_res = await self.session.execute(inc_stmt)
            incident = inc_res.scalar_one_or_none()
            if incident:
                incident_data = {
                    "id": str(incident.id),
                    "human_id": incident.human_id,
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                    "parameters": parameters or {},
                }

        initial_context: dict[str, Any] = {
            "parameters": parameters or {},
            "incident_id": str(incident_id) if incident_id else None,
            "alert_id": str(alert_id) if alert_id else None,
            "incident": incident_data,
            "steps": {},
        }

        execution = PlaybookExecution(
            playbook_id=playbook.id,
            playbook_version_id=version.id,
            version_number=version.version,
            incident_id=incident_id,
            alert_id=alert_id,
            triggered_by=triggered_by,
            triggered_by_user_id=triggered_by_user_id,
            idempotency_key=idempotency_key,
            is_dry_run=is_dry_run,
            status="PENDING",
            current_step_index=0,
            context_state=initial_context,
        )
        self.session.add(execution)
        await self.session.flush()

        actor: User | None = None
        if triggered_by_user_id:
            u_stmt = select(User).where(User.id == triggered_by_user_id)
            actor = (await self.session.execute(u_stmt)).scalar_one_or_none()

        await AuditService.record(
            self.session,
            action="playbook.execution.created",
            actor=actor,
            target_type="playbook_execution",
            target_id=str(execution.id),
            details={
                "playbook_slug": playbook.slug,
                "version": version.version,
                "incident_id": str(incident_id) if incident_id else None,
                "is_dry_run": is_dry_run,
            },
        )

        return execution

    async def execute_loop(self, execution_id: uuid.UUID) -> PlaybookExecution:
        """Run or resume execution steps until completion, failure, or human approval."""
        stmt = (
            select(PlaybookExecution)
            .where(PlaybookExecution.id == execution_id)
            .options(
                selectinload(PlaybookExecution.playbook),
                selectinload(PlaybookExecution.steps),
            )
        )
        res = await self.session.execute(stmt)
        execution = res.scalar_one_or_none()
        if not execution:
            raise AppError(code="NOT_FOUND", message="Playbook execution not found", status_code=404)

        # Load version definition
        v_stmt = select(PlaybookVersion).where(PlaybookVersion.id == execution.playbook_version_id)
        v_res = await self.session.execute(v_stmt)
        version = v_res.scalar_one_or_none()
        if not version:
            raise AppError(code="NOT_FOUND", message="Playbook version not found", status_code=404)

        playbook_def = PlaybookDefinition.model_validate(version.definition_json)
        step_defs = playbook_def.steps

        if execution.status == "PENDING":
            execution.status = "RUNNING"
            execution.started_at = utc_now()
            await self.session.flush()

        actor: User | None = None
        if execution.triggered_by_user_id:
            u_stmt = select(User).where(User.id == execution.triggered_by_user_id)
            actor = (await self.session.execute(u_stmt)).scalar_one_or_none()

        # Iterate over steps starting from current_step_index
        while execution.current_step_index < len(step_defs):
            step_idx = execution.current_step_index
            step_def = step_defs[step_idx]
            execution.current_step_id = step_def.id

            # Render template parameters against current execution context
            rendered_params = render_template(step_def.parameters, execution.context_state)

            # Evaluate step condition
            if step_def.condition:
                should_run = evaluate_condition(step_def.condition, execution.context_state)
                if not should_run:
                    logger.info("Step %s skipped due to condition %s", step_def.id, step_def.condition)
                    step_record = PlaybookExecutionStep(
                        execution_id=execution.id,
                        step_index=step_idx,
                        step_id=step_def.id,
                        step_type=step_def.type,
                        step_name=step_def.name,
                        status="SKIPPED",
                        attempt_count=1,
                        inputs_json=rendered_params,
                        outputs_json={"reason": "Condition evaluated to false"},
                        started_at=utc_now(),
                        completed_at=utc_now(),
                    )
                    self.session.add(step_record)
                    execution.steps.append(step_record)
                    execution.context_state.setdefault("steps", {})[step_def.id] = {
                        "status": "SKIPPED",
                        "outputs": {},
                    }
                    execution.current_step_index += 1
                    await self.session.flush()
                    continue

            # Human Approval Checkpoint
            if step_def.require_approval and not execution.is_dry_run:
                # Propose response action and suspend execution cleanly
                target_indicator = render_template(step_def.target_indicator, execution.context_state) if step_def.target_indicator else None
                target_hostname = render_template(step_def.target_hostname, execution.context_state) if step_def.target_hostname else None
                target_username = render_template(step_def.target_username, execution.context_state) if step_def.target_username else None

                justification = rendered_params.get(
                    "justification",
                    rendered_params.get(
                        "reason",
                        f"Automated playbook '{execution.playbook.name}' proposed containment action for step '{step_def.name}'.",
                    ),
                )

                expires_at = utc_now() + datetime.timedelta(hours=step_def.approval_timeout_hours)

                # Requester is the user who triggered the playbook, or a system fallback
                requester_id = execution.triggered_by_user_id
                if not requester_id:
                    inc_stmt = select(Incident).where(Incident.id == execution.incident_id)
                    inc_res = await self.session.execute(inc_stmt)
                    inc = inc_res.scalar_one_or_none()
                    if inc and inc.created_by_id:
                        requester_id = inc.created_by_id
                    else:
                        requester_id = uuid.uuid4()

                response_action = ResponseAction(
                    incident_id=execution.incident_id,  # type: ignore[arg-type]
                    playbook_execution_id=execution.id,
                    action_type=step_def.action_type,
                    target_indicator=str(target_indicator) if target_indicator else None,
                    target_hostname=str(target_hostname) if target_hostname else None,
                    target_username=str(target_username) if target_username else None,
                    title=f"Approval Required: {step_def.name}",
                    justification=str(justification),
                    parameters_json=rendered_params,
                    risk_impact=step_def.risk_impact,
                    status="PENDING_APPROVAL",
                    adapter_name="simulated",
                    is_simulated=True,
                    requested_by_id=requester_id,
                    expires_at=expires_at,
                )
                self.session.add(response_action)
                await self.session.flush()

                # Record execution step as WAITING_APPROVAL
                step_record = PlaybookExecutionStep(
                    execution_id=execution.id,
                    step_index=step_idx,
                    step_id=step_def.id,
                    step_type=step_def.type,
                    step_name=step_def.name,
                    status="WAITING_APPROVAL",
                    attempt_count=1,
                    inputs_json=rendered_params,
                    outputs_json={"response_action_id": str(response_action.id)},
                    started_at=utc_now(),
                )
                self.session.add(step_record)
                execution.steps.append(step_record)

                # Persist execution checkpoint and halt Celery execution
                execution.status = "WAITING_APPROVAL"
                execution.waiting_response_action_id = response_action.id
                await self.session.flush()

                await AuditService.record(
                    self.session,
                    action="playbook.execution.waiting_approval",
                    actor=actor,
                    target_type="playbook_execution",
                    target_id=str(execution.id),
                    details={
                        "step_id": step_def.id,
                        "response_action_id": str(response_action.id),
                        "action_type": step_def.action_type,
                        "risk_impact": step_def.risk_impact,
                    },
                )

                await publish_realtime_event(
                    "playbook.waiting_approval",
                    {
                        "execution_id": str(execution.id),
                        "response_action_id": str(response_action.id),
                        "step_id": step_def.id,
                    },
                )

                # EXIT Celery worker cleanly! No thread blocking!
                return execution

            # Dry-Run simulation for approval steps
            if step_def.require_approval and execution.is_dry_run:
                step_output = {
                    "is_dry_run": True,
                    "simulated_approval": True,
                    "action_type": step_def.action_type,
                    "risk_impact": step_def.risk_impact,
                    "parameters": rendered_params,
                    "message": f"[DRY-RUN] Simulated human approval for '{step_def.name}'",
                }
                step_record = PlaybookExecutionStep(
                    execution_id=execution.id,
                    step_index=step_idx,
                    step_id=step_def.id,
                    step_type=step_def.type,
                    step_name=step_def.name,
                    status="COMPLETED",
                    attempt_count=1,
                    inputs_json=rendered_params,
                    outputs_json=step_output,
                    started_at=utc_now(),
                    completed_at=utc_now(),
                    duration_ms=5,
                )
                self.session.add(step_record)
                execution.steps.append(step_record)
                execution.context_state.setdefault("steps", {})[step_def.id] = {
                    "status": "COMPLETED",
                    "outputs": step_output,
                }
                execution.current_step_index += 1
                await self.session.flush()
                continue

            # Automated Step Execution
            handler = step_registry.get(step_def.type)
            if not handler:
                err_msg = f"Unknown step handler type: '{step_def.type}'"
                logger.error(err_msg)
                step_record = PlaybookExecutionStep(
                    execution_id=execution.id,
                    step_index=step_idx,
                    step_id=step_def.id,
                    step_type=step_def.type,
                    step_name=step_def.name,
                    status="FAILED",
                    attempt_count=1,
                    inputs_json=rendered_params,
                    outputs_json={},
                    error_details=err_msg,
                    started_at=utc_now(),
                    completed_at=utc_now(),
                )
                self.session.add(step_record)
                execution.steps.append(step_record)
                if step_def.on_failure == "abort":
                    execution.status = "FAILED"
                    execution.error_message = err_msg
                    execution.completed_at = utc_now()
                    await self.session.flush()
                    return execution
                else:
                    execution.current_step_index += 1
                    await self.session.flush()
                    continue

            # Run handler with timing
            t0 = time.perf_counter()
            start_ts = utc_now()
            try:
                result = await handler(rendered_params, execution.context_state, self.session)
                duration_ms = int((time.perf_counter() - t0) * 1000)

                step_record = PlaybookExecutionStep(
                    execution_id=execution.id,
                    step_index=step_idx,
                    step_id=step_def.id,
                    step_type=step_def.type,
                    step_name=step_def.name,
                    status="COMPLETED",
                    attempt_count=1,
                    inputs_json=rendered_params,
                    outputs_json=result,
                    duration_ms=duration_ms,
                    started_at=start_ts,
                    completed_at=utc_now(),
                )
                self.session.add(step_record)
                execution.steps.append(step_record)
                execution.context_state.setdefault("steps", {})[step_def.id] = {
                    "status": "COMPLETED",
                    "outputs": result,
                }
                execution.current_step_index += 1
                await self.session.flush()

            except Exception as exc:
                duration_ms = int((time.perf_counter() - t0) * 1000)
                err_text = str(exc)
                logger.error("Step %s failed: %s", step_def.id, err_text, exc_info=True)

                step_record = PlaybookExecutionStep(
                    execution_id=execution.id,
                    step_index=step_idx,
                    step_id=step_def.id,
                    step_type=step_def.type,
                    step_name=step_def.name,
                    status="FAILED",
                    attempt_count=1,
                    inputs_json=rendered_params,
                    outputs_json={},
                    error_details=err_text,
                    duration_ms=duration_ms,
                    started_at=start_ts,
                    completed_at=utc_now(),
                )
                self.session.add(step_record)
                execution.steps.append(step_record)

                if step_def.on_failure == "abort":
                    execution.status = "FAILED"
                    execution.error_message = f"Step '{step_def.id}' aborted execution: {err_text}"
                    execution.completed_at = utc_now()
                    await self.session.flush()
                    return execution
                else:
                    execution.context_state.setdefault("steps", {})[step_def.id] = {
                        "status": "FAILED",
                        "error": err_text,
                    }
                    execution.current_step_index += 1
                    await self.session.flush()

        # All steps completed!
        execution.status = "COMPLETED"
        execution.completed_at = utc_now()
        await self.session.flush()

        await AuditService.record(
            self.session,
            action="playbook.execution.completed",
            actor=actor,
            target_type="playbook_execution",
            target_id=str(execution.id),
            details={"playbook_id": str(execution.playbook_id), "is_dry_run": execution.is_dry_run},
        )

        await publish_realtime_event(
            "playbook.completed",
            {"execution_id": str(execution.id), "status": "COMPLETED"},
        )

        return execution

    async def resume_execution(
        self,
        execution_id: uuid.UUID,
        action_approved: bool,
    ) -> PlaybookExecution:
        """Resume an execution halted in WAITING_APPROVAL after an approval decision."""
        stmt = (
            select(PlaybookExecution)
            .where(PlaybookExecution.id == execution_id)
            .options(
                selectinload(PlaybookExecution.playbook),
                selectinload(PlaybookExecution.steps),
            )
        )
        res = await self.session.execute(stmt)
        execution = res.scalar_one_or_none()
        if not execution:
            raise AppError(code="NOT_FOUND", message="Playbook execution not found", status_code=404)

        if execution.status != "WAITING_APPROVAL":
            raise AppError(
                code="INVALID_STATE",
                message=f"Execution {execution_id} is in status '{execution.status}', not 'WAITING_APPROVAL'.",
                status_code=400,
            )

        # Retrieve the waiting response action
        action_stmt = select(ResponseAction).where(ResponseAction.id == execution.waiting_response_action_id)
        action_res = await self.session.execute(action_stmt)
        response_action = action_res.scalar_one_or_none()
        if not response_action:
            raise AppError(code="NOT_FOUND", message="Waiting response action not found", status_code=404)

        # Find the execution step that was WAITING_APPROVAL
        step_stmt = select(PlaybookExecutionStep).where(
            PlaybookExecutionStep.execution_id == execution.id,
            PlaybookExecutionStep.step_index == execution.current_step_index,
        )
        step_res = await self.session.execute(step_stmt)
        waiting_step = step_res.scalar_one_or_none()

        if action_approved:
            # Execute the containment action via SimulatedResponseAdapter
            adapter = get_response_adapter(response_action.adapter_name)
            telemetry = await adapter.execute(response_action)

            response_action.status = "COMPLETED"
            response_action.executed_at = utc_now()
            response_action.execution_result = telemetry
            await self.session.flush()

            if waiting_step:
                waiting_step.status = "COMPLETED"
                waiting_step.outputs_json = telemetry
                waiting_step.completed_at = utc_now()

            execution.context_state.setdefault("steps", {})[execution.current_step_id or f"step_{execution.current_step_index}"] = {
                "status": "COMPLETED",
                "outputs": telemetry,
            }

            # Advance to the next step
            execution.current_step_index += 1
            execution.waiting_response_action_id = None
            execution.status = "RUNNING"
            await self.session.flush()

            # Continue execution loop for remaining steps
            return await self.execute_loop(execution.id)

        else:
            # Action was rejected
            if waiting_step:
                waiting_step.status = "REJECTED"
                waiting_step.outputs_json = {"decision": "rejected"}
                waiting_step.completed_at = utc_now()

            execution.context_state.setdefault("steps", {})[execution.current_step_id or f"step_{execution.current_step_index}"] = {
                "status": "REJECTED",
                "outputs": {"decision": "rejected"},
            }

            execution.status = "FAILED"
            execution.error_message = "Execution halted due to rejected human approval."
            execution.completed_at = utc_now()
            execution.waiting_response_action_id = None
            await self.session.flush()
            return execution

    async def expire_stale_actions(self) -> int:
        """Find and expire stale PENDING_APPROVAL response actions past expires_at."""
        now = utc_now()
        stmt = select(ResponseAction).where(
            ResponseAction.status == "PENDING_APPROVAL",
            ResponseAction.expires_at < now,
        )
        res = await self.session.execute(stmt)
        stale_actions = res.scalars().all()

        count = 0
        for action in stale_actions:
            action.status = "EXPIRED"
            count += 1

            if action.playbook_execution_id:
                exec_stmt = select(PlaybookExecution).where(PlaybookExecution.id == action.playbook_execution_id)
                exec_res = await self.session.execute(exec_stmt)
                execution = exec_res.scalar_one_or_none()
                if execution and execution.status == "WAITING_APPROVAL":
                    execution.status = "EXPIRED"
                    execution.error_message = "Execution expired due to approval timeout."
                    execution.completed_at = now

        await self.session.flush()
        return count
