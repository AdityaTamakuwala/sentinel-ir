"""Simulation Scenarios and Execution API endpoints (`/api/v1/simulations`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.user import User
from app.services.simulation.engine import SimulationService

router = APIRouter(prefix="/simulations", tags=["Simulation Engine"])


class ScenarioOut(BaseModel):
    slug: str
    scenario_id: str
    name: str
    short_summary: str
    description: str
    category: str
    severity: str
    expected_mitre_techniques: list[str]
    associated_playbook_slug: str
    expected_response_actions: list[str]
    expected_investigation_path: list[str]
    alerts_count: int


class ScenarioDetailOut(ScenarioOut):
    synthetic_indicators: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    executive_summary_template: str


class LaunchScenarioRequest(BaseModel):
    mode: str = Field(
        default="full_chain",
        description="Execution mode: 'full_chain', 'alerts_only', or 'incident_only'.",
    )


class SimulationExecutionOut(BaseModel):
    id: uuid.UUID
    scenario_slug: str
    scenario_name: str
    status: str
    mode: str
    alerts_count: int
    incident_id: uuid.UUID | None
    playbook_execution_id: uuid.UUID | None
    execution_log: list[dict[str, Any]]
    error_message: str | None
    launched_by_id: uuid.UUID | None
    started_at: str
    completed_at: str | None
    is_simulated: bool


@router.get("/scenarios", response_model=list[ScenarioOut])
async def list_scenarios(
    _actor: User = Depends(require_permission(PermissionCode.SIMULATION_RUN)),
) -> list[dict[str, Any]]:
    """List all 7 reproducible incident simulation scenarios."""
    return SimulationService.list_scenarios()


@router.get("/scenarios/{slug}", response_model=ScenarioDetailOut)
async def get_scenario(
    slug: str,
    _actor: User = Depends(require_permission(PermissionCode.SIMULATION_RUN)),
) -> dict[str, Any]:
    """Retrieve complete metadata and alert details for a simulation scenario."""
    return SimulationService.get_scenario(slug)


@router.post("/scenarios/{slug}/launch", response_model=SimulationExecutionOut)
async def launch_scenario(
    slug: str,
    payload: LaunchScenarioRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.SIMULATION_RUN)),
    db: AsyncSession = Depends(get_db_session),
) -> SimulationExecutionOut:
    """Launch a simulation scenario through the real ingestion and response pipeline."""
    execution = await SimulationService.launch_scenario(
        db,
        slug=slug,
        mode=payload.mode,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return SimulationExecutionOut(
        id=execution.id,
        scenario_slug=execution.scenario_slug,
        scenario_name=execution.scenario_name,
        status=execution.status,
        mode=execution.mode,
        alerts_count=execution.alerts_count,
        incident_id=execution.incident_id,
        playbook_execution_id=execution.playbook_execution_id,
        execution_log=execution.execution_log,
        error_message=execution.error_message,
        launched_by_id=execution.launched_by_id,
        started_at=execution.started_at.isoformat(),
        completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
        is_simulated=execution.is_simulated,
    )


@router.get("/executions", response_model=list[SimulationExecutionOut])
async def list_executions(
    scenario_slug: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _actor: User = Depends(require_permission(PermissionCode.SIMULATION_RUN)),
    db: AsyncSession = Depends(get_db_session),
) -> list[SimulationExecutionOut]:
    """List history of scenario executions ordered newest first."""
    executions = await SimulationService.list_executions(
        db,
        limit=limit,
        offset=offset,
        scenario_slug=scenario_slug,
    )
    return [
        SimulationExecutionOut(
            id=e.id,
            scenario_slug=e.scenario_slug,
            scenario_name=e.scenario_name,
            status=e.status,
            mode=e.mode,
            alerts_count=e.alerts_count,
            incident_id=e.incident_id,
            playbook_execution_id=e.playbook_execution_id,
            execution_log=e.execution_log,
            error_message=e.error_message,
            launched_by_id=e.launched_by_id,
            started_at=e.started_at.isoformat(),
            completed_at=e.completed_at.isoformat() if e.completed_at else None,
            is_simulated=e.is_simulated,
        )
        for e in executions
    ]


@router.get("/executions/{execution_id}", response_model=SimulationExecutionOut)
async def get_execution(
    execution_id: uuid.UUID,
    _actor: User = Depends(require_permission(PermissionCode.SIMULATION_RUN)),
    db: AsyncSession = Depends(get_db_session),
) -> SimulationExecutionOut:
    """Fetch status and detailed step execution log for a specific simulation run."""
    e = await SimulationService.get_execution(db, execution_id)
    return SimulationExecutionOut(
        id=e.id,
        scenario_slug=e.scenario_slug,
        scenario_name=e.scenario_name,
        status=e.status,
        mode=e.mode,
        alerts_count=e.alerts_count,
        incident_id=e.incident_id,
        playbook_execution_id=e.playbook_execution_id,
        execution_log=e.execution_log,
        error_message=e.error_message,
        launched_by_id=e.launched_by_id,
        started_at=e.started_at.isoformat(),
        completed_at=e.completed_at.isoformat() if e.completed_at else None,
        is_simulated=e.is_simulated,
    )


@router.post("/reset")
async def reset_simulation_data(
    actor: User = Depends(require_permission(PermissionCode.SIMULATION_RUN)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Purge all simulation-flagged records (is_simulated=True). Real operational data is preserved."""
    counts = await SimulationService.reset_simulation_data(db, actor=actor)
    return {
        "status": "success",
        "message": "All simulated records safely purged.",
        "details": counts,
    }

