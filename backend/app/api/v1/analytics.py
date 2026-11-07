"""SOC Command Centre Operational Analytics endpoints (`/api/v1/analytics`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.user import User
from app.services.analytics_service import AnalyticsService

router = APIRouter(prefix="/analytics", tags=["SOC Command Centre Analytics"])


@router.get("/command-center")
async def get_command_center(
    window_days: int = Query(default=30, ge=1, le=365),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    source_system: str | None = Query(default=None),
    assigned_to_id: uuid.UUID | None = Query(default=None),
    include_simulated: bool = Query(default=True),
    _actor: User = Depends(require_permission(PermissionCode.DASHBOARD_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """SOC Command Centre metrics with MTTA, MTTR, SLA status, and active workload."""
    return await AnalyticsService.get_command_center_metrics(
        db,
        window_days=window_days,
        severity=severity,
        status_filter=status,
        source_system=source_system,
        assigned_to_id=assigned_to_id,
        include_simulated=include_simulated,
    )


@router.get("/overview")
async def get_overview(
    window_days: int = Query(default=30, ge=1, le=365),
    include_simulated: bool = Query(default=True),
    _actor: User = Depends(require_permission(PermissionCode.DASHBOARD_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Executive SOC Overview with MTTD, MTTA, MTTC, MTTR, SLA compliance, and distributions."""
    return await AnalyticsService.get_soc_overview(
        db,
        window_days=window_days,
        include_simulated=include_simulated,
    )


@router.get("/trends")
async def get_trends(
    window_days: int = Query(default=30, ge=1, le=90),
    include_simulated: bool = Query(default=True),
    _actor: User = Depends(require_permission(PermissionCode.DASHBOARD_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Daily time series trends for alerts, incidents, and severities."""
    return await AnalyticsService.get_analytics_trends(
        db,
        window_days=window_days,
        include_simulated=include_simulated,
    )


@router.get("/performance")
async def get_performance(
    window_days: int = Query(default=30, ge=1, le=365),
    include_simulated: bool = Query(default=True),
    _actor: User = Depends(require_permission(PermissionCode.DASHBOARD_VIEW)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Playbook automation success rates, human approval metrics, and MITRE frequencies."""
    return await AnalyticsService.get_analytics_performance(
        db,
        window_days=window_days,
        include_simulated=include_simulated,
    )
