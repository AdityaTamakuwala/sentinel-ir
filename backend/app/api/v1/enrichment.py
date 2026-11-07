"""Threat Intelligence Enrichment API Endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.investigation import Indicator
from app.models.user import User
from app.schemas.enrichment import (
    BatchEnrichmentResponse,
    EnrichmentResultOut,
    IndicatorDetailOut,
    PaginatedIndicatorsOut,
    ThreatIndicatorLookupRequest,
    ThreatIntelStatsOut,
)
from app.services.enrichment.engine import EnrichmentService

router = APIRouter(prefix="/enrichment", tags=["Enrichment & Threat Intelligence"])


def _to_indicator_out(ind: Indicator) -> IndicatorDetailOut:
    return IndicatorDetailOut(
        id=ind.id,
        ioc_type=ind.ioc_type,
        value=ind.value,
        is_internal=ind.is_internal,
        reputation=ind.reputation,
        confidence=ind.confidence,
        first_seen_at=ind.first_seen_at,
        last_seen_at=ind.last_seen_at,
        is_simulated=ind.is_simulated,
        enrichments=[
            EnrichmentResultOut(
                id=e.id,
                indicator_id=e.indicator_id,
                provider=e.provider,
                status=e.status,
                reputation=e.reputation,
                malicious_count=e.malicious_count,
                total_engines=e.total_engines,
                confidence_score=e.confidence_score,
                summary=e.summary,
                source_references=e.source_references,
                is_mock=e.is_mock,
                looked_up_at=e.looked_up_at,
                expires_at=e.expires_at,
            )
            for e in ind.enrichments
        ],
    )


@router.post("/lookup", response_model=IndicatorDetailOut)
async def lookup_indicator(
    payload: ThreatIndicatorLookupRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.ENRICHMENT_RUN)),
    db: AsyncSession = Depends(get_db_session),
) -> IndicatorDetailOut:
    """Perform on-demand multi-provider threat intelligence lookup for an indicator."""
    ind = await EnrichmentService.enrich_indicator(
        db,
        ioc_type=payload.ioc_type,
        value=payload.value,
        force_refresh=payload.force_refresh,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return _to_indicator_out(ind)


@router.post("/incidents/{incident_id}/enrich", response_model=BatchEnrichmentResponse)
async def enrich_incident_indicators(
    incident_id: uuid.UUID,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.ENRICHMENT_RUN)),
    db: AsyncSession = Depends(get_db_session),
) -> BatchEnrichmentResponse:
    """Batch-enrich all indicators associated with a specific incident."""
    indicators = await EnrichmentService.enrich_incident_indicators(
        db,
        incident_id=incident_id,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return BatchEnrichmentResponse(
        incident_id=incident_id,
        total_indicators=len(indicators),
        enriched_count=len(indicators),
        results=[_to_indicator_out(i) for i in indicators],
    )


@router.get("/indicators", response_model=PaginatedIndicatorsOut)
async def list_indicators(
    search: str | None = Query(default=None, max_length=128),
    ioc_type: str | None = Query(default=None, max_length=16),
    reputation: str | None = Query(default=None, max_length=24),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    actor: User = Depends(require_permission(PermissionCode.ENRICHMENT_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> PaginatedIndicatorsOut:
    """List and search threat intelligence indicators with reputation breakdown."""
    rows, total = await EnrichmentService.get_indicators(
        db,
        search=search,
        ioc_type=ioc_type,
        reputation=reputation,
        page=page,
        page_size=page_size,
    )
    return PaginatedIndicatorsOut(
        items=[_to_indicator_out(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats", response_model=ThreatIntelStatsOut)
async def get_threat_intel_stats(
    actor: User = Depends(require_permission(PermissionCode.ENRICHMENT_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> ThreatIntelStatsOut:
    """Get aggregated threat intelligence statistics and high-priority threats."""
    stats = await EnrichmentService.get_stats(db)
    return ThreatIntelStatsOut(
        total_indicators=stats["total_indicators"],
        malicious_count=stats["malicious_count"],
        suspicious_count=stats["suspicious_count"],
        benign_count=stats["benign_count"],
        internal_count=stats["internal_count"],
        top_threats=[_to_indicator_out(i) for i in stats["top_threats"]],
    )
