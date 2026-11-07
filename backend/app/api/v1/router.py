"""Root `/api/v1` router aggregator."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.analytics import router as analytics_router
from app.api.v1.audit import router as audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.enrichment import router as enrichment_router
from app.api.v1.events import router as events_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.ingest import router as ingest_router
from app.api.v1.mitre import router as mitre_router
from app.api.v1.notifications import router as notifications_router
from app.api.v1.playbooks import router as playbooks_router
from app.api.v1.reports import router as reports_router
from app.api.v1.responses import router as responses_router
from app.api.v1.simulations import router as simulations_router
from app.api.v1.users import router as users_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth_router)
api_v1_router.include_router(users_router)
api_v1_router.include_router(ingest_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(evidence_router)
api_v1_router.include_router(enrichment_router)
api_v1_router.include_router(mitre_router)
api_v1_router.include_router(playbooks_router)
api_v1_router.include_router(responses_router)
api_v1_router.include_router(simulations_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(notifications_router)
api_v1_router.include_router(audit_router)
api_v1_router.include_router(analytics_router)
