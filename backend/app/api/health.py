"""Liveness, readiness (PostgreSQL + Redis), and access-restricted Prometheus metrics."""

from __future__ import annotations

import hmac
from datetime import UTC, datetime

from fastapi import APIRouter, Header, Response, status
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rbac import public_endpoint
from app.db.session import check_database_ready, check_redis_ready

router = APIRouter(tags=["Operational Health"])


class LivenessResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str


class ComponentHealth(BaseModel):
    status: str
    detail: str


class ReadinessResponse(BaseModel):
    status: str
    timestamp: str
    components: dict[str, ComponentHealth]


@router.get("/health/live", response_model=LivenessResponse)
@public_endpoint(reason="Container orchestrator liveness probe")
async def health_live() -> LivenessResponse:
    settings = get_settings()
    return LivenessResponse(
        status="alive",
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        timestamp=datetime.now(UTC).isoformat(),
    )


@router.get("/health/ready", response_model=ReadinessResponse)
@public_endpoint(reason="Container orchestrator readiness probe")
async def health_ready() -> JSONResponse:
    db_ok, db_detail = await check_database_ready()
    redis_ok, redis_detail = await check_redis_ready()

    overall_ok = db_ok and redis_ok
    payload = ReadinessResponse(
        status="ready" if overall_ok else "degraded",
        timestamp=datetime.now(UTC).isoformat(),
        components={
            "postgresql": ComponentHealth(
                status="up" if db_ok else "down",
                detail=db_detail,
            ),
            "redis": ComponentHealth(
                status="up" if redis_ok else "down",
                detail=redis_detail,
            ),
        },
    )
    return JSONResponse(
        status_code=status.HTTP_200_OK if overall_ok else status.HTTP_503_SERVICE_UNAVAILABLE,
        content=payload.model_dump(),
    )


@router.get("/metrics", include_in_schema=False)
@public_endpoint(reason="Protected by dedicated METRICS_BEARER_TOKEN")
async def prometheus_metrics(authorization: str | None = Header(default=None)) -> Response:
    settings = get_settings()
    expected = f"Bearer {settings.METRICS_BEARER_TOKEN}"
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise AppError(
            code="METRICS_UNAUTHORIZED",
            message="Valid metrics bearer token required.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
