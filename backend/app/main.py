"""SENTINEL IR — FastAPI Application Entry Point."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.health import router as health_router
from app.api.v1.router import api_v1_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import CorrelationAndMetricsMiddleware
from app.db.session import reset_connections

logger = logging.getLogger("sentinel.startup")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    settings = get_settings()
    configure_logging(settings.LOG_LEVEL)
    settings.validate_startup_safety()
    logger.info(
        "SENTINEL IR API initialized",
        extra={
            "structured_data": {
                "app_env": settings.APP_ENV,
                "version": settings.APP_VERSION,
            }
        },
    )
    yield
    await reset_connections()


def create_app() -> FastAPI:
    settings = get_settings()
    is_prod = settings.APP_ENV == "production"

    app = FastAPI(
        title="SENTINEL IR API",
        description=(
            "Enterprise Security Incident Response, Investigation, Threat Intelligence & SOAR Platform"
        ),
        version=settings.APP_VERSION,
        docs_url=None if is_prod else "/docs",
        redoc_url=None if is_prod else "/redoc",
        openapi_url=None if is_prod else "/openapi.json",
        lifespan=lifespan,
    )

    # Deny cross-origin browser requests by default (Next.js proxies `/api/*` same-origin)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-CSRF-Token", "X-Request-ID", "Idempotency-Key"],
    )
    app.add_middleware(CorrelationAndMetricsMiddleware)

    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(api_v1_router)
    return app


app = create_app()

