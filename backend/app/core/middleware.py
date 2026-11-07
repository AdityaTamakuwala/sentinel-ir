"""HTTP middleware for correlation IDs, hardened security headers, and Prometheus metrics."""

from __future__ import annotations

import logging
import re
import time
import uuid

from prometheus_client import Counter, Histogram
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import correlation_id_ctx, set_correlation_id

logger = logging.getLogger("sentinel.http")

SAFE_CORRELATION_RE = re.compile(r"^[A-Za-z0-9._-]{4,64}$")

HTTP_REQUESTS_TOTAL = Counter(
    "sentinel_http_requests_total",
    "Total HTTP requests handled by SENTINEL IR API",
    ["method", "path_template", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "sentinel_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path_template"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


def _normalize_path(path: str) -> str:
    """Collapse UUIDs and numeric IDs so Prometheus label cardinality stays bounded."""
    collapsed = re.sub(
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "/{uuid}",
        path,
    )
    collapsed = re.sub(r"/INC-\d{4}-\d{4,}", "/{incident_id}", collapsed)
    collapsed = re.sub(r"/\d+", "/{id}", collapsed)
    return collapsed


class CorrelationAndMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming_id = request.headers.get("X-Request-ID", "").strip()
        corr_id = incoming_id if SAFE_CORRELATION_RE.match(incoming_id) else str(uuid.uuid4())
        token = set_correlation_id(corr_id)
        request.state.correlation_id = corr_id

        start = time.perf_counter()
        path_template = _normalize_path(request.url.path)
        try:
            response = await call_next(request)
        finally:
            duration = time.perf_counter() - start
            HTTP_REQUEST_DURATION_SECONDS.labels(
                method=request.method, path_template=path_template
            ).observe(duration)

        HTTP_REQUESTS_TOTAL.labels(
            method=request.method,
            path_template=path_template,
            status_code=str(response.status_code),
        ).inc()

        response.headers["X-Request-ID"] = corr_id

        # Hardened HTTP security headers
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        )
        # Swagger/OpenAPI docs only in non-prod need inline styles; API JSON responses get strict CSP
        if not request.url.path.startswith(("/docs", "/redoc")):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )

        if request.url.path not in ("/health/live", "/health/ready", "/metrics"):
            logger.info(
                "HTTP request completed",
                extra={
                    "structured_data": {
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                        "duration_ms": round(duration * 1000, 2),
                        "client_ip": request.client.host if request.client else "unknown",
                    }
                },
            )

        correlation_id_ctx.reset(token)
        return response

