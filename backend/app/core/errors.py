"""Consistent API error envelope with correlation IDs and zero stack-trace leakage."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.logging import get_correlation_id

logger = logging.getLogger("sentinel.errors")


class AppError(Exception):
    """Domain/application error mapped cleanly to HTTP status + structured envelope."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


def error_envelope(code: str, message: str, details: Any | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "correlation_id": get_correlation_id(),
        }
    }
    if details is not None:
        body["error"]["details"] = details
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(exc.code, exc.message, exc.details),
            headers={"X-Request-ID": get_correlation_id()},
        )

    @app.exception_handler(HTTPException)
    async def handle_http_exception(_request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        message = detail if isinstance(detail, str) else "Request failed."
        extra = detail if not isinstance(detail, str) else None
        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(f"HTTP_{exc.status_code}", message, extra),
            headers={"X-Request-ID": get_correlation_id()},
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        sanitized_errors = []
        for err in exc.errors():
            sanitized_errors.append(
                {
                    "loc": [str(part) for part in err.get("loc", [])],
                    "msg": err.get("msg", "Invalid input"),
                    "type": err.get("type", "validation_error"),
                }
            )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_envelope(
                "VALIDATION_ERROR",
                "Request validation failed.",
                sanitized_errors,
            ),
            headers={"X-Request-ID": get_correlation_id()},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled server exception",
            extra={
                "structured_data": {
                    "path": request.url.path,
                    "method": request.method,
                    "error_type": type(exc).__name__,
                }
            },
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_envelope(
                "INTERNAL_SERVER_ERROR",
                "An unexpected internal error occurred. Reference correlation_id for SOC diagnostics.",
            ),
            headers={"X-Request-ID": get_correlation_id()},
        )

