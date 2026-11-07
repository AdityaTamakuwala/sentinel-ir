"""Structured JSON logging with correlation ID propagation and secret redaction."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

correlation_id_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="-"
)

SENSITIVE_FIELD_SUBSTRINGS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "fernet",
    "private_key",
)


def get_correlation_id() -> str:
    return correlation_id_ctx.get()


def set_correlation_id(value: str) -> contextvars.Token[str]:
    return correlation_id_ctx.set(value)


def redact_mapping(data: Any) -> Any:
    """Recursively redact sensitive keys so credentials never enter log streams."""
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if any(sub in key_lower for sub in SENSITIVE_FIELD_SUBSTRINGS):
                sanitized[str(k)] = "[REDACTED]"
            else:
                sanitized[str(k)] = redact_mapping(v)
        return sanitized
    if isinstance(data, list):
        return [redact_mapping(item) for item in data]
    return data


class StructuredJsonFormatter(logging.Formatter):
    """Formats every log record as a single-line UTC JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": getattr(record, "correlation_id", None) or get_correlation_id(),
        }
        extra_fields = getattr(record, "structured_data", None)
        if isinstance(extra_fields, dict):
            payload.update(redact_mapping(extra_fields))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())
    root.handlers = [handler]

    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

