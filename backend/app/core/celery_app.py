"""Celery application with correlation ID propagation and periodic SOC maintenance jobs."""

from __future__ import annotations

from typing import Any

from celery import Celery  # type: ignore[import-untyped]
from celery.signals import before_task_publish, task_prerun  # type: ignore[import-untyped]

from app.core.config import get_settings
from app.core.logging import configure_logging, get_correlation_id, set_correlation_id

settings = get_settings()
configure_logging(settings.LOG_LEVEL)

celery_app = Celery(
    "sentinel_ir",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.tasks.maintenance",
        "app.tasks.playbook_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    beat_schedule={
        "expire-pending-response-approvals": {
            "task": "sentinel.tasks.expire_stale_approvals",
            "schedule": 60.0,
        },
        "cleanup-expired-tokens-and-cache": {
            "task": "sentinel.tasks.cleanup_expired_records",
            "schedule": 900.0,
        },
    },
)


@before_task_publish.connect
def inject_correlation_header(headers: dict[str, Any] | None = None, **_kwargs: Any) -> None:
    if headers is not None and "correlation_id" not in headers:
        headers["correlation_id"] = get_correlation_id()


@task_prerun.connect
def restore_correlation_header(task: Any = None, **_kwargs: Any) -> None:
    req = getattr(task, "request", None)
    if req is not None:
        corr_id = getattr(req, "correlation_id", None) or (req.headers or {}).get("correlation_id")
        if corr_id:
            set_correlation_id(str(corr_id))

