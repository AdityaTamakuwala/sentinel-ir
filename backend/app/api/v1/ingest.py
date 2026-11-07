"""Authenticated & HMAC-Signed Wazuh Alert Ingestion Webhook (`/api/v1/ingest`)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.core.rbac import public_endpoint
from app.db.session import get_db_session
from app.schemas.alert import WebhookIngestResponse
from app.services.alert_service import AlertService, parse_wazuh_alert_payload

router = APIRouter(prefix="/ingest", tags=["Alert Ingestion"])


@router.post(
    "/wazuh",
    response_model=WebhookIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
@public_endpoint(
    reason="Machine-to-machine Wazuh webhook authenticated via hashed API key + HMAC-SHA256 + timestamp replay window"
)
async def ingest_wazuh_webhook(
    request: Request,
    x_sentinel_api_key: str | None = Header(default=None, alias="X-Sentinel-API-Key"),
    x_sentinel_signature: str | None = Header(default=None, alias="X-Sentinel-Signature"),
    x_sentinel_timestamp: str | None = Header(default=None, alias="X-Sentinel-Timestamp"),
    db: AsyncSession = Depends(get_db_session),
) -> WebhookIngestResponse:
    raw_body = await request.body()
    client_ip = request.client.host if request.client else None

    await AlertService.verify_wazuh_webhook(
        db,
        raw_body=raw_body,
        api_key=x_sentinel_api_key,
        signature_header=x_sentinel_signature,
        timestamp_header=x_sentinel_timestamp,
        source_ip=client_ip,
    )

    try:
        payload = json.loads(raw_body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Root JSON payload must be an object.")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AppError(
            code="INVALID_WAZUH_JSON",
            message="Webhook body must be a valid UTF-8 JSON object.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from exc

    normalized = parse_wazuh_alert_payload(payload)
    alert, created_new = await AlertService.ingest_normalized_alert(
        db,
        normalized,
        actor=None,
        source_ip=client_ip,
        deduplicate=True,
    )
    return WebhookIngestResponse(
        alert_id=alert.id,
        created_new=created_new,
        occurrence_count=alert.occurrence_count,
        fingerprint=alert.fingerprint,
    )

