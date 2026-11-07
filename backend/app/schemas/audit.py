"""Audit Log & Chain Verification Pydantic v2 schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    id: uuid.UUID
    occurred_at: datetime
    actor_user_id: uuid.UUID | None
    actor_username: str
    actor_role: str | None
    action: str
    target_type: str
    target_id: str | None
    outcome: str
    source_ip: str | None
    correlation_id: str
    details_json: dict[str, Any]
    prev_hash: str
    entry_hash: str


class PaginatedAuditLogsOut(BaseModel):
    items: list[AuditLogItemOut]
    total: int
    page: int
    page_size: int


class AuditChainVerificationOut(BaseModel):
    valid: bool
    checked_count: int
    head_hash: str | None = None
    broken_at_seq: int | None = None
    reason: str | None = None

