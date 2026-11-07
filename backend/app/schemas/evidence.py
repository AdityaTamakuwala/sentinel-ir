"""Pydantic v2 schemas for Evidence Management, Integrity Verification, Chain of Custody, and Notifications."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceVersionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    version_number: int
    original_filename: str
    detected_mime_type: str
    size_bytes: int
    sha256_hash: str
    av_scan_status: str
    uploaded_by_username: str | None = None
    notes: str | None = None
    created_at: datetime


class EvidenceCustodyLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    version_number: int | None
    actor_id: uuid.UUID | None
    actor_label: str
    action: str
    sha256_recorded: str
    ip_address: str | None
    correlation_id: str | None
    details: dict[str, Any]
    created_at: datetime


class EvidenceDetailOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    incident_human_id: str | None = None
    title: str
    description: str
    evidence_type: str
    status: str
    withdrawn_reason: str | None
    withdrawn_at: datetime | None
    current_version: int
    uploaded_by_username: str
    sha256_hash: str
    original_filename: str
    detected_mime_type: str
    size_bytes: int
    is_simulated: bool
    created_at: datetime
    updated_at: datetime
    versions: list[EvidenceVersionOut] = Field(default_factory=list)
    custody_logs: list[EvidenceCustodyLogOut] = Field(default_factory=list)


class PaginatedEvidenceOut(BaseModel):
    items: list[EvidenceDetailOut]
    total: int
    page: int
    page_size: int


class EvidenceWithdrawRequest(BaseModel):
    reason: str = Field(min_length=5, max_length=1000)


class EvidenceIntegrityVerifyOut(BaseModel):
    evidence_id: uuid.UUID
    version_number: int
    valid: bool
    expected_sha256: str
    computed_sha256: str | None
    size_bytes: int
    detail: str
    verified_at: datetime


class NotificationItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    body: str
    severity: str
    event_type: str
    link_url: str | None
    is_read: bool
    read_at: datetime | None
    created_at: datetime


class NotificationListOut(BaseModel):
    items: list[NotificationItemOut]
    unread_count: int

