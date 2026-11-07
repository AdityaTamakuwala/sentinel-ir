"""Alert Ingestion, Alert Detail, and Triage Workbench Pydantic v2 schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ManualAlertCreateRequest(BaseModel):
    source_system: str = Field(default="manual", min_length=2, max_length=64)
    rule_id: str = Field(default="MANUAL-001", min_length=2, max_length=64)
    rule_description: str = Field(..., min_length=4, max_length=500)
    event_category: str = Field(default="general", min_length=2, max_length=64)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    event_timestamp: datetime | None = None
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, max_length=128)
    file_hash: str | None = Field(default=None, max_length=128)
    domain: str | None = Field(default=None, max_length=255)
    mitre_techniques: list[dict[str, str]] = Field(default_factory=list)
    raw_payload: dict[str, Any] | None = None


class JsonBatchAlertImportRequest(BaseModel):
    alerts: list[dict[str, Any]] = Field(..., min_length=1, max_length=100)
    format: Literal["wazuh", "normalized"] = "wazuh"


class AlertTriageRequest(BaseModel):
    action: Literal["mark_reviewed", "mark_false_positive", "escalate", "assign", "add_note"]
    reason: str | None = Field(default=None, max_length=2000)
    assigned_to_id: uuid.UUID | None = None
    note: str | None = Field(default=None, max_length=4000)
    severity: Literal["low", "medium", "high", "critical"] | None = None


class AssetSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    ip_address: str | None
    asset_type: str
    os_name: str | None
    criticality: str
    owner: str | None
    department: str | None
    environment: str
    is_simulated: bool


class AlertOccurrenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    occurred_at: datetime
    ingested_at: datetime
    raw_payload: dict[str, Any]


class AlertListItemOut(BaseModel):
    id: uuid.UUID
    external_alert_id: str | None
    source_system: str
    rule_id: str
    rule_description: str
    event_category: str
    event_timestamp: datetime
    ingested_at: datetime
    src_ip: str | None
    dst_ip: str | None
    hostname: str | None
    username: str | None
    file_hash: str | None
    domain: str | None
    severity: str
    triage_status: str
    assigned_to_id: uuid.UUID | None
    assigned_to_username: str | None = None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_simulated: bool
    linked_incident_id: uuid.UUID | None = None
    linked_incident_human_id: str | None = None


class PaginatedAlertsOut(BaseModel):
    items: list[AlertListItemOut]
    total: int
    page: int
    page_size: int


class AlertDetailOut(AlertListItemOut):
    false_positive_reason: str | None
    triage_notes: str | None
    fingerprint: str
    raw_payload: dict[str, Any]
    mitre_mappings_raw: list[dict[str, Any]]
    recommended_steps: list[str]
    asset: AssetSummaryOut | None = None
    occurrences: list[AlertOccurrenceOut] = Field(default_factory=list)
    related_alerts: list[AlertListItemOut] = Field(default_factory=list)
    notes: list[dict[str, Any]] = Field(default_factory=list)
    enrichment_summary: list[dict[str, Any]] = Field(default_factory=list)
    version: int


class WebhookIngestResponse(BaseModel):
    alert_id: uuid.UUID
    created_new: bool
    occurrence_count: int
    fingerprint: str

