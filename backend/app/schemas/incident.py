"""Incident Lifecycle, Risk Breakdown, Timeline, Notes, and Linking Pydantic v2 schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=4, max_length=255)
    description: str = Field(..., min_length=4, max_length=8000)
    category: str = Field(default="general", min_length=2, max_length=64)
    base_severity: Literal["low", "medium", "high", "critical"] = "medium"
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    assigned_to_id: uuid.UUID | None = None


class IncidentTransitionRequest(BaseModel):
    target_status: Literal[
        "NEW",
        "TRIAGED",
        "INVESTIGATING",
        "CONTAINMENT",
        "ERADICATION",
        "RECOVERY",
        "RESOLVED",
        "CLOSED",
    ]
    expected_version: int = Field(..., ge=1)
    reason: str | None = Field(default=None, max_length=4000)
    closure_category: str | None = Field(default=None, max_length=64)
    closure_justification: str | None = Field(default=None, max_length=4000)


class IncidentAssignRequest(BaseModel):
    assigned_to_id: uuid.UUID | None
    expected_version: int = Field(..., ge=1)
    note: str | None = Field(default=None, max_length=1000)


class IncidentRiskOverrideRequest(BaseModel):
    override_severity: Literal["low", "medium", "high", "critical"]
    justification: str = Field(..., min_length=10, max_length=2000)
    expected_version: int = Field(..., ge=1)


class IncidentUpdateFieldsRequest(BaseModel):
    title: str | None = Field(default=None, min_length=4, max_length=255)
    description: str | None = Field(default=None, min_length=4, max_length=8000)
    priority: Literal["p1", "p2", "p3", "p4"] | None = None
    executive_summary: str | None = Field(default=None, max_length=8000)
    root_cause: str | None = Field(default=None, max_length=8000)
    lessons_learned: str | None = Field(default=None, max_length=8000)
    recommendations_text: str | None = Field(default=None, max_length=8000)
    expected_version: int = Field(..., ge=1)


class IncidentLinkAlertRequest(BaseModel):
    alert_id: uuid.UUID


class IncidentLinkRelatedRequest(BaseModel):
    target_incident_id: uuid.UUID
    link_type: Literal["related", "duplicate", "parent_child", "merged"] = "related"
    notes: str | None = Field(default=None, max_length=1000)


class NoteCreateRequest(BaseModel):
    content: str = Field(..., min_length=2, max_length=10000)


class NoteUpdateRequest(BaseModel):
    content: str = Field(..., min_length=2, max_length=10000)


class TimelineEntryOut(BaseModel):
    id: uuid.UUID
    event_type: str
    title: str
    description: str
    actor_id: uuid.UUID | None
    actor_label: str
    metadata_json: dict[str, Any]
    occurred_at: datetime


class IncidentListItemOut(BaseModel):
    id: uuid.UUID
    human_id: str
    title: str
    category: str
    severity: str
    priority: str
    status: str
    risk_score: int
    assigned_to_id: uuid.UUID | None
    assigned_to_username: str | None = None
    alert_count: int = 0
    sla_status: str
    sla_resolve_due_at: str | None
    is_simulated: bool
    version: int
    created_at: datetime
    updated_at: datetime


class PaginatedIncidentsOut(BaseModel):
    items: list[IncidentListItemOut]
    total: int
    page: int
    page_size: int


class IncidentDetailOut(IncidentListItemOut):
    description: str
    risk_breakdown: dict[str, Any]
    risk_override_severity: str | None
    risk_override_reason: str | None
    acknowledged_at: datetime | None
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    closure_category: str | None
    closure_justification: str | None
    executive_summary: str | None
    root_cause: str | None
    lessons_learned: str | None
    recommendations_text: str | None
    allowed_transitions: list[str]
    linked_alerts: list[dict[str, Any]]
    affected_assets: list[dict[str, Any]]
    affected_users: list[dict[str, Any]]
    indicators: list[dict[str, Any]]
    mitre_techniques: list[dict[str, Any]]
    notes: list[dict[str, Any]]
    evidence_items: list[dict[str, Any]]
    response_actions: list[dict[str, Any]]
    related_incidents: list[dict[str, Any]]
    timeline: list[TimelineEntryOut]

