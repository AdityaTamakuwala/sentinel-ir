"""Pydantic schemas for Declarative Playbooks, Execution Lifecycles, and Response Approvals."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PlaybookStepDefinition(BaseModel):
    id: str = Field(min_length=1, max_length=64, description="Unique step identifier within the playbook")
    type: str = Field(min_length=1, max_length=64, description="Action type from StepRegistry")
    name: str = Field(min_length=1, max_length=128, description="Human-readable step title")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Input parameters and template expressions")
    condition: str | None = Field(default=None, description="Optional evaluation condition expression")
    require_approval: bool = Field(default=False, description="Whether execution halts for human approval")
    approval_level: str = Field(default="soc_l2", pattern="^(soc_l2|soc_manager|admin)$")
    approval_timeout_hours: int = Field(default=24, ge=1, le=168)
    action_type: str = Field(
        default="isolate_endpoint_recommendation",
        pattern="^(mark_ioc_malicious|block_ip_recommendation|isolate_endpoint_recommendation|disable_account_recommendation|reset_password_recommendation|escalation_request|send_notification)$",
    )
    risk_impact: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    target_indicator: str | None = None
    target_hostname: str | None = None
    target_username: str | None = None
    on_failure: str = Field(default="abort", pattern="^(abort|continue|retry)$")
    retry_count: int = Field(default=0, ge=0, le=5)
    retry_delay_seconds: int = Field(default=5, ge=1, le=300)


class PlaybookDefinition(BaseModel):
    id: str = Field(min_length=1, max_length=32, description="Canonical Playbook ID, e.g. PB-001")
    slug: str = Field(min_length=1, max_length=64, description="URL-safe unique identifier")
    name: str = Field(min_length=1, max_length=128, description="Playbook display name")
    description: str = Field(default="", description="Operational purpose and scope")
    version: int = Field(default=1, ge=1)
    category: str = Field(
        default="malware",
        pattern="^(malware|phishing|credential_compromise|unauthorized_access|ransomware|data_exfiltration|denial_of_service|custom)$",
    )
    triggers: dict[str, Any] = Field(default_factory=dict, description="Matching alert rules and incident criteria")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Configurable playbook inputs")
    steps: list[PlaybookStepDefinition] = Field(min_length=1, description="Ordered workflow steps")


class PlaybookOut(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str
    is_enabled: bool
    auto_trigger_mode: str
    current_version: int
    is_builtin: bool
    step_count: int = 0
    created_at: datetime
    updated_at: datetime


class PlaybookDetailOut(PlaybookOut):
    definition_yaml: str
    definition_json: dict[str, Any]
    trigger_config: dict[str, Any]
    input_schema: dict[str, Any]


class PlaybookExecuteRequest(BaseModel):
    incident_id: uuid.UUID | None = None
    alert_id: uuid.UUID | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    is_dry_run: bool = Field(default=False, description="Simulate execution without creating pending response actions")
    idempotency_key: str | None = Field(default=None, max_length=128)


class PlaybookExecutionStepOut(BaseModel):
    id: uuid.UUID
    step_index: int
    step_id: str
    step_type: str
    step_name: str
    status: str
    attempt_count: int
    inputs_json: dict[str, Any]
    outputs_json: dict[str, Any]
    error_details: str | None
    duration_ms: int | None
    started_at: datetime | None
    completed_at: datetime | None


class PlaybookExecutionOut(BaseModel):
    id: uuid.UUID
    playbook_id: uuid.UUID
    playbook_slug: str
    playbook_name: str
    version_number: int
    incident_id: uuid.UUID | None
    alert_id: uuid.UUID | None
    triggered_by: str
    triggered_by_username: str | None
    is_dry_run: bool
    status: str
    current_step_index: int
    current_step_id: str | None
    waiting_response_action_id: uuid.UUID | None
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    steps: list[PlaybookExecutionStepOut] = Field(default_factory=list)


class ResponseApprovalOut(BaseModel):
    id: uuid.UUID
    response_action_id: uuid.UUID
    approver_id: uuid.UUID
    approver_username: str
    decision: str  # approved, rejected
    comment: str
    decided_at: datetime


class ResponseActionOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    playbook_execution_id: uuid.UUID | None
    action_type: str
    target_indicator: str | None
    target_hostname: str | None
    target_username: str | None
    title: str
    justification: str
    parameters_json: dict[str, Any]
    risk_impact: str
    status: str
    adapter_name: str
    is_simulated: bool
    requested_by_id: uuid.UUID
    requested_by_username: str
    approved_by_id: uuid.UUID | None
    approved_by_username: str | None
    expires_at: datetime
    executed_at: datetime | None
    execution_result: dict[str, Any] | None
    failure_reason: str | None
    created_at: datetime
    approvals: list[ResponseApprovalOut] = Field(default_factory=list)


class ResponseActionProposeRequest(BaseModel):
    incident_id: uuid.UUID
    action_type: str = Field(
        pattern="^(mark_ioc_malicious|block_ip_recommendation|isolate_endpoint_recommendation|disable_account_recommendation|reset_password_recommendation|escalation_request|send_notification)$"
    )
    title: str = Field(min_length=5, max_length=255)
    justification: str = Field(min_length=10, max_length=2000)
    risk_impact: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    target_indicator: str | None = Field(default=None, max_length=512)
    target_hostname: str | None = Field(default=None, max_length=128)
    target_username: str | None = Field(default=None, max_length=128)
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_hours: int = Field(default=24, ge=1, le=168)


class ResponseApprovalRequest(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    comment: str = Field(min_length=3, max_length=1000)

