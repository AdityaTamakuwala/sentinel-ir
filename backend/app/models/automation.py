"""Declarative Playbooks, Durable Executions, Human-Approved Response Actions, and Reports."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class Playbook(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "playbooks"
    __table_args__ = (
        CheckConstraint(
            "auto_trigger_mode IN ('disabled', 'propose', 'auto_run_readonly')",
            name="valid_playbook_trigger_mode",
        ),
    )

    slug: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_trigger_mode: Mapped[str] = mapped_column(
        String(24), default="propose", nullable=False
    )
    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    versions: Mapped[list[PlaybookVersion]] = relationship(
        "PlaybookVersion",
        back_populates="playbook",
        cascade="all, delete-orphan",
        order_by="PlaybookVersion.version.desc()",
        lazy="selectin",
    )


class PlaybookVersion(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "playbook_versions"
    __table_args__ = (
        UniqueConstraint("playbook_id", "version", name="uq_playbook_version"),
    )

    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbooks.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    definition_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    definition_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    trigger_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    playbook: Mapped[Playbook] = relationship("Playbook", back_populates="versions")


class PlaybookExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "playbook_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'WAITING_APPROVAL', 'COMPLETED', 'FAILED', 'CANCELLED', 'EXPIRED')",
            name="valid_playbook_execution_status",
        ),
        CheckConstraint(
            "triggered_by IN ('manual', 'alert_trigger', 'simulation')",
            name="valid_playbook_triggered_by",
        ),
        Index("ix_playbook_executions_status_created", "status", "created_at"),
    )

    playbook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbooks.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    playbook_version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    triggered_by: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    is_dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING", index=True)
    current_step_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_step_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    waiting_response_action_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    playbook: Mapped[Playbook] = relationship("Playbook", lazy="selectin")
    steps: Mapped[list[PlaybookExecutionStep]] = relationship(
        "PlaybookExecutionStep",
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="PlaybookExecutionStep.step_index.asc()",
        lazy="selectin",
    )


class PlaybookExecutionStep(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "playbook_execution_steps"

    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_executions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    step_index: Mapped[int] = mapped_column(Integer, nullable=False)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False)
    step_type: Mapped[str] = mapped_column(String(64), nullable=False)
    step_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    inputs_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    outputs_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_details: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    execution: Mapped[PlaybookExecution] = relationship("PlaybookExecution", back_populates="steps")


class ResponseAction(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint(
            "action_type IN ('mark_ioc_malicious', 'block_ip_recommendation', 'isolate_endpoint_recommendation', 'disable_account_recommendation', 'reset_password_recommendation', 'escalation_request', 'send_notification')",
            name="valid_response_action_type",
        ),
        CheckConstraint(
            "status IN ('PROPOSED', 'PENDING_APPROVAL', 'APPROVED', 'EXECUTING', 'COMPLETED', 'FAILED', 'REJECTED', 'EXPIRED', 'CANCELLED')",
            name="valid_response_action_status",
        ),
        CheckConstraint(
            "risk_impact IN ('low', 'medium', 'high', 'critical')",
            name="valid_response_action_impact",
        ),
        Index("ix_response_actions_status_expires", "status", "expires_at"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    playbook_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_executions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    action_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    target_indicator: Mapped[str | None] = mapped_column(String(512), nullable=True)
    target_hostname: Mapped[str | None] = mapped_column(String(128), nullable=True)
    target_username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    parameters_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    risk_impact: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="PENDING_APPROVAL", index=True
    )
    adapter_name: Mapped[str] = mapped_column(String(32), nullable=False, default="simulated")
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)

    requested_by: Mapped[Any] = relationship(
        "User", foreign_keys=[requested_by_id], lazy="selectin"
    )
    approved_by: Mapped[Any] = relationship("User", foreign_keys=[approved_by_id], lazy="selectin")
    approvals: Mapped[list[ResponseApproval]] = relationship(
        "ResponseApproval",
        back_populates="response_action",
        cascade="all, delete-orphan",
        order_by="ResponseApproval.decided_at.asc()",
        lazy="selectin",
    )


class ResponseApproval(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "response_approvals"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('approved', 'rejected')",
            name="valid_approval_decision",
        ),
    )

    response_action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("response_actions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approver_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    response_action: Mapped[ResponseAction] = relationship(
        "ResponseAction", back_populates="approvals"
    )
    approver: Mapped[Any] = relationship("User", lazy="selectin")


class IncidentReport(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_reports"
    __table_args__ = (
        CheckConstraint(
            "report_format IN ('pdf', 'json', 'stix')",
            name="valid_report_format",
        ),
        CheckConstraint(
            "tlp_classification IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:RED')",
            name="valid_report_tlp",
        ),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    incident_version_snapshot: Mapped[int] = mapped_column(Integer, nullable=False)
    report_format: Mapped[str] = mapped_column(String(16), nullable=False, default="pdf")
    tlp_classification: Mapped[str] = mapped_column(
        String(24), nullable=False, default="TLP:AMBER"
    )
    snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    storage_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sha256_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    generated_by: Mapped[Any] = relationship("User", lazy="selectin")

