"""Incidents, Alert Links, Incident Links, Affected Entities, and Append-Only Timeline."""

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
    Sequence,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

INCIDENT_NUMBER_SEQ = Sequence("incident_human_id_seq", start=1, increment=1)

INCIDENT_STATUSES = (
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT",
    "ERADICATION",
    "RECOVERY",
    "RESOLVED",
    "CLOSED",
)


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="valid_incident_severity",
        ),
        CheckConstraint(
            "priority IN ('p1', 'p2', 'p3', 'p4')",
            name="valid_incident_priority",
        ),
        CheckConstraint(
            "status IN ('NEW', 'TRIAGED', 'INVESTIGATING', 'CONTAINMENT', 'ERADICATION', 'RECOVERY', 'RESOLVED', 'CLOSED')",
            name="valid_incident_status",
        ),
        Index("ix_incidents_status_severity_created", "status", "severity", "created_at"),
    )

    human_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="general", index=True)

    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", index=True)
    priority: Mapped[str] = mapped_column(String(8), nullable=False, default="p3", index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="NEW", index=True)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Explainable risk scoring & audited analyst override
    risk_score: Mapped[int] = mapped_column(Integer, default=30, nullable=False)
    risk_breakdown: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    risk_override_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_override_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_overridden_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Operational timestamps & SLA clocks
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_ack_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_resolve_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sla_paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_paused_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    closure_category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    closure_justification: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Analyst-authored report fields (never hallucinated)
    executive_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    assigned_to: Mapped[Any] = relationship("User", foreign_keys=[assigned_to_id], lazy="selectin")
    created_by: Mapped[Any] = relationship("User", foreign_keys=[created_by_id], lazy="selectin")

    alert_links: Mapped[list[IncidentAlert]] = relationship(
        "IncidentAlert", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    asset_links: Mapped[list[IncidentAsset]] = relationship(
        "IncidentAsset", back_populates="incident", cascade="all, delete-orphan", lazy="selectin"
    )
    affected_users: Mapped[list[IncidentAffectedUser]] = relationship(
        "IncidentAffectedUser",
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    timeline_entries: Mapped[list[IncidentTimeline]] = relationship(
        "IncidentTimeline",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimeline.occurred_at.asc()",
    )


class IncidentAlert(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_alerts"
    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_pair"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    linked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    incident: Mapped[Incident] = relationship("Incident", back_populates="alert_links")
    alert: Mapped[Any] = relationship("Alert", lazy="selectin")


class IncidentLink(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_links"
    __table_args__ = (
        UniqueConstraint(
            "source_incident_id", "target_incident_id", name="uq_incident_links_pair"
        ),
        CheckConstraint(
            "link_type IN ('related', 'duplicate', 'parent_child', 'merged')",
            name="valid_incident_link_type",
        ),
    )

    source_incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    link_type: Mapped[str] = mapped_column(String(32), nullable=False, default="related")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class IncidentAsset(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_assets"
    __table_args__ = (
        UniqueConstraint("incident_id", "asset_id", name="uq_incident_assets_pair"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    impact_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    incident: Mapped[Incident] = relationship("Incident", back_populates="asset_links")
    asset: Mapped[Any] = relationship("Asset", lazy="selectin")


class IncidentAffectedUser(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_affected_users"
    __table_args__ = (
        UniqueConstraint("incident_id", "username", name="uq_incident_affected_username"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False, default="standard")
    is_privileged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    compromise_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    incident: Mapped[Incident] = relationship("Incident", back_populates="affected_users")


class IncidentTimeline(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_timeline"
    __table_args__ = (
        Index("ix_incident_timeline_inc_occurred", "incident_id", "occurred_at"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_label: Mapped[str] = mapped_column(String(128), nullable=False, default="SYSTEM")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    incident: Mapped[Incident] = relationship("Incident", back_populates="timeline_entries")

