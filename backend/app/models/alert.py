"""Assets, Webhook Sources, Alerts, and Deduplicated Alert Occurrences."""

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
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(
            "criticality IN ('low', 'medium', 'high', 'critical')",
            name="valid_asset_criticality",
        ),
    )

    hostname: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False, default="server")
    os_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class WebhookSource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "webhook_sources"
    __table_args__ = (
        CheckConstraint(
            "source_type IN ('wazuh', 'generic')",
            name="valid_webhook_source_type",
        ),
    )

    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False, default="wazuh")
    api_key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    encrypted_hmac_secret: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, default=120, nullable=False)
    tolerance_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class Alert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name="valid_alert_severity",
        ),
        CheckConstraint(
            "triage_status IN ('new', 'in_review', 'escalated', 'incident_created', 'false_positive')",
            name="valid_alert_triage_status",
        ),
        Index("ix_alerts_fingerprint_last_seen", "fingerprint", "last_seen_at"),
        Index("ix_alerts_status_severity_ingested", "triage_status", "severity", "ingested_at"),
    )

    external_alert_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    source_system: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_description: Mapped[str] = mapped_column(Text, nullable=False)
    event_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    file_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    triage_status: Mapped[str] = mapped_column(String(32), nullable=False, default="new")
    false_positive_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    triage_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    mitre_mappings_raw: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    recommended_steps: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    scenario_slug: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    assigned_to: Mapped[ Any ] = relationship("User", foreign_keys=[assigned_to_id], lazy="selectin")
    asset: Mapped[Asset | None] = relationship("Asset", lazy="selectin")
    occurrences: Mapped[list[AlertOccurrence]] = relationship(
        "AlertOccurrence",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertOccurrence.occurred_at.desc()",
    )


class AlertOccurrence(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "alert_occurrences"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    alert: Mapped[Alert] = relationship("Alert", back_populates="occurrences")

