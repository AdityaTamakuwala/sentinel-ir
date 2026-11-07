"""Threat indicators, enrichments, MITRE ATT&CK techniques, notes, and immutable evidence."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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


class Indicator(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_indicators_type_value"),
        CheckConstraint(
            "ioc_type IN ('ip', 'domain', 'sha256', 'md5', 'sha1', 'url', 'email')",
            name="valid_ioc_type",
        ),
        CheckConstraint(
            "reputation IN ('unknown', 'benign', 'suspicious', 'malicious', 'internal')",
            name="valid_ioc_reputation",
        ),
    )

    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    is_internal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reputation: Mapped[str] = mapped_column(String(24), default="unknown", nullable=False, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    marked_malicious_by_action_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    enrichments: Mapped[list[EnrichmentResult]] = relationship(
        "EnrichmentResult",
        back_populates="indicator",
        cascade="all, delete-orphan",
        order_by="EnrichmentResult.looked_up_at.desc()",
        lazy="selectin",
    )


class IncidentIndicator(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_indicators"
    __table_args__ = (
        UniqueConstraint("incident_id", "indicator_id", name="uq_incident_indicator_pair"),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    indicator: Mapped[Indicator] = relationship("Indicator", lazy="selectin")


class EnrichmentResult(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "enrichment_results"
    __table_args__ = (
        CheckConstraint(
            "status IN ('success', 'not_applicable_internal', 'provider_unavailable', 'rate_limited', 'error')",
            name="valid_enrichment_status",
        ),
        Index("ix_enrichment_indicator_provider", "indicator_id", "provider", "looked_up_at"),
    )

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reputation: Mapped[str] = mapped_column(String(24), nullable=False, default="unknown")
    malicious_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    total_engines: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    source_references: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    is_mock: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    looked_up_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    indicator: Mapped[Indicator] = relationship("Indicator", back_populates="enrichments")


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)  # e.g. T1110, T1110.001
    stix_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tactics: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detection: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mitigations: Mapped[list[dict[str, str]]] = mapped_column(JSONB, nullable=False, default=list)
    platforms: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    url: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parent_id: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    attack_version: Mapped[str] = mapped_column(String(32), nullable=False, default="15.1")
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class IncidentTechnique(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_techniques"
    __table_args__ = (
        UniqueConstraint("incident_id", "technique_id", name="uq_incident_technique_pair"),
        CheckConstraint(
            "source IN ('alert_metadata', 'enrichment', 'playbook_rule', 'analyst')",
            name="valid_incident_technique_source",
        ),
        CheckConstraint(
            "status IN ('suggested', 'confirmed', 'rejected')",
            name="valid_incident_technique_status",
        ),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    technique_id: Mapped[str] = mapped_column(
        String(24),
        ForeignKey("mitre_techniques.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="suggested")
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    linked_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    technique: Mapped[MitreTechnique] = relationship("MitreTechnique", lazy="selectin")


class InvestigationNote(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "investigation_notes"

    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    current_content: Mapped[str] = mapped_column(Text, nullable=False)
    revision_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    author: Mapped[Any] = relationship("User", lazy="selectin")
    revisions: Mapped[list[NoteRevision]] = relationship(
        "NoteRevision",
        back_populates="note",
        cascade="all, delete-orphan",
        order_by="NoteRevision.revision_number.asc()",
        lazy="selectin",
    )


class NoteRevision(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "note_revisions"
    __table_args__ = (
        UniqueConstraint("note_id", "revision_number", name="uq_note_revision_num"),
    )

    note_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigation_notes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    edited_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    note: Mapped[InvestigationNote] = relationship("InvestigationNote", back_populates="revisions")
    edited_by: Mapped[Any] = relationship("User", lazy="selectin")


class Evidence(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint(
            "evidence_type IN ('file', 'screenshot', 'log_excerpt', 'json_artifact', 'ioc_record', 'note')",
            name="valid_evidence_type",
        ),
        CheckConstraint(
            "status IN ('active', 'withdrawn')",
            name="valid_evidence_status",
        ),
    )

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_type: Mapped[str] = mapped_column(String(32), nullable=False, default="file")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active", index=True)
    withdrawn_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    withdrawn_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    uploaded_by: Mapped[Any] = relationship("User", foreign_keys=[uploaded_by_id], lazy="selectin")
    versions: Mapped[list[EvidenceVersion]] = relationship(
        "EvidenceVersion",
        back_populates="evidence",
        cascade="all, delete-orphan",
        order_by="EvidenceVersion.version_number.desc()",
        lazy="selectin",
    )
    custody_logs: Mapped[list[EvidenceCustodyLog]] = relationship(
        "EvidenceCustodyLog",
        back_populates="evidence",
        cascade="all, delete-orphan",
        order_by="EvidenceCustodyLog.created_at.asc()",
        lazy="selectin",
    )


class EvidenceVersion(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "evidence_versions"
    __table_args__ = (
        UniqueConstraint("evidence_id", "version_number", name="uq_evidence_version_num"),
    )

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    detected_mime_type: Mapped[str] = mapped_column(String(128), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    av_scan_status: Mapped[str] = mapped_column(String(24), nullable=False, default="skipped")
    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    evidence: Mapped[Evidence] = relationship("Evidence", back_populates="versions")
    uploaded_by: Mapped[Any] = relationship("User", lazy="selectin")


class EvidenceCustodyLog(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "evidence_custody_log"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("evidence.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    version_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_label: Mapped[str] = mapped_column(String(128), nullable=False, default="SYSTEM")
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256_recorded: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    evidence: Mapped[Evidence] = relationship("Evidence", back_populates="custody_logs")

