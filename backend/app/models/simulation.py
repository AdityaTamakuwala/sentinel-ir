"""Simulation Scenario Executions and Live Run Tracking."""

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


class SimulationExecution(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')",
            name="valid_simulation_status",
        ),
        CheckConstraint(
            "mode IN ('full_chain', 'alerts_only', 'incident_only')",
            name="valid_simulation_mode",
        ),
        Index("ix_simulation_executions_slug_created", "scenario_slug", "created_at"),
    )

    scenario_slug: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scenario_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="PENDING", nullable=False, index=True)
    mode: Mapped[str] = mapped_column(String(24), default="full_chain", nullable=False)

    alerts_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    playbook_execution_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("playbook_executions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    execution_log: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    launched_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    launched_by: Mapped[Any] = relationship("User", lazy="selectin")
    incident: Mapped[Any] = relationship("Incident", lazy="selectin")
    playbook_execution: Mapped[Any] = relationship("PlaybookExecution", lazy="selectin")

