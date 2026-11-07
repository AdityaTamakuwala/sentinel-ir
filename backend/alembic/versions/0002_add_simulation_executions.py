"""add_simulation_executions

Revision ID: 0002_add_simulation_executions
Revises: 0001_initial_schema
Create Date: 2026-11-08 00:41:00.000000

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_add_simulation_executions"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "simulation_executions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scenario_slug", sa.String(length=64), nullable=False),
        sa.Column("scenario_name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False, server_default="PENDING"),
        sa.Column("mode", sa.String(length=24), nullable=False, server_default="full_chain"),
        sa.Column("alerts_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("incident_id", sa.UUID(), nullable=True),
        sa.Column("playbook_execution_id", sa.UUID(), nullable=True),
        sa.Column("execution_log", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("launched_by_id", sa.UUID(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_simulated", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')", name="valid_simulation_status"),
        sa.CheckConstraint("mode IN ('full_chain', 'alerts_only', 'incident_only')", name="valid_simulation_mode"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["playbook_execution_id"], ["playbook_executions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["launched_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_simulation_executions_scenario_slug", "simulation_executions", ["scenario_slug"], unique=False)
    op.create_index("ix_simulation_executions_status", "simulation_executions", ["status"], unique=False)
    op.create_index("ix_simulation_executions_slug_created", "simulation_executions", ["scenario_slug", "created_at"], unique=False)

    # Grant DML permissions to runtime application user if role exists
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE simulation_executions TO sentinel_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.drop_index("ix_simulation_executions_slug_created", table_name="simulation_executions")
    op.drop_index("ix_simulation_executions_status", table_name="simulation_executions")
    op.drop_index("ix_simulation_executions_scenario_slug", table_name="simulation_executions")
    op.drop_table("simulation_executions")

