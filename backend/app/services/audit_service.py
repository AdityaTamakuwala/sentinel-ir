"""Tamper-evident, advisory-locked, SHA-256 hash-chained Audit Logging Service."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_correlation_id, redact_mapping
from app.models.ops import AuditLog
from app.models.user import User

GENESIS_PREV_HASH = "0" * 64
AUDIT_ADVISORY_LOCK_KEY = 948271


def compute_audit_entry_hash(
    *,
    prev_hash: str,
    entry_id: uuid.UUID,
    occurred_at: datetime,
    actor_user_id: uuid.UUID | None,
    actor_username: str,
    actor_role: str | None,
    action: str,
    target_type: str,
    target_id: str | None,
    outcome: str,
    correlation_id: str,
    details_json: dict[str, Any],
) -> str:
    """Deterministic canonical SHA-256 over immutable audit event fields."""
    ts_utc = occurred_at.astimezone(UTC).isoformat(timespec="microseconds")
    canonical_details = json.dumps(details_json, sort_keys=True, separators=(",", ":"), default=str)
    material = "|".join(
        [
            prev_hash,
            str(entry_id),
            ts_utc,
            str(actor_user_id) if actor_user_id else "",
            actor_username,
            actor_role or "",
            action,
            target_type,
            target_id or "",
            outcome,
            correlation_id,
            canonical_details,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditService:
    @staticmethod
    async def record(
        db: AsyncSession,
        *,
        action: str,
        target_type: str = "system",
        target_id: str | None = None,
        outcome: str = "success",
        actor: User | None = None,
        actor_username_override: str | None = None,
        source_ip: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Append a cryptographically chained audit event under a transaction advisory lock."""
        # Serialize audit chain tail reads/inserts within the current PostgreSQL transaction
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_ADVISORY_LOCK_KEY},
        )

        prev_row = await db.execute(
            select(AuditLog.entry_hash).order_by(AuditLog.seq.desc()).limit(1)
        )
        prev_hash = prev_row.scalar_one_or_none() or GENESIS_PREV_HASH

        entry_id = uuid.uuid4()
        occurred_at = datetime.now(UTC)
        actor_user_id = actor.id if actor else None
        actor_username = (
            actor.username
            if actor
            else (actor_username_override or "system")
        )
        actor_role = actor.role.name if (actor and actor.role) else None
        corr_id = get_correlation_id()
        sanitized_details: dict[str, Any] = redact_mapping(details or {})

        entry_hash = compute_audit_entry_hash(
            prev_hash=prev_hash,
            entry_id=entry_id,
            occurred_at=occurred_at,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            correlation_id=corr_id,
            details_json=sanitized_details,
        )

        entry = AuditLog(
            id=entry_id,
            occurred_at=occurred_at,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            actor_role=actor_role,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            source_ip=source_ip,
            correlation_id=corr_id,
            details_json=sanitized_details,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        db.add(entry)
        await db.flush()
        return entry

    @staticmethod
    async def verify_chain(db: AsyncSession) -> dict[str, Any]:
        """Walk the entire audit_logs table in `seq` order and verify every link & hash."""
        result = await db.execute(select(AuditLog).order_by(AuditLog.seq.asc()))
        rows = list(result.scalars().all())

        expected_prev = GENESIS_PREV_HASH
        expected_seq = 1
        for row in rows:
            if row.seq != expected_seq:
                return {
                    "valid": False,
                    "checked_count": expected_seq - 1,
                    "broken_at_seq": row.seq,
                    "reason": f"Missing sequence gap: expected seq {expected_seq}, found {row.seq}.",
                }
            if row.prev_hash != expected_prev:
                return {
                    "valid": False,
                    "checked_count": expected_seq - 1,
                    "broken_at_seq": row.seq,
                    "reason": "prev_hash mismatch; chain link broken.",
                }
            recomputed = compute_audit_entry_hash(
                prev_hash=row.prev_hash,
                entry_id=row.id,
                occurred_at=row.occurred_at,
                actor_user_id=row.actor_user_id,
                actor_username=row.actor_username,
                actor_role=row.actor_role,
                action=row.action,
                target_type=row.target_type,
                target_id=row.target_id,
                outcome=row.outcome,
                correlation_id=row.correlation_id,
                details_json=row.details_json,
            )
            if recomputed != row.entry_hash:
                return {
                    "valid": False,
                    "checked_count": expected_seq - 1,
                    "broken_at_seq": row.seq,
                    "reason": "entry_hash cryptographic verification failed.",
                }
            expected_prev = row.entry_hash
            expected_seq += 1

        return {
            "valid": True,
            "checked_count": len(rows),
            "head_hash": expected_prev if rows else GENESIS_PREV_HASH,
            "broken_at_seq": None,
            "reason": None,
        }

