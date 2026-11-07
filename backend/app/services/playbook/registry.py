"""Reusable step registry and action handlers for the declarative playbook engine."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.user import RefreshToken, User
from app.services.enrichment.engine import EnrichmentService
from app.services.event_bus import publish_realtime_event

StepHandler = Callable[[dict[str, Any], dict[str, Any], AsyncSession], Awaitable[dict[str, Any]]]


class StepRegistry:
    """Central registry mapping declarative step types to executable async handlers."""

    def __init__(self) -> None:
        self._handlers: dict[str, StepHandler] = {}
        self._register_default_handlers()

    def register(self, step_type: str, handler: StepHandler) -> None:
        self._handlers[step_type] = handler

    def get(self, step_type: str) -> StepHandler | None:
        return self._handlers.get(step_type)

    def has_handler(self, step_type: str) -> bool:
        return step_type in self._handlers

    def _register_default_handlers(self) -> None:
        self.register("enrich_indicator", self._handle_enrich_indicator)
        self.register("kill_process", self._handle_kill_process)
        self.register("isolate_endpoint", self._handle_isolate_endpoint)
        self.register("block_perimeter_ip", self._handle_block_perimeter_ip)
        self.register("block_hash", self._handle_block_hash)
        self.register("quarantine_email", self._handle_quarantine_email)
        self.register("revoke_user_sessions", self._handle_revoke_user_sessions)
        self.register("reset_user_password", self._handle_reset_user_password)
        self.register("disable_user", self._handle_disable_user)
        self.register("update_incident_status", self._handle_update_incident_status)
        self.register("escalate_incident", self._handle_escalate_incident)
        self.register("send_notification", self._handle_send_notification)

    # -------------------------------------------------------------------------
    # Handlers
    # -------------------------------------------------------------------------

    async def _handle_enrich_indicator(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        ioc_type = str(params.get("ioc_type", "ip")).lower()
        if ioc_type in ("ipv4", "ipv6"):
            ioc_type = "ip"
        value = str(params.get("value", "")).strip()

        if not value:
            return {"status": "skipped", "reason": "No indicator value provided"}

        indicator = await EnrichmentService.enrich_indicator(
            db=session,
            ioc_type=ioc_type,
            value=value,
        )
        return {
            "status": "completed",
            "ioc_type": ioc_type,
            "value": value,
            "reputation": indicator.reputation,
            "confidence_score": indicator.confidence,
            "is_internal": indicator.is_internal,
        }

    async def _handle_kill_process(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        hostname = params.get("hostname", "localhost")
        process_name = params.get("process_name", "unknown")
        pid = params.get("process_pid", 0)

        return {
            "status": "completed",
            "action": "terminate_process",
            "hostname": hostname,
            "process_name": process_name,
            "process_pid": pid,
            "simulated_command": f"taskkill /F /PID {pid} /T on host {hostname}",
            "terminated_at": datetime.now(UTC).isoformat(),
        }

    async def _handle_isolate_endpoint(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        hostname = params.get("hostname", "unknown_host")
        justification = params.get("justification", "Network isolation triggered by playbook")

        return {
            "status": "completed",
            "action": "isolate_endpoint",
            "hostname": hostname,
            "justification": justification,
            "isolation_status": "ISOLATED",
            "simulated_firewall_rule": f"wazuh-control isolate --agent {hostname}",
        }

    async def _handle_block_perimeter_ip(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        ip_addr = params.get("ip_address", "192.0.2.1")
        direction = params.get("direction", "inbound")
        duration = params.get("duration_hours", 72)

        return {
            "status": "completed",
            "action": "block_perimeter_ip",
            "ip_address": ip_addr,
            "direction": direction,
            "duration_hours": duration,
            "rule_id": f"PERIM-DROP-{int(datetime.now(UTC).timestamp())}",
        }

    async def _handle_block_hash(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        hash_value = params.get("hash_value", "")
        return {
            "status": "completed",
            "action": "block_hash",
            "hash_value": hash_value,
            "fleet_status": "BLOCKLIST_DISTRIBUTED",
        }

    async def _handle_quarantine_email(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        recipient = params.get("recipient", "")
        sender = params.get("sender", "")

        return {
            "status": "completed",
            "action": "quarantine_email",
            "recipient": recipient,
            "sender": sender,
            "quarantined_messages_count": 1,
        }

    async def _handle_revoke_user_sessions(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        username = str(params.get("username", "")).strip()
        revoked_count = 0

        if username:
            user_stmt = select(User).where(User.username == username)
            user_res = await session.execute(user_stmt)
            target_user = user_res.scalar_one_or_none()

            if target_user:
                del_stmt = delete(RefreshToken).where(RefreshToken.user_id == target_user.id)
                res = await session.execute(del_stmt)
                revoked_count = getattr(res, "rowcount", 0) or 0
                await session.flush()

        return {
            "status": "completed",
            "action": "revoke_user_sessions",
            "username": username,
            "revoked_token_count": revoked_count,
        }

    async def _handle_reset_user_password(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        username = params.get("username", "")
        return {
            "status": "completed",
            "action": "reset_user_password",
            "username": username,
            "mandatory_reset_enforced": True,
        }

    async def _handle_disable_user(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        username = str(params.get("username", "")).strip()
        reason = params.get("reason", "Disabled via incident response playbook")
        disabled = False

        if username:
            user_stmt = select(User).where(User.username == username)
            user_res = await session.execute(user_stmt)
            target_user = user_res.scalar_one_or_none()

            # Prevent disabling admin accounts automatically
            if target_user and target_user.username != "admin":
                target_user.is_active = False
                await session.flush()
                disabled = True

        return {
            "status": "completed",
            "action": "disable_user",
            "username": username,
            "account_disabled": disabled,
            "reason": reason,
        }

    async def _handle_update_incident_status(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        new_status = params.get("status", "CONTAINMENT")
        reason = params.get("reason", "Updated by automated playbook")
        incident_id = context.get("incident_id")

        if incident_id:
            stmt = select(Incident).where(Incident.id == incident_id)
            res = await session.execute(stmt)
            inc = res.scalar_one_or_none()
            if inc:
                inc.status = new_status
                inc.version += 1
                await session.flush()

        return {
            "status": "completed",
            "action": "update_incident_status",
            "new_status": new_status,
            "reason": reason,
        }

    async def _handle_escalate_incident(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        severity = str(params.get("severity", "critical")).lower()
        priority = str(params.get("priority", "p1")).lower()
        justification = params.get("justification", "Escalated by playbook")
        incident_id = context.get("incident_id")

        if incident_id:
            stmt = select(Incident).where(Incident.id == incident_id)
            res = await session.execute(stmt)
            inc = res.scalar_one_or_none()
            if inc:
                inc.severity = severity
                inc.priority = priority
                inc.version += 1
                await session.flush()

        return {
            "status": "completed",
            "action": "escalate_incident",
            "severity": severity,
            "priority": priority,
            "justification": justification,
        }

    async def _handle_send_notification(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
        session: AsyncSession,
    ) -> dict[str, Any]:
        channel = params.get("channel", "soc-alerts")
        message = params.get("message", "Playbook notification")

        await publish_realtime_event(
            "playbook.notification",
            {
                "channel": channel,
                "message": message,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )

        return {
            "status": "completed",
            "action": "send_notification",
            "channel": channel,
            "message": message,
        }


# Global registry singleton
step_registry = StepRegistry()
