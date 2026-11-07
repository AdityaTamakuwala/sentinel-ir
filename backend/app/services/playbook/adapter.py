"""Safe response action adapter interface and simulated containment execution engine."""

from __future__ import annotations

import abc
import datetime
from typing import Any

from app.models.automation import ResponseAction
from app.models.incident import Incident


class ResponseAdapter(abc.ABC):
    """Abstract interface for executing containment and remediation actions."""

    @abc.abstractmethod
    def get_adapter_name(self) -> str:
        """Unique adapter name identifier."""
        raise NotImplementedError

    @abc.abstractmethod
    async def execute(
        self,
        action: ResponseAction,
        incident: Incident | None = None,
    ) -> dict[str, Any]:
        """Execute response action and return execution telemetry dictionary."""
        raise NotImplementedError


class SimulatedResponseAdapter(ResponseAdapter):
    """High-fidelity simulated containment adapter.

    Guarantees no destructive operating system or active-response calls are executed
    on the host environment while recording realistic command strings, egress telemetry,
    and target metadata.
    """

    def get_adapter_name(self) -> str:
        return "simulated"

    async def execute(
        self,
        action: ResponseAction,
        incident: Incident | None = None,
    ) -> dict[str, Any]:
        executed_at_iso = datetime.datetime.now(datetime.UTC).isoformat()
        action_type = action.action_type
        params = action.parameters_json or {}

        telemetry: dict[str, Any] = {
            "status": "success",
            "is_simulated": True,
            "adapter": self.get_adapter_name(),
            "action_type": action_type,
            "action_id": str(action.id),
            "executed_at": executed_at_iso,
            "incident_id": str(action.incident_id),
            "risk_impact": action.risk_impact,
        }

        if action_type == "isolate_endpoint_recommendation":
            hostname = action.target_hostname or params.get("hostname", "UNKNOWN_HOST")
            telemetry["simulated_command"] = f"wazuh-control isolate-host --agent-name {hostname} --enforce"
            telemetry["network_rules_applied"] = [
                f"iptables -I INPUT -s 0.0.0.0/0 -d {hostname} -j DROP",
                f"iptables -I OUTPUT -s {hostname} -d 0.0.0.0/0 -j DROP",
                f"iptables -I INPUT -s 10.0.0.1 -d {hostname} -j ACCEPT",  # keep management tunnel open
            ]
            telemetry["message"] = f"Simulated network quarantine enforced on host '{hostname}'."

        elif action_type == "block_ip_recommendation":
            ip_addr = action.target_indicator or params.get("ip_address", "192.0.2.1")
            direction = params.get("direction", "inbound")
            telemetry["simulated_command"] = f"pan-os-cli security-rule create --action drop --source-ip {ip_addr} --direction {direction}"
            telemetry["firewall_rule"] = {
                "chain": "PERIMETER_DROP",
                "ip": ip_addr,
                "direction": direction,
                "duration_hours": params.get("duration_hours", 72),
            }
            telemetry["message"] = f"Simulated perimeter firewall block enacted on IP '{ip_addr}'."

        elif action_type == "disable_account_recommendation":
            username = action.target_username or params.get("username", "unknown_user")
            telemetry["simulated_command"] = f"dsquery user -samid '{username}' | dsmod user -disabled yes"
            telemetry["directory_status"] = "ACCOUNT_DISABLED"
            telemetry["sessions_invalidated"] = True
            telemetry["message"] = f"Simulated account suspension enforced for user '{username}'."

        elif action_type == "reset_password_recommendation":
            username = action.target_username or params.get("username", "unknown_user")
            telemetry["simulated_command"] = f"dsmod user -samid '{username}' -pwdneverexpires no -mustchpwd yes"
            telemetry["password_reset_flag"] = True
            telemetry["message"] = f"Simulated mandatory password reset flagged for user '{username}'."

        elif action_type == "mark_ioc_malicious":
            ioc = action.target_indicator or params.get("indicator", "")
            telemetry["simulated_command"] = f"sentinel-ioc-feed mark-malicious --value '{ioc}'"
            telemetry["message"] = f"Simulated IOC '{ioc}' marked as high-confidence malicious."

        elif action_type == "escalation_request":
            telemetry["simulated_command"] = f"pagerduty-cli incident trigger --severity {action.risk_impact}"
            telemetry["message"] = "Simulated leadership escalation notification dispatched."

        elif action_type == "send_notification":
            telemetry["simulated_command"] = f"webhook-notify --target '{params.get('channel', 'general')}'"
            telemetry["message"] = "Simulated notification successfully dispatched."

        else:
            telemetry["simulated_command"] = f"custom-action --type {action_type}"
            telemetry["message"] = f"Simulated execution for action '{action_type}' completed successfully."

        return telemetry


_DEFAULT_ADAPTER = SimulatedResponseAdapter()


def get_response_adapter(name: str = "simulated") -> ResponseAdapter:
    """Factory retrieving registered ResponseAdapter instance."""
    # Always default to safe SimulatedResponseAdapter
    return _DEFAULT_ADAPTER
