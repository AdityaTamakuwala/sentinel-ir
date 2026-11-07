"""Enterprise Webhook Notification Dispatcher for Slack, Microsoft Teams, and Generic Webhooks."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from app.models.automation import ResponseAction
from app.models.incident import Incident

logger = logging.getLogger("sentinel.notifications.webhook")


class NotificationDispatcher:
    """Dispatches real-time incident lifecycle and approval alerts to external chat platforms."""

    @classmethod
    def format_slack_incident_card(cls, incident: Incident, event_type: str) -> dict[str, Any]:
        sev_color = {
            "critical": "#DC2626",
            "high": "#EA580C",
            "medium": "#D97706",
            "low": "#2563EB",
        }.get(incident.severity, "#4B5563")

        return {
            "attachments": [
                {
                    "color": sev_color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"🚨 SENTINEL IR: [{incident.human_id}] {event_type.upper()}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Severity:*\n`{incident.severity.upper()}`"},
                                {"type": "mrkdwn", "text": f"*Status:*\n`{incident.status}`"},
                                {"type": "mrkdwn", "text": f"*Category:*\n{incident.category}"},
                                {"type": "mrkdwn", "text": f"*Risk Score:*\n{incident.risk_score}/100"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Title:*\n{incident.title}\n\n*Description:*\n{incident.description}",
                            },
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"Simulated: *{'YES' if incident.is_simulated else 'NO'}* | Triggered: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                                }
                            ],
                        },
                    ],
                }
            ]
        }

    @classmethod
    def format_teams_incident_card(cls, incident: Incident, event_type: str) -> dict[str, Any]:
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"SENTINEL IR: [{incident.human_id}] {event_type.upper()}",
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": "Attention" if incident.severity in ("critical", "high") else "Default",
                            },
                            {
                                "type": "TextBlock",
                                "text": incident.title,
                                "wrap": True,
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Severity", "value": incident.severity.upper()},
                                    {"title": "Status", "value": incident.status},
                                    {"title": "Category", "value": incident.category},
                                    {"title": "Risk Score", "value": f"{incident.risk_score} / 100"},
                                    {"title": "Simulated", "value": str(incident.is_simulated)},
                                ],
                            },
                        ],
                    },
                }
            ],
        }

    @classmethod
    def format_approval_request_card(cls, action: ResponseAction, incident: Incident) -> dict[str, Any]:
        target = action.target_indicator or action.target_hostname or action.target_username or "N/A"
        return {
            "attachments": [
                {
                    "color": "#DC2626" if action.risk_impact == "critical" else "#D97706",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"⚠️ FOUR-EYES APPROVAL REQUIRED: {action.action_type.upper()}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Incident:*\n{incident.human_id}"},
                                {"type": "mrkdwn", "text": f"*Action Type:*\n`{action.action_type}`"},
                                {"type": "mrkdwn", "text": f"*Target:*\n`{target}`"},
                                {"type": "mrkdwn", "text": f"*Risk Impact:*\n`{action.risk_impact.upper()}`"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"Proposed by *{action.requested_by.username if action.requested_by else 'System'}*. Second analyst or manager approval required before adapter execution.",
                            },
                        },
                    ],
                }
            ]
        }

    @classmethod
    async def dispatch_webhook(
        cls,
        webhook_url: str | None,
        payload: dict[str, Any],
        platform: str = "slack",
    ) -> dict[str, Any]:
        """Post payload to webhook URL or record simulated dispatch."""
        if not webhook_url or webhook_url.startswith("http://disabled"):
            logger.debug("Webhook dispatch skipped (no destination configured): %s", platform)
            return {"status": "simulated", "platform": platform, "dispatched": False}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(webhook_url, json=payload)
                return {
                    "status": "success" if res.status_code < 400 else "error",
                    "status_code": res.status_code,
                    "platform": platform,
                    "dispatched": True,
                }
        except Exception as exc:
            logger.warning("Failed to dispatch external webhook to %s: %s", platform, exc)
            return {"status": "failed", "error": str(exc), "platform": platform, "dispatched": False}
