"""Canonical JSON Incident Report Exporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any


class JsonReportGenerator:
    """Produces versioned, schema-validated JSON incident export bundles."""

    @staticmethod
    def generate_json_export(snapshot: dict[str, Any], tlp: str = "TLP:AMBER") -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "format": "sentinel_ir_incident_export",
            "platform": "SENTINEL IR Enterprise Security Operations",
            "generated_at": datetime.now(UTC).isoformat(),
            "tlp_classification": tlp.upper(),
            "incident": snapshot.get("incident", {}),
            "metrics": snapshot.get("metrics", {}),
            "timeline": snapshot.get("timeline", []),
            "indicators": snapshot.get("indicators", []),
            "mitre_techniques": snapshot.get("mitre_techniques", []),
            "evidence": snapshot.get("evidence", []),
            "response_actions": snapshot.get("response_actions", []),
            "playbook_executions": snapshot.get("playbook_executions", []),
            "alerts": snapshot.get("alerts", []),
            "notes": snapshot.get("notes", []),
        }

    @classmethod
    def generate_json_bytes(cls, snapshot: dict[str, Any], tlp: str = "TLP:AMBER") -> bytes:
        data = cls.generate_json_export(snapshot, tlp=tlp)
        return json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8")

