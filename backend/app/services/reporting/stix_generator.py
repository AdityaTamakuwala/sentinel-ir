"""OASIS STIX 2.1 Compliant Incident Bundle Exporter."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any


class Stix2BundleGenerator:
    """Generates standard-compliant OASIS STIX 2.1 bundles from incident snapshots."""

    @classmethod
    def generate_stix_bundle(cls, snapshot: dict[str, Any], tlp: str = "TLP:AMBER") -> dict[str, Any]:
        incident_info = snapshot.get("incident", {})
        indicators = snapshot.get("indicators", [])
        techniques = snapshot.get("mitre_techniques", [])

        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        created_iso = incident_info.get("created_at") or now_iso
        if len(created_iso) == 19:
            created_iso += ".000Z"

        bundle_id = f"bundle--{uuid.uuid4()}"
        objects: list[dict[str, Any]] = []

        # 1. Identity Object (SENTINEL IR SOC)
        soc_identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'sentinel-ir.local')}"
        objects.append(
            {
                "type": "identity",
                "spec_version": "2.1",
                "id": soc_identity_id,
                "created": created_iso,
                "modified": now_iso,
                "name": "SENTINEL IR SOC Security Operations",
                "description": "Enterprise Security Incident Response, Threat Intelligence and SOAR Platform.",
                "identity_class": "organization",
                "sectors": ["technology", "defense"],
                "labels": ["soc", "incident-response"],
            }
        )

        # 2. Incident Object
        incident_uuid = incident_info.get("id") or str(uuid.uuid4())
        stix_incident_id = f"incident--{incident_uuid}"
        objects.append(
            {
                "type": "incident",
                "spec_version": "2.1",
                "id": stix_incident_id,
                "created": created_iso,
                "modified": now_iso,
                "name": f"{incident_info.get('human_id', 'INC')}: {incident_info.get('title', 'Security Incident')}",
                "description": incident_info.get("description", ""),
                "labels": [
                    f"severity-{incident_info.get('severity', 'medium')}",
                    f"category-{incident_info.get('category', 'general')}",
                    f"status-{incident_info.get('status', 'NEW').lower()}",
                ],
                "confidence": incident_info.get("risk_score", 50),
            }
        )

        # 3. Indicators of Compromise (STIX 2.1 Indicator SDOs)
        indicator_stix_ids: list[str] = []
        for ioc in indicators:
            ioc_type = ioc.get("ioc_type", "ip")
            ioc_val = str(ioc.get("value", "")).replace("'", "\\'")

            pattern: str
            if ioc_type in ("ip", "ipv4"):
                pattern = f"[ipv4-addr:value = '{ioc_val}']"
            elif ioc_type in ("ipv6",):
                pattern = f"[ipv6-addr:value = '{ioc_val}']"
            elif ioc_type == "domain":
                pattern = f"[domain-name:value = '{ioc_val}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{ioc_val}']"
            elif ioc_type in ("sha256", "md5", "sha1"):
                hash_key = ioc_type.upper() if ioc_type != "sha256" else "SHA-256"
                pattern = f"[file:hashes.'{hash_key}' = '{ioc_val}']"
            elif ioc_type == "email":
                pattern = f"[email-addr:value = '{ioc_val}']"
            else:
                pattern = f"[file:name = '{ioc_val}']"

            rep = ioc.get("reputation", "malicious")
            ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'{ioc_type}:{ioc_val}')}"
            indicator_stix_ids.append(ind_id)

            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_id,
                    "created": ioc.get("first_seen_at") or created_iso,
                    "modified": ioc.get("last_seen_at") or now_iso,
                    "name": f"IOC: {ioc.get('value')}",
                    "description": f"Extracted during triage of {incident_info.get('human_id')}.",
                    "indicator_types": ["malicious-activity"] if rep == "malicious" else ["anomalous-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                    "valid_from": ioc.get("first_seen_at") or created_iso,
                    "confidence": int(ioc.get("confidence") or 80),
                }
            )

        # 4. Attack Patterns (MITRE ATT&CK Techniques)
        attack_pattern_ids: list[str] = []
        for tech in techniques:
            tech_id = tech.get("technique_id", "T1000")
            ap_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, tech_id)}"
            attack_pattern_ids.append(ap_id)

            tactics = tech.get("tactics") or ["execution"]
            kill_chain = [
                {"kill_chain_name": "mitre-attack", "phase_name": t.lower().replace(" ", "-")}
                for t in tactics
            ]

            objects.append(
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": ap_id,
                    "created": created_iso,
                    "modified": now_iso,
                    "name": tech.get("name") or tech_id,
                    "description": tech.get("rationale") or f"MITRE ATT&CK Technique {tech_id}",
                    "kill_chain_phases": kill_chain,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tech_id,
                            "url": tech.get("url") or f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                        }
                    ],
                }
            )

        # 5. Observed Data Object
        if indicators:
            objects.append(
                {
                    "type": "observed-data",
                    "spec_version": "2.1",
                    "id": f"observed-data--{uuid.uuid4()}",
                    "created": created_iso,
                    "modified": now_iso,
                    "first_observed": created_iso,
                    "last_observed": now_iso,
                    "number_observed": len(indicators),
                    "objects": {},
                }
            )

        # 6. STIX Relationship Objects (SROs)
        # Relationship: Indicator -> indicates -> Attack Pattern
        for ind_id in indicator_stix_ids:
            for ap_id in attack_pattern_ids:
                objects.append(
                    {
                        "type": "relationship",
                        "spec_version": "2.1",
                        "id": f"relationship--{uuid.uuid4()}",
                        "created": created_iso,
                        "modified": now_iso,
                        "relationship_type": "indicates",
                        "source_ref": ind_id,
                        "target_ref": ap_id,
                    }
                )

        # Relationship: Attack Pattern -> targets -> Identity
        for ap_id in attack_pattern_ids:
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": created_iso,
                    "modified": now_iso,
                    "relationship_type": "targets",
                    "source_ref": ap_id,
                    "target_ref": soc_identity_id,
                }
            )

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    @classmethod
    def generate_stix_bytes(cls, snapshot: dict[str, Any], tlp: str = "TLP:AMBER") -> bytes:
        data = cls.generate_stix_bundle(snapshot, tlp=tlp)
        return json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8")

