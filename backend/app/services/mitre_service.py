"""Offline MITRE ATT&CK STIX loader, Enterprise Matrix aggregator, and Incident mapping service."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.errors import AppError
from app.models.base import utc_now
from app.models.investigation import IncidentTechnique, MitreTechnique
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event

logger = logging.getLogger("sentinel.mitre")

# Standard Enterprise ATT&CK 14 Tactics in kill-chain progression order
TACTIC_PROGRESSION: list[dict[str, str]] = [
    {"id": "TA0043", "shortname": "reconnaissance", "name": "Reconnaissance", "description": "Gather adversary pre-attack intelligence"},
    {"id": "TA0042", "shortname": "resource-development", "name": "Resource Development", "description": "Establish infrastructure and capabilities"},
    {"id": "TA0001", "shortname": "initial-access", "name": "Initial Access", "description": "Entry vectors into target network"},
    {"id": "TA0002", "shortname": "execution", "name": "Execution", "description": "Running adversary-controlled code"},
    {"id": "TA0003", "shortname": "persistence", "name": "Persistence", "description": "Maintaining foothold across reboots"},
    {"id": "TA0004", "shortname": "privilege-escalation", "name": "Privilege Escalation", "description": "Gaining higher-level permissions"},
    {"id": "TA0005", "shortname": "defense-evasion", "name": "Defense Evasion", "description": "Avoiding detection and security controls"},
    {"id": "TA0006", "shortname": "credential-access", "name": "Credential Access", "description": "Stealing passwords, tokens, and hashes"},
    {"id": "TA0007", "shortname": "discovery", "name": "Discovery", "description": "Observing internal environment and topology"},
    {"id": "TA0008", "shortname": "lateral-movement", "name": "Lateral Movement", "description": "Traversing through network systems"},
    {"id": "TA0009", "shortname": "collection", "name": "Collection", "description": "Gathering target data of interest"},
    {"id": "TA0011", "shortname": "command-and-control", "name": "Command and Control", "description": "Communicating with compromised systems"},
    {"id": "TA0010", "shortname": "exfiltration", "name": "Exfiltration", "description": "Stealing data out of target environment"},
    {"id": "TA0040", "shortname": "impact", "name": "Impact", "description": "Manipulating, disrupting, or destroying systems"},
]


class MitreService:
    """Enterprise MITRE ATT&CK Matrix navigation and incident mapping service."""

    @classmethod
    async def load_mitre_stix(cls, db: AsyncSession, json_path: Path | None = None) -> int:
        """Load pinned official MITRE ATT&CK Enterprise STIX 2.1 dataset offline into PostgreSQL."""
        settings = get_settings()
        path = json_path or (settings.resolved_data_dir / "mitre" / "enterprise-attack-15.1.json")

        if not path.exists():
            logger.warning(f"MITRE STIX file not found at {path}")
            return 0

        with open(path, encoding="utf-8") as f:
            stix_data = json.load(f)

        objects = stix_data.get("objects", [])
        attack_patterns = [o for o in objects if o.get("type") == "attack-pattern"]
        loaded_count = 0

        logger.info(f"Loading {len(attack_patterns)} MITRE ATT&CK techniques from {path.name}...")

        batch: list[dict[str, Any]] = []
        for obj in attack_patterns:
            # Extract official MITRE ID (e.g. T1059.001)
            ext_refs = obj.get("external_references", [])
            mitre_id = None
            url = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    url = ref.get("url", "")
                    break

            if not mitre_id:
                continue

            # Extract tactics
            tactics = [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
            ]

            is_sub = bool(obj.get("x_mitre_is_subtechnique", False)) or ("." in mitre_id)
            parent_id = mitre_id.split(".")[0] if is_sub and "." in mitre_id else None
            is_deprecated = bool(obj.get("x_mitre_deprecated", False) or obj.get("revoked", False))

            batch.append(
                {
                    "id": mitre_id,
                    "stix_id": obj["id"],
                    "name": obj.get("name", mitre_id),
                    "tactics": tactics,
                    "description": obj.get("description", ""),
                    "detection": obj.get("x_mitre_detection", ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "mitigations": [],
                    "url": url or f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/",
                    "is_subtechnique": is_sub,
                    "parent_id": parent_id,
                    "attack_version": str(obj.get("x_mitre_version", "15.1")),
                    "deprecated": is_deprecated,
                }
            )

            if len(batch) >= 100:
                stmt = insert(MitreTechnique).values(batch)
                stmt = stmt.on_conflict_do_update(
                    index_elements=[MitreTechnique.id],
                    set_={
                        "name": stmt.excluded.name,
                        "tactics": stmt.excluded.tactics,
                        "description": stmt.excluded.description,
                        "detection": stmt.excluded.detection,
                        "platforms": stmt.excluded.platforms,
                        "url": stmt.excluded.url,
                        "is_subtechnique": stmt.excluded.is_subtechnique,
                        "parent_id": stmt.excluded.parent_id,
                        "attack_version": stmt.excluded.attack_version,
                        "deprecated": stmt.excluded.deprecated,
                    },
                )
                await db.execute(stmt)
                loaded_count += len(batch)
                batch = []

        if batch:
            stmt = insert(MitreTechnique).values(batch)
            stmt = stmt.on_conflict_do_update(
                index_elements=[MitreTechnique.id],
                set_={
                    "name": stmt.excluded.name,
                    "tactics": stmt.excluded.tactics,
                    "description": stmt.excluded.description,
                    "detection": stmt.excluded.detection,
                    "platforms": stmt.excluded.platforms,
                    "url": stmt.excluded.url,
                    "is_subtechnique": stmt.excluded.is_subtechnique,
                    "parent_id": stmt.excluded.parent_id,
                    "attack_version": stmt.excluded.attack_version,
                    "deprecated": stmt.excluded.deprecated,
                },
            )
            await db.execute(stmt)
            loaded_count += len(batch)

        await db.commit()
        logger.info(f"Successfully loaded {loaded_count} MITRE techniques into database.")
        return loaded_count

    @classmethod
    async def get_matrix(cls, db: AsyncSession) -> dict[str, Any]:
        """Aggregate the full 14-tactic Enterprise ATT&CK matrix with active incident mapping counts."""
        # 1. Fetch count of active incidents mapped to each technique
        incident_count_stmt = (
            select(IncidentTechnique.technique_id, func.count(IncidentTechnique.incident_id))
            .where(IncidentTechnique.status != "rejected")
            .group_by(IncidentTechnique.technique_id)
        )
        count_rows = (await db.execute(incident_count_stmt)).all()
        counts: dict[str, int] = {str(row[0]): int(row[1]) for row in count_rows}

        # 2. Query all non-deprecated techniques
        tech_stmt = (
            select(MitreTechnique)
            .where(MitreTechnique.deprecated.is_(False))
            .order_by(MitreTechnique.id.asc())
        )
        techniques = list((await db.execute(tech_stmt)).scalars().all())

        # 3. Bucket techniques into tactics
        tactics_map: dict[str, list[dict[str, Any]]] = {
            t["shortname"]: [] for t in TACTIC_PROGRESSION
        }

        for tech in techniques:
            tech_data = {
                "id": tech.id,
                "stix_id": tech.stix_id,
                "name": tech.name,
                "tactics": tech.tactics,
                "description": tech.description[:300] + ("..." if len(tech.description) > 300 else ""),
                "detection": tech.detection,
                "mitigations": tech.mitigations,
                "platforms": tech.platforms,
                "url": tech.url,
                "is_subtechnique": tech.is_subtechnique,
                "parent_id": tech.parent_id,
                "attack_version": tech.attack_version,
                "deprecated": tech.deprecated,
                "incident_count": counts.get(tech.id, 0),
            }
            for tactic in tech.tactics:
                if tactic in tactics_map:
                    tactics_map[tactic].append(tech_data)

        # Build output structure
        tactic_columns = []
        for t_meta in TACTIC_PROGRESSION:
            column_techs: list[dict[str, Any]] = tactics_map.get(t_meta["shortname"], [])
            sorted_techs = sorted(
                column_techs,
                key=lambda x: (bool(x["is_subtechnique"]), -int(x["incident_count"]), str(x["id"])),
            )
            tactic_columns.append(
                {
                    "tactic_id": t_meta["id"],
                    "name": t_meta["name"],
                    "shortname": t_meta["shortname"],
                    "description": t_meta["description"],
                    "techniques": sorted_techs,
                }
            )

        total_mapped = sum(counts.values())

        return {
            "tactics": tactic_columns,
            "total_techniques": len(techniques),
            "total_mapped_incidents": total_mapped,
            "version": "15.1",
        }

    @classmethod
    async def search_techniques(
        cls,
        db: AsyncSession,
        search: str | None = None,
        tactic: str | None = None,
        is_subtechnique: bool | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[MitreTechnique], int]:
        """Search and paginate ATT&CK techniques."""
        filters: list[Any] = [MitreTechnique.deprecated.is_(False)]

        if search and search.strip():
            q = f"%{search.strip()}%"
            filters.append(
                or_(
                    MitreTechnique.id.ilike(q),
                    MitreTechnique.name.ilike(q),
                    MitreTechnique.description.ilike(q),
                )
            )

        if is_subtechnique is not None:
            filters.append(MitreTechnique.is_subtechnique == is_subtechnique)

        count_stmt = select(func.count(MitreTechnique.id)).where(*filters)
        total = int((await db.execute(count_stmt)).scalar_one())

        stmt = (
            select(MitreTechnique)
            .where(*filters)
            .order_by(MitreTechnique.id.asc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = list((await db.execute(stmt)).scalars().all())

        if tactic and tactic.strip():
            t_filter = tactic.strip().lower()
            filtered_rows = [r for r in rows if t_filter in [t.lower() for t in r.tactics]]
            return filtered_rows, len(filtered_rows)

        return rows, total

    @classmethod
    async def get_technique(cls, db: AsyncSession, technique_id: str) -> MitreTechnique | None:
        """Fetch detail of a single MITRE ATT&CK technique."""
        stmt = select(MitreTechnique).where(MitreTechnique.id == technique_id.strip().upper())
        return (await db.execute(stmt)).scalar_one_or_none()

    @classmethod
    async def map_technique_to_incident(
        cls,
        db: AsyncSession,
        incident_id: uuid.UUID,
        technique_id: str,
        source: str = "analyst",
        rationale: str | None = None,
        actor: User | None = None,
        source_ip: str | None = None,
    ) -> IncidentTechnique:
        """Link a MITRE technique to an incident."""
        clean_tid = technique_id.strip().upper()

        # Verify technique exists (or create stub)
        tech = await cls.get_technique(db, clean_tid)
        if tech is None:
            tech = MitreTechnique(
                id=clean_tid,
                stix_id=f"attack-pattern--custom-{clean_tid.lower()}",
                name=f"Custom Technique {clean_tid}",
                tactics=["execution"],
                description="Custom technique mapped by analyst.",
                url=f"https://attack.mitre.org/techniques/{clean_tid.replace('.', '/')}/",
                is_subtechnique="." in clean_tid,
                parent_id=clean_tid.split(".")[0] if "." in clean_tid else None,
            )
            db.add(tech)
            await db.flush()

        # Check existing mapping
        exist_stmt = select(IncidentTechnique).where(
            IncidentTechnique.incident_id == incident_id,
            IncidentTechnique.technique_id == clean_tid,
        )
        existing = (await db.execute(exist_stmt)).scalar_one_or_none()
        if existing:
            existing.status = "suggested"
            existing.rationale = rationale or existing.rationale
            await db.commit()
            return existing

        mapping = IncidentTechnique(
            incident_id=incident_id,
            technique_id=clean_tid,
            source=source,
            status="suggested",
            rationale=rationale,
            created_by_id=actor.id if actor else None,
            created_at=utc_now(),
        )
        db.add(mapping)
        await db.commit()
        await db.refresh(mapping, ["technique"])

        await publish_realtime_event(
            "incident.technique_mapped",
            {
                "incident_id": str(incident_id),
                "technique_id": clean_tid,
                "technique_name": tech.name,
                "status": mapping.status,
            },
            required_permission="incidents:view",
        )

        if actor:
            await AuditService.record(
                db,
                action="incident.technique_mapped",
                actor=actor,
                target_type="incident",
                target_id=str(incident_id),
                outcome="success",
                source_ip=source_ip,
                details={"technique_id": clean_tid, "source": source, "rationale": rationale},
            )
            await db.commit()

        return mapping

    @classmethod
    async def confirm_technique(
        cls,
        db: AsyncSession,
        incident_id: uuid.UUID,
        technique_id: str,
        confirm: bool,
        notes: str | None = None,
        actor: User | None = None,
        source_ip: str | None = None,
    ) -> IncidentTechnique:
        """Confirm or reject a suggested MITRE ATT&CK technique mapping."""
        clean_tid = technique_id.strip().upper()
        stmt = (
            select(IncidentTechnique)
            .where(
                IncidentTechnique.incident_id == incident_id,
                IncidentTechnique.technique_id == clean_tid,
            )
            .options(selectinload(IncidentTechnique.technique))
        )
        mapping = (await db.execute(stmt)).scalar_one_or_none()
        if mapping is None:
            raise AppError(
                code="TECHNIQUE_MAPPING_NOT_FOUND",
                message=f"Technique {clean_tid} is not mapped to incident {incident_id}.",
                status_code=404,
            )

        new_status = "confirmed" if confirm else "rejected"
        mapping.status = new_status
        mapping.confirmed_by_id = actor.id if actor else None
        mapping.confirmed_at = utc_now()
        if notes:
            mapping.rationale = f"{mapping.rationale or ''}\n[Review Note]: {notes}".strip()

        await db.commit()
        await db.refresh(mapping, ["technique"])

        await publish_realtime_event(
            "incident.technique_confirmed",
            {
                "incident_id": str(incident_id),
                "technique_id": clean_tid,
                "status": new_status,
                "confirmed_by": actor.username if actor else None,
            },
            required_permission="incidents:view",
        )

        if actor:
            await AuditService.record(
                db,
                action="incident.technique_confirmed",
                actor=actor,
                target_type="incident",
                target_id=str(incident_id),
                outcome="success",
                source_ip=source_ip,
                details={
                    "technique_id": clean_tid,
                    "status": new_status,
                    "notes": notes,
                },
            )
            await db.commit()

        return mapping

    @classmethod
    async def remove_mapping(
        cls,
        db: AsyncSession,
        incident_id: uuid.UUID,
        technique_id: str,
        actor: User | None = None,
        source_ip: str | None = None,
    ) -> None:
        """Remove a technique mapping from an incident."""
        clean_tid = technique_id.strip().upper()
        stmt = delete(IncidentTechnique).where(
            IncidentTechnique.incident_id == incident_id,
            IncidentTechnique.technique_id == clean_tid,
        )
        await db.execute(stmt)
        await db.commit()

        if actor:
            await AuditService.record(
                db,
                action="incident.technique_removed",
                actor=actor,
                target_type="incident",
                target_id=str(incident_id),
                outcome="success",
                source_ip=source_ip,
                details={"technique_id": clean_tid},
            )
            await db.commit()
