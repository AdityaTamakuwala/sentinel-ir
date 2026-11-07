"""MITRE ATT&CK Matrix, Techniques, and Incident Mapping API Endpoints."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import PermissionCode, require_permission
from app.db.session import get_db_session
from app.models.investigation import IncidentTechnique, MitreTechnique
from app.models.user import User
from app.schemas.mitre import (
    IncidentMitreConfirmRequest,
    IncidentMitreMapRequest,
    IncidentTechniqueOut,
    MitreMatrixOut,
    MitreTechniqueOut,
    MitreTechniqueSearchOut,
)
from app.services.mitre_service import MitreService

router = APIRouter(tags=["MITRE ATT&CK Framework"])


def _to_technique_out(t: MitreTechnique, incident_count: int = 0) -> MitreTechniqueOut:
    return MitreTechniqueOut(
        id=t.id,
        stix_id=t.stix_id,
        name=t.name,
        tactics=t.tactics,
        description=t.description,
        detection=t.detection,
        mitigations=t.mitigations,
        platforms=t.platforms,
        url=t.url,
        is_subtechnique=t.is_subtechnique,
        parent_id=t.parent_id,
        attack_version=t.attack_version,
        deprecated=t.deprecated,
        incident_count=incident_count,
    )


def _to_mapping_out(m: IncidentTechnique) -> IncidentTechniqueOut:
    return IncidentTechniqueOut(
        id=m.id,
        incident_id=m.incident_id,
        technique_id=m.technique_id,
        technique_name=m.technique.name if m.technique else m.technique_id,
        tactics=m.technique.tactics if m.technique else [],
        source=m.source,
        status=m.status,
        rationale=m.rationale,
        created_by=str(m.created_by_id) if m.created_by_id else None,
        confirmed_by=str(m.confirmed_by_id) if m.confirmed_by_id else None,
        confirmed_at=m.confirmed_at,
        created_at=m.created_at,
    )


@router.get("/mitre/matrix", response_model=MitreMatrixOut)
async def get_mitre_matrix(
    actor: User = Depends(require_permission(PermissionCode.MITRE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> MitreMatrixOut:
    """Retrieve the full 14-tactic Enterprise ATT&CK matrix with mapped incident coverage counts."""
    data = await MitreService.get_matrix(db)
    return MitreMatrixOut(**data)


@router.get("/mitre/techniques", response_model=MitreTechniqueSearchOut)
async def list_mitre_techniques(
    search: str | None = Query(default=None, max_length=128),
    tactic: str | None = Query(default=None, max_length=64),
    is_subtechnique: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    actor: User = Depends(require_permission(PermissionCode.MITRE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> MitreTechniqueSearchOut:
    """Search and paginate MITRE ATT&CK techniques."""
    rows, total = await MitreService.search_techniques(
        db,
        search=search,
        tactic=tactic,
        is_subtechnique=is_subtechnique,
        page=page,
        page_size=page_size,
    )
    return MitreTechniqueSearchOut(
        items=[_to_technique_out(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/mitre/techniques/{technique_id}", response_model=MitreTechniqueOut)
async def get_mitre_technique_detail(
    technique_id: str,
    actor: User = Depends(require_permission(PermissionCode.MITRE_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> MitreTechniqueOut:
    """Fetch complete details, mitigations, and detection guidance for a specific technique."""
    tech = await MitreService.get_technique(db, technique_id)
    if tech is None:
        raise HTTPException(status_code=404, detail=f"MITRE Technique {technique_id} not found.")
    return _to_technique_out(tech)


@router.post("/mitre/load", status_code=status.HTTP_200_OK)
async def reload_mitre_stix(
    actor: User = Depends(require_permission(PermissionCode.INTEGRATIONS_MANAGE)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Offline reload of the pinned official MITRE ATT&CK STIX 2.1 dataset."""
    count = await MitreService.load_mitre_stix(db)
    return {"status": "success", "techniques_loaded": count, "version": "15.1"}


@router.post("/incidents/{incident_id}/mitre", response_model=IncidentTechniqueOut, status_code=status.HTTP_201_CREATED)
async def map_technique_to_incident(
    incident_id: uuid.UUID,
    payload: IncidentMitreMapRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.MITRE_MAP)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentTechniqueOut:
    """Link a MITRE ATT&CK technique to an incident with 'suggested' status."""
    mapping = await MitreService.map_technique_to_incident(
        db,
        incident_id=incident_id,
        technique_id=payload.technique_id,
        source=payload.source,
        rationale=payload.rationale,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return _to_mapping_out(mapping)


@router.post("/incidents/{incident_id}/mitre/{technique_id}/confirm", response_model=IncidentTechniqueOut)
async def confirm_technique_mapping(
    incident_id: uuid.UUID,
    technique_id: str,
    payload: IncidentMitreConfirmRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.MITRE_CONFIRM)),
    db: AsyncSession = Depends(get_db_session),
) -> IncidentTechniqueOut:
    """Confirm or reject a suggested MITRE technique mapping. Requires SOC L2 or higher."""
    mapping = await MitreService.confirm_technique(
        db,
        incident_id=incident_id,
        technique_id=technique_id,
        confirm=payload.confirm,
        notes=payload.notes,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return _to_mapping_out(mapping)


@router.delete("/incidents/{incident_id}/mitre/{technique_id}")
async def remove_technique_mapping(
    incident_id: uuid.UUID,
    technique_id: str,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.MITRE_CONFIRM)),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str]:
    """Remove a MITRE technique mapping from an incident."""
    await MitreService.remove_mapping(
        db,
        incident_id=incident_id,
        technique_id=technique_id,
        actor=actor,
        source_ip=request.client.host if request.client else None,
    )
    return {"status": "deleted", "technique_id": technique_id}
