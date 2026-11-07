"""Pydantic schemas for MITRE ATT&CK Matrix, techniques, and incident mappings."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class MitreTechniqueOut(BaseModel):
    id: str = Field(description="MITRE ATT&CK Technique ID, e.g., T1059.001")
    stix_id: str = Field(description="Unique STIX 2.1 object identifier")
    name: str = Field(description="Technique display name")
    tactics: list[str] = Field(default_factory=list, description="Associated tactic shortnames")
    description: str = Field(default="", description="Summary of adversary behavior")
    detection: str = Field(default="", description="Guidance for detecting this technique")
    mitigations: list[dict[str, str]] = Field(default_factory=list, description="Mitigations")
    platforms: list[str] = Field(default_factory=list, description="Target platforms (e.g. Linux, Windows)")
    url: str = Field(default="", description="Official MITRE ATT&CK web page URL")
    is_subtechnique: bool = Field(default=False)
    parent_id: str | None = Field(default=None)
    attack_version: str = Field(default="15.1")
    deprecated: bool = Field(default=False)
    incident_count: int = Field(default=0, description="Active mapped incidents in SENTINEL IR")


class MitreTacticColumn(BaseModel):
    tactic_id: str = Field(description="MITRE Tactic ID, e.g. TA0001")
    name: str = Field(description="Tactic Name, e.g. Initial Access")
    shortname: str = Field(description="Tactic slug, e.g. initial-access")
    description: str = Field(default="")
    techniques: list[MitreTechniqueOut] = Field(default_factory=list)


class MitreMatrixOut(BaseModel):
    tactics: list[MitreTacticColumn]
    total_techniques: int
    total_mapped_incidents: int
    version: str = "15.1"


class MitreTechniqueSearchOut(BaseModel):
    items: list[MitreTechniqueOut]
    total: int
    page: int
    page_size: int


class IncidentMitreMapRequest(BaseModel):
    technique_id: str = Field(min_length=3, max_length=24, description="e.g. T1059 or T1059.001")
    rationale: str | None = Field(default=None, max_length=1000)
    source: str = Field(default="analyst", pattern="^(alert_metadata|enrichment|playbook_rule|analyst)$")


class IncidentMitreConfirmRequest(BaseModel):
    confirm: bool = Field(description="True to confirm, False to reject")
    notes: str | None = Field(default=None, max_length=500)


class IncidentTechniqueOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    technique_id: str
    technique_name: str
    tactics: list[str]
    source: str
    status: str  # suggested, confirmed, rejected
    rationale: str | None
    created_by: str | None
    confirmed_by: str | None
    confirmed_at: datetime | None
    created_at: datetime
