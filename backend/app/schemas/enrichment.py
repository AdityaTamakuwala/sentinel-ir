"""Pydantic schemas for Threat Intelligence Enrichment, Indicators, and Lookups."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ThreatIndicatorLookupRequest(BaseModel):
    ioc_type: str = Field(pattern="^(ip|domain|sha256|md5|sha1|url|email)$")
    value: str = Field(min_length=1, max_length=512)
    force_refresh: bool = Field(default=False, description="Bypass 24h Redis cache to re-query providers")


class EnrichmentResultOut(BaseModel):
    id: uuid.UUID
    indicator_id: uuid.UUID
    provider: str
    status: str  # success, not_applicable_internal, provider_unavailable, rate_limited, error
    reputation: str  # unknown, benign, suspicious, malicious, clean, internal
    malicious_count: int | None = None
    total_engines: int | None = None
    confidence_score: int | None = None
    summary: str
    source_references: list[str] = Field(default_factory=list)
    is_mock: bool = Field(description="Strictly labeled true when simulated or fallback provider used")
    looked_up_at: datetime
    expires_at: datetime | None = None


class IndicatorDetailOut(BaseModel):
    id: uuid.UUID
    ioc_type: str
    value: str
    is_internal: bool
    reputation: str
    confidence: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_simulated: bool
    enrichments: list[EnrichmentResultOut] = Field(default_factory=list)


class PaginatedIndicatorsOut(BaseModel):
    items: list[IndicatorDetailOut]
    total: int
    page: int
    page_size: int


class BatchEnrichmentResponse(BaseModel):
    incident_id: uuid.UUID
    total_indicators: int
    enriched_count: int
    results: list[IndicatorDetailOut]


class ThreatIntelStatsOut(BaseModel):
    total_indicators: int
    malicious_count: int
    suspicious_count: int
    benign_count: int
    internal_count: int
    top_threats: list[IndicatorDetailOut] = Field(default_factory=list)
