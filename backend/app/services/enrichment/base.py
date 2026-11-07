"""Base interfaces and data structures for modular threat intelligence providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.base import utc_now


class ThreatIntelResult(BaseModel):
    ioc_type: str
    value: str
    provider: str
    status: str = Field(description="success, not_applicable_internal, provider_unavailable, rate_limited, error")
    reputation: str = Field(description="unknown, benign, suspicious, malicious, clean, internal")
    confidence_score: int = Field(default=0, ge=0, le=100)
    malicious_count: int | None = None
    total_engines: int | None = None
    summary: str = ""
    raw_data: dict[str, Any] = Field(default_factory=dict)
    source_references: list[str] = Field(default_factory=list)
    is_mock: bool = Field(default=True, description="Strictly labeled true when mock/simulated")
    looked_up_at: datetime = Field(default_factory=utc_now)


class ThreatIntelProvider(ABC):
    """Abstract interface that every threat intelligence integration must implement."""

    @abstractmethod
    def provider_name(self) -> str:
        """Unique provider identifier, e.g. 'virustotal', 'abuseipdb', 'alienvault_otx', 'mock'."""
        ...

    @abstractmethod
    def supported_ioc_types(self) -> set[str]:
        """Set of supported IOC types (e.g. {'ip', 'domain', 'sha256', 'md5', 'url'})."""
        ...

    @abstractmethod
    def is_configured(self) -> bool:
        """Whether valid API credentials exist for real external calls."""
        ...

    @abstractmethod
    async def lookup(self, ioc_type: str, value: str) -> ThreatIntelResult:
        """Perform lookup for the given indicator."""
        ...

