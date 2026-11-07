"""AbuseIPDB v2 API threat intelligence adapter."""

from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.models.base import utc_now
from app.services.enrichment.base import ThreatIntelProvider, ThreatIntelResult


class AbuseIPDBAdapter(ThreatIntelProvider):
    """Integrates with AbuseIPDB v2 API for IP reputation lookups."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = (api_key or settings.ABUSEIPDB_API_KEY).strip()
        self.base_url = (base_url or settings.ABUSEIPDB_BASE_URL).rstrip("/")

    def provider_name(self) -> str:
        return "abuseipdb"

    def supported_ioc_types(self) -> set[str]:
        return {"ip"}

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, ioc_type: str, value: str) -> ThreatIntelResult:
        if ioc_type != "ip":
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="error",
                reputation="unknown",
                confidence_score=0,
                summary="AbuseIPDB only supports IP address lookups.",
                is_mock=False,
                looked_up_at=utc_now(),
            )

        if not self.is_configured():
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="provider_unavailable",
                reputation="unknown",
                confidence_score=0,
                summary="AbuseIPDB API key not configured.",
                is_mock=False,
                looked_up_at=utc_now(),
            )

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": value.strip(),
            "maxAgeInDays": "90",
            "verbose": "",
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.base_url}/check", headers=headers, params=params)

            if resp.status_code == 429:
                return ThreatIntelResult(
                    ioc_type=ioc_type,
                    value=value,
                    provider=self.provider_name(),
                    status="rate_limited",
                    reputation="unknown",
                    confidence_score=0,
                    summary="AbuseIPDB daily API quota exceeded.",
                    is_mock=False,
                    looked_up_at=utc_now(),
                )

            if resp.status_code != 200:
                return ThreatIntelResult(
                    ioc_type=ioc_type,
                    value=value,
                    provider=self.provider_name(),
                    status="error",
                    reputation="unknown",
                    confidence_score=0,
                    summary=f"AbuseIPDB error {resp.status_code}: {resp.text[:200]}",
                    is_mock=False,
                    looked_up_at=utc_now(),
                )

            data = resp.json().get("data", {})
            abuse_score = int(data.get("abuseConfidenceScore", 0))
            total_reports = int(data.get("totalReports", 0))
            country_code = data.get("countryCode", "Unknown")
            usage_type = data.get("usageType", "Unknown")
            is_tor = bool(data.get("isTor", False))

            if abuse_score >= 50 or is_tor:
                rep = "malicious"
                conf = max(abuse_score, 85 if is_tor else 70)
            elif abuse_score >= 15 or total_reports > 2:
                rep = "suspicious"
                conf = 60
            else:
                rep = "benign"
                conf = 85

            tor_note = " [Tor Exit Node]" if is_tor else ""
            summary = (
                f"AbuseIPDB Confidence Score: {abuse_score}% ({total_reports} reports, "
                f"Country: {country_code}, Usage: {usage_type}){tor_note}"
            )

            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="success",
                reputation=rep,
                confidence_score=conf,
                malicious_count=total_reports,
                total_engines=100,
                summary=summary,
                raw_data=data,
                source_references=[f"https://www.abuseipdb.com/check/{value}"],
                is_mock=False,
                looked_up_at=utc_now(),
            )

        except Exception as exc:
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="error",
                reputation="unknown",
                confidence_score=0,
                summary=f"AbuseIPDB connection error: {str(exc)}",
                is_mock=False,
                looked_up_at=utc_now(),
            )

