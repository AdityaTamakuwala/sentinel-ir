"""VirusTotal v3 API threat intelligence adapter."""

from __future__ import annotations

import base64

import httpx

from app.core.config import get_settings
from app.models.base import utc_now
from app.services.enrichment.base import ThreatIntelProvider, ThreatIntelResult


class VirusTotalAdapter(ThreatIntelProvider):
    """Integrates with the official VirusTotal v3 REST API."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = (api_key or settings.VIRUSTOTAL_API_KEY).strip()
        self.base_url = (base_url or settings.VIRUSTOTAL_BASE_URL).rstrip("/")

    def provider_name(self) -> str:
        return "virustotal"

    def supported_ioc_types(self) -> set[str]:
        return {"ip", "domain", "sha256", "md5", "sha1", "url"}

    def is_configured(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, ioc_type: str, value: str) -> ThreatIntelResult:
        if not self.is_configured():
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="provider_unavailable",
                reputation="unknown",
                confidence_score=0,
                summary="VirusTotal API key not configured.",
                is_mock=False,
                looked_up_at=utc_now(),
            )

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        endpoint = self._build_endpoint(ioc_type, value)
        if not endpoint:
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="error",
                reputation="unknown",
                confidence_score=0,
                summary=f"Unsupported IOC type: {ioc_type}",
                is_mock=False,
                looked_up_at=utc_now(),
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(endpoint, headers=headers)

            if resp.status_code == 404:
                return ThreatIntelResult(
                    ioc_type=ioc_type,
                    value=value,
                    provider=self.provider_name(),
                    status="success",
                    reputation="unknown",
                    confidence_score=30,
                    malicious_count=0,
                    total_engines=0,
                    summary="Indicator not found in VirusTotal dataset.",
                    raw_data={},
                    source_references=[],
                    is_mock=False,
                    looked_up_at=utc_now(),
                )

            if resp.status_code == 429:
                return ThreatIntelResult(
                    ioc_type=ioc_type,
                    value=value,
                    provider=self.provider_name(),
                    status="rate_limited",
                    reputation="unknown",
                    confidence_score=0,
                    summary="VirusTotal API rate limit quota exceeded.",
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
                    summary=f"VirusTotal API HTTP error {resp.status_code}: {resp.text[:200]}",
                    is_mock=False,
                    looked_up_at=utc_now(),
                )

            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious >= 3:
                rep = "malicious"
                conf = min(99, 70 + (malicious * 2))
            elif malicious in (1, 2) or suspicious >= 2:
                rep = "suspicious"
                conf = 60
            elif harmless > 5:
                rep = "benign"
                conf = 85
            else:
                rep = "unknown"
                conf = 30

            summary = f"VirusTotal detection: {malicious}/{total} security vendors flagged as malicious."
            vt_link = f"https://www.virustotal.com/gui/search/{value}"

            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="success",
                reputation=rep,
                confidence_score=conf,
                malicious_count=malicious,
                total_engines=total,
                summary=summary,
                raw_data={"stats": stats, "reputation": attrs.get("reputation", 0)},
                source_references=[vt_link],
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
                summary=f"VirusTotal connection error: {str(exc)}",
                is_mock=False,
                looked_up_at=utc_now(),
            )

    def _build_endpoint(self, ioc_type: str, value: str) -> str | None:
        val = value.strip()
        if ioc_type == "ip":
            return f"{self.base_url}/ip_addresses/{val}"
        if ioc_type == "domain":
            return f"{self.base_url}/domains/{val}"
        if ioc_type in ("sha256", "md5", "sha1"):
            return f"{self.base_url}/files/{val}"
        if ioc_type == "url":
            url_id = base64.urlsafe_b64encode(val.encode()).decode().strip("=")
            return f"{self.base_url}/urls/{url_id}"
        return None
