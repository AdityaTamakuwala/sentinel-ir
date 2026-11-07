"""AlienVault OTX v1 API threat intelligence adapter."""

from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.models.base import utc_now
from app.services.enrichment.base import ThreatIntelProvider, ThreatIntelResult


class AlienVaultOTXAdapter(ThreatIntelProvider):
    """Integrates with AlienVault Open Threat Exchange (OTX) API."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = (api_key or settings.OTX_API_KEY).strip()
        self.base_url = (base_url or settings.OTX_BASE_URL).rstrip("/")

    def provider_name(self) -> str:
        return "alienvault_otx"

    def supported_ioc_types(self) -> set[str]:
        return {"ip", "domain", "sha256", "md5"}

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
                summary="AlienVault OTX API key not configured.",
                is_mock=False,
                looked_up_at=utc_now(),
            )

        headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

        section = self._ioc_section(ioc_type)
        if not section:
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="error",
                reputation="unknown",
                confidence_score=0,
                summary=f"OTX does not support IOC type: {ioc_type}",
                is_mock=False,
                looked_up_at=utc_now(),
            )

        endpoint = f"{self.base_url}/indicators/{section}/{value.strip()}/general"

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
                    summary="No threat pulses found in AlienVault OTX.",
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
                    summary="AlienVault OTX rate limit exceeded.",
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
                    summary=f"AlienVault OTX error {resp.status_code}: {resp.text[:200]}",
                    is_mock=False,
                    looked_up_at=utc_now(),
                )

            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = int(pulse_info.get("count", 0))
            pulses = pulse_info.get("pulses", [])
            adversary = data.get("adversary", "")

            tags: set[str] = set()
            references: list[str] = [f"https://otx.alienvault.com/indicator/{section}/{value}"]
            for p in pulses[:5]:
                for tag in p.get("tags", []):
                    tags.add(tag)
                for ref in p.get("references", []):
                    if ref and ref.startswith("http"):
                        references.append(ref)

            if pulse_count >= 5 or adversary:
                rep = "malicious"
                conf = min(98, 75 + pulse_count * 2)
            elif pulse_count >= 1:
                rep = "suspicious"
                conf = 65
            else:
                rep = "benign"
                conf = 80

            adv_note = f" (Adversary: {adversary})" if adversary else ""
            summary = (
                f"AlienVault OTX: Flagged in {pulse_count} threat pulse(s){adv_note}. "
                f"Tags: {', '.join(sorted(tags)[:6]) if tags else 'None'}"
            )

            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="success",
                reputation=rep,
                confidence_score=conf,
                malicious_count=pulse_count,
                total_engines=100,
                summary=summary,
                raw_data={"pulse_count": pulse_count, "adversary": adversary, "tags": list(tags)},
                source_references=references[:5],
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
                summary=f"AlienVault OTX connection error: {str(exc)}",
                is_mock=False,
                looked_up_at=utc_now(),
            )

    def _ioc_section(self, ioc_type: str) -> str | None:
        if ioc_type == "ip":
            return "IPv4"
        if ioc_type == "domain":
            return "domain"
        if ioc_type in ("sha256", "md5"):
            return "file"
        return None

