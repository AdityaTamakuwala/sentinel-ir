"""Realistic deterministic Mock Threat Intelligence Provider.

Used for local labs, automated test suites, and demo environments.
All responses are strictly labeled with `is_mock: True`.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.models.base import utc_now
from app.services.enrichment.base import ThreatIntelProvider, ThreatIntelResult

_KNOWN_IOC_DATABASE: dict[str, dict[str, Any]] = {
    # Tor exit nodes / known C2 IPs
    "185.220.101.5": {
        "reputation": "malicious",
        "confidence_score": 96,
        "malicious_count": 48,
        "total_engines": 88,
        "summary": "Confirmed Tor exit node and known Cobalt Strike C2 egress relay.",
        "references": ["https://metrics.torproject.org", "https://abuseipdb.com/check/185.220.101.5"],
    },
    "45.33.32.156": {
        "reputation": "suspicious",
        "confidence_score": 74,
        "malicious_count": 14,
        "total_engines": 85,
        "summary": "High volume of SSH brute force and port reconnaissance activity observed in last 7 days.",
        "references": ["https://abuseipdb.com/check/45.33.32.156"],
    },
    "198.51.100.23": {
        "reputation": "malicious",
        "confidence_score": 92,
        "malicious_count": 52,
        "total_engines": 90,
        "summary": "Associated with FIN7 financial malware dropper infrastructure.",
        "references": ["https://otx.alienvault.com/indicator/ip/198.51.100.23"],
    },
    # Benign public DNS & infrastructure
    "8.8.8.8": {
        "reputation": "benign",
        "confidence_score": 99,
        "malicious_count": 0,
        "total_engines": 92,
        "summary": "Google Public DNS Anycast Resolver.",
        "references": ["https://dns.google"],
    },
    "1.1.1.1": {
        "reputation": "benign",
        "confidence_score": 99,
        "malicious_count": 0,
        "total_engines": 92,
        "summary": "Cloudflare Anycast DNS Resolver.",
        "references": ["https://1.1.1.1"],
    },
    # Malicious domains
    "c2-stealer.darknet-relay.org": {
        "reputation": "malicious",
        "confidence_score": 98,
        "malicious_count": 39,
        "total_engines": 74,
        "summary": "Dynamic DNS domain hosting RedLine Stealer payload delivery endpoint.",
        "references": ["https://virustotal.com/gui/domain/c2-stealer.darknet-relay.org"],
    },
    "bad-actor-c2.net": {
        "reputation": "malicious",
        "confidence_score": 95,
        "malicious_count": 42,
        "total_engines": 80,
        "summary": "Known adversary command and control rendezvous domain.",
        "references": ["https://otx.alienvault.com/indicator/domain/bad-actor-c2.net"],
    },
    "evil-update.com": {
        "reputation": "malicious",
        "confidence_score": 88,
        "malicious_count": 29,
        "total_engines": 76,
        "summary": "Typosquatted domain distributing fake browser update malware.",
        "references": ["https://virustotal.com/gui/domain/evil-update.com"],
    },
    # Benign domains
    "microsoft.com": {
        "reputation": "benign",
        "confidence_score": 100,
        "malicious_count": 0,
        "total_engines": 94,
        "summary": "Microsoft Corporation corporate domain.",
        "references": ["https://microsoft.com"],
    },
    "google.com": {
        "reputation": "benign",
        "confidence_score": 100,
        "malicious_count": 0,
        "total_engines": 94,
        "summary": "Google LLC primary search and services domain.",
        "references": ["https://google.com"],
    },
    # File hashes
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "reputation": "malicious",
        "confidence_score": 100,
        "malicious_count": 68,
        "total_engines": 72,
        "summary": "WannaCry ransomware PE32 binary variant. Ransom note, Killswitch domain query, SMB propagation.",
        "references": ["https://virustotal.com/gui/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"],
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "reputation": "suspicious",
        "confidence_score": 90,
        "malicious_count": 58,
        "total_engines": 65,
        "summary": "Standard EICAR Anti-Virus Test File signature.",
        "references": ["https://eicar.org"],
    },
}


class MockThreatIntelProvider(ThreatIntelProvider):
    """Deterministic mock provider providing high-fidelity SOC analyst enrichment."""

    def provider_name(self) -> str:
        return "mock_intel"

    def supported_ioc_types(self) -> set[str]:
        return {"ip", "domain", "sha256", "md5", "sha1", "url", "email"}

    def is_configured(self) -> bool:
        return True

    async def lookup(self, ioc_type: str, value: str) -> ThreatIntelResult:
        cleaned = value.strip().lower()
        if cleaned in _KNOWN_IOC_DATABASE:
            entry = _KNOWN_IOC_DATABASE[cleaned]
            return ThreatIntelResult(
                ioc_type=ioc_type,
                value=value,
                provider=self.provider_name(),
                status="success",
                reputation=entry["reputation"],
                confidence_score=entry["confidence_score"],
                malicious_count=entry["malicious_count"],
                total_engines=entry["total_engines"],
                summary=f"[MOCK] {entry['summary']}",
                raw_data={"database_match": True, **entry},
                source_references=entry.get("references", []),
                is_mock=True,
                looked_up_at=utc_now(),
            )

        # Deterministic hash generation for any novel query
        seed = int(hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:8], 16)
        mod = seed % 100
        if mod > 80:
            rep = "malicious"
            conf = 80 + (mod % 20)
            malicious = 25 + (mod % 40)
            summary = "[MOCK] Adversary infrastructure identified via automated behavioral correlation heuristics."
        elif mod > 60:
            rep = "suspicious"
            conf = 55 + (mod % 25)
            malicious = 4 + (mod % 10)
            summary = "[MOCK] Low-confidence anomalies observed across multiple threat feeds."
        elif mod > 20:
            rep = "benign"
            conf = 70 + (mod % 30)
            malicious = 0
            summary = "[MOCK] No malicious telemetry observed across threat intelligence databases."
        else:
            rep = "unknown"
            conf = 20
            malicious = 0
            summary = "[MOCK] Insufficient global telemetry to establish indicator reputation."

        total_engines = 70 + (seed % 25)
        return ThreatIntelResult(
            ioc_type=ioc_type,
            value=value,
            provider=self.provider_name(),
            status="success",
            reputation=rep,
            confidence_score=conf,
            malicious_count=malicious,
            total_engines=total_engines,
            summary=summary,
            raw_data={"deterministic_seed": seed, "reputation": rep},
            source_references=["https://sentinel-ir.internal/mock-threat-intel"],
            is_mock=True,
            looked_up_at=utc_now(),
        )

