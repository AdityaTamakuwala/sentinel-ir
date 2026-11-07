"""Internal indicator safety guard.

RFC 1918 private IPv4 addresses, loopback, link-local, private IPv6, and intranet domains
MUST NEVER be sent to external threat intelligence APIs (VirusTotal, AbuseIPDB, OTX).
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from app.services.enrichment.base import ThreatIntelResult

_INTERNAL_DOMAIN_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".home",
    ".test",
    ".localhost",
    ".priv",
    "bank.corp",
)


def is_internal_ip(ip_str: str) -> bool:
    """Return True if `ip_str` is private, loopback, link-local, multicast, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
        )
    except ValueError:
        return False


def is_internal_domain(domain_str: str) -> bool:
    """Return True if `domain_str` matches internal/intranet naming conventions."""
    d = domain_str.strip().lower()
    if d in ("localhost", "local") or d.endswith(".localdomain"):
        return True
    return any(d == s.lstrip(".") or d.endswith(s) for s in _INTERNAL_DOMAIN_SUFFIXES)


def is_internal_indicator(ioc_type: str, value: str) -> bool:
    """Check if an indicator represents an internal or intranet asset."""
    val = value.strip().lower()
    t = ioc_type.strip().lower()

    if t == "ip":
        return is_internal_ip(val)
    if t == "domain":
        return is_internal_domain(val)
    if t == "url":
        try:
            parsed = urlparse(val)
            host = parsed.hostname or ""
            return is_internal_ip(host) or is_internal_domain(host)
        except Exception:
            return False
    return False


def make_internal_intel_result(ioc_type: str, value: str) -> ThreatIntelResult:
    """Construct standard safe internal skip result."""
    return ThreatIntelResult(
        ioc_type=ioc_type,
        value=value,
        provider="internal_filter",
        status="not_applicable_internal",
        reputation="internal",
        confidence_score=100,
        malicious_count=0,
        total_engines=0,
        summary="Internal RFC 1918 / intranet asset — external lookup skipped to prevent data leakage.",
        raw_data={"internal": True, "reason": "rfc1918_or_intranet_domain"},
        source_references=[],
        is_mock=False,
    )

