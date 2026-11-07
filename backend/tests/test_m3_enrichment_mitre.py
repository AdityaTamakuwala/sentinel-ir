"""Milestone 3 Integration & Security Tests:
1. RFC 1918 internal IP & intranet domain safety guard (never transmitted externally).
2. Threat intelligence enrichment (Mock & Adapters, Redis 24h caching, rate-limiting, batch incident enrichment).
3. Pinned offline MITRE ATT&CK STIX 2.1 loader and 14-tactic Enterprise Matrix navigator.
4. Incident technique mapping lifecycle (suggested -> confirmed/rejected with L2+ RBAC guard and audit logs).
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient

from app.db.session import get_redis_client
from app.services.enrichment.internal_guard import is_internal_indicator, is_internal_ip
from app.services.enrichment.rate_limiter import check_provider_rate_limit
from tests.conftest import login_as


@pytest.mark.asyncio
async def test_internal_rfc1918_and_domain_safety_filter(
    async_client: AsyncClient,
) -> None:
    """Validate that private IPs and intranet assets are NEVER sent externally and return not_applicable_internal."""
    # 1. Unit assertions on internal IP ranges
    assert is_internal_ip("10.0.4.15") is True
    assert is_internal_ip("172.16.100.5") is True
    assert is_internal_ip("192.168.1.254") is True
    assert is_internal_ip("127.0.0.1") is True
    assert is_internal_ip("169.254.169.254") is True
    assert is_internal_ip("8.8.8.8") is False
    assert is_internal_ip("185.220.101.5") is False

    assert is_internal_indicator("ip", "10.50.1.1") is True
    assert is_internal_indicator("domain", "ad01.bank.corp") is True
    assert is_internal_indicator("domain", "workstation.local") is True
    assert is_internal_indicator("url", "http://192.168.1.1/admin") is True
    assert is_internal_indicator("domain", "evil-c2.net") is False

    # 2. API endpoint lookup with internal indicator
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    resp = await async_client.post(
        "/api/v1/enrichment/lookup",
        headers={"X-CSRF-Token": l1_csrf},
        json={"ioc_type": "ip", "value": "10.20.40.31"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_internal"] is True
    assert data["reputation"] == "internal"
    assert data["confidence"] == 100
    assert len(data["enrichments"]) >= 1
    assert data["enrichments"][0]["status"] == "not_applicable_internal"
    assert "RFC 1918" in data["enrichments"][0]["summary"]


@pytest.mark.asyncio
async def test_threat_intelligence_enrichment_and_redis_cache(
    async_client: AsyncClient,
) -> None:
    """Validate on-demand lookup, Redis caching, batch incident enrichment, and stats."""
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # 1. Lookup external malicious indicator (Tor exit node)
    tor_ip = "185.220.101.5"
    lookup_res = await async_client.post(
        "/api/v1/enrichment/lookup",
        headers={"X-CSRF-Token": l1_csrf},
        json={"ioc_type": "ip", "value": tor_ip},
    )
    assert lookup_res.status_code == 200
    tor_data = lookup_res.json()
    assert tor_data["value"] == tor_ip
    assert tor_data["is_internal"] is False
    assert tor_data["reputation"] == "malicious"
    assert tor_data["confidence"] >= 90
    assert len(tor_data["enrichments"]) >= 1
    first_enrich = tor_data["enrichments"][0]
    assert first_enrich["status"] == "success"
    assert first_enrich["is_mock"] is True  # Mock provider in testing

    # 2. Verify Redis cache key was set
    redis = get_redis_client()
    cache_key = f"sentinel:enrichment:ip:{tor_ip}"
    cached_val = await redis.get(cache_key)
    assert cached_val is not None
    assert "malicious" in str(cached_val)

    # 3. Second lookup uses cache (returns 200 instantly)
    second_lookup = await async_client.post(
        "/api/v1/enrichment/lookup",
        headers={"X-CSRF-Token": l1_csrf},
        json={"ioc_type": "ip", "value": tor_ip, "force_refresh": False},
    )
    assert second_lookup.status_code == 200
    assert second_lookup.json()["reputation"] == "malicious"

    # 4. Lookup benign public DNS
    dns_res = await async_client.post(
        "/api/v1/enrichment/lookup",
        headers={"X-CSRF-Token": l1_csrf},
        json={"ioc_type": "ip", "value": "1.1.1.1"},
    )
    assert dns_res.status_code == 200
    assert dns_res.json()["reputation"] == "benign"

    # 5. Create an incident with indicators and test batch enrichment
    inc_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "C2 Threat Intel Enrichment Case",
            "description": "Verifying multi-indicator batch enrichment on case creation.",
            "category": "command_and_control",
            "base_severity": "high",
        },
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    batch_res = await async_client.post(
        f"/api/v1/enrichment/incidents/{inc_id}/enrich",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert batch_res.status_code == 200
    batch_data = batch_res.json()
    assert batch_data["incident_id"] == inc_id

    # 6. Indicators table and threat intelligence stats
    list_res = await async_client.get("/api/v1/enrichment/indicators")
    assert list_res.status_code == 200
    indicators = list_res.json()["items"]
    assert len(indicators) >= 2

    stats_res = await async_client.get("/api/v1/enrichment/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_indicators"] >= 2
    assert stats["malicious_count"] >= 1


@pytest.mark.asyncio
async def test_redis_token_bucket_rate_limiter() -> None:
    """Verify Redis sliding-window token-bucket rate limiter rejects bursts above quota."""
    redis = get_redis_client()
    provider = f"test_provider_{uuid.uuid4().hex[:6]}"

    # Allowed 3 requests per 60s
    assert await check_provider_rate_limit(redis, provider, max_requests=3, window_seconds=60) is True
    assert await check_provider_rate_limit(redis, provider, max_requests=3, window_seconds=60) is True
    assert await check_provider_rate_limit(redis, provider, max_requests=3, window_seconds=60) is True

    # 4th request in the same window must be rate-limited (False)
    assert await check_provider_rate_limit(redis, provider, max_requests=3, window_seconds=60) is False


@pytest.mark.asyncio
async def test_mitre_stix_offline_matrix_and_technique_search(
    async_client: AsyncClient,
) -> None:
    """Verify official MITRE ATT&CK STIX 2.1 offline loader, matrix aggregation, and search."""
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # 1. Fetch full 14-tactic Enterprise Matrix
    matrix_res = await async_client.get("/api/v1/mitre/matrix")
    assert matrix_res.status_code == 200
    matrix = matrix_res.json()
    tactics = matrix["tactics"]
    assert len(tactics) == 14
    expected_shortnames = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]
    actual_shortnames = [t["shortname"] for t in tactics]
    assert actual_shortnames == expected_shortnames
    assert matrix["total_techniques"] > 500

    # 2. Search for techniques by keyword
    search_res = await async_client.get("/api/v1/mitre/techniques?search=PowerShell")
    assert search_res.status_code == 200
    items = search_res.json()["items"]
    assert any("T1059" in item["id"] for item in items)

    # 3. Fetch single technique details
    tech_res = await async_client.get("/api/v1/mitre/techniques/T1059.001")
    assert tech_res.status_code == 200
    tech = tech_res.json()
    assert tech["id"] == "T1059.001"
    assert "PowerShell" in tech["name"]
    assert tech["is_subtechnique"] is True
    assert tech["parent_id"] == "T1059"
    assert "execution" in tech["tactics"]
    assert len(tech["url"]) > 10


@pytest.mark.asyncio
async def test_mitre_incident_mapping_lifecycle_and_rbac(
    async_client: AsyncClient,
) -> None:
    """Verify incident technique mapping, L1 suggestion, and L2+ confirmation enforcement."""
    # 1. Create a fresh test incident as L1
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    inc_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "MITRE ATT&CK Mapping Case",
            "description": "Validating technique mapping and confirmation governance.",
            "category": "credential_compromise",
            "base_severity": "high",
        },
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    # 2. Suggest MITRE technique mapping as L1 -> status is 'suggested'
    map_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/mitre",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "technique_id": "T1078",
            "rationale": "Analyst observed usage of compromised service account.",
            "source": "analyst",
        },
    )
    assert map_res.status_code == 201
    mapping = map_res.json()
    assert mapping["technique_id"] == "T1078"
    assert mapping["status"] == "suggested"

    # 3. L1 analyst tries to confirm technique mapping -> must be forbidden (403, requires mitre:confirm)
    l1_confirm = await async_client.post(
        f"/api/v1/incidents/{inc_id}/mitre/T1078/confirm",
        headers={"X-CSRF-Token": l1_csrf},
        json={"confirm": True, "notes": "L1 trying to confirm technique"},
    )
    assert l1_confirm.status_code == 403

    # 4. L2 analyst confirms technique mapping -> succeeds!
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    l2_confirm = await async_client.post(
        f"/api/v1/incidents/{inc_id}/mitre/T1078/confirm",
        headers={"X-CSRF-Token": l2_csrf},
        json={"confirm": True, "notes": "Confirmed valid accounts abused for lateral movement."},
    )
    assert l2_confirm.status_code == 200
    confirmed = l2_confirm.json()
    assert confirmed["status"] == "confirmed"
    assert confirmed["confirmed_by"] is not None
    assert confirmed["confirmed_at"] is not None

    # 5. Verify incident detail reflects confirmed technique
    detail_res = await async_client.get(f"/api/v1/incidents/{inc_id}")
    assert detail_res.status_code == 200
    inc_techniques = detail_res.json()["mitre_techniques"]
    t1078_entry = next((t for t in inc_techniques if t["technique_id"] == "T1078"), None)
    assert t1078_entry is not None
    assert t1078_entry["status"] == "confirmed"

    # 6. Remove technique mapping as L2
    delete_res = await async_client.delete(
        f"/api/v1/incidents/{inc_id}/mitre/T1078",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert delete_res.status_code == 200
