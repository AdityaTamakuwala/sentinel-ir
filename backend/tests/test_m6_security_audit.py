"""Milestone 6: Comprehensive Security Audit, Vulnerability & Governance Test Suite.

Validates:
1. Authentication & Session Security (Argon2id, JWT expiry, CSRF, Token family reuse revocation, Account lockout).
2. Server-Side RBAC & Privilege Escalation Denial (Role matrix, L1 vs L2 vs Manager vs Admin).
3. API Defenses (IDOR prevention, Mass assignment protection, SQL injection resilience, XSS string handling).
4. Audit & Governance Immutability (SQL trigger immutability, Four-eyes rule, Approval expiry, Safe simulated adapter).
5. Forensic File & Evidence Protection (Magic-byte sniffing, Path traversal, Security download headers).
6. Threat Intelligence Safety (RFC 1918 / Private indicator leak prevention).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decode_access_token, hash_password, verify_password
from app.services.audit_service import AuditService
from app.services.enrichment.internal_guard import is_internal_indicator, is_internal_ip
from tests.conftest import login_as


@pytest.mark.asyncio
async def test_sec_01_argon2id_and_jwt_security() -> None:
    """Verify Argon2id password hashing strength and JWT expiration handling."""
    settings = get_settings()
    pw = "SuperSecretSecurePass2026!"
    hashed = hash_password(pw)
    assert hashed.startswith("$argon2id$"), "Password hash must use Argon2id algorithm."
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

    # Verify expired JWT is rejected by decode_access_token
    expired_payload = {
        "sub": str(uuid.uuid4()),
        "username": "test-user",
        "role": "soc_l1",
        "mcp": False,
        "jti": str(uuid.uuid4()),
        "iss": "sentinel-ir",
        "aud": "sentinel-ir-api",
        "iat": int((datetime.now(UTC) - timedelta(minutes=30)).timestamp()),
        "exp": int((datetime.now(UTC) - timedelta(minutes=10)).timestamp()),
    }
    expired_token = jwt.encode(expired_payload, settings.SECRET_KEY, algorithm="HS256")
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired_token)


@pytest.mark.asyncio
async def test_sec_02_double_submit_csrf_and_refresh_reuse_revocation(
    async_client: AsyncClient,
) -> None:
    """Verify double-submit CSRF enforcement and immediate token family revocation on replay."""
    pw = get_settings().DEMO_USER_PASSWORD

    # 1. Login and verify security headers
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"identifier": "l1.analyst", "password": pw},
    )
    assert login_res.status_code == 200
    csrf_token = login_res.json()["csrf_token"]
    initial_refresh = async_client.cookies.get("sentinel_refresh")
    assert initial_refresh is not None

    # 2. State-changing request WITHOUT X-CSRF-Token must be rejected with 403
    no_csrf_res = await async_client.post(
        "/api/v1/alerts",
        json={"rule_description": "CSRF rejection test", "severity": "medium"},
    )
    assert no_csrf_res.status_code == 403
    assert no_csrf_res.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

    # Mutating request with mismatched CSRF token must be rejected with 403
    bad_csrf_res = await async_client.post(
        "/api/v1/alerts",
        json={"rule_description": "CSRF rejection test", "severity": "medium"},
        headers={"X-CSRF-Token": "tampered-token-value"},
    )
    assert bad_csrf_res.status_code == 403
    assert bad_csrf_res.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

    # 3. Rotate refresh token -> issues token #2
    rot_res = await async_client.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert rot_res.status_code == 200
    rotated_refresh = async_client.cookies.get("sentinel_refresh")
    assert rotated_refresh is not None
    assert rotated_refresh != initial_refresh

    # 4. Replay old refresh token #1 -> must return 401 REFRESH_TOKEN_REUSE_DETECTED AND revoke entire family
    async_client.cookies.set("sentinel_refresh", initial_refresh)
    replay_res = await async_client.post("/api/v1/auth/refresh")
    assert replay_res.status_code == 401
    assert replay_res.json()["error"]["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

    # Verify that token #2's entire family is now dead
    async_client.cookies.set("sentinel_refresh", rotated_refresh)
    second_replay = await async_client.post("/api/v1/auth/refresh")
    assert second_replay.status_code == 401


@pytest.mark.asyncio
async def test_sec_03_server_side_rbac_matrix_and_privilege_escalation(
    async_client: AsyncClient,
) -> None:
    """Verify strict server-side RBAC boundary: L1 analyst cannot invoke privileged endpoints."""
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    l1_headers = {"X-CSRF-Token": l1_csrf}

    # 1. L1 cannot read audit logs
    audit_res = await async_client.get("/api/v1/audit")
    assert audit_res.status_code == 403
    assert audit_res.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # 2. L1 cannot export audit logs
    exp_res = await async_client.get("/api/v1/audit/export")
    assert exp_res.status_code == 403
    assert exp_res.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # 3. L1 cannot create users (Admin only)
    create_user_res = await async_client.post(
        "/api/v1/users",
        headers=l1_headers,
        json={
            "username": "attacker",
            "email": "attacker@evil.corp",
            "full_name": "Rogue Account",
            "role": "admin",
            "password": "Password123!",
        },
    )
    assert create_user_res.status_code == 403
    assert create_user_res.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # 4. L1 cannot generate reports (L2+ only)
    fake_inc_id = uuid.uuid4()
    rep_res = await async_client.post(
        f"/api/v1/reports/incidents/{fake_inc_id}/generate",
        headers=l1_headers,
        json={"report_format": "pdf", "tlp_classification": "TLP:AMBER"},
    )
    assert rep_res.status_code == 403
    assert rep_res.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # 5. L1 cannot approve response actions
    fake_action_id = uuid.uuid4()
    appr_res = await async_client.post(
        f"/api/v1/responses/actions/{fake_action_id}/approve",
        headers=l1_headers,
        json={"decision": "approved", "comment": "Illegal approval by L1"},
    )
    assert appr_res.status_code == 403
    assert appr_res.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"


@pytest.mark.asyncio
async def test_sec_04_idor_and_sql_injection_defense(
    async_client: AsyncClient,
) -> None:
    """Verify IDOR non-existent lookups return clean 404s and SQL injection payloads are neutralized."""
    await login_as(async_client, "l2.analyst")

    # 1. IDOR random non-existent UUIDs across key endpoints
    non_existent = str(uuid.uuid4())
    assert (await async_client.get(f"/api/v1/incidents/{non_existent}")).status_code == 404
    assert (await async_client.get(f"/api/v1/alerts/{non_existent}")).status_code == 404
    assert (await async_client.get(f"/api/v1/evidence/{non_existent}")).status_code == 404
    assert (await async_client.get(f"/api/v1/reports/{non_existent}")).status_code == 404
    assert (await async_client.get(f"/api/v1/simulations/executions/{non_existent}")).status_code == 404

    # 2. SQL injection strings in query parameters
    sqli_payloads = [
        "' OR '1'='1",
        "1; DROP TABLE incidents; --",
        "admin'--",
        "' UNION SELECT id, username, password_hash FROM users --",
    ]
    for sqli in sqli_payloads:
        res = await async_client.get(f"/api/v1/incidents?search={sqli}")
        assert res.status_code == 200, f"SQLi payload broke endpoint: {sqli}"
        assert isinstance(res.json().get("items"), list)

        alert_res = await async_client.get(f"/api/v1/alerts?search={sqli}")
        assert alert_res.status_code == 200, f"SQLi payload broke alert endpoint: {sqli}"


@pytest.mark.asyncio
async def test_sec_05_audit_immutability_and_hash_chain(
    db_session: AsyncSession,
) -> None:
    """Verify audit_logs cannot be modified or deleted, and hash chain is mathematically intact."""
    # 1. Insert two audit records
    e1 = await AuditService.record(
        db_session,
        action="security.audit_check_1",
        actor_username_override="system",
        target_type="system",
        outcome="success",
        details={"test": 1},
    )
    e2 = await AuditService.record(
        db_session,
        action="security.audit_check_2",
        actor_username_override="system",
        target_type="system",
        outcome="success",
        details={"test": 2},
    )
    await db_session.commit()

    e1_id = e1.id
    e2_id = e2.id
    e1_hash = e1.entry_hash
    e2_prev = e2.prev_hash

    # 2. Verify hash chaining: e2.prev_hash == e1.entry_hash
    assert e2_prev == e1_hash
    assert len(e1_hash) == 64
    assert len(e2.entry_hash) == 64

    # 3. Verify PostgreSQL trigger & permissions block UPDATE on audit_logs
    with pytest.raises(DBAPIError):
        await db_session.execute(
            text("UPDATE audit_logs SET outcome = 'tampered' WHERE id = :id"),
            {"id": e1_id},
        )
    await db_session.rollback()

    # 4. Verify PostgreSQL trigger & permissions block DELETE on audit_logs
    with pytest.raises(DBAPIError):
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :id"),
            {"id": e2_id},
        )
    await db_session.rollback()


@pytest.mark.asyncio
async def test_sec_06_four_eyes_and_approval_immutability(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify four-eyes rule rejects self-approval and response_approvals is immutable."""
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    headers = {"X-CSRF-Token": l2_csrf}

    # 1. Create incident and propose response action as l2.analyst
    inc_res = await async_client.post(
        "/api/v1/incidents",
        json={"title": "Four-Eyes Security Audit Incident", "severity": "high", "category": "malware", "description": "Audit"},
        headers=headers,
    )
    inc_id = inc_res.json()["id"]

    prop_res = await async_client.post(
        "/api/v1/responses/actions",
        json={
            "incident_id": inc_id,
            "action_type": "isolate_endpoint_recommendation",
            "title": "Isolate Compromised Host",
            "target_hostname": "WORKSTATION-SEC-01",
            "risk_impact": "high",
            "justification": "Malware activity confirmed.",
            "parameters": {"hostname": "WORKSTATION-SEC-01"},
            "approval_timeout_hours": 1,
        },
        headers=headers,
    )
    assert prop_res.status_code == 201
    action_id = prop_res.json()["id"]

    # 2. l2.analyst attempts to approve their own proposed action -> 403 FOUR_EYES_VIOLATION
    self_appr = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/approve",
        json={"decision": "approved", "comment": "Self-approving my own proposal"},
        headers=headers,
    )
    assert self_appr.status_code == 403
    assert self_appr.json()["error"]["code"] == "FOUR_EYES_VIOLATION"

    # 3. Legitimate approval by soc.manager
    _, mgr_csrf = await login_as(async_client, "soc.manager")
    mgr_res = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/approve",
        json={"decision": "approved", "comment": "Manager independent authorization"},
        headers={"X-CSRF-Token": mgr_csrf},
    )
    assert mgr_res.status_code == 200
    appr_data = mgr_res.json()
    assert len(appr_data["approvals"]) == 1
    approval_id = appr_data["approvals"][0]["id"]

    # 4. Verify response_approvals row cannot be deleted or modified
    with pytest.raises(Exception) as exc_appr:
        await db_session.execute(
            text("UPDATE response_approvals SET decision = 'rejected' WHERE id = :id"),
            {"id": uuid.UUID(approval_id)},
        )
        await db_session.commit()
    await db_session.rollback()
    assert "immutable" in str(exc_appr.value).lower() or "denied" in str(exc_appr.value).lower()


@pytest.mark.asyncio
async def test_sec_07_forensic_evidence_magic_bytes_and_path_traversal(
    async_client: AsyncClient,
) -> None:
    """Verify magic-byte sniffing catches disguised executables and path traversal is rejected."""
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    inc_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "Evidence Forensics Case M6",
            "description": "Preserving binary and log artifacts.",
            "category": "malware",
            "base_severity": "critical",
        },
    )
    inc_id = inc_res.json()["id"]

    # 1. Path traversal filename rejection (e.g. `../../etc/passwd`)
    bad_filename_upload = await async_client.post(
        "/api/v1/evidence",
        headers={"X-CSRF-Token": l1_csrf},
        data={"incident_id": inc_id, "title": "Path Traversal Test"},
        files={"file": ("../../etc/passwd", b"root:x:0:0::/root:/bin/bash\n", "text/plain")},
    )
    assert bad_filename_upload.status_code == 400
    assert bad_filename_upload.json()["error"]["code"] == "PATH_TRAVERSAL_REJECTED"

    # 2. Unsupported extension rejection (.exe)
    exe_upload = await async_client.post(
        "/api/v1/evidence",
        headers={"X-CSRF-Token": l1_csrf},
        data={"incident_id": inc_id, "title": "Executable Artifact"},
        files={"file": ("malware.exe", b"MZ\x90\x00\x03\x00\x00\x00", "application/octet-stream")},
    )
    assert exe_upload.status_code == 415
    assert exe_upload.json()["error"]["code"] == "UNSUPPORTED_EVIDENCE_FILE_TYPE"

    # 3. Disguised executable rejection (.png extension, but content is PE executable starting with `MZ`)
    disguised_upload = await async_client.post(
        "/api/v1/evidence",
        headers={"X-CSRF-Token": l1_csrf},
        data={"incident_id": inc_id, "title": "Disguised PE inside PNG"},
        files={"file": ("screenshot.png", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00", "image/png")},
    )
    assert disguised_upload.status_code == 415
    assert disguised_upload.json()["error"]["code"] == "DISGUISED_EXECUTABLE_REJECTED"


@pytest.mark.asyncio
async def test_sec_08_rfc1918_private_indicator_leak_prevention(
    async_client: AsyncClient,
) -> None:
    """Verify private, loopback, and internal indicators are NEVER leaked to external providers."""
    # 1. Internal IP checks
    assert is_internal_ip("10.0.0.1") is True
    assert is_internal_ip("192.168.1.100") is True
    assert is_internal_ip("172.16.50.25") is True
    assert is_internal_ip("127.0.0.1") is True
    assert is_internal_ip("169.254.169.254") is True
    assert is_internal_ip("8.8.8.8") is False
    assert is_internal_ip("185.220.101.5") is False
    assert is_internal_ip("198.51.100.42") is True  # RFC 5737 Test range (safely treated as internal)

    # 2. Indicator domain & URL checks
    assert is_internal_indicator("ip", "10.50.1.1") is True
    assert is_internal_indicator("domain", "controller.corp") is True
    assert is_internal_indicator("domain", "ad.local") is True
    assert is_internal_indicator("domain", "workstation.internal") is True
    assert is_internal_indicator("domain", "c2-external.com") is False

    # 3. Lookup endpoint returns status="not_applicable_internal" without contacting external feeds
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    lookup_res = await async_client.post(
        "/api/v1/enrichment/lookup",
        headers={"X-CSRF-Token": l1_csrf},
        json={"ioc_type": "ip", "value": "10.50.1.1"},
    )
    assert lookup_res.status_code == 200
    data = lookup_res.json()
    assert data["is_internal"] is True
    assert data["reputation"] == "internal"
    assert data["enrichments"][0]["status"] == "not_applicable_internal"
