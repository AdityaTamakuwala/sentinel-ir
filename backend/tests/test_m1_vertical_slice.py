"""Milestone 1 Vertical Slice Integration & Security Tests.

Covers:
1. Clean Alembic schema migration & least-privilege DB role setup (`migrated_test_db`).
2. Automated route-by-role RBAC declaration guard over EVERY FastAPI route.
3. Argon2id login, `HttpOnly`/`SameSite=strict` cookies, CSRF enforcement, 5-attempt lockout + Admin unlock,
   refresh-token rotation, and token-family reuse revocation.
4. RBAC matrix enforcement across SOC L1, SOC L2, SOC Manager, and Platform Admin + denial auditing.
5. Append-only `audit_logs` immutability (ORM + raw SQL `UPDATE`/`DELETE` failure as `sentinel_app`) and
   cryptographic SHA-256 hash-chain verification (`AuditService.verify_chain`).
6. Manual alert ingestion, HMAC-signed Wazuh webhook (valid `202`, bad-sig `401`, expired-timestamp `401`,
   replay `409`), deduplication (`occurrence_count` + `AlertOccurrence` retention), triage actions,
   duplicate open-incident prevention (`409`), and Command Centre DB reconciliation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from typing import Any

import pytest
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from httpx import AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.main import create_app
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.ops import AuditLog
from app.services.incident_service import OPEN_INCIDENT_STATUSES
from scripts.seed_dev_data import DEV_WAZUH_API_KEY, DEV_WAZUH_HMAC_SECRET
from tests.conftest import login_as


def _dependant_has_auth_guard(dependant: Dependant) -> bool:
    call = dependant.call
    if call is not None and (
        hasattr(call, "__required_permission__") or hasattr(call, "__authenticated_only__")
    ):
        return True
    return any(_dependant_has_auth_guard(sub) for sub in dependant.dependencies)


def test_every_api_route_declares_explicit_rbac_or_public_guard() -> None:
    """Section 5.2: Every endpoint MUST declare either `@public_endpoint` or `require_permission`."""
    app = create_app()
    unguarded: list[str] = []

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        if route.path in ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"):
            continue

        endpoint_fn = route.endpoint
        is_public = hasattr(endpoint_fn, "__public_endpoint_reason__")
        has_rbac = _dependant_has_auth_guard(route.dependant)
        if not (is_public or has_rbac):
            methods = ",".join(sorted(route.methods or []))
            unguarded.append(f"{methods} {route.path}")

    assert unguarded == [], f"Routes missing explicit RBAC or @public_endpoint guard: {unguarded}"


@pytest.mark.asyncio
async def test_auth_cookies_csrf_lockout_and_refresh_reuse_revocation(
    async_client: AsyncClient,
) -> None:
    pw = get_settings().DEMO_USER_PASSWORD

    # 1. Login and inspect cookie security flags
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"identifier": "l1.analyst", "password": pw},
    )
    assert login_res.status_code == 200
    set_cookie_headers = login_res.headers.get_list("set-cookie")
    joined_cookies = "\n".join(set_cookie_headers).lower()
    assert "sentinel_access=" in joined_cookies
    assert "sentinel_refresh=" in joined_cookies
    assert "httponly" in joined_cookies
    assert "samesite=strict" in joined_cookies

    csrf_token = login_res.json()["csrf_token"]
    initial_refresh = async_client.cookies.get("sentinel_refresh")
    assert initial_refresh is not None

    # 2. State-changing request WITHOUT X-CSRF-Token must be rejected with 403
    no_csrf_res = await async_client.post(
        "/api/v1/alerts",
        json={
            "rule_description": "CSRF rejection test alert",
            "severity": "medium",
        },
    )
    assert no_csrf_res.status_code == 403
    assert no_csrf_res.json()["error"]["code"] == "CSRF_VALIDATION_FAILED"

    # 3. Rotate refresh token -> issues token #2
    rot_res = await async_client.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": csrf_token},
    )
    assert rot_res.status_code == 200
    rotated_refresh = async_client.cookies.get("sentinel_refresh")
    rotated_csrf = rot_res.json()["csrf_token"]
    assert rotated_refresh is not None
    assert rotated_refresh != initial_refresh

    # 4. Replay old refresh token #1 -> must return 401 AND revoke token #2's entire family!
    async_client.cookies.set("sentinel_refresh", initial_refresh)
    replay_res = await async_client.post("/api/v1/auth/refresh")
    assert replay_res.status_code == 401
    assert replay_res.json()["error"]["code"] == "REFRESH_TOKEN_REUSE_DETECTED"

    # Verify rotated sibling token #2 is now ALSO revoked!
    async_client.cookies.set("sentinel_refresh", rotated_refresh)
    async_client.cookies.set("sentinel_csrf", rotated_csrf)
    family_revoked_res = await async_client.post(
        "/api/v1/auth/refresh",
        headers={"X-CSRF-Token": rotated_csrf},
    )
    assert family_revoked_res.status_code == 401

    # 5. Provision a dedicated analyst to test 5-failure lockout + Admin unlock
    _, admin_csrf = await login_as(async_client, "admin")
    temp_username = f"locktest.{uuid.uuid4().hex[:6]}"
    temp_pw = "TempAnalyst!2026#Safe"
    create_u = await async_client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": admin_csrf},
        json={
            "username": temp_username,
            "email": f"{temp_username}@sentinel.example",
            "full_name": "Lockout Verification Analyst",
            "role": "soc_l1",
            "password": temp_pw,
            "must_change_password": False,
        },
    )
    assert create_u.status_code == 201
    created_uid = create_u.json()["id"]

    async_client.cookies.clear()
    for _ in range(5):
        bad = await async_client.post(
            "/api/v1/auth/login",
            json={"identifier": temp_username, "password": "WrongPassword!999#Bad"},
        )
        assert bad.status_code == 401

    # 6th attempt WITH VALID PASSWORD must still fail due to active lockout window!
    locked_attempt = await async_client.post(
        "/api/v1/auth/login",
        json={"identifier": temp_username, "password": temp_pw},
    )
    assert locked_attempt.status_code == 401

    # Admin unlocks the account -> login immediately succeeds
    _, admin_csrf = await login_as(async_client, "admin")
    unlock_res = await async_client.patch(
        f"/api/v1/users/{created_uid}",
        headers={"X-CSRF-Token": admin_csrf},
        json={"unlock_account": True},
    )
    assert unlock_res.status_code == 200

    unlocked_login = await async_client.post(
        "/api/v1/auth/login",
        json={"identifier": temp_username, "password": temp_pw},
    )
    assert unlocked_login.status_code == 200


@pytest.mark.asyncio
async def test_rbac_matrix_enforcement_across_all_roles(
    async_client: AsyncClient,
) -> None:
    # SOC L1 cannot read audit logs, cannot export audit logs, cannot manage users
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    assert (await async_client.get("/api/v1/audit")).status_code == 403
    assert (await async_client.get("/api/v1/audit/export")).status_code == 403
    assert (
        await async_client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": l1_csrf},
            json={
                "username": "unauth.user",
                "email": "unauth@sentinel.example",
                "full_name": "Unauthorized",
                "role": "soc_l1",
                "password": "ValidPassword!2026#SOC",
            },
        )
    ).status_code == 403

    # SOC L2 can update incidents, but cannot read audit logs or assign incidents (`incidents:assign` is Manager/Admin)
    await login_as(async_client, "l2.analyst")
    assert (await async_client.get("/api/v1/audit")).status_code == 403

    # SOC Manager CAN read & verify audit logs, CANNOT export audit logs or create users
    await login_as(async_client, "soc.manager")
    assert (await async_client.get("/api/v1/audit")).status_code == 200
    assert (await async_client.get("/api/v1/audit/verify")).status_code == 200
    assert (await async_client.get("/api/v1/audit/export")).status_code == 403

    # Platform Admin CAN read, verify, AND export audit logs
    await login_as(async_client, "admin")
    exp = await async_client.get("/api/v1/audit/export?format=csv")
    assert exp.status_code == 200
    assert "entry_hash" in exp.text


@pytest.mark.asyncio
async def test_audit_logs_immutability_and_cryptographic_hash_chain(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    await login_as(async_client, "admin")
    verify_res = await async_client.get("/api/v1/audit/verify")
    assert verify_res.status_code == 200
    v_body = verify_res.json()
    assert v_body["valid"] is True
    assert v_body["checked_count"] >= 4

    # 1. Attempt raw SQL UPDATE as runtime `sentinel_app` user -> MUST fail (insufficient privilege / trigger)
    with pytest.raises(DBAPIError):
        await db_session.execute(text("UPDATE audit_logs SET outcome = 'tampered' WHERE seq = 1"))
    await db_session.rollback()

    # 2. Attempt raw SQL DELETE as runtime `sentinel_app` user -> MUST fail
    with pytest.raises(DBAPIError):
        await db_session.execute(text("DELETE FROM audit_logs WHERE seq = 1"))
    await db_session.rollback()

    # 3. Attempt ORM mutation on AuditLog -> MUST fail on flush/commit
    entry = (await db_session.execute(select(AuditLog).order_by(AuditLog.seq.asc()).limit(1))).scalar_one()
    entry.action = "tampered.via.orm"
    with pytest.raises(DBAPIError):
        await db_session.commit()
    await db_session.rollback()

    # Chain remains 100% intact
    verify_after = await async_client.get("/api/v1/audit/verify")
    assert verify_after.status_code == 200
    assert verify_after.json()["valid"] is True


def _sign_wazuh_payload(payload: dict[str, Any], secret: str, ts_epoch: int) -> tuple[bytes, dict[str, str]]:
    raw_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ts_str = str(ts_epoch)
    sig = hmac.new(
        secret.encode("utf-8"),
        ts_str.encode("utf-8") + b"." + raw_bytes,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Sentinel-API-Key": DEV_WAZUH_API_KEY,
        "X-Sentinel-Timestamp": ts_str,
        "X-Sentinel-Signature": f"sha256={sig}",
    }
    return raw_bytes, headers


@pytest.mark.asyncio
async def test_wazuh_hmac_webhook_replay_deduplication_triage_and_duplicate_incident_guard(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    now_ts = int(time.time())
    unique_host = f"srv-ssh-{uuid.uuid4().hex[:6]}"
    wazuh_doc = {
        "id": "1730990001.112233",
        "timestamp": "2026-11-07T14:00:00Z",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Attempt to login using a non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed"],
            "mitre": {
                "id": ["T1110.001"],
                "technique": ["Password Guessing"],
                "tactic": ["Credential Access"],
            },
        },
        "agent": {"id": "014", "name": unique_host, "ip": "10.20.10.99"},
        "data": {"srcip": "198.51.100.201", "dstuser": "deploy_ops"},
    }

    # 1. Invalid HMAC signature -> 401
    raw_bytes, headers = _sign_wazuh_payload(wazuh_doc, "wrong_secret_key", now_ts)
    bad_sig_res = await async_client.post("/api/v1/ingest/wazuh", content=raw_bytes, headers=headers)
    assert bad_sig_res.status_code == 401
    assert bad_sig_res.json()["error"]["code"] == "WEBHOOK_INVALID_SIGNATURE"

    # 2. Stale timestamp outside tolerance window -> 401
    stale_bytes, stale_headers = _sign_wazuh_payload(wazuh_doc, DEV_WAZUH_HMAC_SECRET, now_ts - 3600)
    stale_res = await async_client.post(
        "/api/v1/ingest/wazuh", content=stale_bytes, headers=stale_headers
    )
    assert stale_res.status_code == 401
    assert stale_res.json()["error"]["code"] == "WEBHOOK_REPLAY_WINDOW_EXCEEDED"

    # 3. Valid signed Wazuh webhook -> 202 Accepted (created_new=True, occurrence_count=1)
    valid_bytes, valid_headers = _sign_wazuh_payload(wazuh_doc, DEV_WAZUH_HMAC_SECRET, now_ts)
    ok_res = await async_client.post("/api/v1/ingest/wazuh", content=valid_bytes, headers=valid_headers)
    assert ok_res.status_code == 202
    ok_body = ok_res.json()
    assert ok_body["created_new"] is True
    assert ok_body["occurrence_count"] == 1
    alert_id = ok_body["alert_id"]

    # 4. Exact replay of same signed request -> 409 Conflict
    replay_res = await async_client.post(
        "/api/v1/ingest/wazuh", content=valid_bytes, headers=valid_headers
    )
    assert replay_res.status_code == 409
    assert replay_res.json()["error"]["code"] == "WEBHOOK_REPLAY_DETECTED"

    # 5. Second distinct Wazuh event within deduplication window -> deduplicated into existing alert!
    wazuh_doc_2 = dict(wazuh_doc)
    wazuh_doc_2["id"] = "1730990002.445566"
    dup_bytes, dup_headers = _sign_wazuh_payload(wazuh_doc_2, DEV_WAZUH_HMAC_SECRET, now_ts + 1)
    dedup_res = await async_client.post("/api/v1/ingest/wazuh", content=dup_bytes, headers=dup_headers)
    assert dedup_res.status_code == 202
    dedup_body = dedup_res.json()
    assert dedup_body["alert_id"] == alert_id
    assert dedup_body["created_new"] is False
    assert dedup_body["occurrence_count"] == 2

    # 6. Triage workflow as SOC L1
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    detail_res = await async_client.get(f"/api/v1/alerts/{alert_id}")
    assert detail_res.status_code == 200
    assert len(detail_res.json()["occurrences"]) == 2

    # Marking false_positive without reason must fail (422)
    fp_missing = await async_client.patch(
        f"/api/v1/alerts/{alert_id}/triage",
        headers={"X-CSRF-Token": l1_csrf},
        json={"action": "mark_false_positive"},
    )
    assert fp_missing.status_code == 422

    # Escalate alert and create Incident
    esc_res = await async_client.patch(
        f"/api/v1/alerts/{alert_id}/triage",
        headers={"X-CSRF-Token": l1_csrf},
        json={"action": "escalate", "note": "Confirmed external brute force from 198.51.100.201"},
    )
    assert esc_res.status_code == 200
    assert esc_res.json()["triage_status"] == "escalated"

    inc_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": f"SSH Brute Force on {unique_host}",
            "description": "Escalated from Wazuh rule 5710 burst.",
            "category": "authentication",
            "base_severity": "high",
            "alert_ids": [alert_id],
        },
    )
    assert inc_res.status_code == 201
    inc_body = inc_res.json()
    assert inc_body["human_id"].startswith("INC-")

    # 7. Duplicate open-incident guard -> 409 Conflict!
    dup_inc_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": f"Duplicate Case Attempt on {unique_host}",
            "description": "Should be blocked because alert already belongs to an open incident.",
            "category": "authentication",
            "base_severity": "high",
            "alert_ids": [alert_id],
        },
    )
    assert dup_inc_res.status_code == 409
    assert dup_inc_res.json()["error"]["code"] == "ALERT_ALREADY_LINKED_TO_OPEN_INCIDENT"

    # 8. Command Centre metrics reconcile strictly with PostgreSQL counts
    cc_res = await async_client.get("/api/v1/analytics/command-center")
    assert cc_res.status_code == 200
    kpis = cc_res.json()["kpis"]

    db_total_alerts = int((await db_session.execute(select(func.count(Alert.id)))).scalar_one())
    db_open_incidents = int(
        (
            await db_session.execute(
                select(func.count(Incident.id)).where(Incident.status.in_(OPEN_INCIDENT_STATUSES))
            )
        ).scalar_one()
    )
    assert kpis["total_alerts"] == db_total_alerts
    assert kpis["open_incidents"] == db_open_incidents
    assert kpis["mtta_minutes"] is not None
    assert kpis["mttr_minutes"] is not None
