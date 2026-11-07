"""Milestone 2 Integration & Security Tests: Incident Lifecycle, Optimistic Concurrency,
Forensic Evidence (Streaming SHA-256, Magic Sniffing, Path Traversal, Chain of Custody),
and Server-Sent Events (SSE) Live Stream with Last-Event-ID Replay.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.services.event_bus import publish_realtime_event
from tests.conftest import login_as


@pytest.mark.asyncio
async def test_incident_state_machine_allowed_and_forbidden_transitions(
    async_client: AsyncClient,
) -> None:
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # 1. Create a fresh test incident (starts in NEW status, version 1)
    create_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "State Machine Validation Case",
            "description": "Validating full lifecycle progression and illegal transition barriers.",
            "category": "malware",
            "base_severity": "high",
        },
    )
    assert create_res.status_code == 201
    inc = create_res.json()
    inc_id = inc["id"]
    assert inc["status"] == "NEW"
    ver = inc["version"]

    # 2. Forbidden direct jump from NEW -> CLOSED (must fail with 409)
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    bad_jump = await async_client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers={"X-CSRF-Token": l2_csrf},
        json={
            "target_status": "CLOSED",
            "expected_version": ver,
            "closure_category": "false_positive",
            "closure_justification": "Attempting invalid direct closure from NEW status.",
        },
    )
    assert bad_jump.status_code == 409
    assert bad_jump.json()["error"]["code"] == "ILLEGAL_STATE_TRANSITION"

    # 3. Valid progression: NEW -> TRIAGED -> INVESTIGATING -> CONTAINMENT -> ERADICATION -> RECOVERY -> RESOLVED
    transitions = [
        ("TRIAGED", "Triaged by L1"),
        ("INVESTIGATING", "Beginning host analysis"),
        ("CONTAINMENT", "Host isolated"),
        ("ERADICATION", "Malicious registry key removed"),
        ("RECOVERY", "Restoring network connectivity"),
        ("RESOLVED", "All telemetry normal"),
    ]
    for target_st, reason_text in transitions:
        res = await async_client.post(
            f"/api/v1/incidents/{inc_id}/transition",
            headers={"X-CSRF-Token": l2_csrf},
            json={
                "target_status": target_st,
                "expected_version": ver,
                "reason": reason_text,
            },
        )
        assert res.status_code == 200, f"Transition to {target_st} failed: {res.text}"
        inc = res.json()
        assert inc["status"] == target_st
        ver = inc["version"]

    # 4. RESOLVED -> CLOSED without justification must fail (422)
    missing_justification = await async_client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers={"X-CSRF-Token": l2_csrf},
        json={
            "target_status": "CLOSED",
            "expected_version": ver,
            "closure_category": "true_positive_mitigated",
            "closure_justification": "short",  # min 10 chars
        },
    )
    assert missing_justification.status_code == 422

    # 5. RESOLVED -> CLOSED with valid justification as L2 -> succeeds!
    closed_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers={"X-CSRF-Token": l2_csrf},
        json={
            "target_status": "CLOSED",
            "expected_version": ver,
            "closure_category": "true_positive_mitigated",
            "closure_justification": "Malware successfully purged, endpoint clean, and hashes blocklisted.",
        },
    )
    assert closed_res.status_code == 200
    inc = closed_res.json()
    assert inc["status"] == "CLOSED"
    assert inc["closed_at"] is not None
    ver = inc["version"]

    # 6. Reopening CLOSED incident as SOC L1 must be forbidden (403)
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    l1_reopen = await async_client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "target_status": "INVESTIGATING",
            "expected_version": ver,
            "reason": "L1 trying to reopen closed case",
        },
    )
    assert l1_reopen.status_code == 403
    assert l1_reopen.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # 7. Reopening CLOSED incident as SOC L2 with reason -> succeeds!
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    reopen_ok = await async_client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        headers={"X-CSRF-Token": l2_csrf},
        json={
            "target_status": "INVESTIGATING",
            "expected_version": ver,
            "reason": "Recurrence of beaconing activity observed on adjacent host.",
        },
    )
    assert reopen_ok.status_code == 200
    inc = reopen_ok.json()
    assert inc["status"] == "INVESTIGATING"
    assert inc["closed_at"] is None  # Reset closure timestamp


@pytest.mark.asyncio
async def test_optimistic_concurrency_control(
    async_client: AsyncClient,
) -> None:
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    create_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "Optimistic Concurrency Case",
            "description": "Testing version conflict on simultaneous modifications.",
            "category": "credential_compromise",
            "base_severity": "medium",
        },
    )
    assert create_res.status_code == 201
    inc = create_res.json()
    inc_id = inc["id"]
    initial_ver = inc["version"]

    # First update: L2 changes title with expected_version = initial_ver -> succeeds (version increments)
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    first_update = await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"X-CSRF-Token": l2_csrf},
        json={
            "title": "Updated Title First",
            "expected_version": initial_ver,
        },
    )
    assert first_update.status_code == 200
    assert first_update.json()["version"] == initial_ver + 1

    # Second concurrent update with stale expected_version -> 409 OPTIMISTIC_LOCK_CONFLICT!
    stale_update = await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers={"X-CSRF-Token": l2_csrf},
        json={
            "title": "Concurrent Conflicting Title",
            "expected_version": initial_ver,
        },
    )
    assert stale_update.status_code == 409
    assert stale_update.json()["error"]["code"] == "OPTIMISTIC_LOCK_CONFLICT"


@pytest.mark.asyncio
async def test_evidence_security_sniffing_path_traversal_and_chain_of_custody(
    async_client: AsyncClient,
) -> None:
    _, l1_csrf = await login_as(async_client, "l1.analyst")
    inc_res = await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "Evidence Forensics Case",
            "description": "Preserving binary and log artifacts.",
            "category": "malware",
            "base_severity": "critical",
        },
    )
    inc_id = inc_res.json()["id"]

    # 1. Path traversal filename rejection (e.g. `../../etc/passwd` or `foo/bar.txt`)
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

    # 3. Disguised executable rejection (extension is .png, but content starts with Windows PE `MZ` or Linux ELF `\x7fELF`)
    disguised_upload = await async_client.post(
        "/api/v1/evidence",
        headers={"X-CSRF-Token": l1_csrf},
        data={"incident_id": inc_id, "title": "Disguised PE inside PNG"},
        files={"file": ("screenshot.png", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00", "image/png")},
    )
    assert disguised_upload.status_code == 415
    assert disguised_upload.json()["error"]["code"] == "DISGUISED_EXECUTABLE_REJECTED"

    # 4. Valid PNG upload with genuine PNG signature
    png_bytes = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
        b"\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    valid_upload = await async_client.post(
        "/api/v1/evidence",
        headers={"X-CSRF-Token": l1_csrf},
        data={
            "incident_id": inc_id,
            "title": "C2 Memory Dump Screenshot",
            "description": "Visual evidence of suspicious beaconing window.",
            "evidence_type": "screenshot",
        },
        files={"file": ("c2_window.png", png_bytes, "image/png")},
    )
    assert valid_upload.status_code == 201
    ev_data = valid_upload.json()
    ev_id = ev_data["id"]
    expected_sha256 = ev_data["sha256_hash"]
    assert len(expected_sha256) == 64
    assert ev_data["current_version"] == 1
    assert ev_data["status"] == "active"

    # Verify initial custody log entry was created
    detail_res = await async_client.get(f"/api/v1/evidence/{ev_id}")
    assert detail_res.status_code == 200
    custody = detail_res.json()["custody_logs"]
    assert any(c["action"] == "uploaded" for c in custody)

    # 5. Cryptographic SHA-256 verification endpoint
    verify_res = await async_client.post(
        f"/api/v1/evidence/{ev_id}/verify",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert verify_res.status_code == 200
    v_body = verify_res.json()
    assert v_body["valid"] is True
    assert v_body["expected_sha256"] == expected_sha256
    assert v_body["computed_sha256"] == expected_sha256

    # 6. Secure download with attachment, nosniff, and sandbox headers
    dl_res = await async_client.get(f"/api/v1/evidence/{ev_id}/download")
    assert dl_res.status_code == 200
    assert dl_res.headers["content-disposition"].startswith("attachment;")
    assert dl_res.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in dl_res.headers.get("content-security-policy", "")
    assert dl_res.content == png_bytes

    # Verify custody log recorded download
    custody_after_dl = (await async_client.get(f"/api/v1/evidence/{ev_id}")).json()["custody_logs"]
    assert any(c["action"] == "downloaded" for c in custody_after_dl)

    # 7. Upload new immutable version (v2)
    v2_res = await async_client.post(
        f"/api/v1/evidence/{ev_id}/versions",
        headers={"X-CSRF-Token": l1_csrf},
        data={"notes": "Enhanced resolution crop"},
        files={"file": ("c2_window_v2.png", png_bytes, "image/png")},
    )
    assert v2_res.status_code == 201
    assert v2_res.json()["current_version"] == 2
    assert len(v2_res.json()["versions"]) == 2

    # 8. Soft-withdraw evidence (requires L2/Manager/Admin)
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    withdraw_res = await async_client.post(
        f"/api/v1/evidence/{ev_id}/withdraw",
        headers={"X-CSRF-Token": l2_csrf},
        json={"reason": "Superceded by raw network packet capture artifact."},
    )
    assert withdraw_res.status_code == 200
    assert withdraw_res.json()["status"] == "withdrawn"

    # Attempting to add a new version to a withdrawn artifact must be rejected (409)
    blocked_ver = await async_client.post(
        f"/api/v1/evidence/{ev_id}/versions",
        headers={"X-CSRF-Token": l2_csrf},
        files={"file": ("c2_window_v3.png", png_bytes, "image/png")},
    )
    assert blocked_ver.status_code == 409
    assert blocked_ver.json()["error"]["code"] == "EVIDENCE_WITHDRAWN"


@pytest.mark.asyncio
async def test_server_sent_events_stream_and_last_event_id_replay(
    async_client: AsyncClient,
) -> None:
    # 1. Connect without auth -> 401
    async_client.cookies.clear()
    unauth_stream = await async_client.get("/api/v1/events/stream?once=true")
    assert unauth_stream.status_code == 401

    # 2. Login as SOC L1 and publish an event to the Redis event bus
    await login_as(async_client, "l1.analyst")
    ev_id = await publish_realtime_event(
        "incident.created",
        {"human_id": "INC-TEST-SSE", "severity": "high"},
        required_permission="incidents:view",
    )
    assert ev_id is not None

    # 3. Request SSE stream with `last_event_id = ev_id - 1` -> verifies replay buffer catches up!
    stream_res = await async_client.get(
        f"/api/v1/events/stream?once=true&last_event_id={ev_id - 1}"
    )
    assert stream_res.status_code == 200
    assert "text/event-stream" in stream_res.headers["content-type"]
    body_text = stream_res.text
    assert "event: connected" in body_text
    assert f"id: {ev_id}" in body_text
    assert "INC-TEST-SSE" in body_text


@pytest.mark.asyncio
async def test_notifications_centre_lifecycle(
    async_client: AsyncClient,
) -> None:
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # Creating a critical incident automatically sends a high-priority Notification to SOC L2
    await async_client.post(
        "/api/v1/incidents",
        headers={"X-CSRF-Token": l1_csrf},
        json={
            "title": "Critical Notification Test Incident",
            "description": "Triggering notification dispatch.",
            "category": "malware",
            "base_severity": "critical",
        },
    )

    # Check notification as SOC L2
    _, l2_csrf = await login_as(async_client, "l2.analyst")
    notif_res = await async_client.get("/api/v1/notifications")
    assert notif_res.status_code == 200
    data = notif_res.json()
    assert len(data["items"]) >= 1
    target_notif = data["items"][0]
    notif_id = target_notif["id"]

    # Mark single notification as read
    read_res = await async_client.post(
        f"/api/v1/notifications/{notif_id}/read",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert read_res.status_code == 200
    assert read_res.json()["is_read"] is True

    # Mark all read
    mark_all = await async_client.post(
        "/api/v1/notifications/read-all",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert mark_all.status_code == 204
    after = (await async_client.get("/api/v1/notifications")).json()
    assert after["unread_count"] == 0
