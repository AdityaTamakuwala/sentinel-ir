"""Integration and security tests for Milestone 4: Playbooks, Executions, and Four-Eyes Approvals."""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.automation import Playbook, ResponseAction
from app.models.base import utc_now
from app.models.incident import Incident
from app.models.user import User
from app.services.playbook.adapter import SimulatedResponseAdapter
from app.services.playbook.engine import PlaybookEngine
from app.services.playbook.loader import PlaybookLoader
from tests.conftest import login_as

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent.parent / "playbooks"


@pytest.mark.asyncio
async def test_declarative_yaml_playbooks_loading_and_validation(db_session: AsyncSession) -> None:
    """Verify all 6 YAML playbooks parse cleanly, pass Pydantic schema validation, and sync to DB."""
    yaml_files = sorted(PLAYBOOKS_DIR.glob("*.yaml"))
    assert len(yaml_files) >= 6, f"Expected at least 6 playbooks in {PLAYBOOKS_DIR}, found {len(yaml_files)}"

    expected_slugs = {
        "phishing-investigation",
        "endpoint-malware-containment",
        "brute-force-credential-stuffing",
        "unauthorized-access-investigation",
        "ransomware-rapid-response",
        "data-exfiltration-triage",
    }

    found_slugs = set()
    for yf in yaml_files:
        definition, raw_dict = PlaybookLoader.parse_yaml_definition(yf.read_text(encoding="utf-8"))
        assert definition.id.startswith("PB-")
        assert len(definition.steps) >= 3
        found_slugs.add(definition.slug)

    for slug in expected_slugs:
        assert slug in found_slugs, f"Missing required playbook slug: {slug}"

    # Sync all playbooks to database
    synced = await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)
    assert len(synced) >= 6

    # Verify database persistence
    stmt = select(Playbook)
    res = await db_session.execute(stmt)
    db_playbooks = res.scalars().all()
    assert len(db_playbooks) >= 6


@pytest.mark.asyncio
async def test_playbook_execution_automated_steps_and_dry_run(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify automated step execution, dry-run simulation mode, and idempotency key guard."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)

    cookies, csrf = await login_as(async_client, "l2.analyst")

    # 1. Trigger dry run of endpoint-malware-containment
    payload = {
        "parameters": {
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "process_name": "mimikatz.exe",
            "process_pid": 1337,
            "target_hostname": "WORKSTATION-09",
        },
        "is_dry_run": True,
        "idempotency_key": "test-dryrun-key-001",
    }

    resp = await async_client.post(
        "/api/v1/playbooks/endpoint-malware-containment/execute",
        json=payload,
        cookies=cookies,
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "COMPLETED"
    assert data["is_dry_run"] is True
    assert len(data["steps"]) >= 4

    # 2. Idempotency test: repeating with same idempotency key returns existing execution
    resp2 = await async_client.post(
        "/api/v1/playbooks/endpoint-malware-containment/execute",
        json=payload,
        cookies=cookies,
        headers={"X-CSRF-Token": csrf},
    )
    assert resp2.status_code == 200
    assert resp2.json()["id"] == data["id"]


@pytest.mark.asyncio
async def test_waiting_approval_persistence_and_four_eyes_enforcement(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify WAITING_APPROVAL state persistence, strict four-eyes rejection, role-tier guard, and resume."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)

    # 1. Create a test incident
    l2_cookies, l2_csrf = await login_as(async_client, "l2.analyst")
    inc_resp = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Suspected Phishing Campaign targeting Finance",
            "base_severity": "high",
            "category": "phishing",
            "description": "Employee reported high-risk email containing external credential-harvesting link.",
        },
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert inc_resp.status_code == 201, inc_resp.text
    incident_id = inc_resp.json()["id"]

    # 2. Trigger PB-001 (Phishing Investigation) as l2.analyst
    exec_resp = await async_client.post(
        "/api/v1/playbooks/phishing-investigation/execute",
        json={
            "incident_id": incident_id,
            "parameters": {
                "sender_email": "attacker@evil-domain.com",
                "sender_domain": "evil-domain.com",
                "suspicious_url": "http://evil-domain.com/login",
                "affected_user": "target_employee",
            },
            "is_dry_run": False,
        },
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert exec_resp.status_code == 200, exec_resp.text
    exec_data = exec_resp.json()

    # The playbook halts at step_disable_user (require_approval: true)
    assert exec_data["status"] == "WAITING_APPROVAL"
    action_id = exec_data["waiting_response_action_id"]
    assert action_id is not None

    # Verify action details
    act_resp = await async_client.get(
        f"/api/v1/responses/actions/{action_id}",
        cookies=l2_cookies,
    )
    assert act_resp.status_code == 200
    action_data = act_resp.json()
    assert action_data["status"] == "PENDING_APPROVAL"
    assert action_data["risk_impact"] == "high"
    assert action_data["target_username"] == "target_employee"

    # 3. FOUR-EYES TEST: l2.analyst (requester) attempts to self-approve
    self_appr = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/approve",
        json={"decision": "approved", "comment": "Self-approving my own containment action"},
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert self_appr.status_code == 403
    assert self_appr.json()["error"]["code"] == "FOUR_EYES_VIOLATION"

    # 4. ROLE TIER TEST: l1.analyst attempts to approve a response action
    l1_cookies, l1_csrf = await login_as(async_client, "l1.analyst")
    l1_appr = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/approve",
        json={"decision": "approved", "comment": "L1 analyst approving action"},
        cookies=l1_cookies,
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert l1_appr.status_code == 403
    assert l1_appr.json()["error"]["code"] == "INSUFFICIENT_PERMISSIONS"

    # 5. SUCCESSFUL APPROVAL: soc.manager approves
    mgr_cookies, mgr_csrf = await login_as(async_client, "soc.manager")
    mgr_appr = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/approve",
        json={"decision": "approved", "comment": "Manager approved suspension of compromised account"},
        cookies=mgr_cookies,
        headers={"X-CSRF-Token": mgr_csrf},
    )
    assert mgr_appr.status_code == 200, mgr_appr.text
    mgr_data = mgr_appr.json()
    assert mgr_data["status"] in ("APPROVED", "COMPLETED")
    assert len(mgr_data["approvals"]) == 1
    assert mgr_data["approvals"][0]["decision"] == "approved"

    # 6. RESUMPTION TEST: Verify playbook resumed and reached COMPLETED
    resumed_exec_resp = await async_client.get(
        f"/api/v1/playbooks/executions/{exec_data['id']}",
        cookies=mgr_cookies,
    )
    assert resumed_exec_resp.status_code == 200
    resumed_data = resumed_exec_resp.json()
    assert resumed_data["status"] == "COMPLETED"
    assert resumed_data["completed_at"] is not None


@pytest.mark.asyncio
async def test_response_action_rejection_halts_playbook(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify rejecting an approval halts execution with status FAILED and records reason."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)

    l2_cookies, l2_csrf = await login_as(async_client, "l2.analyst")

    # Create incident
    inc_resp = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Brute-force auth spike",
            "base_severity": "medium",
            "category": "credential_compromise",
            "description": "External IP failed 500 login attempts.",
        },
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    incident_id = inc_resp.json()["id"]

    # Trigger PB-003 (Brute-Force Credential Stuffing)
    exec_resp = await async_client.post(
        "/api/v1/playbooks/brute-force-credential-stuffing/execute",
        json={
            "incident_id": incident_id,
            "parameters": {
                "source_ip": "198.51.100.25",
                "target_username": "svc_accounting",
                "failed_attempts": 500,
            },
        },
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    exec_data = exec_resp.json()
    assert exec_data["status"] == "WAITING_APPROVAL"
    action_id = exec_data["waiting_response_action_id"]

    # Manager rejects the perimeter IP block (since L2 requested it)
    mgr_cookies, mgr_csrf = await login_as(async_client, "soc.manager")
    rej_resp = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/reject",
        json={"decision": "rejected", "comment": "IP belongs to authorized vendor proxy, block rejected."},
        cookies=mgr_cookies,
        headers={"X-CSRF-Token": mgr_csrf},
    )
    assert rej_resp.status_code == 200
    rej_data = rej_resp.json()
    assert rej_data["status"] == "REJECTED"

    # Verify execution halted with FAILED status
    check_exec = await async_client.get(
        f"/api/v1/playbooks/executions/{exec_data['id']}",
        cookies=mgr_cookies,
    )
    assert check_exec.status_code == 200
    exec_final = check_exec.json()
    assert exec_final["status"] == "FAILED"
    assert "rejected" in (exec_final["error_message"] or "").lower()


@pytest.mark.asyncio
async def test_response_action_approval_expiration(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify expired response actions cannot be approved and are swept by expiry engine."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)

    l1_cookies, l1_csrf = await login_as(async_client, "l1.analyst")
    l2_cookies, l2_csrf = await login_as(async_client, "l2.analyst")

    # 1. Propose action manually
    inc_stmt = select(Incident).limit(1)
    incident = (await db_session.execute(inc_stmt)).scalar_one()

    prop_resp = await async_client.post(
        "/api/v1/responses/actions",
        json={
            "incident_id": str(incident.id),
            "action_type": "block_ip_recommendation",
            "title": "Perimeter IP Block for Malicious Scanner",
            "justification": "Port scan observed against DMZ web servers",
            "risk_impact": "low",
            "target_indicator": "203.0.113.88",
            "timeout_hours": 1,
        },
        cookies=l1_cookies,
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert prop_resp.status_code == 201, prop_resp.text
    action_id = prop_resp.json()["id"]

    # 2. Artificially backdate expires_at in DB
    act_stmt = select(ResponseAction).where(ResponseAction.id == action_id)
    act_obj = (await db_session.execute(act_stmt)).scalar_one()
    act_obj.expires_at = utc_now() - datetime.timedelta(hours=2)
    await db_session.commit()

    # 3. Attempt approval after expiration -> should fail with ACTION_EXPIRED
    appr_resp = await async_client.post(
        f"/api/v1/responses/actions/{action_id}/approve",
        json={"decision": "approved", "comment": "Late approval attempt"},
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert appr_resp.status_code == 400
    assert appr_resp.json()["error"]["code"] == "ACTION_EXPIRED"

    # 4. Engine sweep expires stale actions
    engine = PlaybookEngine(db_session)
    expired_count = await engine.expire_stale_actions()
    assert expired_count >= 1
    await db_session.commit()

    # Verify action status is now EXPIRED
    chk_resp = await async_client.get(
        f"/api/v1/responses/actions/{action_id}",
        cookies=l2_cookies,
    )
    assert chk_resp.status_code == 200
    assert chk_resp.json()["status"] == "EXPIRED"


@pytest.mark.asyncio
async def test_safe_simulated_response_adapter_telemetry(db_session: AsyncSession) -> None:
    """Verify SimulatedResponseAdapter tags is_simulated=True and produces safe structured telemetry."""
    user_stmt = select(User).limit(1)
    user = (await db_session.execute(user_stmt)).scalar_one()

    inc_stmt = select(Incident).limit(1)
    incident = (await db_session.execute(inc_stmt)).scalar_one()

    adapter = SimulatedResponseAdapter()
    assert adapter.get_adapter_name() == "simulated"

    action = ResponseAction(
        incident_id=incident.id,
        action_type="isolate_endpoint_recommendation",
        title="Quarantine Host SEC-01",
        justification="Ransomware lateral movement prevention",
        parameters_json={"hostname": "SEC-01"},
        risk_impact="critical",
        status="APPROVED",
        adapter_name="simulated",
        is_simulated=True,
        requested_by_id=user.id,
        expires_at=utc_now() + datetime.timedelta(hours=24),
    )

    telemetry = await adapter.execute(action, incident)
    assert telemetry["is_simulated"] is True
    assert telemetry["status"] == "success"
    assert "simulated_command" in telemetry
    assert "wazuh-control isolate-host" in telemetry["simulated_command"]
    assert "network_rules_applied" in telemetry


@pytest.mark.asyncio
async def test_sixth_playbook_pure_yaml_extensibility(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Prove that PB-006 (Data Exfiltration Triage) functions purely from YAML with zero Python changes."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)

    l2_cookies, l2_csrf = await login_as(async_client, "l2.analyst")

    # Get PB-006 details
    pb_resp = await async_client.get(
        "/api/v1/playbooks/data-exfiltration-triage",
        cookies=l2_cookies,
    )
    assert pb_resp.status_code == 200, pb_resp.text
    pb_data = pb_resp.json()
    assert pb_data["name"] == "Anomalous Data Exfiltration Triage & Block"
    assert pb_data["step_count"] >= 4

    # Dry-run execute PB-006
    exec_resp = await async_client.post(
        "/api/v1/playbooks/data-exfiltration-triage/execute",
        json={
            "parameters": {
                "destination_ip": "198.51.100.99",
                "user_account": "exfil_user",
                "bytes_transferred": 500000000,
            },
            "is_dry_run": True,
        },
        cookies=l2_cookies,
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert exec_resp.status_code == 200, exec_resp.text
    data = exec_resp.json()
    assert data["status"] == "COMPLETED"
    assert data["is_dry_run"] is True
