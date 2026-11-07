"""Integration and security tests for Milestone 5: Simulation Scenarios, Reporting & SOC Analytics."""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.automation import PlaybookExecution, ResponseAction
from app.models.base import utc_now
from app.models.incident import Incident
from app.models.investigation import Indicator
from app.services.notification_dispatcher import NotificationDispatcher
from app.services.playbook.loader import PlaybookLoader
from app.services.simulation.scenarios import SCENARIOS_CATALOG, list_available_scenarios
from tests.conftest import login_as

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent.parent / "playbooks"


@pytest.mark.asyncio
async def test_simulation_scenarios_catalog_and_metadata(
    async_client: AsyncClient,
) -> None:
    """Verify all 7 reproducible scenarios are registered with valid metadata and reachable via API."""
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # 1. Check Python catalog directly
    scenarios = list_available_scenarios()
    assert len(scenarios) == 7

    expected_slugs = {
        "s01_brute_force",
        "s02_endpoint_malware",
        "s03_phishing_campaign",
        "s04_privilege_escalation",
        "s05_ransomware_activity",
        "s06_data_exfiltration",
        "s07_multi_stage_attack",
    }
    assert set(SCENARIOS_CATALOG.keys()) == expected_slugs

    # 2. Query API listing
    res = await async_client.get(
        "/api/v1/simulations/scenarios",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 7

    for item in data:
        assert item["slug"] in expected_slugs
        assert item["scenario_id"].startswith("SIM-SCN-")
        assert len(item["expected_mitre_techniques"]) >= 1
        assert item["associated_playbook_slug"]
        assert len(item["expected_response_actions"]) >= 1
        assert item["alerts_count"] >= 1

    # 3. Query specific scenario detail
    det_res = await async_client.get(
        "/api/v1/simulations/scenarios/s01_brute_force",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert det_res.status_code == 200
    det = det_res.json()
    assert det["slug"] == "s01_brute_force"
    assert len(det["synthetic_indicators"]) >= 1
    assert det["synthetic_indicators"][0]["value"] == "198.51.100.45"
    assert len(det["alerts"]) >= 1

    # 4. Unknown scenario returns 404
    bad_res = await async_client.get(
        "/api/v1/simulations/scenarios/unknown_scenario",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert bad_res.status_code == 404
    assert bad_res.json()["error"]["code"] == "SCENARIO_NOT_FOUND"


@pytest.mark.asyncio
async def test_simulation_launch_full_chain_and_execution_tracking(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify scenario launches through real ingestion, creates incident, enriches IOCs, and triggers playbook."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)

    _, l2_csrf = await login_as(async_client, "l2.analyst")

    # Launch S-01 in full_chain mode
    launch_res = await async_client.post(
        "/api/v1/simulations/scenarios/s01_brute_force/launch",
        headers={"X-CSRF-Token": l2_csrf},
        json={"mode": "full_chain"},
    )
    assert launch_res.status_code == 200
    exec_data = launch_res.json()
    assert exec_data["status"] == "COMPLETED"
    assert exec_data["mode"] == "full_chain"
    assert exec_data["scenario_slug"] == "s01_brute_force"
    assert exec_data["alerts_count"] >= 1
    assert exec_data["incident_id"] is not None
    assert exec_data["playbook_execution_id"] is not None
    assert exec_data["is_simulated"] is True

    # Verify execution log steps
    steps = [log["step"] for log in exec_data["execution_log"]]
    assert "INITIALIZATION" in steps
    assert "ALERT_INGESTION" in steps
    assert "INCIDENT_CREATION" in steps
    assert "PLAYBOOK_EXECUTION" in steps
    assert "COMPLETION" in steps

    incident_id = uuid.UUID(exec_data["incident_id"])
    playbook_exec_id = uuid.UUID(exec_data["playbook_execution_id"])

    # Verify created incident in database
    inc_stmt = select(Incident).where(Incident.id == incident_id)
    inc = (await db_session.execute(inc_stmt)).scalar_one()
    assert inc.is_simulated is True
    assert "[SIMULATION]" in inc.title
    assert inc.severity == "high"

    # Verify synthetic indicator persistence and is_simulated flag
    ind_stmt = select(Indicator).where(Indicator.value == "198.51.100.45")
    ind = (await db_session.execute(ind_stmt)).scalar_one()
    assert ind.is_simulated is True
    assert ind.reputation == "malicious"
    assert ind.confidence == 95

    # Verify playbook execution paused at WAITING_APPROVAL
    pb_stmt = select(PlaybookExecution).where(PlaybookExecution.id == playbook_exec_id)
    pb_exec = (await db_session.execute(pb_stmt)).scalar_one()
    assert pb_exec.status == "WAITING_APPROVAL"

    # Verify ResponseAction created requiring four-eyes approval
    act_stmt = select(ResponseAction).where(ResponseAction.incident_id == incident_id)
    actions = (await db_session.execute(act_stmt)).scalars().all()
    assert len(actions) >= 1
    action = actions[0]
    assert action.status == "PENDING_APPROVAL"
    assert action.requested_by_id is not None

    # Verify execution listing API
    hist_res = await async_client.get(
        "/api/v1/simulations/executions",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert hist_res.status_code == 200
    executions = hist_res.json()
    assert any(e["id"] == exec_data["id"] for e in executions)

    # Verify execution detail API
    get_res = await async_client.get(
        f"/api/v1/simulations/executions/{exec_data['id']}",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert get_res.status_code == 200
    assert get_res.json()["id"] == exec_data["id"]


@pytest.mark.asyncio
async def test_simulation_launch_modes_and_multi_stage_correlation(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify alerts_only mode and multi-stage APT scenario correlating 5 alerts into 1 incident."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # 1. Test alerts_only mode on s02_endpoint_malware
    ao_res = await async_client.post(
        "/api/v1/simulations/scenarios/s02_endpoint_malware/launch",
        headers={"X-CSRF-Token": l1_csrf},
        json={"mode": "alerts_only"},
    )
    assert ao_res.status_code == 200
    ao_data = ao_res.json()
    assert ao_data["mode"] == "alerts_only"
    assert ao_data["alerts_count"] >= 1
    assert ao_data["incident_id"] is None
    assert ao_data["playbook_execution_id"] is None

    # 2. Test S-07 Multi-Stage APT Attack in full_chain mode
    apt_res = await async_client.post(
        "/api/v1/simulations/scenarios/s07_multi_stage_attack/launch",
        headers={"X-CSRF-Token": l1_csrf},
        json={"mode": "full_chain"},
    )
    assert apt_res.status_code == 200
    apt_data = apt_res.json()
    assert apt_data["alerts_count"] == 5
    assert apt_data["incident_id"] is not None

    # Verify 5 alerts linked to 1 incident
    apt_inc_id = uuid.UUID(apt_data["incident_id"])
    assert apt_inc_id is not None
    alert_stmt = select(Alert).where(Alert.scenario_slug == "s07_multi_stage_attack")
    apt_alerts = (await db_session.execute(alert_stmt)).scalars().all()
    assert len(apt_alerts) == 5
    for a in apt_alerts:
        assert a.is_simulated is True


@pytest.mark.asyncio
async def test_simulation_data_reset_safety_guardrail(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify simulation reset purges ONLY simulated data and preserves non-simulated records."""
    _, mgr_csrf = await login_as(async_client, "soc.manager")

    # 1. Create a real operational incident (is_simulated = False)
    real_inc = Incident(
        id=uuid.uuid4(),
        human_id="INC-2026-REAL-TEST",
        title="Real Operational Incident For Safety Testing",
        description="Must never be deleted by simulation reset.",
        severity="medium",
        status="INVESTIGATING",
        is_simulated=False,
    )
    db_session.add(real_inc)

    # 2. Create a real operational alert (is_simulated = False)
    real_alert = Alert(
        id=uuid.uuid4(),
        source_system="production_ids",
        rule_id="real-rule-01",
        rule_description="Real production IDS rule",
        event_category="network",
        severity="medium",
        event_timestamp=utc_now(),
        ingested_at=utc_now(),
        first_seen_at=utc_now(),
        last_seen_at=utc_now(),
        fingerprint=hashlib.sha256(b"real-alert-fingerprint").hexdigest(),
        raw_payload={"real": True},
        is_simulated=False,
    )
    db_session.add(real_alert)
    await db_session.commit()

    # 3. Call simulation reset
    reset_res = await async_client.post(
        "/api/v1/simulations/reset",
        headers={"X-CSRF-Token": mgr_csrf},
    )
    assert reset_res.status_code == 200
    reset_data = reset_res.json()
    assert reset_data["status"] == "success"

    # 4. Verify simulated records deleted
    sim_inc_count = (
        await db_session.execute(
            select(Incident).where(Incident.is_simulated.is_(True))
        )
    ).scalars().all()
    assert len(sim_inc_count) == 0

    # 5. Verify real operational incident and alert still exist intact
    check_real_inc = (
        await db_session.execute(
            select(Incident).where(Incident.id == real_inc.id)
        )
    ).scalar_one_or_none()
    assert check_real_inc is not None
    assert check_real_inc.human_id == "INC-2026-REAL-TEST"

    check_real_alert = (
        await db_session.execute(
            select(Alert).where(Alert.id == real_alert.id)
        )
    ).scalar_one_or_none()
    assert check_real_alert is not None


@pytest.mark.asyncio
async def test_incident_report_generation_weasyprint_pdf(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify WeasyPrint PDF report generation, SHA-256 calculation, and binary download stream."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)
    _, l2_csrf = await login_as(async_client, "l2.analyst")

    # Launch scenario to have a rich incident
    launch_res = await async_client.post(
        "/api/v1/simulations/scenarios/s01_brute_force/launch",
        headers={"X-CSRF-Token": l2_csrf},
        json={"mode": "full_chain"},
    )
    inc_id = launch_res.json()["incident_id"]

    # 1. Generate PDF Report
    gen_res = await async_client.post(
        f"/api/v1/reports/incidents/{inc_id}/generate",
        headers={"X-CSRF-Token": l2_csrf},
        json={"report_format": "pdf", "tlp_classification": "TLP:AMBER"},
    )
    assert gen_res.status_code == 200
    report_data = gen_res.json()
    report_id = report_data["id"]
    assert report_data["report_format"] == "pdf"
    assert report_data["tlp_classification"] == "TLP:AMBER"
    assert report_data["sha256_hash"] is not None
    assert len(report_data["sha256_hash"]) == 64
    assert report_data["is_simulated"] is True

    # 2. Download PDF file
    dl_res = await async_client.get(
        f"/api/v1/reports/{report_id}/download",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert dl_res.status_code == 200
    assert dl_res.headers["content-type"] == "application/pdf"
    assert "attachment;" in dl_res.headers["content-disposition"]
    assert dl_res.headers["x-content-type-options"] == "nosniff"
    assert dl_res.headers["x-tlp-classification"] == "TLP:AMBER"

    pdf_bytes = dl_res.content
    assert len(pdf_bytes) > 100
    assert pdf_bytes.startswith(b"%PDF-")

    # Verify SHA-256 integrity
    computed_hash = hashlib.sha256(pdf_bytes).hexdigest()
    assert computed_hash == report_data["sha256_hash"]


@pytest.mark.asyncio
async def test_incident_report_generation_json_and_stix2(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify versioned JSON export and OASIS STIX 2.1 bundle export schemas."""
    await PlaybookLoader.sync_builtin_playbooks(db_session, PLAYBOOKS_DIR)
    _, l2_csrf = await login_as(async_client, "l2.analyst")

    launch_res = await async_client.post(
        "/api/v1/simulations/scenarios/s03_phishing_campaign/launch",
        headers={"X-CSRF-Token": l2_csrf},
        json={"mode": "full_chain"},
    )
    inc_id = launch_res.json()["incident_id"]

    # 1. Generate JSON Export
    json_gen = await async_client.post(
        f"/api/v1/reports/incidents/{inc_id}/generate",
        headers={"X-CSRF-Token": l2_csrf},
        json={"report_format": "json", "tlp_classification": "TLP:GREEN"},
    )
    assert json_gen.status_code == 200
    json_rep_id = json_gen.json()["id"]

    json_dl = await async_client.get(
        f"/api/v1/reports/{json_rep_id}/download",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert json_dl.status_code == 200
    assert json_dl.headers["content-type"] == "application/json"
    json_doc = json.loads(json_dl.content.decode("utf-8"))
    assert json_doc["schema_version"] == "1.0.0"
    assert json_doc["tlp_classification"] == "TLP:GREEN"
    assert "incident" in json_doc
    assert "indicators" in json_doc
    assert len(json_doc["indicators"]) >= 1

    # 2. Generate STIX 2.1 Bundle Export
    stix_gen = await async_client.post(
        f"/api/v1/reports/incidents/{inc_id}/generate",
        headers={"X-CSRF-Token": l2_csrf},
        json={"report_format": "stix", "tlp_classification": "TLP:AMBER"},
    )
    assert stix_gen.status_code == 200
    stix_rep_id = stix_gen.json()["id"]

    stix_dl = await async_client.get(
        f"/api/v1/reports/{stix_rep_id}/download",
        headers={"X-CSRF-Token": l2_csrf},
    )
    assert stix_dl.status_code == 200
    stix_doc = json.loads(stix_dl.content.decode("utf-8"))

    # STIX 2.1 Schema validation
    assert stix_doc["type"] == "bundle"
    assert stix_doc["id"].startswith("bundle--")
    objects = stix_doc["objects"]
    assert len(objects) >= 4

    types_in_bundle = {obj["type"] for obj in objects}
    assert "identity" in types_in_bundle
    assert "incident" in types_in_bundle
    assert "indicator" in types_in_bundle
    assert "attack-pattern" in types_in_bundle
    assert "relationship" in types_in_bundle

    # Verify indicator pattern syntax
    indicators = [o for o in objects if o["type"] == "indicator"]
    assert any("[domain-name:value" in ind["pattern"] for ind in indicators)


@pytest.mark.asyncio
async def test_soc_analytics_database_reconciliation(
    async_client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify true SQL-driven SOC Command Analytics: overview, trends, performance, and command-center."""
    _, l1_csrf = await login_as(async_client, "l1.analyst")

    # 1. Test Command Center endpoint
    cc_res = await async_client.get(
        "/api/v1/analytics/command-center?window_days=30&include_simulated=true",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert cc_res.status_code == 200
    cc = cc_res.json()
    assert "kpis" in cc
    assert "sla_summary" in cc
    assert "severity_distribution" in cc
    assert "trends" in cc

    # 2. Test Overview endpoint
    ov_res = await async_client.get(
        "/api/v1/analytics/overview?window_days=30&include_simulated=true",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert ov_res.status_code == 200
    ov = ov_res.json()
    kpis = ov["kpis"]
    assert kpis["mttd_minutes"] is not None
    assert kpis["mtta_minutes"] is not None
    assert kpis["mttc_minutes"] is not None
    assert kpis["mttr_minutes"] is not None
    assert kpis["total_incidents"] >= 1
    assert "severity_distribution" in ov
    assert "status_distribution" in ov
    assert "category_distribution" in ov

    # 3. Test Trends endpoint
    tr_res = await async_client.get(
        "/api/v1/analytics/trends?window_days=14&include_simulated=true",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert tr_res.status_code == 200
    tr = tr_res.json()
    assert len(tr["daily_trends"]) == 14
    assert "date" in tr["daily_trends"][0]
    assert "alerts" in tr["daily_trends"][0]
    assert "incidents" in tr["daily_trends"][0]

    # 4. Test Performance endpoint
    pf_res = await async_client.get(
        "/api/v1/analytics/performance?window_days=30&include_simulated=true",
        headers={"X-CSRF-Token": l1_csrf},
    )
    assert pf_res.status_code == 200
    pf = pf_res.json()
    assert "playbooks" in pf
    assert "response_actions" in pf
    assert "mitre_techniques" in pf
    assert "threat_intelligence" in pf


@pytest.mark.asyncio
async def test_notification_dispatcher_formatting(db_session: AsyncSession) -> None:
    """Verify Slack, Microsoft Teams, and Four-Eyes approval notification payload generation."""
    inc = Incident(
        id=uuid.uuid4(),
        human_id="INC-2026-DISPATCH",
        title="Spearphishing and Lateral Intrusion",
        description="Suspicious SMB traffic and payload delivery.",
        severity="critical",
        category="malware",
        status="CONTAINMENT",
        risk_score=85,
        is_simulated=True,
    )

    action = ResponseAction(
        id=uuid.uuid4(),
        incident_id=inc.id,
        action_type="isolate_endpoint_recommendation",
        title="Isolate Compromised Host",
        justification="Host active malware containment",
        target_hostname="CORP-WS-099",
        risk_impact="high",
        status="PENDING_APPROVAL",
        requested_by_id=uuid.uuid4(),
        expires_at=utc_now(),
    )

    # 1. Slack Incident Card
    slack_card = NotificationDispatcher.format_slack_incident_card(inc, "escalated")
    assert "attachments" in slack_card
    assert slack_card["attachments"][0]["color"] == "#DC2626"
    blocks = slack_card["attachments"][0]["blocks"]
    assert any("INC-2026-DISPATCH" in str(b) for b in blocks)

    # 2. Teams Incident Card
    teams_card = NotificationDispatcher.format_teams_incident_card(inc, "escalated")
    assert teams_card["type"] == "message"
    card_body = teams_card["attachments"][0]["content"]["body"]
    assert any("INC-2026-DISPATCH" in str(b) for b in card_body)

    # 3. Approval Request Card
    approval_card = NotificationDispatcher.format_approval_request_card(action, inc)
    assert "attachments" in approval_card
    assert approval_card["attachments"][0]["color"] == "#D97706"
    blocks = approval_card["attachments"][0]["blocks"]
    assert any("FOUR-EYES APPROVAL" in str(b) for b in blocks)

    # 4. Webhook dispatch fallback
    result = await NotificationDispatcher.dispatch_webhook(
        webhook_url=None,
        payload=slack_card,
        platform="slack",
    )
    assert result["status"] == "simulated"
    assert result["dispatched"] is False
