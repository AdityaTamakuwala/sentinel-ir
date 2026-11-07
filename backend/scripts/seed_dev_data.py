"""Idempotent development & demo data seeder for SENTINEL IR.

Strictly refuses to run when `APP_ENV == 'production'`.
Uses RFC 5737 documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and `.example` domains for all simulated external indicators.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.rbac import (
    PERMISSION_DESCRIPTIONS,
    ROLE_PERMISSION_MATRIX,
    PermissionCode,
    RoleName,
)
from app.core.security import encrypt_secret, hash_password, sha256_hex
from app.db.session import get_session_factory, reset_connections
from app.models.alert import Alert, Asset, WebhookSource
from app.models.incident import IncidentTimeline
from app.models.investigation import MitreTechnique
from app.models.ops import IntegrationConfig, SlaPolicy
from app.models.user import Permission, Role, RolePermission, User
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService
from app.services.enrichment.engine import EnrichmentService
from app.services.incident_service import DEFAULT_SLA_MINUTES, IncidentService
from app.services.mitre_service import MitreService

logger = logging.getLogger("sentinel.seed")

ROLE_DISPLAY = {
    RoleName.SOC_L1: ("SOC Analyst L1", "Initial alert triage, enrichment requests, note taking, and escalation"),
    RoleName.SOC_L2: ("SOC Analyst L2", "Deep incident investigation, playbook execution, MITRE confirmation, and case closure"),
    RoleName.SOC_MANAGER: ("SOC Manager", "SOC command oversight, analyst assignment, response approvals, and workflow governance"),
    RoleName.ADMIN: ("Platform Administrator", "User/role administration, integration secrets, system policies, and audit export"),
}

# Local-dev-only deterministic Wazuh webhook credentials documented in docs/WAZUH_INTEGRATION.md
DEV_WAZUH_API_KEY = "sir_whk_dev_wazuh_key_2026_local_only"
DEV_WAZUH_HMAC_SECRET = "sir_whk_dev_hmac_secret_2026_local_only"


async def ensure_rbac_and_policies(db: AsyncSession) -> dict[str, Role]:
    perm_map: dict[PermissionCode, Permission] = {}
    for code in PermissionCode:
        module, desc = PERMISSION_DESCRIPTIONS[code]
        res = await db.execute(select(Permission).where(Permission.code == code.value))
        perm = res.scalar_one_or_none()
        if perm is None:
            perm = Permission(id=uuid.uuid4(), code=code.value, module=module, description=desc)
            db.add(perm)
            await db.flush()
        perm_map[code] = perm

    role_map: dict[str, Role] = {}
    for role_enum in RoleName:
        disp, desc = ROLE_DISPLAY[role_enum]
        role_res = await db.execute(select(Role).where(Role.name == role_enum.value))
        role = role_res.scalar_one_or_none()
        if role is None:
            role = Role(
                id=uuid.uuid4(),
                name=role_enum.value,
                display_name=disp,
                description=desc,
            )
            db.add(role)
            await db.flush()
        role_map[role_enum.value] = role

        existing_rp = await db.execute(
            select(RolePermission.permission_id).where(RolePermission.role_id == role.id)
        )
        existing_pids = set(existing_rp.scalars().all())
        for pcode in ROLE_PERMISSION_MATRIX[role_enum]:
            p_obj = perm_map[pcode]
            if p_obj.id not in existing_pids:
                db.add(RolePermission(role_id=role.id, permission_id=p_obj.id))

    for sev, (ack_m, res_m) in DEFAULT_SLA_MINUTES.items():
        s_res = await db.execute(select(SlaPolicy).where(SlaPolicy.severity == sev))
        if s_res.scalar_one_or_none() is None:
            db.add(SlaPolicy(severity=sev, ack_minutes=ack_m, resolve_minutes=res_m))

    default_integrations = [
        ("wazuh_webhook", "Wazuh Manager Alert Webhook", "ingestion", True, False, None, 120, 0),
        ("virustotal", "VirusTotal v3 Threat Intelligence", "enrichment", True, True, "https://www.virustotal.com/api/v3", 4, 3600),
        ("abuseipdb", "AbuseIPDB v2 IP Reputation", "enrichment", True, True, "https://api.abuseipdb.com/api/v2", 30, 3600),
        ("otx", "AlienVault OTX DirectConnect", "enrichment", True, True, "https://otx.alienvault.com/api/v1", 30, 3600),
        ("slack_webhook", "Slack SOC Escalation Channel", "notification", False, True, None, 30, 0),
        ("teams_webhook", "Microsoft Teams SOC Webhook", "notification", False, True, None, 30, 0),
        ("simulated_response", "Safe Simulated Containment Adapter", "response", True, True, None, 60, 0),
    ]
    for slug, name, cat, enabled, mock_fb, base_url, rl, ttl in default_integrations:
        ic_res = await db.execute(select(IntegrationConfig).where(IntegrationConfig.slug == slug))
        if ic_res.scalar_one_or_none() is None:
            db.add(
                IntegrationConfig(
                    slug=slug,
                    name=name,
                    category=cat,
                    is_enabled=enabled,
                    use_mock_fallback=mock_fb,
                    base_url=base_url,
                    rate_limit_per_minute=rl,
                    cache_ttl_seconds=ttl,
                )
            )

    await db.commit()
    return role_map


async def seed_demo_environment(db: AsyncSession) -> None:
    settings = get_settings()
    if settings.APP_ENV == "production":
        raise RuntimeError("Refusing to seed demo users or simulated data in production mode.")

    role_map = await ensure_rbac_and_policies(db)

    # Seed 4 demo SOC users
    demo_pw_hash = hash_password(settings.DEMO_USER_PASSWORD)
    demo_specs = [
        ("l1.analyst", "l1.analyst@sentinel.local", "Maya Lin (SOC L1)", "soc_l1"),
        ("l2.analyst", "l2.analyst@sentinel.local", "Devon Brooks (SOC L2)", "soc_l2"),
        ("soc.manager", "soc.manager@sentinel.local", "Elena Rostova (SOC Manager)", "soc_manager"),
        ("admin", "admin@sentinel.local", "Marcus Vance (Platform Admin)", "admin"),
    ]
    users_by_role: dict[str, User] = {}
    for uname, email, full_name, rname in demo_specs:
        u_res = await db.execute(select(User).where(User.username == uname))
        user = u_res.scalar_one_or_none()
        if user is None:
            user = User(
                id=uuid.uuid4(),
                username=uname,
                email=email,
                full_name=full_name,
                password_hash=demo_pw_hash,
                role_id=role_map[rname].id,
                is_active=True,
                is_demo_user=True,
                must_change_password=False,
            )
            db.add(user)
            await db.flush()
            user.role = role_map[rname]
            await AuditService.record(
                db,
                action="seed.demo_user_provisioned",
                target_type="user",
                target_id=str(user.id),
                details={"username": uname, "role": rname},
            )
        users_by_role[rname] = user

    # Seed dev Wazuh webhook source
    wh_hash = sha256_hex(DEV_WAZUH_API_KEY)
    wh_res = await db.execute(select(WebhookSource).where(WebhookSource.api_key_hash == wh_hash))
    if wh_res.scalar_one_or_none() is None:
        db.add(
            WebhookSource(
                name="HomeLab Wazuh Manager (Dev)",
                source_type="wazuh",
                api_key_prefix=DEV_WAZUH_API_KEY[:12],
                api_key_hash=wh_hash,
                encrypted_hmac_secret=encrypt_secret(DEV_WAZUH_HMAC_SECRET),
                is_active=True,
                rate_limit_per_minute=120,
                tolerance_seconds=300,
                created_by_id=users_by_role["admin"].id,
            )
        )

    # Seed realistic enterprise assets
    asset_specs = [
        ("prod-bastion-01", "10.20.10.14", "server", "Ubuntu 24.04 LTS", "critical", "Platform Infra", "Engineering"),
        ("dc01-corp", "10.20.1.10", "domain_controller", "Windows Server 2022", "critical", "Identity Ops", "IT Security"),
        ("fin-wkstn-04", "10.20.40.31", "workstation", "Windows 11 Enterprise", "high", "Treasury Desk", "Finance"),
        ("pay-api-gw-02", "10.20.20.19", "server", "Debian 12", "critical", "Payments Core", "Core Banking"),
        ("dev-ci-runner-03", "10.20.60.55", "server", "Ubuntu 22.04 LTS", "medium", "Release Eng", "Engineering"),
    ]
    for hostname, ip, atype, os_name, crit, owner, dept in asset_specs:
        a_res = await db.execute(select(Asset).where(Asset.hostname == hostname))
        if a_res.scalar_one_or_none() is None:
            db.add(
                Asset(
                    hostname=hostname,
                    ip_address=ip,
                    asset_type=atype,
                    os_name=os_name,
                    criticality=crit,
                    owner=owner,
                    department=dept,
                    environment="production",
                    is_simulated=True,
                )
            )
    await db.commit()

    # Only seed initial sample alerts & incidents if database has 0 alerts
    existing_alerts = (await db.execute(select(Alert.id).limit(1))).scalar_one_or_none()
    if existing_alerts is not None:
        return

    now = datetime.now(UTC)
    l1 = users_by_role["soc_l1"]
    l2 = users_by_role["soc_l2"]
    mgr = users_by_role["soc_manager"]

    # Seed Golden-Path Alert 1 + Alert 2 (SSH Brute Force + Post-Failure Valid Account Login)
    a1, _ = await AlertService.ingest_normalized_alert(
        db,
        {
            "source_system": "wazuh",
            "rule_id": "5712",
            "rule_description": "sshd: Multiple authentication failures from external IP against privileged deploy account",
            "event_category": "authentication",
            "event_timestamp": now - timedelta(hours=3, minutes=18),
            "src_ip": "198.51.100.42",
            "dst_ip": "10.20.10.14",
            "hostname": "prod-bastion-01",
            "username": "svc_deploy",
            "severity": "high",
            "mitre_mappings_raw": [
                {"id": "T1110.001", "name": "Password Guessing", "tactic": "credential-access", "source": "alert_metadata"}
            ],
            "raw_payload": {
                "rule": {"id": "5712", "level": 10, "mitre": {"id": ["T1110.001"]}},
                "agent": {"name": "prod-bastion-01", "ip": "10.20.10.14"},
                "data": {"srcip": "198.51.100.42", "dstuser": "svc_deploy"},
                "_sentinel_simulated": True,
            },
            "is_simulated": True,
            "scenario_slug": "ssh_bruteforce_success",
        },
        actor=l1,
        deduplicate=False,
    )

    a2, _ = await AlertService.ingest_normalized_alert(
        db,
        {
            "source_system": "wazuh",
            "rule_id": "5715",
            "rule_description": "sshd: Successful login for svc_deploy immediately following brute-force burst",
            "event_category": "authentication",
            "event_timestamp": now - timedelta(hours=3, minutes=12),
            "src_ip": "198.51.100.42",
            "dst_ip": "10.20.10.14",
            "hostname": "prod-bastion-01",
            "username": "svc_deploy",
            "severity": "critical",
            "mitre_mappings_raw": [
                {"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access", "source": "alert_metadata"}
            ],
            "raw_payload": {
                "rule": {"id": "5715", "level": 13, "mitre": {"id": ["T1078"]}},
                "agent": {"name": "prod-bastion-01", "ip": "10.20.10.14"},
                "data": {"srcip": "198.51.100.42", "dstuser": "svc_deploy"},
                "_sentinel_simulated": True,
            },
            "is_simulated": True,
            "scenario_slug": "ssh_bruteforce_success",
        },
        actor=l1,
        deduplicate=False,
    )

    # Golden-Path Incident 1 (CONTAINMENT state, assigned to L2)
    inc1 = await IncidentService.create_incident(
        db,
        title="Compromised Bastion Service Account After External SSH Brute Force",
        description=(
            "Privileged deployment account `svc_deploy` on `prod-bastion-01` experienced repeated SSH "
            "password guessing from `198.51.100.42` followed by an interactive SSH authentication success."
        ),
        category="credential_compromise",
        base_severity="critical",
        alert_ids=[a1.id, a2.id],
        assigned_to_id=l2.id,
        actor=l1,
        is_simulated=True,
    )
    inc1 = await IncidentService.transition_status(
        db,
        incident_id=inc1.id,
        target_status="INVESTIGATING",
        expected_version=inc1.version,
        actor=l2,
        reason="Confirmed post-failure session PID 24810 in auth.log; escalating to active investigation.",
    )
    inc1 = await IncidentService.transition_status(
        db,
        incident_id=inc1.id,
        target_status="CONTAINMENT",
        expected_version=inc1.version,
        actor=l2,
        reason="Initiated containment workflow for 198.51.100.42 and credential rotation on svc_deploy.",
    )
    inc1.executive_summary = (
        "SIMULATED GOLDEN-PATH CASE: External threat actor from documentation IP 198.51.100.42 "
        "successfully guessed credentials for `svc_deploy` on `prod-bastion-01`. SOC L1 triaged within "
        "8 minutes and escalated to SOC L2 for containment."
    )
    inc1.root_cause = "Legacy SSH password authentication remained enabled for deployment service account."
    inc1.lessons_learned = "Enforce SSH certificate/key-only authentication and hardware MFA across all bastion hosts."

    # Seed Historical Resolved Incident (for realistic MTTR & MTTA calculation!)
    a3, _ = await AlertService.ingest_normalized_alert(
        db,
        {
            "source_system": "wazuh",
            "rule_id": "87901",
            "rule_description": "Suspicious high-entropy TXT DNS queries toward external C2 beacon domain",
            "event_category": "dns",
            "event_timestamp": now - timedelta(days=2, hours=5),
            "src_ip": "10.20.60.55",
            "dst_ip": "203.0.113.53",
            "hostname": "dev-ci-runner-03",
            "username": "ci-runner",
            "domain": "beacon-sync.telemetry-check.example",
            "severity": "high",
            "mitre_mappings_raw": [
                {"id": "T1071.004", "name": "DNS", "tactic": "command-and-control", "source": "alert_metadata"}
            ],
            "is_simulated": True,
        },
        actor=l1,
        deduplicate=False,
    )
    inc2 = await IncidentService.create_incident(
        db,
        title="Anomalous DNS Tunneling Probe on CI Runner",
        description="High-entropy DNS TXT queries detected from `dev-ci-runner-03` to `beacon-sync.telemetry-check.example`.",
        category="command_and_control",
        base_severity="high",
        alert_ids=[a3.id],
        assigned_to_id=l2.id,
        actor=mgr,
        is_simulated=True,
    )
    # Backdate timestamps realistically for historical MTTA (12m) & MTTR (95m)
    hist_created = now - timedelta(days=2, hours=4)
    inc2.created_at = hist_created
    inc2.acknowledged_at = hist_created + timedelta(minutes=12)
    inc2.status = "CLOSED"
    inc2.contained_at = hist_created + timedelta(minutes=44)
    inc2.resolved_at = hist_created + timedelta(minutes=95)
    inc2.closed_at = hist_created + timedelta(minutes=130)
    inc2.closure_category = "true_positive_mitigated"
    inc2.closure_justification = "Ephemeral CI runner destroyed and rebuilt from signed image; egress DNS restricted."
    db.add(
        IncidentTimeline(
            incident_id=inc2.id,
            event_type="status_changed",
            title="Lifecycle transition: RESOLVED → CLOSED",
            description=inc2.closure_justification,
            actor_id=l2.id,
            actor_label=l2.username,
            occurred_at=inc2.closed_at,
        )
    )

    # Seed Unreviewed Alert Inbox items ready for live Analyst Triage
    await AlertService.ingest_normalized_alert(
        db,
        {
            "source_system": "wazuh",
            "rule_id": "92052",
            "rule_description": "Sysmon Event 1: Encoded PowerShell execution bypassing execution policy on finance workstation",
            "event_category": "execution",
            "event_timestamp": now - timedelta(minutes=28),
            "src_ip": "192.0.2.88",
            "dst_ip": "10.20.40.31",
            "hostname": "fin-wkstn-04",
            "username": "m.patel",
            "severity": "high",
            "mitre_mappings_raw": [
                {"id": "T1059.001", "name": "PowerShell", "tactic": "execution", "source": "alert_metadata"}
            ],
            "is_simulated": True,
        },
        actor=None,
        deduplicate=False,
    )

    await AlertService.ingest_normalized_alert(
        db,
        {
            "source_system": "wazuh",
            "rule_id": "87105",
            "rule_description": "Endpoint Malware Alert: Suspicious binary dropped in user AppData Temp directory",
            "event_category": "malware",
            "event_timestamp": now - timedelta(minutes=14),
            "src_ip": "203.0.113.77",
            "dst_ip": "10.20.40.31",
            "hostname": "fin-wkstn-04",
            "username": "m.patel",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "severity": "critical",
            "mitre_mappings_raw": [
                {"id": "T1204.002", "name": "Malicious File", "tactic": "execution", "source": "alert_metadata"}
            ],
            "is_simulated": True,
        },
        actor=None,
        deduplicate=False,
    )

    # 8. Seed offline MITRE ATT&CK techniques if full dataset not loaded
    from sqlalchemy import func
    mitre_count = int((await db.execute(select(func.count(MitreTechnique.id)))).scalar_one())
    if mitre_count < 100:
        await MitreService.load_mitre_stix(db)

    # Map core techniques to the active incident (INC-1)
    await MitreService.map_technique_to_incident(
        db,
        incident_id=inc1.id,
        technique_id="T1059.001",
        source="alert_metadata",
        rationale="PowerShell execution observed with base64 encoded payload",
        actor=l2,
    )
    await MitreService.confirm_technique(
        db,
        incident_id=inc1.id,
        technique_id="T1059.001",
        confirm=True,
        notes="Confirmed adversary used powershell.exe -enc parameter",
        actor=l2,
    )
    await MitreService.map_technique_to_incident(
        db,
        incident_id=inc1.id,
        technique_id="T1078",
        source="analyst",
        rationale="Compromised local administrator account utilized for persistence",
        actor=l1,
    )

    # 9. Enrich demo indicators with deterministic threat intel
    demo_iocs = [
        ("ip", "185.220.101.5"),
        ("ip", "10.20.40.31"),
        ("ip", "8.8.8.8"),
        ("domain", "c2-stealer.darknet-relay.org"),
        ("sha256", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
    ]
    for ioc_type, val in demo_iocs:
        await EnrichmentService.enrich_indicator(db, ioc_type, val, actor=l1)

    await db.commit()
    logger.info("Development seed completed successfully.")


async def _main() -> None:
    factory = get_session_factory()
    async with factory() as session:
        await seed_demo_environment(session)
    await reset_connections()


if __name__ == "__main__":
    asyncio.run(_main())
