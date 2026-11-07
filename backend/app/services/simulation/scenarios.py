"""Seven realistic, reproducible SOC incident simulation scenarios.

Uses RFC 5737 / RFC 3849 documentation addresses and synthetic indicators.
All activity is flagged is_simulated=True per architectural guidelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SyntheticIndicator:
    ioc_type: str
    value: str
    reputation: str = "malicious"
    confidence: int = 90
    description: str = ""


@dataclass(frozen=True)
class SimulationAlertSpec:
    title: str
    description: str
    source_system: str
    rule_id: str
    rule_description: str
    event_category: str
    severity: str
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    mitre_techniques: list[dict[str, str]] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScenarioDefinition:
    slug: str
    scenario_id: str
    name: str
    short_summary: str
    description: str
    category: str
    severity: str
    expected_mitre_techniques: list[str]
    associated_playbook_slug: str
    expected_response_actions: list[str]
    expected_investigation_path: list[str]
    synthetic_indicators: list[SyntheticIndicator]
    alerts: list[SimulationAlertSpec]
    executive_summary_template: str


SCENARIOS_CATALOG: dict[str, ScenarioDefinition] = {
    # -------------------------------------------------------------------------
    # S-01: Brute Force / Credential Stuffing
    # -------------------------------------------------------------------------
    "s01_brute_force": ScenarioDefinition(
        slug="s01_brute_force",
        scenario_id="SIM-SCN-001",
        name="Perimeter Brute-Force & Credential Stuffing",
        short_summary="Multiple failed SSH authentications followed by anomalous login from untrusted IP.",
        description=(
            "Simulates an automated perimeter dictionary attack against corporate SSH gateway. "
            "Anomalous source IP 198.51.100.45 generates 14 failed authentication attempts across 3 minutes, "
            "followed by a successful login for privileged service account 'finance-svc'."
        ),
        category="authentication",
        severity="high",
        expected_mitre_techniques=["T1110.001", "T1110.003", "T1078"],
        associated_playbook_slug="brute-force-credential-stuffing",
        expected_response_actions=["block_ip", "revoke_user_session"],
        expected_investigation_path=[
            "1. Triage alert burst from external IP 198.51.100.45.",
            "2. Perform threat intelligence enrichment on source IP.",
            "3. Confirm successful login event for service account finance-svc.",
            "4. Trigger PB-003 perimeter containment playbook.",
            "5. Require four-eyes human approval before firewall egress block.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="ip",
                value="198.51.100.45",
                reputation="malicious",
                confidence=95,
                description="Simulated perimeter brute-force botnet IP (RFC 5737 TEST-NET-2).",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="Wazuh Rule 5710: SSH Brute Force Login Attempt Followed by Success",
                description="Failed authentication burst (14 events) followed by successful SSH PAM session for 'finance-svc' from 198.51.100.45.",
                source_system="wazuh",
                rule_id="5710",
                rule_description="sshd: Multiple failed logins followed by success from single remote IP",
                event_category="authentication",
                severity="high",
                src_ip="198.51.100.45",
                dst_ip="10.0.1.5",
                hostname="prod-bastion-01.corp.internal",
                username="finance-svc",
                mitre_techniques=[
                    {"id": "T1110.001", "name": "Password Guessing", "tactic": "credential-access"},
                    {"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access"},
                ],
                raw_payload={
                    "event_source": "sshd",
                    "attack_type": "credential_stuffing",
                    "failed_count": 14,
                    "target_account": "finance-svc",
                    "target_asset": "prod-bastion-01.corp.internal",
                    "origin_ip": "198.51.100.45",
                    "is_simulated": True,
                },
            )
        ],
        executive_summary_template=(
            "Perimeter automated authentication attack identified targeting service account 'finance-svc'. "
            "Source IP 198.51.100.45 staged 14 dictionary attempts before gaining interactive session access. "
            "PB-003 containment executed with perimeter firewall block and session revocation."
        ),
    ),

    # -------------------------------------------------------------------------
    # S-02: Endpoint Malware Detection
    # -------------------------------------------------------------------------
    "s02_endpoint_malware": ScenarioDefinition(
        slug="s02_endpoint_malware",
        scenario_id="SIM-SCN-002",
        name="Endpoint Ransomware/Trojan Dropper Execution",
        short_summary="EDR detection of suspicious dropper executable spawned by PowerShell on workstation.",
        description=(
            "Simulates an endpoint malware detection alert on workstation FIN-WS-088. "
            "PowerShell spawns an unsigned payload 'updater_svc.exe' from %TEMP%, which attempts to "
            "dump local LSASS memory and establish persistence in registry run keys."
        ),
        category="malware",
        severity="critical",
        expected_mitre_techniques=["T1059.001", "T1204.002", "T1027"],
        associated_playbook_slug="endpoint-malware-containment",
        expected_response_actions=["isolate_endpoint"],
        expected_investigation_path=[
            "1. Triage critical EDR alert from endpoint FIN-WS-088.",
            "2. Extract payload SHA-256 and query threat enrichment.",
            "3. Inspect parent process tree (PowerShell -> updater_svc.exe).",
            "4. Map MITRE execution and defense evasion techniques.",
            "5. Execute PB-002 with human four-eyes approval to isolate endpoint from network.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="sha256",
                value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                reputation="malicious",
                confidence=99,
                description="Simulated synthetic Trojan dropper payload hash.",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="EDR Detection: Malicious Dropper Executed from Temp Directory",
                description="Suspicious binary 'updater_svc.exe' (SHA-256: 275a021b...) spawned by powershell.exe on FIN-WS-088.",
                source_system="edr_sentinel",
                rule_id="87105",
                rule_description="EDR alert: Unsigned binary execution from temporary user directory",
                event_category="malware",
                severity="critical",
                src_ip="10.40.12.88",
                hostname="FIN-WS-088",
                username="alice.finance",
                file_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                mitre_techniques=[
                    {"id": "T1059.001", "name": "PowerShell", "tactic": "execution"},
                    {"id": "T1204.002", "name": "Malicious File", "tactic": "execution"},
                    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
                ],
                raw_payload={
                    "process_name": "updater_svc.exe",
                    "parent_process": "powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\stage.ps1",
                    "file_path": "C:\\Users\\alice.finance\\AppData\\Local\\Temp\\updater_svc.exe",
                    "file_hash_sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    "endpoint_id": "EP-FIN-088",
                    "is_simulated": True,
                },
            )
        ],
        executive_summary_template=(
            "High-severity endpoint security event on host FIN-WS-088. Malicious payload was staged and executed "
            "via PowerShell bypass script. Threat enrichment confirmed SHA-256 dropper signature. "
            "Active network containment executed via PB-002 following manager four-eyes approval."
        ),
    ),

    # -------------------------------------------------------------------------
    # S-03: Phishing Campaign
    # -------------------------------------------------------------------------
    "s03_phishing_campaign": ScenarioDefinition(
        slug="s03_phishing_campaign",
        scenario_id="SIM-SCN-003",
        name="Executive Credential Harvesting Phishing Campaign",
        short_summary="Inbound spearphishing email impersonating corporate payroll portal to steal credentials.",
        description=(
            "Simulates an inbound phishing attack targeting HR personnel. Email sent from spoofed address "
            "'benefits-update@phish-delivery.example.org' contains an urgent link directing users to lookalike "
            "credential harvesting site 'https://portal-verification.example.org/login/auth'."
        ),
        category="social_engineering",
        severity="high",
        expected_mitre_techniques=["T1566.002", "T1566.001"],
        associated_playbook_slug="phishing-investigation",
        expected_response_actions=["quarantine_email", "disable_user_account"],
        expected_investigation_path=[
            "1. Ingest email security gateway alert for suspicious inbound message.",
            "2. Enrich sender domain and landing URL indicators.",
            "3. Identify targeted internal accounts and check for URL click telemetry.",
            "4. Trigger PB-001 Phishing Triage & Response playbook.",
            "5. Request four-eyes approval to quarantine mail cluster-wide and reset compromised passwords.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="domain",
                value="portal-verification.example.org",
                reputation="malicious",
                confidence=92,
                description="Simulated lookalike credential harvesting domain.",
            ),
            SyntheticIndicator(
                ioc_type="url",
                value="https://portal-verification.example.org/login/auth",
                reputation="malicious",
                confidence=95,
                description="Simulated credential phishing landing page.",
            ),
            SyntheticIndicator(
                ioc_type="email",
                value="benefits-update@phish-delivery.example.org",
                reputation="suspicious",
                confidence=85,
                description="Simulated adversary sender email address.",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="Mail Gateway: Spearphishing Link Detected in Inbound Message",
                description="Targeted phishing email received with malicious link to portal-verification.example.org.",
                source_system="email_gateway",
                rule_id="100201",
                rule_description="Inbound email containing unverified domain and credential harvesting heuristics",
                event_category="network",
                severity="high",
                domain="portal-verification.example.org",
                username="hr-benefits@sentinel-corp.internal",
                mitre_techniques=[
                    {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "initial-access"},
                ],
                raw_payload={
                    "sender": "benefits-update@phish-delivery.example.org",
                    "recipient": "hr-benefits@sentinel-corp.internal",
                    "subject": "URGENT: Required Annual Benefits Verification 2026",
                    "phishing_url": "https://portal-verification.example.org/login/auth",
                    "spf_result": "softfail",
                    "dmarc_result": "fail",
                    "is_simulated": True,
                },
            )
        ],
        executive_summary_template=(
            "Targeted credential phishing campaign intercepted by mail filters and analyst triage. "
            "Adversary leveraged lookalike domain portal-verification.example.org. "
            "PB-001 executed to quarantine delivery across all mailboxes and reset vulnerable accounts."
        ),
    ),

    # -------------------------------------------------------------------------
    # S-04: Unauthorized Access / Privilege Escalation
    # -------------------------------------------------------------------------
    "s04_privilege_escalation": ScenarioDefinition(
        slug="s04_privilege_escalation",
        scenario_id="SIM-SCN-004",
        name="Unauthorized Local Sudo Privilege Elevation",
        short_summary="Service account 'web-svc' spawned interactive root shell via sudo on database host.",
        description=(
            "Simulates an unauthorized privilege escalation anomaly on production server PROD-DB-01. "
            "The low-privilege service account 'web-svc' executed 'sudo /bin/bash -p' outside of any change "
            "window or administrative ticket reference, indicating possible container breakout or compromised web tier."
        ),
        category="privilege_escalation",
        severity="high",
        expected_mitre_techniques=["T1548.003", "T1078.003"],
        associated_playbook_slug="unauthorized-access-investigation",
        expected_response_actions=["terminate_process", "revoke_access_token"],
        expected_investigation_path=[
            "1. Receive host audit alert for sudo execution from non-human account.",
            "2. Verify lack of corresponding change control ticket or administrative session.",
            "3. Inspect command lineage and active process tree on PROD-DB-01.",
            "4. Execute PB-004 to terminate anomalous process and revoke active tokens.",
            "5. Transition incident to Containment and preserve bash history evidence.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="ip",
                value="10.10.20.15",
                reputation="internal",
                confidence=100,
                description="Production database server internal IP (PROD-DB-01).",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="Host Audit: Unauthorized Sudo Shell Invoked by Service Account",
                description="Service account web-svc executed 'sudo /bin/bash -p' without approval ticket on PROD-DB-01.",
                source_system="auditd",
                rule_id="5402",
                rule_description="Auditd: Successful sudo invocation to root shell by non-administrative user",
                event_category="privilege_escalation",
                severity="high",
                src_ip="10.10.20.15",
                hostname="PROD-DB-01",
                username="web-svc",
                mitre_techniques=[
                    {"id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "privilege-escalation"},
                    {"id": "T1078.003", "name": "Local Accounts", "tactic": "defense-evasion"},
                ],
                raw_payload={
                    "command": "sudo -u root /bin/bash -p",
                    "invoking_user": "web-svc",
                    "target_user": "root",
                    "tty": "pts/2",
                    "parent_process": "gunicorn: worker [app.wsgi]",
                    "audit_rule": "sudo_root_shell",
                    "is_simulated": True,
                },
            )
        ],
        executive_summary_template=(
            "Unauthorized privilege elevation detected on production database host PROD-DB-01. "
            "Application service account 'web-svc' spawned an interactive root shell via sudo. "
            "PB-004 initiated immediate process termination and token revocation with four-eyes verification."
        ),
    ),

    # -------------------------------------------------------------------------
    # S-05: Ransomware Activity
    # -------------------------------------------------------------------------
    "s05_ransomware_activity": ScenarioDefinition(
        slug="s05_ransomware_activity",
        scenario_id="SIM-SCN-005",
        name="High-Speed Ransomware Encryption Outbreak",
        short_summary="Rapid file renaming to .encrypted extension and shadow copy deletion on file server.",
        description=(
            "Simulates an active ransomware encryption outbreak on central file server CORP-FS-02. "
            "More than 350 files renamed with extension '.encrypted' in 45 seconds, accompanied by "
            "the deletion of Volume Shadow Copies via 'vssadmin.exe delete shadows /all /quiet'."
        ),
        category="ransomware",
        severity="critical",
        expected_mitre_techniques=["T1486", "T1490"],
        associated_playbook_slug="ransomware-rapid-response",
        expected_response_actions=["isolate_endpoint", "block_network_egress"],
        expected_investigation_path=[
            "1. Triage critical ransomware indicator alert across corporate file shares.",
            "2. Correlate rapid file system modifications with shadow copy deletion commands.",
            "3. Confirm external C2 beaconing indicator (198.51.100.99).",
            "4. Trigger emergency PB-005 Ransomware Outbreak playbook.",
            "5. Enforce four-eyes approval for immediate host isolation and egress firewall block.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="ip",
                value="198.51.100.99",
                reputation="malicious",
                confidence=98,
                description="Simulated Ransomware C2 Key Exchange Server (RFC 5737).",
            ),
            SyntheticIndicator(
                ioc_type="sha256",
                value="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                reputation="malicious",
                confidence=99,
                description="Simulated Ransomware Encryptor Payload Hash.",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="Critical: Rapid Mass File Encryption & Shadow Copy Deletion",
                description="Active ransomware pattern detected: 350+ files encrypted and shadow copies purged on CORP-FS-02.",
                source_system="edr_sentinel",
                rule_id="87105",
                rule_description="EDR alert: Mass file encryption activity and shadow copy suppression",
                event_category="malware",
                severity="critical",
                src_ip="10.20.10.50",
                dst_ip="198.51.100.99",
                hostname="CORP-FS-02",
                username="SYSTEM",
                file_hash="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                mitre_techniques=[
                    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "impact"},
                    {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "impact"},
                ],
                raw_payload={
                    "files_encrypted_count": 352,
                    "target_share": "D:\\Shares\\Corporate\\Finance",
                    "command_executed": "vssadmin.exe delete shadows /all /quiet",
                    "ransom_note_path": "D:\\Shares\\Corporate\\HOW_TO_RECOVER_FILES.txt",
                    "c2_destination": "198.51.100.99:443",
                    "is_simulated": True,
                },
            )
        ],
        executive_summary_template=(
            "Critical ransomware incident detected on central storage node CORP-FS-02. "
            "Ransomware process initiated mass encryption and destroyed recovery shadow copies. "
            "PB-005 containment isolated the endpoint and blocked egress C2 communication."
        ),
    ),

    # -------------------------------------------------------------------------
    # S-06: Data Exfiltration
    # -------------------------------------------------------------------------
    "s06_data_exfiltration": ScenarioDefinition(
        slug="s06_data_exfiltration",
        scenario_id="SIM-SCN-006",
        name="Anomalous Cloud Data Exfiltration to Unsanctioned IP",
        short_summary="Sustained outbound transfer of 48.5 GB to untrusted external IP over encrypted channel.",
        description=(
            "Simulates high-volume outbound data exfiltration from internal analytics server ANALYTICS-SRV-01. "
            "Anomalous transfer of 48.5 GB in 15 minutes to unsanctioned external IP 203.0.113.88 over TLS port 443, "
            "matching data staging and exfiltration behavioral signatures."
        ),
        category="exfiltration",
        severity="critical",
        expected_mitre_techniques=["T1048.003", "T1567"],
        associated_playbook_slug="data-exfiltration-triage",
        expected_response_actions=["block_ip", "revoke_credentials"],
        expected_investigation_path=[
            "1. Triage network flow anomaly alert indicating large outbound volume.",
            "2. Perform threat intelligence lookup on destination IP 203.0.113.88.",
            "3. Identify sending internal host and service credentials involved.",
            "4. Trigger PB-006 Anomalous Data Exfiltration playbook.",
            "5. Enforce four-eyes approval to sever network session and revoke cloud tokens.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="ip",
                value="203.0.113.88",
                reputation="malicious",
                confidence=94,
                description="Simulated unauthorized cloud storage exfiltration endpoint (RFC 5737 TEST-NET-3).",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="Network Anomaly: High-Volume Outbound Data Exfiltration Detected",
                description="Sustained 48.5 GB transfer in 15 minutes from ANALYTICS-SRV-01 to unsanctioned IP 203.0.113.88.",
                source_system="network_sensor",
                rule_id="87901",
                rule_description="Network IDS: Anomalous outbound data volume exceeding historical baseline by 800%",
                event_category="network",
                severity="critical",
                src_ip="10.30.5.12",
                dst_ip="203.0.113.88",
                hostname="ANALYTICS-SRV-01",
                username="data-pipeline",
                mitre_techniques=[
                    {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol", "tactic": "exfiltration"},
                    {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
                ],
                raw_payload={
                    "bytes_transferred": 52080000000,
                    "duration_seconds": 890,
                    "protocol": "tcp/443",
                    "destination_ip": "203.0.113.88",
                    "source_host": "ANALYTICS-SRV-01",
                    "data_staged_path": "/opt/staging/analytics_dump.tar.gz",
                    "is_simulated": True,
                },
            )
        ],
        executive_summary_template=(
            "Major data loss incident detected on analytics cluster. 48.5 GB of proprietary data was staged "
            "and transferred to external IP 203.0.113.88. PB-006 executed automated perimeter IP blocks "
            "and credential revocation following four-eyes approval."
        ),
    ),

    # -------------------------------------------------------------------------
    # S-07: Multi-Stage Attack
    # -------------------------------------------------------------------------
    "s07_multi_stage_attack": ScenarioDefinition(
        slug="s07_multi_stage_attack",
        scenario_id="SIM-SCN-007",
        name="Multi-Stage Advanced Persistent Threat (APT) Intrusion",
        short_summary="Full kill-chain intrusion: Phishing -> Dropper -> Sudo Escalation -> Lateral Move -> Exfil.",
        description=(
            "Simulates a comprehensive enterprise APT campaign progressing across multiple kill-chain phases: "
            "1) Initial access via targeted spearphishing link, "
            "2) Endpoint PowerShell payload execution on developer workstation, "
            "3) Local privilege escalation to administrator, "
            "4) Internal reconnaissance & credential dumping, "
            "5) Lateral movement to internal file repository, and "
            "6) Scheduled external data exfiltration to 198.51.100.120."
        ),
        category="advanced_threat",
        severity="critical",
        expected_mitre_techniques=["T1566.002", "T1059.001", "T1548.003", "T1003", "T1021.002", "T1048"],
        associated_playbook_slug="ransomware-rapid-response",
        expected_response_actions=["isolate_endpoint", "block_ip"],
        expected_investigation_path=[
            "1. Ingest sequence of correlated alerts reflecting complete attack lifecycle.",
            "2. Consolidate into single enterprise master incident (INC-YYYY-XXXX).",
            "3. Enrich multiple cross-domain indicators (IPs, domain, SHA-256 hashes).",
            "4. Map full ATT&CK kill-chain tactics across the 6 mapped techniques.",
            "5. Execute multi-step containment playbook with manager four-eyes approvals.",
        ],
        synthetic_indicators=[
            SyntheticIndicator(
                ioc_type="ip",
                value="198.51.100.120",
                reputation="malicious",
                confidence=96,
                description="Simulated APT C2 & Staging Server (RFC 5737).",
            ),
            SyntheticIndicator(
                ioc_type="domain",
                value="portal-update.example.org",
                reputation="malicious",
                confidence=90,
                description="Simulated APT spearphishing domain.",
            ),
            SyntheticIndicator(
                ioc_type="sha256",
                value="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                reputation="malicious",
                confidence=99,
                description="Simulated APT stage-1 loader payload hash.",
            ),
        ],
        alerts=[
            SimulationAlertSpec(
                title="APT Stage 1: Spearphishing Link Clicked by Engineering Lead",
                description="User clicked spearphishing URL directing to adversary staging site portal-update.example.org.",
                source_system="email_gateway",
                rule_id="100201",
                rule_description="Inbound spearphishing link clicked by corporate user",
                event_category="social_engineering",
                severity="medium",
                domain="portal-update.example.org",
                username="eng.lead@sentinel-corp.internal",
                mitre_techniques=[{"id": "T1566.002", "name": "Spearphishing Link", "tactic": "initial-access"}],
                raw_payload={"stage": "initial_access", "target_user": "eng.lead", "is_simulated": True},
            ),
            SimulationAlertSpec(
                title="APT Stage 2: In-Memory PowerShell Payload Execution",
                description="Obfuscated PowerShell command downloaded secondary stage loader onto ENG-WS-012.",
                source_system="edr_sentinel",
                rule_id="92052",
                rule_description="EDR alert: Suspicious obfuscated PowerShell execution",
                event_category="execution",
                severity="high",
                hostname="ENG-WS-012",
                username="eng.lead",
                file_hash="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                mitre_techniques=[{"id": "T1059.001", "name": "PowerShell", "tactic": "execution"}],
                raw_payload={"stage": "execution", "host": "ENG-WS-012", "is_simulated": True},
            ),
            SimulationAlertSpec(
                title="APT Stage 3: Local Token Manipulation & Privilege Elevation",
                description="Attacker escalated privileges to NT AUTHORITY\\SYSTEM using token manipulation exploit.",
                source_system="edr_sentinel",
                rule_id="5402",
                rule_description="Host Security: Token privilege elevation anomaly",
                event_category="privilege_escalation",
                severity="high",
                hostname="ENG-WS-012",
                username="SYSTEM",
                mitre_techniques=[{"id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "privilege-escalation"}],
                raw_payload={"stage": "privilege_escalation", "host": "ENG-WS-012", "is_simulated": True},
            ),
            SimulationAlertSpec(
                title="APT Stage 4: Lateral Movement via SMB to Core File Server",
                description="Adversary leveraged dumped credentials to establish SMB session from ENG-WS-012 to CORP-FS-01.",
                source_system="network_sensor",
                rule_id="87901",
                rule_description="Network IDS: Lateral SMB connection using administrative service ticket",
                event_category="network",
                severity="critical",
                src_ip="10.40.10.12",
                dst_ip="10.20.10.1",
                hostname="CORP-FS-01",
                mitre_techniques=[{"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "lateral-movement"}],
                raw_payload={"stage": "lateral_movement", "source": "10.40.10.12", "destination": "10.20.10.1", "is_simulated": True},
            ),
            SimulationAlertSpec(
                title="APT Stage 5: Outbound Encrypted C2 Beaconing & Data Transfer",
                description="Correlated outbound exfiltration stream to external C2 node 198.51.100.120.",
                source_system="network_sensor",
                rule_id="87901",
                rule_description="Network IDS: High-entropy outbound connection to known APT infrastructure",
                event_category="exfiltration",
                severity="critical",
                src_ip="10.20.10.1",
                dst_ip="198.51.100.120",
                mitre_techniques=[{"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"}],
                raw_payload={"stage": "exfiltration", "destination": "198.51.100.120", "is_simulated": True},
            ),
        ],
        executive_summary_template=(
            "Coordinated multi-stage advanced persistent threat (APT) campaign detected and contained. "
            "Intrusion commenced with credential phishing and progressed through PowerShell execution, "
            "privilege elevation, lateral movement, and attempted exfiltration. "
            "All affected assets isolated and C2 network routes suppressed via approved response playbooks."
        ),
    ),
}


def list_available_scenarios() -> list[ScenarioDefinition]:
    """Return all 7 reproducible scenario definitions."""
    return list(SCENARIOS_CATALOG.values())


def get_scenario_definition(slug: str) -> ScenarioDefinition | None:
    """Retrieve a specific scenario definition by slug."""
    return SCENARIOS_CATALOG.get(slug)
