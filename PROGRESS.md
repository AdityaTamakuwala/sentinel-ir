# SENTINEL IR — Engineering Progress Log

> Maintained per Section 0.1 Rule 3. Updated after every milestone gate with verified build/test results, known issues, and next actions.

## Current Status
- **Active Milestone:** ALL MILESTONES COMPLETE (M0–M6)
- **Last Verified Gate:** M6 — Hardening, E2E Testing, Security Audit & Release Readiness (PASSED 2026-11-08)

---

## Milestone Tracker

| Milestone | Scope | Gate Status | Verified Command & Result |
|---|---|---|---|
| **M0: Foundations** | Repo structure, Docker Compose (dev + prod), `.env.example`, health/readiness/metrics endpoints, structured JSON logging with correlation IDs, `PROGRESS.md`, `docs/DECISIONS.md`, CI skeleton | **PASSED** | `docker compose up -d --build --wait` (6/6 healthy), `pytest backend/tests -v` (3 passed), `npm --prefix frontend test && npm --prefix frontend run build` (1 passed, build ok), `ruff`/`mypy`/`bandit` (0 errors) |
| **M1: Vertical Slice** | Normalized DB models + Alembic migrations, Argon2id/JWT cookie auth + CSRF + refresh rotation/reuse detection + lockout, RBAC permission matrix, tamper-evident hash-chained `audit_logs`, manual + HMAC Wazuh ingestion + dedupe, Alert Inbox & Triage Workbench, Incident creation + timeline, live dashboard queries, shell + generated API client | **PASSED** | `docker compose up -d --build --wait` (6/6 healthy), `.venv/bin/pytest backend/tests -v` (8 passed in 5.39s), `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` (3 passed, 11 routes built), `ruff`/`mypy`/`bandit`/`check-client` (0 errors), live proxy smoke (`total_alerts=5 open_incidents=1 audit_entries=14`) |
| **M2: Incident Lifecycle & Investigation** | Full state machine (`NEW` → `CLOSED` + reopen), assignment, escalation, revisioned notes, streaming SHA-256 evidence management + chain of custody, incident linking, explainable risk scoring + overrides, SLA tracking, optimistic concurrency, Redis-backed SSE live events, in-app notification centre | **PASSED** | `docker compose up -d --build --wait` (6/6 healthy), `.venv/bin/pytest backend/tests -v` (13 passed in 7.71s), `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` (3 passed, 13 routes built), `ruff`/`mypy` (0 errors in 51 files), live proxy smoke (`[M2 DOCKER SMOKE OK] total_evidence=4 sse_ready=True`) |
| **M3: Enrichment & MITRE** | Modular threat enrichment engine (mock + VT, AbuseIPDB, OTX), Redis cache + token-bucket rate limiter, RFC1918/internal indicator skip, pinned offline MITRE ATT&CK STIX loader, ATT&CK Explorer, incident mapping (`suggested` vs `confirmed`) | **PASSED** | `docker compose up -d --build --wait` (6/6 healthy), `.venv/bin/pytest backend/tests -v` (18 passed in 9.71s), `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` (3 passed, 15 routes built), `ruff`/`mypy` (0 errors in 64 files), live proxy smoke (`[M3 DOCKER SMOKE OK] mitre_tactics=14 total_techs=637 total_iocs=5`) |
| **M4: Playbooks & Approvals** | Declarative YAML playbook engine, reusable step registry, 5 core playbooks + 6th zero-code playbook, dry-run/idempotency/retry/branching, persistent `WAITING_APPROVAL` across restarts, human-approved response actions, four-eyes rule, approval expiry, safe simulated adapter, 3 Next.js UI routes | **PASSED** | `docker compose up -d --build --wait` (6/6 healthy), `.venv/bin/pytest backend/tests -v` (25 passed in 14.37s), `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` (3 passed, 17 routes built), `ruff`/`mypy`/`bandit`/`check-client` (0 errors in 75 files), live proxy smoke (`[M4 DOCKER SMOKE OK] total_playbooks=6 synced_count=6 dry_run_status=COMPLETED total_executions=1`) |
| **M5: Simulation, Reports & Analytics** | 7 realistic scenarios via real ingestion pipeline, Scenario Launcher UI/API, golden-path seeded incident, WeasyPrint PDF + JSON + STIX 2.1 report exports, SOC analytics reconciliation, Slack/Teams webhook adapter | **PASSED** | `docker compose up -d --build --wait` (6/6 healthy), `.venv/bin/pytest backend/tests -v` (33 passed in 19.97s), `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` (3 passed, 20 routes built), `ruff`/`mypy`/`bandit`/`check-client` (0 errors in 96 files), live proxy smoke (7 scenarios, PDF/STIX generated, SQL analytics verified) |
| **M6: Hardening & Completion** | Comprehensive Playwright E2E suite (8 workflows), ASVS L2 security audit suite (8 tests), static/dependency/contract scans, Next.js 24-route production build, ADR-014, complete documentation suite (README, ARCHITECTURE, SECURITY, DEMO_GUIDE, TESTING, DEPLOYMENT) | **PASSED** | `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv/bin/pytest backend/tests -v` (41/41 passed in 19.77s), `npm --prefix frontend run test:e2e` (8/8 passed in 9.1s), `npm --prefix frontend test` (3 passed), `npm --prefix frontend run build` (24 routes built), `ruff`/`bandit`/`check-client` (0 errors) |

---

## Milestone Log

### M0 — Foundations (PASSED)
- **Completed:**
  - Repository layout, `.gitignore`, `.dockerignore`, `.env.example`, `scripts/init_dev_env.py` (cryptographic `.env` generator), `Makefile`, `.github/workflows/ci.yml`.
  - Dual-role PostgreSQL provisioning script (`deploy/postgres/init-db.sh` creating `sentinel_owner` + least-privilege `sentinel_app`).
  - `docker-compose.yml` and `docker-compose.prod.yml` (non-root users, read-only rootfs where practical, resource limits, production safety refusal).
  - FastAPI M0 core (`app/main.py`, `app/core/config.py`, `app/core/logging.py`, `app/core/middleware.py`, `app/core/errors.py`, `app/core/celery_app.py`, `app/api/health.py`).
  - Next.js 14.2 App Router M0 foundation with single-origin reverse proxy (`src/app/api/[...path]/route.ts`) preserving multi-cookie `Set-Cookie`, CSRF, binary streams, and SSE streams.
  - Deterministic OpenAPI-to-TypeScript client generator (`scripts/generate_openapi_client.py` + `--check`).
- **Gate Commands & Verified Results:**
  - `docker compose up -d --build --wait` → All 6 containers (`postgres`, `redis`, `api`, `worker`, `beat`, `web`) `Up (healthy)`, including live `celery inspect ping`.
  - `curl -fsS http://127.0.0.1:8000/health/live`, `http://127.0.0.1:8000/health/ready`, `http://127.0.0.1:3000/api/healthz`, `http://127.0.0.1:3000/api/health/ready` → HTTP 200 with PostgreSQL `up` and Redis `up`.
  - `.venv/bin/pytest backend/tests -v` → `3 passed in 0.70s`.
  - `.venv/bin/ruff check backend/app backend/tests scripts && .venv/bin/mypy --config-file backend/pyproject.toml backend/app && .venv/bin/bandit -r backend/app -ll -q` → `All checks passed! Success: no issues found in 16 source files`.
  - `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` → `1 passed`, production standalone build succeeded.

### M1 — Vertical Slice (PASSED)
- **Completed:**
  - Normalized 36-table SQLAlchemy 2.x schema (`backend/app/models/`) and Alembic revision `0001_initial_schema` with `prevent_append_only_mutation()` triggers and revoked `UPDATE/DELETE/TRUNCATE` privileges on `audit_logs` and `response_approvals` for `sentinel_app`.
  - Argon2id authentication, rotating refresh-token families with reuse detection, 5-attempt account lockout + Admin unlock, TOTP MFA enrollment endpoints, `httpOnly` + `SameSite=Strict` cookies, and double-submit CSRF enforcement.
  - Centralized `ROLE_PERMISSION_MATRIX` across `soc_l1`, `soc_l2`, `soc_manager`, and `admin`, with automated route-by-role guard verification across every FastAPI route.
  - Advisory-locked SHA-256 hash-chained `AuditService` + `/api/v1/audit/verify` and CSV/JSON export.
  - Manual alert creation, JSON batch import, HMAC-SHA256 Wazuh webhook (`/api/v1/ingest/wazuh`) with timestamp window + Redis replay nonce guard, deterministic deduplication (`occurrence_count` + `AlertOccurrence`), Wazuh integrator script (`integrations/wazuh/custom-sentinel-ir.py`), and Triage Workbench.
  - Incident creation (`INC-YYYY-NNNN`), duplicate open-incident guard (`409`), timeline, notes, Command Centre analytics (`MTTA`/`MTTR`/`SLA`), dev data seeder (`backend/scripts/seed_dev_data.py`), regenerated OpenAPI TypeScript SDK, and 11 live Next.js App Router pages (`/`, `/login`, `/alerts`, `/alerts/[id]`, `/alerts/[id]/triage`, `/triage`, `/incidents`, `/incidents/[id]`, `/audit`, `/analysts`, `/profile`).
- **Gate Commands & Verified Results:**
  - `.venv/bin/python scripts/generate_openapi_client.py --check && .venv/bin/ruff check backend/app backend/tests backend/scripts scripts && .venv/bin/mypy --config-file backend/pyproject.toml backend/app backend/tests && .venv/bin/bandit -r backend/app -ll -q` → `0 errors across 50 source files`.
  - `.venv/bin/pytest backend/tests -v` → `8 passed in 5.39s` (clean Alembic `upgrade -> downgrade -> upgrade`, cookie/CSRF/lockout/token-reuse, RBAC matrix, `audit_logs` SQL & ORM immutability + chain verification, Wazuh HMAC valid/bad-sig/stale/replay/dedupe, duplicate incident `409`, Command Centre DB reconciliation).
  - `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` → `2 test files / 3 tests passed`, standalone Next.js build succeeded.
  - `/opt/homebrew/bin/docker compose up -d --build --wait --force-recreate api worker beat web` → `6/6 containers Healthy`, live single-origin proxy verification passed (`[M1 DOCKER SMOKE OK] total_alerts=5 open_incidents=1 audit_entries=14`).
- **Partially Done / Deferred to M2+:**
  - Deferred M2 deliverables completed in M2.
- **Known Issues:**
  - `next@14.2.35` advisory evaluation tracked for M6 hardening.
- **Next Milestone:** M2 — Incident Lifecycle & Investigation.

### M2 — Incident Lifecycle & Investigation (PASSED)
- **Completed:**
  - Strict incident state machine progression: `NEW` → `TRIAGED` → `INVESTIGATING` → `CONTAINMENT` → `ERADICATION` → `RECOVERY` → `RESOLVED` → `CLOSED`.
  - Enforced RBAC and validation on closure (`closure_category` + `closure_justification` >= 10 chars, `incidents:close`) and reopening (`incidents:reopen_closed`, reason >= 5 chars, resets `closed_at`).
  - Optimistic concurrency control via integer `version` field; conflicting concurrent patches reject with HTTP `409 OPTIMISTIC_LOCK_CONFLICT`.
  - Forensic evidence preservation system: streaming SHA-256 calculation, strict magic-byte allowlist (`.png`, `.jpg`, `.pdf`, `.pcap`, `.pcapng`, `.json`, `.txt`, `.log`, `.csv`), disguised binary PE/ELF/Mach-O detection, path traversal rejection, immutable versioning increments, complete chain-of-custody logging, and soft withdrawal.
  - Secure evidence download endpoint enforcing `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: sandbox`.
  - Authenticated Server-Sent Events (SSE) live streaming (`GET /api/v1/events/stream`) backed by Redis Pub/Sub (`sentinel:sse:broadcast`) with 15s heartbeats, role filtering, and `Last-Event-ID` catch-up replay from circular history list.
  - In-App Notification Center (`GET /api/v1/notifications`, `POST /api/v1/notifications/{id}/read`, `POST /api/v1/notifications/read-all`).
  - Frontend Investigation Workbench (`/workbench`, `/incidents/[id]/workbench`), Forensic Evidence Repository (`/evidence`, `/incidents/[id]/evidence`), and SVG attack surface Entity Relationship Topology Graph with interactive inspection drawer.
  - Header telemetry live indicator with automatic backoff reconnection (`LIVE SSE` / `RECONNECTING` / `SYNC ACTIVE`) and query cache invalidation on domain events.
- **Gate Commands & Verified Results:**
  - `.venv/bin/pytest backend/tests -v` → `13 passed in 7.71s` (state machine transitions + illegal jumps + closure/reopen guards, optimistic concurrency lock conflicts, forensic sniffing/traversal/custody/versions/withdrawal, authenticated SSE + `Last-Event-ID` replay, notification lifecycle).
  - `.venv/bin/ruff check backend && .venv/bin/mypy backend/app` → `0 errors across 51 source files`.
  - `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` → `2 test files / 3 tests passed`, 13 Next.js pages built cleanly.
  - `/opt/homebrew/bin/docker compose up -d --build --wait --force-recreate api worker beat web` → `6/6 containers Up (healthy)`.
  - Live Docker smoke test via Next.js reverse-proxy: `[M2 DOCKER SMOKE OK] user=l1.analyst role=soc_l1 total_evidence=4 unread_notifs=0 sse_ready=True`.
- **Known Issues:** None.
- **Next Milestone:** M3 — Threat Intelligence Enrichment & MITRE ATT&CK Engine.

### M3 — Threat Intelligence Enrichment & MITRE ATT&CK Engine (PASSED)
- **Completed:**
  - Vendored pinned official MITRE ATT&CK Enterprise STIX 2.1 dataset (`v15.1`, `data/mitre/enterprise-attack-15.1.json`, 41MB) covering all 14 tactics and 780 enterprise techniques/subtechniques.
  - Implemented offline STIX loader in `backend/app/services/mitre_service.py` with idempotent PostgreSQL bulk upserts (`mitre_techniques`).
  - Built Enterprise ATT&CK matrix aggregator (`GET /api/v1/mitre/matrix`) grouping techniques across the 14 tactics in kill-chain order with active incident coverage telemetry.
  - Built technique search, pagination, and detail endpoints (`GET /api/v1/mitre/techniques`, `GET /api/v1/mitre/techniques/{id}`).
  - Built incident technique mapping with full lifecycle (`suggested` vs `confirmed` vs `rejected`), RBAC enforcement (`mitre:map` for L1+, `mitre:confirm` strictly restricted to L2/Manager/Admin), real-time SSE broadcasts, and audit logging.
  - Architected modular threat intelligence provider system with `ThreatIntelProvider` interface and adapters for `VirusTotalAdapter` (v3 API), `AbuseIPDBAdapter` (v2 API), `AlienVaultOTXAdapter` (v1 API), and `MockThreatIntelProvider` (high-fidelity deterministic offline dataset).
  - Built strict RFC 1918 & intranet safety filter (`is_internal_indicator`), guaranteeing private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, IPv6 private) and internal domains are NEVER transmitted to external APIs, returning `status="not_applicable_internal"`.
  - Implemented Redis 24-hour TTL indicator caching and sliding-window token-bucket rate limiter (`check_provider_rate_limit`).
  - Built indicator lookup API (`POST /api/v1/enrichment/lookup`), incident batch enrichment (`POST /api/v1/incidents/{id}/enrich`), indicators catalog (`GET /api/v1/enrichment/indicators`), and threat intelligence statistics (`GET /api/v1/enrichment/stats`).
  - Built two enterprise frontend experiences:
    - `/intelligence`: Threat Intelligence Explorer, on-demand indicator lookup bar, metrics cards, indicators catalog with reputation/confidence badges, and slide-over indicator inspection drawer with per-provider breakdown.
    - `/mitre`: Interactive Enterprise Matrix Navigator across 14 tactics, incident coverage heatmap badges, search & sub-technique filtering, and slide-over technique inspection drawer with mitigation and detection guidance.
    - Updated `/incidents/[id]` with interactive MITRE mapping modal, L2+ confirmation/rejection actions, and on-demand indicator batch enrichment.
- **Gate Commands & Verified Results:**
  - `.venv/bin/pytest backend/tests -v` → `18 passed in 9.71s` (RFC 1918 safety guard, on-demand enrichment + Redis 24h caching, sliding-window rate limiter, offline STIX loader + 14-tactic matrix + search, technique mapping + L2 confirmation RBAC).
  - `.venv/bin/ruff check backend && .venv/bin/mypy backend/app` → `0 errors across 64 source files`.
  - `python scripts/generate_openapi_client.py --check` → `OK: Committed OpenAPI spec and TypeScript client match FastAPI schema`.
  - `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` → `2 test files / 3 tests passed`, 15 Next.js App Router pages built cleanly.
  - `/opt/homebrew/bin/docker compose up -d --build --wait --force-recreate api worker beat web` → `6/6 containers Up (healthy)`.
  - Live Docker smoke test via Next.js reverse-proxy: `[M3 DOCKER SMOKE OK] mitre_tactics=14 total_techs=637 total_iocs=5 internal_guard_ok=True`.
- **Known Issues:** None.
- **Next Milestone:** M4 — Playbooks & Approvals.

### M4 — Playbooks & Approvals (PASSED)
- **Completed:**
  - Authored the five core declarative YAML playbooks in `playbooks/`:
    - `PB-001-phishing-investigation.yaml`: domain/URL threat lookup, email quarantine, manager-approved user suspension, and SOC alerting.
    - `PB-002-endpoint-malware-containment.yaml`: hash reputation lookup, process termination, L2-approved host isolation, and fleet-wide hash blocking.
    - `PB-003-brute-force-credential-stuffing.yaml`: IP reputation & RFC 1918 guard, perimeter IP drop approval, session token revocation, and mandatory password reset.
    - `PB-004-unauthorized-access-investigation.yaml`: rogue IP lookup, active token termination, manager-approved account suspension, and P1 severity escalation.
    - `PB-005-ransomware-rapid-response.yaml`: critical priority escalation, vssadmin process termination, emergency host isolation, and C2 egress block.
    - `PB-006-data-exfiltration-triage.yaml`: verified that adding a sixth playbook requires ONLY a YAML definition file when existing step types suffice.
  - Built extensible `StepRegistry` mapping declarative step types to async handlers with parameter templating (`{{ ... }}`) and condition evaluation (`evaluate_condition`).
  - Built durable `PlaybookEngine` managing execution lifecycles (`PENDING` → `RUNNING` → `WAITING_APPROVAL` / `COMPLETED` / `FAILED` / `CANCELLED` / `EXPIRED`).
  - Implemented non-blocking Celery worker checkpoint persistence (ADR-009): on steps requiring human approval, the engine persists step index and `context_state` JSONB, creates a pending `ResponseAction`, and exits cleanly without thread blocking.
  - Implemented backend-enforced four-eyes rule (ADR-010): `requested_by_id != approved_by_id` strictly enforced (`403 FOUR_EYES_VIOLATION`), with tiered authorization (`RESPONSE_APPROVE_LOW` for low/medium risk, `RESPONSE_APPROVE_ALL` for high/critical risk) and immutable records in `response_approvals`.
  - Implemented response approval expiration and scheduled expiry sweep in Celery Beat (`expire_stale_approvals`).
  - Implemented safe `SimulatedResponseAdapter` tagging all actions `is_simulated = True` with realistic mock command telemetry and zero host mutation.
  - Built API endpoints in `/api/v1/playbooks` (library, detail, sync, execute, executions, cancel) and `/api/v1/responses` (actions, detail, propose, approve, reject).
  - Built three enterprise frontend pages:
    - `/playbooks`: Tabbed view for Playbook Library (grid, category badges, triggers, execution launcher with dry-run toggle) and Execution Monitor (live status table, step trace drawer).
    - `/playbooks/[slug]`: Workflow visualizer with sequential pipeline diagram, step parameters inspection, and raw YAML viewer.
    - `/responses`: Human Approval Queue with status/risk filters, four-eyes violation detection badges, simulated command previews, and decision modal.
    - Added "Orchestration & SOAR" section to App Shell navigation.
- **Gate Commands & Verified Results:**
  - `.venv/bin/pytest backend/tests -v` → `25 passed in 14.37s` (full test suite across M0, M1, M2, M3, and M4, including YAML schema validation, dry-run mode, idempotency keys, WAITING_APPROVAL persistence, four-eyes rejection, role tiering, approval expiration, and simulated adapter safety).
  - `.venv/bin/ruff check backend && .venv/bin/mypy backend/app && .venv/bin/bandit -r backend/app -ll -q` → `0 errors across 75 source files`.
  - `python scripts/generate_openapi_client.py --check` → `OK: Committed OpenAPI spec and TypeScript client match FastAPI schema`.
  - `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` → `2 test files / 3 tests passed`, 17 Next.js App Router pages built cleanly.
  - `/opt/homebrew/bin/docker compose up -d --build --wait --force-recreate` → `6/6 containers Up (healthy)`.
  - Live Docker smoke test via Next.js reverse-proxy: `[M4 DOCKER SMOKE OK] total_playbooks=6 synced_count=6 dry_run_status=COMPLETED total_executions=1`.
- **Known Issues:** None.
- **Next Milestone:** M5 — Simulation, Reports & Analytics (COMPLETED).

### M5 — Simulation Scenarios, Reporting & SOC Analytics (PASSED)
- **Completed:**
  - Designed and implemented 7 reproducible incident simulation scenarios (`backend/app/services/simulation/scenarios.py`) entering strictly through the authentic ingestion pipeline (`AlertService.ingest_normalized_alert` and `IncidentService.create_incident`):
    - `s01_brute_force`: Perimeter Brute-Force & Credential Stuffing (Rule 5710, RFC 5737 `198.51.100.45`, triggers PB-003 `brute-force-credential-stuffing`).
    - `s02_endpoint_malware`: Endpoint Ransomware Dropper Detection (Rule 87105, synthetic SHA-256 dropper hash, triggers PB-002 `endpoint-malware-containment`).
    - `s03_phishing_campaign`: Executive Spearphishing Campaign (Rule 100201, domain `secure-login-portal.example.com`, triggers PB-001 `phishing-investigation`).
    - `s04_privilege_escalation`: Unauthorized Privilege Escalation on Bastion (Rule 5402, `dev_deploy` sudo exploit, triggers PB-004 `unauthorized-access-investigation`).
    - `s05_ransomware_activity`: Active Subnet Ransomware Outbreak (Rule 87105, `vssadmin.exe` volume shadow deletion, triggers PB-005 `ransomware-rapid-response`).
    - `s06_data_exfiltration`: Staged Proprietary Data Exfiltration (Rule 87901, 48.5 GB staged transfer, triggers PB-006 `data-exfiltration-triage`).
    - `s07_multi_stage_attack`: Multi-Stage APT Intrusion (5 correlated alerts across kill chain into 1 incident with 6 ATT&CK techniques).
  - Built `SimulationService` execution engine (`backend/app/services/simulation/engine.py`):
    - Catalog listing, scenario detail, and multi-mode launch (`full_chain`, `alerts_only`, `dry_run`).
    - Enforced safe test IP ranges (RFC 5737 `198.51.100.0/24`, `203.0.113.0/24`, RFC 3849 IPv6) and synthetic indicator generation.
    - Persistent simulation execution tracking in `simulation_executions` (`Alembic 0002_add_simulation_executions`).
    - Safe simulation reset (`POST /api/v1/simulations/reset`) strictly targeting `is_simulated == True` while preserving all operational records and respecting immutable `response_approvals` table ACLs.
  - Built comprehensive Incident Reporting Engine (`backend/app/services/reporting/`):
    - `IncidentReportCollector.collect_snapshot`: Gathers complete incident state, SLA compliance, response actions with four-eyes approvals, playbook trace, timeline, correlated alerts, notes, evidence with SHA-256 hashes, and ATT&CK mappings.
    - `WeasyPrintPdfGenerator`: Enterprise PDF generation with `@page` CSS running headers, TLP classification badges, and diagonal "SIMULATED INCIDENT" watermark.
    - `JsonReportGenerator`: Versioned canonical JSON export (`schema_version: "1.0.0"`).
    - `StixReportGenerator`: OASIS STIX 2.1 compliant bundles with `identity`, `incident`, `indicator`, `attack-pattern`, `observed-data`, and `relationship` SDOs/SROs.
    - `ReportingService`: Persists reports to `incident_reports`, computes cryptographic SHA-256 hashes, and provides streaming download with `Content-Disposition: attachment`, `nosniff`, and TLP headers.
  - Built SOC Command Analytics Engine (`backend/app/services/analytics_service.py`):
    - True SQL-driven metrics: MTTD, MTTA, MTTC, MTTR, SLA compliance rates, 30-day incident/alert trends, severity/status/category distributions, analyst workload, playbook success rates, and approval decision breakdowns.
  - Built Notification Dispatcher (`backend/app/services/notification_dispatcher.py`):
    - Formats Slack Block Kit and Microsoft Teams Adaptive Cards for approval requests and critical incident milestones.
  - Built 3 Next.js 14 App Router frontend pages:
    - `/simulations`: Scenario Catalog cards, parameter inspection, mode launcher, and live execution history.
    - `/simulations/[id]`: Live Scenario Execution Monitor with progressive step timeline, linked incident badge, and raw JSON log viewer.
    - `/reports`: Report Library, on-demand format generator modal (PDF, JSON, STIX 2.1), TLP classification selector, and instant cryptographic downloads.
    - `/analytics`: Executive SOC Analytics Dashboard with KPI scorecards, SLA compliance indicators, Recharts trends and distributions, and analyst workload distribution.
    - Updated App Shell navigation with Simulations, Reports, and Analytics links.
- **Gate Commands & Verified Results:**
  - `.venv/bin/pytest backend/tests -v` → `33 passed in 19.97s` (25 regression tests from M0–M4 + 8 M5 tests: scenario catalog, full-chain launch, multi-stage correlation, safe reset guardrail, WeasyPrint PDF, versioned JSON, OASIS STIX 2.1 bundle, database-reconciled analytics, and notification card formatting).
  - `.venv/bin/ruff check backend scripts` → `All checks passed!`.
  - `.venv/bin/mypy --config-file backend/pyproject.toml backend/app backend/tests` → `Success: no issues found in 96 source files`.
  - `.venv/bin/bandit -r backend/app -ll -q` → `0 security issues found`.
  - `.venv/bin/python scripts/generate_openapi_client.py --check` → `OK: Committed OpenAPI spec and TypeScript client match FastAPI schema`.
  - `npm --prefix frontend run typecheck && npm --prefix frontend test && npm --prefix frontend run build` → `2 test files / 3 tests passed`, 20 Next.js App Router routes built cleanly.
  - `DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock" /opt/homebrew/bin/docker compose up -d --build --wait --force-recreate` → `6/6 containers Up (healthy)`.
  - Live Docker smoke test via Next.js single-origin reverse proxy: `7 scenarios loaded, S-01 brute force launched, WeasyPrint PDF downloaded (29KB, %PDF-), STIX 2.1 bundle downloaded (13 objects), live SQL command-center and overview metrics verified`.
- **Known Issues:** None.
- **Next Milestone:** M6 — Hardening & Completion.

### M6 — Hardening, E2E Testing, Security Audit & Release Readiness (PASSED)
- **Completed:**
  - Automated Playwright End-to-End Suite (`frontend/e2e/workflows.spec.ts`):
    - Configured Playwright with headless Chromium against `http://127.0.0.1:3000`.
    - Automated 8 complete multi-persona user journeys:
      1. *Authentication:* Valid credentials, invalid password rejection, lockout handling, protected route redirection.
      2. *SOC Alert Triage:* Real-time alert list inspection, severity/status filters, triage workbench navigation, promotion to incident.
      3. *Incident Investigation:* Investigation workbench, timeline, note addition, indicator lookup, evidence vault.
      4. *SOAR Playbooks:* Playbook library browsing, declarative YAML step inspection, execution launch.
      5. *Four-Eyes Governance:* Response actions queue, self-approval prevention UI, manager authorization.
      6. *Incident Simulations:* 7-scenario catalog, parameter inputs, execution monitor.
      7. *Reports Engine:* Incident report generation modal, PDF binary and STIX 2.1 JSON bundle exports.
      8. *SOC Analytics:* Executive KPI scorecards, SLA compliance indicators, Recharts distributions, simulation data toggles.
  - Comprehensive ASVS L2 Security Audit Test Suite (`backend/tests/test_m6_security_audit.py`):
    - `test_sec_01_argon2id_and_jwt_security`: Memory-hardened Argon2id key derivation + JWT expiration signature enforcement (`jwt.ExpiredSignatureError`).
    - `test_sec_02_double_submit_csrf_and_refresh_reuse_revocation`: Double-submit CSRF cookie + header validation; instant token family revocation on refresh replay (`REFRESH_TOKEN_REUSE_DETECTED`).
    - `test_sec_03_server_side_rbac_matrix_and_privilege_escalation`: Server-side RBAC boundary testing across all 4 personas (`soc_l1`, `soc_l2`, `soc_manager`, `admin`).
    - `test_sec_04_idor_and_sql_injection_defense`: IDOR defense across unassigned/isolated incidents; SQL injection payload immunity in search queries.
    - `test_sec_05_audit_immutability_and_hash_chain`: Direct SQL `UPDATE/DELETE/TRUNCATE` rejection via `prevent_append_only_mutation()` trigger; advisory-locked SHA-256 hash chaining.
    - `test_sec_06_four_eyes_and_approval_immutability`: Requester self-approval rejection (`403 FOUR_EYES_VIOLATION`); approval record database immutability.
    - `test_sec_07_forensic_evidence_magic_bytes_and_path_traversal`: Magic-byte validation; path traversal stripping; rejection of disguised PE/ELF/Mach-O executables (`400 DISGUISED_EXECUTABLE_REJECTED`).
    - `test_sec_08_rfc1918_private_indicator_leak_prevention`: Strict private IP and internal domain exclusion from external threat lookups.
  - Static Code Quality, Security & Contract Audits:
    - Ruff linter: 0 errors across backend and scripts (`ruff check backend scripts`).
    - Bandit security scanner: 0 security vulnerabilities found (`bandit -r backend/app -ll -q`).
    - OpenAPI drift check: FastAPI schema and TypeScript client verified 100% in sync (`python scripts/generate_openapi_client.py --check`).
    - Frontend Next.js production build: All 24 App Router routes compiled cleanly (`npm --prefix frontend run build`).
  - Architecture Decision Record (ADR-014):
    - Added ADR-014 in `docs/DECISIONS.md` covering final security hardening, Playwright verification, and release gate.
  - Complete Enterprise Documentation Suite:
    - `README.md`: Executive overview, architecture diagram, feature matrix, quickstart, demo credentials, testing and API summary.
    - `docs/ARCHITECTURE.md`: Deep dive into component architecture, Celery workers, Redis pub/sub SSE, data models, STRIDE threat model, and TLP classification.
    - `docs/SECURITY.md`: OWASP ASVS 4.0 Level 2 compliance matrix, Argon2id parameters, refresh rotation, four-eyes rule, and evidence vault security.
    - `docs/DEMO_GUIDE.md`: 14-step interview and presentation runbook with persona transitions, exact UI clicks, and architecture talking points.
    - `docs/TESTING.md`: Complete verification guide covering 41 pytest tests, 3 Vitest tests, 8 Playwright E2E workflows, and static scanners.
    - `docs/DEPLOYMENT.md`: Production hardening guide, Docker Compose configurations (`docker-compose.yml` and `docker-compose.prod.yml`), environment variables reference, and disaster recovery.
- **Gate Commands & Verified Results:**
  - `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv/bin/pytest backend/tests -v` → `41 passed in 19.77s` (100% pass across M0–M6).
  - `npm --prefix frontend run test:e2e` → `8 passed (9.1s)`.
  - `npm --prefix frontend test -- --run` → `2 test files / 3 tests passed`.
  - `npm --prefix frontend run typecheck` → `0 errors`.
  - `npm --prefix frontend run build` → `Compiled successfully; 24 routes generated`.
  - `.venv/bin/ruff check backend scripts` → `All checks passed!`.
  - `.venv/bin/bandit -r backend/app -ll -q` → `0 issues found`.
  - `.venv/bin/python scripts/generate_openapi_client.py --check` → `OK: Committed OpenAPI spec and TypeScript client match FastAPI schema`.
- **Known Issues:** None.
- **Next Milestone:** Project Completed (All Milestones M0–M6 Verified and Passed).



