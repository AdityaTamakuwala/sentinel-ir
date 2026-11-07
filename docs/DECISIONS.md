# Architectural Decision Records (ADRs) — SENTINEL IR

This document records significant engineering and security design choices made during the construction of SENTINEL IR, including rationale and rejected alternatives.

---

## ADR-001: Single-Origin Browser Architecture via Next.js Reverse Proxy
- **Decision:** The browser communicates exclusively with the Next.js origin (`http://localhost:3000` in dev, TLS-terminated reverse proxy in prod). Next.js proxies `/api/*` requests server-side to FastAPI (`http://api:8000/api/*`), with a dedicated non-buffering Route Handler for `/api/v1/events/stream` (SSE).
- **Reason:** Eliminates cross-origin cookie issues (`SameSite=Strict` works natively), removes the need for permissive CORS rules, and keeps internal backend services unexposed to direct browser traffic.
- **Alternative Rejected:** Separate browser-facing API origin (`localhost:8000`) with `Access-Control-Allow-Credentials: true` and `SameSite=Lax`, which weakens CSRF posture and complicates cookie scoping.

---

## ADR-002: Cookie-Based JWT Authentication, Rotating Refresh Families, and Double-Submit CSRF
- **Decision:** Access tokens (short-lived, 15m) and refresh tokens (rotating, 7d) are stored in `httpOnly`, `SameSite=Strict` cookies (`Secure` enforced whenever `APP_ENV != development` or HTTPS is active). Refresh tokens are stored server-side as SHA-256 hashes grouped by `family_id`. Presenting an already-rotated refresh token triggers immediate revocation of the entire `family_id`. State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) using cookie auth must present an `X-CSRF-Token` header matching a readable `sentinel_csrf` cookie (cryptographically random token bound to session rotation).
- **Reason:** Storing tokens in `localStorage` exposes sessions to token exfiltration if any XSS ever occurs; `httpOnly` + `SameSite=Strict` + double-submit CSRF + refresh reuse detection provides defense-in-depth aligned with OWASP ASVS L2.
- **Alternative Rejected:** Bearer tokens in `localStorage` (vulnerable to XSS theft) or stateful server sessions without refresh reuse telemetry.

---

## ADR-003: Dual PostgreSQL Roles + Trigger + Advisory-Locked Hash Chain for Tamper-Evident Audit Logs
- **Decision:** PostgreSQL is provisioned with two database roles:
  1. `sentinel_owner` (`MIGRATION_DATABASE_URL`): schema owner used exclusively for Alembic migrations.
  2. `sentinel_app` (`DATABASE_URL`): runtime application role used by FastAPI and Celery workers, which has `SELECT, INSERT` on `audit_logs` and explicitly **no** `UPDATE`, `DELETE`, or `TRUNCATE` privileges on `audit_logs`.
  Additionally, a PostgreSQL `BEFORE UPDATE OR DELETE` trigger on `audit_logs` raises an exception even for privileged roles, and every `INSERT` acquires a transaction-scoped PostgreSQL advisory lock (`pg_advisory_xact_lock`) to compute a strictly linear SHA-256 hash chain (`prev_hash` → `entry_hash` ordered by `seq`).
- **Reason:** Guarantees both privilege separation and cryptographic tamper evidence without race conditions under concurrent API traffic.
- **Alternative Rejected:** Application-only immutability (bypassable via raw SQL if app DB credentials leak) or unlocked `MAX(seq)` hash chaining (prone to chain forks under concurrent transactions).

---

## ADR-004: Next.js 14.2 LTS + React 18.3 Frontend Runtime
- **Decision:** Pin Next.js `14.2.x` with React `18.3.x`, TypeScript `5.x`, Tailwind CSS `3.4`, TanStack Query `5.x`, Recharts `2.x`, and Radix UI primitives.
- **Reason:** Recharts 2.x and Radix UI primitives have mature, battle-tested peer compatibility and deterministic standalone Docker builds on React 18.3 + Next 14.2 App Router without experimental React 19 hydration or peer-dependency workarounds.
- **Alternative Rejected:** Bleeding-edge React 19 RC / Next 15 combinations requiring `--legacy-peer-deps` for charting libraries.

---

## ADR-005: Declarative YAML Playbook Engine with Database-Persisted `WAITING_APPROVAL` Checkpoints
- **Decision:** Playbooks are declarative YAML definitions validated by Pydantic schemas and versioned in `playbook_versions`. Execution steps resolve against a Python `StepRegistry`. When an execution encounters `require_approval`, the step creates a `PROPOSED`/`PENDING_APPROVAL` `ResponseAction`, persists the current `step_index` and `context_state` JSONB to `playbook_executions` with status `WAITING_APPROVAL`, and exits the Celery worker cleanly rather than blocking a worker thread. Approval or rejection dispatches a resume Celery task from the persisted checkpoint.
- **Reason:** Blocking Celery workers on human approvals causes worker starvation and loses execution state on container restarts. Checkpoint persistence makes executions durable across full API and worker restarts.
- **Alternative Rejected:** Hardcoded per-playbook Python functions or long-polling sleep loops inside Celery tasks.

---

## ADR-006: Pinned Offline MITRE ATT&CK Enterprise STIX 2.1 Subset & Source-Tracked Mappings
- **Decision:** Vendor a pinned, curated MITRE ATT&CK Enterprise STIX 2.1 bundle (`v15.1`, `data/mitre/enterprise-attack-v15.1.json`) in the repository covering all Enterprise tactics (`TA0001`–`TA0043`) and core enterprise techniques/sub-techniques, loaded idempotently into `mitre_techniques` offline. Every `incident_techniques` mapping records `source` (`alert_metadata`, `enrichment`, `playbook_rule`, `analyst`) and `status` (`suggested` vs `confirmed`).
- **Reason:** Ensures air-gapped / offline reproducibility, fast deterministic startup, explicit provenance for every ATT&CK tag, and prevents fabricated or hallucinated technique assignments.
- **Alternative Rejected:** Fetching STIX JSON over the network at container startup (fails in offline/sandboxed SOC environments).

---

## ADR-007: Safe Simulated Response Adapter by Default
- **Decision:** All containment/response actions execute exclusively after RBAC + four-eyes approval (`requested_by_id != approved_by_id`, unexpired) through a `ResponseAdapter` interface. Only `SimulatedResponseAdapter` is registered as active by default, tagging every execution `is_simulated: true` and recording structured dry-enforcement telemetry.
- **Reason:** Prevents accidental host isolation, account lockout, or firewall changes while proving the full SOAR approval, state machine, and adapter architecture.
- **Alternative Rejected:** Calling live OS commands or external active-response endpoints by default.

---

## ADR-008: Modular Threat Intelligence Pipeline with Strict RFC 1918 Leak Guard & Sliding-Window Redis Rate Limiting
- **Decision:** All threat intelligence lookups pass through a centralized `EnrichmentService` managing a registry of providers (`VirusTotalAdapter`, `AbuseIPDBAdapter`, `AlienVaultOTXAdapter`, `MockThreatIntelProvider`). Before any provider is consulted, `is_internal_indicator` inspects IPv4/IPv6 private/loopback/link-local ranges (RFC 1918, RFC 3927, RFC 4193) and intranet domains (`.local`, `.internal`, `.corp`, `bank.corp`). Internal indicators immediately return `not_applicable_internal` without invoking external APIs or Redis cache. Valid external indicators are checked against a 24-hour Redis cache and throttled via Redis sliding-window token buckets before invoking external HTTP endpoints.
- **Reason:** Guarantees zero internal data leakage to public third-party threat feeds, prevents API rate quota exhaustion, and accelerates SOC triage workflows via low-latency Redis caching.
- **Alternative Rejected:** Direct unconstrained outbound API calls from frontend or individual services without internal filtering.

---

## ADR-009: Non-Blocking Celery Checkpoint Persistence (`WAITING_APPROVAL`) & Resume Protocol
- **Decision:** Playbook executions persist current step index, `context_state` JSONB, and `waiting_response_action_id` with status `WAITING_APPROVAL`, cleanly exiting the Celery worker without blocking worker threads. Human approval or rejection dispatches a resume Celery task that re-hydrates execution state and advances from the persisted checkpoint.
- **Reason:** Blocking worker threads on human approvals causes worker starvation and loses execution state during container or worker restarts. Checkpoint persistence makes executions durable across full system restarts.
- **Alternative Rejected:** Long-polling sleep loops inside Celery tasks or stateful in-memory workflow orchestrators.

---

## ADR-010: Backend-Enforced Four-Eyes Governance & Tiered Containment Authorization
- **Decision:** Under no circumstances may `requested_by_id == approved_by_id` (enforced at API/engine layer with HTTP 403 `FOUR_EYES_VIOLATION`). Low/medium impact containment actions require at least `response:approve_low` (SOC L2+), while high and critical impact actions strictly require `response:approve_all` (SOC Manager or Admin). Every approval or rejection is recorded as an immutable row in `response_approvals` and chained into the advisory-locked audit log.
- **Reason:** Enforces strict separation of duties and prevents accidental or malicious unilateral fleet-wide containment actions.
- **Alternative Rejected:** Client-side only approval restrictions or unilateral automated execution without human governance.

---

## ADR-011: Simulation Isolation, Real Ingestion Path & Synthetic Safe Ranges
- **Decision:** All 7 incident simulation scenarios enter the platform strictly through the authentic ingestion pipeline (`AlertService.ingest_normalized_alert` and `IncidentService.create_incident`). All simulated entities are explicitly tagged with `is_simulated: true` and simulation prefixing (`[SIMULATION]`). All network addresses use IANA documentation test ranges (RFC 5737 `198.51.100.0/24`, `203.0.113.0/24`, RFC 3849 `2001:db8::/32`) and synthetic hashes, completely preventing real external system engagement. Reset operations (`POST /api/v1/simulations/reset`) strictly filter by `is_simulated == true` and preserve non-simulated operational records.
- **Reason:** Exercises true production pipeline logic, deduplication, triage, correlation, and automated playbook triggers without risking external network communication or corrupting production telemetry.
- **Alternative Rejected:** Bypassing ingestion via mock database inserts or using unconstrained/real IP addresses.

---

## ADR-012: Cryptographically Hashed Multiformat Reporting (WeasyPrint PDF, Versioned JSON, OASIS STIX 2.1)
- **Decision:** Implement a three-tier incident reporting engine:
  1. Print-ready WeasyPrint PDF reports rendered via Jinja2 with `@page` CSS running headers, TLP classification badges, and a prominent "SIMULATED INCIDENT" diagonal watermark on simulated records.
  2. Schema-validated canonical JSON export (`schema_version: "1.0.0"`).
  3. OASIS STIX 2.1 compliant bundles (`bundle--<uuid>`) encapsulating `identity`, `incident`, `indicator`, `attack-pattern`, `observed-data`, and `relationship` SDOs/SROs.
  All generated report files compute SHA-256 hashes stored in `incident_reports` for chain-of-custody verification.
- **Reason:** Provides executive-ready PDF artifacts, machine-readable interoperability, and threat-sharing compliance (STIX 2.1) with cryptographic integrity verification.
- **Alternative Rejected:** Client-side PDF rendering (unstable font layout and lack of server-side SHA-256 signing).

---

## ADR-014: Final Security Hardening, Automated Playwright E2E Verification & Release Readiness
- **Decision:** Implement an end-to-end multi-persona verification suite combining Playwright browser testing (covering all 8 core SOC workflows from authentication to four-eyes approvals, attack simulations, and multi-format reports) with an automated security audit test suite (`test_m6_security_audit.py`). Security verification validates Argon2id key derivation, JWT signature expiration, double-submit CSRF tokens, refresh-token family reuse revocation, server-side RBAC matrix boundaries, IDOR defenses, SQL injection immunity via parameterized SQLAlchemy queries, append-only immutable triggers on audit/approvals, file upload magic-byte sniffing (blocking disguised PE/ELF/Mach-O binaries and directory traversal), and RFC 1918 / RFC 5737 egress isolation.
- **Reason:** Guarantees that the entire multi-container enterprise stack (FastAPI, Next.js App Router, PostgreSQL, Redis, Celery workers) functions cohesively under realistic SOC analyst workloads while meeting OWASP ASVS 4.0 Level 2 enterprise security controls without regressions.
- **Alternative Rejected:** Relying solely on isolated backend unit tests or manual browser testing.




