# SENTINEL IR — Security Architecture & Hardening Guide

## 1. Security Posture Overview

**SENTINEL IR** has been engineered in alignment with **OWASP Application Security Verification Standard (ASVS) 4.0 Level 2**. Every security control is enforced strictly on the backend with automated regression and penetration tests proving its resilience.

---

## 2. OWASP ASVS 4.0 Level 2 Compliance Matrix

| ASVS Section | Verification Requirement | Implementation Details in SENTINEL IR | Verified Test |
|---|---|---|---|
| **V2: Authentication** | V2.1.1 (Argon2id password hashing) | Uses `argon2-cffi` (`$argon2id$`) with salt, memory cost (64 MB), time cost (3 iterations). Timing mitigation via dummy password verification for invalid usernames. | `test_sec_01_argon2id_and_jwt_security` |
| **V2: Session Mgmt** | V2.2.1 (Short-lived JWTs + Rotation) | Access tokens expire in 15 minutes; refresh tokens rotate on each exchange. Refresh token reuse triggers immediate family revocation. | `test_sec_02_double_submit_csrf_and_refresh_reuse_revocation` |
| **V3: Access Control** | V3.1.1 (Server-side RBAC) | Centralized `ROLE_PERMISSION_MATRIX` enforced via FastAPI dependency injection (`require_permission`). Every route declares explicit permissions. | `test_sec_03_server_side_rbac_matrix_and_privilege_escalation` |
| **V4: Access Control** | V4.1.2 (IDOR / Multi-tenant Protection) | Sequential IDs combined with ownership and permission checks; state machine enforces valid state transitions. | `test_sec_04_idor_and_sql_injection_defense` |
| **V5: Validation** | V5.1.1 (SQL Injection Immunity) | All queries utilize parameterized SQLAlchemy 2.0 ORM expressions. Raw strings or dynamic string interpolations are prohibited. | `test_sec_04_idor_and_sql_injection_defense` |
| **V8: Data Integrity** | V8.1.1 (Audit Immutability & Hash Chain) | PostgreSQL trigger `prevent_append_only_mutation()` rejects `UPDATE/DELETE/TRUNCATE` on `audit_logs`. Each entry records SHA-256 hash linked to previous entry. | `test_sec_05_audit_immutability_and_hash_chain` |
| **V9: Communication** | V9.1.1 (CSRF & Security Headers) | Double-submit CSRF cookie + header validation on mutating requests. Headers include `X-Content-Type-Options: nosniff`, `Content-Security-Policy`, `X-Frame-Options: DENY`. | `test_sec_02_double_submit_csrf_and_refresh_reuse_revocation` |
| **V12: File Uploads** | V12.1.1 (Magic Byte & Binary Sniffing) | Evidence uploads strictly validate magic-byte signatures against declared MIME types. Disguised Windows PE, Linux ELF, and macOS Mach-O binaries are blocked. Path traversal is stripped. | `test_sec_07_forensic_evidence_magic_bytes_and_path_traversal` |
| **V13: API & Egress** | V13.1.1 (SSRF & Data Leakage Defense) | Indicators are inspected before external threat intelligence calls; RFC 1918, RFC 5737 test ranges, and internal domains are completely skipped. | `test_sec_08_rfc1918_private_indicator_leak_prevention` |

---

## 3. Authentication & Session Security

### 3.1 Key Derivation: Argon2id
All passwords are encrypted using Argon2id with memory-hardened parameters:
```python
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
```
To mitigate timing attacks that allow username enumeration, `verify_dummy_password()` executes an Argon2id comparison against a static hash when a user is not found in the database.

### 3.2 Token Lifecycle & Refresh Family Revocation
- **Access Tokens:** Signed with HMAC-SHA256, valid for 15 minutes. Decoded strictly with required claims (`sub`, `username`, `role`, `jti`, `exp`, `iat`, `iss`, `aud`).
- **Refresh Tokens:** Cryptographically random 64-byte tokens hashed via SHA-256 before storage in PostgreSQL (`refresh_tokens`). Valid for 7 days.
- **Reuse Detection:** Every refresh token exchange generates a new token in the same token family. If an already-exchanged token is presented again, the system recognizes a replay attack and revokes the **entire token family**, forcing all sessions for that lineage to authenticate again.

### 3.3 Account Lockout Policy
- 5 consecutive failed login attempts trigger an immediate account lockout (`locked_until = now + 15 minutes`).
- Lockouts are auditable and can be cleared manually by an `admin` user via `POST /api/v1/auth/users/{id}/unlock`.

---

## 4. Role-Based Access Control (RBAC) Matrix

The platform enforces four distinct SOC personas with granular permissions:

| Permission | L1 Analyst (`soc_l1`) | L2 Responder (`soc_l2`) | SOC Manager (`soc_manager`) | Platform Admin (`admin`) |
|---|:---:|:---:|:---:|:---:|
| `ALERTS_READ` / `ALERTS_TRIAGE` | Yes | Yes | Yes | Yes |
| `INCIDENTS_READ` / `INCIDENTS_UPDATE` | Yes | Yes | Yes | Yes |
| `INCIDENTS_CLOSE` | No | Yes | Yes | Yes |
| `INCIDENTS_REOPEN` | No | No | Yes | Yes |
| `EVIDENCE_UPLOAD` / `EVIDENCE_READ` | Yes | Yes | Yes | Yes |
| `EVIDENCE_WITHDRAW` | No | Yes | Yes | Yes |
| `THREAT_INTEL_READ` / `THREAT_INTEL_ENRICH` | Yes | Yes | Yes | Yes |
| `MITRE_READ` / `MITRE_MAP` | Yes | Yes | Yes | Yes |
| `PLAYBOOKS_READ` | Yes | Yes | Yes | Yes |
| `PLAYBOOKS_EXECUTE` (Dry Run / Run) | No | Yes | Yes | Yes |
| `RESPONSE_APPROVE_TIER1` | No | Yes | Yes | Yes |
| `RESPONSE_APPROVE_TIER2` | No | No | Yes | Yes |
| `AUDIT_READ` / `AUDIT_EXPORT` | No | No | Yes | Yes |
| `REPORTS_GENERATE` / `REPORTS_EXPORT` | No | Yes | Yes | Yes |
| `SIMULATION_RUN` | Yes | Yes | Yes | Yes |
| `SIMULATION_RESET` | No | No | Yes | Yes |
| `USERS_MANAGE` | No | No | No | Yes |

---

## 5. Four-Eyes Response Governance

Critical automated response actions (e.g. firewall rule modifications, endpoint isolation, account suspensions) require human authorization:
1. **Separation of Duties:** The user who triggers the playbook or response action is recorded as `requester_id`. The backend rejects any approval attempt where `approver_id == requester_id` with HTTP `403 FOUR_EYES_VIOLATION`.
2. **Approval Expiration:** Pending response actions specify a strict `expires_at` window (default: 30 minutes). Once expired, approval attempts are rejected with `APPROVAL_EXPIRED`.
3. **Database-Level Immutability:** Approvals are recorded in `response_approvals`. A database trigger blocks any `UPDATE` or `DELETE` on this table.

---

## 6. Forensic Evidence Integrity

Forensic artifacts are handled under strict evidentiary standards:
1. **Magic-Byte Sniffing:** Uploaded files are inspected for real magic bytes (e.g. `%PDF-`, `\x89PNG`, `\xFF\xD8\xFF`, `\xD4\xC3\xB2\xA1`). Mismatched or forged extensions are rejected.
2. **Executable Binary Rejection:** Even if disguised as `.log` or `.txt`, binaries matching Windows PE (`MZ`), Linux ELF (`\x7fELF`), or macOS Mach-O signatures are rejected with HTTP `400 DISGUISED_EXECUTABLE_REJECTED`.
3. **Streaming SHA-256 Hashing:** Files are hashed on the fly during upload in 64 KB memory chunks. The hash is recorded in `evidence.file_hash` and verified on retrieval.
4. **Path Traversal Prevention:** File names are stripped of directories and path separators (`../../`) and stored using deterministic UUIDs.
5. **Download Security:** Served with `Content-Disposition: attachment; filename="..."`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: sandbox`.

---

## 7. Cryptographic Audit Hash Chaining

The `audit_logs` table forms a tamper-evident cryptographic log chain:
1. **Chain Formula:**
   $$\text{entry\_hash} = \text{SHA-256}(\text{previous\_hash} + \text{id} + \text{user\_id} + \text{action} + \text{resource\_type} + \text{timestamp})$$
2. **Advisory Lock Concurrency:** Sequence assignment and hash chaining use PostgreSQL transaction-level advisory locks (`pg_advisory_xact_lock(0x53454E54)`) to prevent hash forks during high-throughput concurrent logging.
3. **Trigger Immunity:** PostgreSQL trigger `prevent_append_only_mutation()` prevents modification or deletion even by database superusers.
4. **Chain Verification:** The `/api/v1/audit/verify` endpoint computes and walks the entire chain from genesis to head, reporting broken links or altered payloads.

---

## 8. Network Egress & SSRF Protection

To ensure the platform cannot be leveraged for Server-Side Request Forgery (SSRF) or accidental exposure of private infrastructure:
- **Private IP Guard:** All indicator enrichment calls evaluate `is_internal_ip()` against:
  - RFC 1918 Private Ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Loopback (`127.0.0.0/8`)
  - RFC 5737 Test Ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
  - RFC 3849 IPv6 Documentation Range (`2001:db8::/32`)
- **Internal Domain Filter:** Internal suffixes (`.local`, `.internal`, `.lan`, `.corp`) are classified as internal and exempted from public threat queries.

