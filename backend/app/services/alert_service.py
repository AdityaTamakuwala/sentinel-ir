"""Alert Ingestion, Wazuh Webhook Verification, Normalization, Deduplication, and Triage Service."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import enforce_rate_limit
from app.core.security import decrypt_secret, sha256_hex
from app.db.session import get_redis_client
from app.models.alert import Alert, AlertOccurrence, Asset, WebhookSource
from app.models.investigation import InvestigationNote, NoteRevision
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event

# Documented deterministic Rule/Category -> MITRE ATT&CK technique fallback catalog
# (Used ONLY when explicit MITRE metadata is absent on the incoming alert; Wazuh rule.mitre takes precedence)
DETERMINISTIC_RULE_MITRE_MAP: dict[str, list[dict[str, str]]] = {
    "5710": [{"id": "T1110.001", "name": "Password Guessing", "tactic": "credential-access", "source": "playbook_rule"}],
    "5712": [{"id": "T1110", "name": "Brute Force", "tactic": "credential-access", "source": "playbook_rule"}],
    "5715": [{"id": "T1078", "name": "Valid Accounts", "tactic": "initial-access", "source": "playbook_rule"}],
    "92052": [{"id": "T1059.001", "name": "PowerShell", "tactic": "execution", "source": "playbook_rule"}],
    "87105": [{"id": "T1204.002", "name": "Malicious File", "tactic": "execution", "source": "playbook_rule"}],
    "5402": [{"id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "privilege-escalation", "source": "playbook_rule"}],
    "87901": [{"id": "T1071.004", "name": "DNS", "tactic": "command-and-control", "source": "playbook_rule"}],
    "100201": [{"id": "T1071.001", "name": "Web Protocols", "tactic": "command-and-control", "source": "playbook_rule"}],
}

RECOMMENDED_STEPS_BY_CATEGORY: dict[str, list[str]] = {
    "authentication": [
        "Verify source IP reputation and geolocation anomalies via Threat Enrichment.",
        "Check whether failed authentication bursts were followed by a successful session.",
        "Inspect target user privilege tier and recent MFA activity.",
    ],
    "malware": [
        "Query SHA-256 file hash across VirusTotal and internal EDR telemetry.",
        "Identify parent process tree and file creation origin on affected endpoint.",
        "Evaluate endpoint isolation via Human-Approved Response Action if malicious.",
    ],
    "execution": [
        "Decode command-line arguments and inspect parent-child process lineage.",
        "Check network connections initiated immediately following script execution.",
        "Preserve raw event log as immutable case evidence.",
    ],
    "privilege_escalation": [
        "Validate change ticket or administrative window for the target user and host.",
        "Inspect preceding authentication source and session commands.",
        "Escalate to Incident if unauthorized privilege elevation is suspected.",
    ],
    "network": [
        "Enrich external destination IP/domain across VirusTotal, AbuseIPDB, and OTX.",
        "Correlate other internal hosts communicating with the same external indicator.",
        "Assess volume, periodicity (beaconing), and protocol anomalies.",
    ],
    "dns": [
        "Analyze queried domain entropy, TLD reputation, and TXT/NULL record frequency.",
        "Correlate endpoint process responsible for DNS resolution.",
        "Block or sinkhole confirmed C2 domains via approved response workflow.",
    ],
}


def compute_alert_fingerprint(
    *,
    source_system: str,
    rule_id: str,
    src_ip: str | None,
    dst_ip: str | None,
    hostname: str | None,
    username: str | None,
    event_category: str,
) -> str:
    """Deterministic SHA-256 deduplication fingerprint per Section 4 Module B."""
    parts = [
        source_system.strip().lower(),
        rule_id.strip().lower(),
        (src_ip or "").strip().lower(),
        (dst_ip or "").strip().lower(),
        (hostname or "").strip().lower(),
        (username or "").strip().lower(),
        event_category.strip().lower(),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def map_wazuh_level_to_severity(level: int) -> str:
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 6:
        return "medium"
    return "low"


def infer_wazuh_category(groups: list[str], description: str) -> str:
    joined = " ".join(groups).lower() + " " + description.lower()
    if any(k in joined for k in ("authentication", "sshd", "pam", "win_authentication", "login", "brute")):
        return "authentication"
    if any(k in joined for k in ("malware", "virustotal", "trojan", "ransomware", "rootcheck", "defender")):
        return "malware"
    if any(k in joined for k in ("sudo", "privilege", "elevation", "admin_group", "uac")):
        return "privilege_escalation"
    if any(k in joined for k in ("powershell", "sysmon_event1", "command", "execution", "script")):
        return "execution"
    if any(k in joined for k in ("dns", "named", "sysmon_event22")):
        return "dns"
    if any(k in joined for k in ("firewall", "ids", "suricata", "network", "connection", "c2")):
        return "network"
    return "general"


def parse_wazuh_alert_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a real Wazuh alert JSON document into SENTINEL IR common alert fields."""
    rule = payload.get("rule") or {}
    agent = payload.get("agent") or {}
    data = payload.get("data") or {}
    syscheck = payload.get("syscheck") or {}

    rule_id = str(rule.get("id") or "wazuh-unknown")
    rule_level = int(rule.get("level") or 5)
    rule_desc = str(rule.get("description") or "Wazuh security alert")
    groups = [str(g) for g in (rule.get("groups") or []) if g]

    # Parse timestamp in UTC
    raw_ts = payload.get("timestamp")
    event_ts = datetime.now(UTC)
    if isinstance(raw_ts, str) and raw_ts.strip():
        try:
            normalized_iso = raw_ts.replace("Z", "+00:00")
            # Wazuh sometimes formats "+0000" without colon
            if len(normalized_iso) >= 5 and normalized_iso[-5] in ("+", "-") and ":" not in normalized_iso[-5:]:
                normalized_iso = f"{normalized_iso[:-2]}:{normalized_iso[-2:]}"
            parsed = datetime.fromisoformat(normalized_iso)
            event_ts = parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            event_ts = datetime.now(UTC)

    # Prefer MITRE ATT&CK mappings carried directly in Wazuh rule metadata
    mitre_raw = rule.get("mitre") or {}
    mitre_ids = [str(x) for x in (mitre_raw.get("id") or []) if x]
    mitre_techs = [str(x) for x in (mitre_raw.get("technique") or []) if x]
    mitre_tactics = [str(x) for x in (mitre_raw.get("tactic") or []) if x]

    mitre_mappings: list[dict[str, str]] = []
    if mitre_ids:
        for idx, tid in enumerate(mitre_ids):
            tname = mitre_techs[idx] if idx < len(mitre_techs) else tid
            ttactic = (
                mitre_tactics[idx].lower().replace(" ", "-")
                if idx < len(mitre_tactics)
                else (mitre_tactics[0].lower().replace(" ", "-") if mitre_tactics else "execution")
            )
            mitre_mappings.append(
                {
                    "id": tid.strip(),
                    "name": tname.strip(),
                    "tactic": ttactic,
                    "source": "alert_metadata",
                }
            )
    elif rule_id in DETERMINISTIC_RULE_MITRE_MAP:
        mitre_mappings = list(DETERMINISTIC_RULE_MITRE_MAP[rule_id])

    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or (data.get("win", {}).get("eventdata", {}).get("ipAddress") if isinstance(data.get("win"), dict) else None)
    )
    dst_ip = data.get("dstip") or data.get("dst_ip") or agent.get("ip")
    hostname = agent.get("name") or payload.get("hostname")
    username = (
        data.get("dstuser")
        or data.get("srcuser")
        or (data.get("win", {}).get("eventdata", {}).get("targetUserName") if isinstance(data.get("win"), dict) else None)
    )
    file_hash = (
        syscheck.get("sha256_after")
        or data.get("sha256")
        or (data.get("virustotal", {}).get("source", {}).get("sha256") if isinstance(data.get("virustotal"), dict) else None)
    )
    domain = data.get("dns", {}).get("question", {}).get("name") if isinstance(data.get("dns"), dict) else data.get("domain")

    category = infer_wazuh_category(groups, rule_desc)
    return {
        "external_alert_id": str(payload.get("id")) if payload.get("id") else None,
        "source_system": "wazuh",
        "rule_id": rule_id,
        "rule_description": rule_desc,
        "event_category": category,
        "event_timestamp": event_ts,
        "src_ip": str(src_ip).strip() if src_ip else None,
        "dst_ip": str(dst_ip).strip() if dst_ip else None,
        "hostname": str(hostname).strip() if hostname else None,
        "username": str(username).strip() if username else None,
        "file_hash": str(file_hash).strip().lower() if file_hash else None,
        "domain": str(domain).strip().lower().rstrip(".") if domain else None,
        "severity": map_wazuh_level_to_severity(rule_level),
        "mitre_mappings_raw": mitre_mappings,
        "raw_payload": payload,
        "is_simulated": bool(payload.get("_sentinel_simulated", False)),
        "scenario_slug": payload.get("_sentinel_scenario"),
    }


class AlertService:
    @staticmethod
    async def verify_wazuh_webhook(
        db: AsyncSession,
        *,
        raw_body: bytes,
        api_key: str | None,
        signature_header: str | None,
        timestamp_header: str | None,
        source_ip: str | None,
    ) -> WebhookSource:
        settings = get_settings()
        if len(raw_body) > settings.WEBHOOK_MAX_PAYLOAD_BYTES:
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "payload_too_large", "size": len(raw_body)},
            )
            await db.commit()
            raise AppError(
                code="PAYLOAD_TOO_LARGE",
                message="Webhook payload exceeds maximum allowed size.",
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        if not api_key or not signature_header or not timestamp_header:
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "missing_security_headers"},
            )
            await db.commit()
            raise AppError(
                code="WEBHOOK_AUTH_MISSING",
                message="Missing X-Sentinel-API-Key, X-Sentinel-Timestamp, or X-Sentinel-Signature header.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        key_hash = sha256_hex(api_key.strip())
        res = await db.execute(
            select(WebhookSource).where(
                WebhookSource.api_key_hash == key_hash,
                WebhookSource.is_active.is_(True),
            )
        )
        source = res.scalar_one_or_none()
        if source is None:
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "invalid_api_key"},
            )
            await db.commit()
            raise AppError(
                code="WEBHOOK_INVALID_KEY",
                message="Invalid or inactive webhook API key.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        await enforce_rate_limit(
            f"webhook:{source.id}",
            max_requests=source.rate_limit_per_minute,
            window_seconds=60,
        )

        try:
            ts_epoch = int(timestamp_header.strip())
        except ValueError as exc:
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                target_id=str(source.id),
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "malformed_timestamp"},
            )
            await db.commit()
            raise AppError(
                code="WEBHOOK_INVALID_TIMESTAMP",
                message="Invalid X-Sentinel-Timestamp epoch integer.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            ) from exc

        now_epoch = int(datetime.now(UTC).timestamp())
        tolerance = source.tolerance_seconds or settings.WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS
        if abs(now_epoch - ts_epoch) > tolerance:
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                target_id=str(source.id),
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "timestamp_outside_window", "skew_seconds": abs(now_epoch - ts_epoch)},
            )
            await db.commit()
            raise AppError(
                code="WEBHOOK_REPLAY_WINDOW_EXCEEDED",
                message="Webhook timestamp is outside the allowed replay window.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        shared_secret = decrypt_secret(source.encrypted_hmac_secret)
        signed_payload = timestamp_header.strip().encode("utf-8") + b"." + raw_body
        expected_hex = hmac.new(
            shared_secret.encode("utf-8"),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()

        provided_sig = signature_header.strip()
        if provided_sig.startswith("sha256="):
            provided_sig = provided_sig[len("sha256=") :]

        if not hmac.compare_digest(expected_hex, provided_sig.lower()):
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                target_id=str(source.id),
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "hmac_signature_mismatch"},
            )
            await db.commit()
            raise AppError(
                code="WEBHOOK_INVALID_SIGNATURE",
                message="HMAC-SHA256 signature verification failed.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        # Replay nonce guard in Redis so exact duplicate signed requests inside the window are rejected
        redis = get_redis_client()
        nonce_key = f"sentinel:webhook_nonce:{source.id}:{ts_epoch}:{expected_hex[:32]}"
        was_set = await redis.set(nonce_key, "1", ex=tolerance + 10, nx=True)
        if not was_set:
            await AuditService.record(
                db,
                action="ingest.webhook_rejected",
                target_type="webhook",
                target_id=str(source.id),
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "replayed_signature_nonce"},
            )
            await db.commit()
            raise AppError(
                code="WEBHOOK_REPLAY_DETECTED",
                message="Duplicate webhook signature replay rejected.",
                status_code=status.HTTP_409_CONFLICT,
            )

        source.last_used_at = datetime.now(UTC)
        return source

    @staticmethod
    async def ingest_normalized_alert(
        db: AsyncSession,
        normalized: dict[str, Any],
        *,
        actor: User | None = None,
        source_ip: str | None = None,
        deduplicate: bool = True,
    ) -> tuple[Alert, bool]:
        """Persist normalized alert or increment deduplicated occurrence within window.

        Returns `(alert, created_new)`.
        """
        settings = get_settings()
        now = datetime.now(UTC)

        category = str(normalized.get("event_category") or "general").strip().lower()
        source_system = str(normalized.get("source_system") or "manual").strip().lower()
        rule_id = str(normalized.get("rule_id") or "custom-001").strip()

        fingerprint = compute_alert_fingerprint(
            source_system=source_system,
            rule_id=rule_id,
            src_ip=normalized.get("src_ip"),
            dst_ip=normalized.get("dst_ip"),
            hostname=normalized.get("hostname"),
            username=normalized.get("username"),
            event_category=category,
        )

        event_ts: datetime = normalized.get("event_timestamp") or now
        if event_ts.tzinfo is None:
            event_ts = event_ts.replace(tzinfo=UTC)

        raw_payload = normalized.get("raw_payload")
        if not isinstance(raw_payload, dict):
            raw_payload = {"event": json.loads(json.dumps(normalized, default=str))}

        if deduplicate:
            window_cutoff = now - timedelta(minutes=settings.DEDUPLICATION_WINDOW_MINUTES)
            existing_res = await db.execute(
                select(Alert)
                .where(
                    Alert.fingerprint == fingerprint,
                    Alert.last_seen_at >= window_cutoff,
                    Alert.triage_status != "false_positive",
                )
                .order_by(Alert.last_seen_at.desc())
                .limit(1)
            )
            existing = existing_res.scalar_one_or_none()
            if existing is not None:
                existing.occurrence_count += 1
                existing.last_seen_at = max(existing.last_seen_at, event_ts, now)
                existing.version += 1
                occ = AlertOccurrence(
                    alert_id=existing.id,
                    occurred_at=event_ts,
                    ingested_at=now,
                    raw_payload=raw_payload,
                )
                db.add(occ)
                await AuditService.record(
                    db,
                    action="alert.deduplicated_occurrence",
                    actor=actor,
                    target_type="alert",
                    target_id=str(existing.id),
                    outcome="success",
                    source_ip=source_ip,
                    details={
                        "fingerprint": fingerprint,
                        "occurrence_count": existing.occurrence_count,
                    },
                )
                await db.commit()
                await db.refresh(existing)
                await publish_realtime_event(
                    "alert.updated",
                    {
                        "alert_id": str(existing.id),
                        "occurrence_count": existing.occurrence_count,
                        "severity": existing.severity,
                    },
                    required_permission="alerts:view",
                )
                return existing, False

        # Match known asset by hostname or destination IP
        asset_id: uuid.UUID | None = None
        hostname = normalized.get("hostname")
        dst_ip = normalized.get("dst_ip")
        if hostname or dst_ip:
            conds = []
            if hostname:
                conds.append(Asset.hostname == hostname)
            if dst_ip:
                conds.append(Asset.ip_address == dst_ip)
            asset_res = await db.execute(select(Asset).where(or_(*conds)).limit(1))
            matched_asset = asset_res.scalar_one_or_none()
            if matched_asset:
                asset_id = matched_asset.id

        mitre_raw = normalized.get("mitre_mappings_raw") or DETERMINISTIC_RULE_MITRE_MAP.get(rule_id, [])
        rec_steps = normalized.get("recommended_steps") or RECOMMENDED_STEPS_BY_CATEGORY.get(
            category,
            [
                "Validate raw event telemetry and correlate surrounding host/user activity.",
                "Enrich external indicators and determine whether escalation to Incident is warranted.",
            ],
        )

        alert = Alert(
            id=uuid.uuid4(),
            external_alert_id=normalized.get("external_alert_id"),
            source_system=source_system,
            rule_id=rule_id,
            rule_description=str(normalized.get("rule_description") or "Security alert"),
            event_category=category,
            event_timestamp=event_ts,
            ingested_at=now,
            src_ip=normalized.get("src_ip"),
            dst_ip=normalized.get("dst_ip"),
            hostname=hostname,
            username=normalized.get("username"),
            file_hash=normalized.get("file_hash"),
            domain=normalized.get("domain"),
            severity=str(normalized.get("severity") or "medium").lower(),
            triage_status="new",
            asset_id=asset_id,
            fingerprint=fingerprint,
            occurrence_count=1,
            first_seen_at=event_ts,
            last_seen_at=max(event_ts, now),
            raw_payload=raw_payload,
            mitre_mappings_raw=mitre_raw,
            recommended_steps=rec_steps,
            is_simulated=bool(normalized.get("is_simulated", False)),
            scenario_slug=normalized.get("scenario_slug"),
        )
        db.add(alert)
        db.add(
            AlertOccurrence(
                alert_id=alert.id,
                occurred_at=event_ts,
                ingested_at=now,
                raw_payload=raw_payload,
            )
        )

        await AuditService.record(
            db,
            action="alert.ingested",
            actor=actor,
            target_type="alert",
            target_id=str(alert.id),
            outcome="success",
            source_ip=source_ip,
            details={
                "source_system": source_system,
                "rule_id": rule_id,
                "severity": alert.severity,
                "is_simulated": alert.is_simulated,
            },
        )
        await db.commit()
        await db.refresh(alert)

        await publish_realtime_event(
            "alert.created",
            {
                "alert_id": str(alert.id),
                "rule_description": alert.rule_description,
                "severity": alert.severity,
                "source_system": alert.source_system,
                "is_simulated": alert.is_simulated,
            },
            required_permission="alerts:view",
        )
        return alert, True

    @staticmethod
    async def triage_alert(
        db: AsyncSession,
        *,
        alert_id: uuid.UUID,
        action: str,
        actor: User,
        reason: str | None = None,
        assigned_to_id: uuid.UUID | None = None,
        note: str | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
    ) -> Alert:
        res = await db.execute(select(Alert).where(Alert.id == alert_id))
        alert = res.scalar_one_or_none()
        if alert is None:
            raise AppError(
                code="ALERT_NOT_FOUND",
                message="Alert not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        before = {
            "triage_status": alert.triage_status,
            "assigned_to_id": str(alert.assigned_to_id) if alert.assigned_to_id else None,
            "severity": alert.severity,
        }

        if action == "mark_reviewed":
            alert.triage_status = "in_review"
            if alert.assigned_to_id is None:
                alert.assigned_to_id = actor.id
        elif action == "mark_false_positive":
            if not reason or len(reason.strip()) < 5:
                raise AppError(
                    code="FALSE_POSITIVE_REASON_REQUIRED",
                    message="A written reason (minimum 5 characters) is required to close an alert as a false positive.",
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
            alert.triage_status = "false_positive"
            alert.false_positive_reason = reason.strip()
        elif action == "escalate":
            alert.triage_status = "escalated"
            if severity in ("low", "medium", "high", "critical"):
                alert.severity = severity
        elif action == "assign":
            if assigned_to_id is not None:
                u_res = await db.execute(select(User).where(User.id == assigned_to_id))
                if u_res.scalar_one_or_none() is None:
                    raise AppError(
                        code="ASSIGNEE_NOT_FOUND",
                        message="Target assignee user does not exist.",
                        status_code=status.HTTP_404_NOT_FOUND,
                    )
            alert.assigned_to_id = assigned_to_id
            if alert.triage_status == "new" and assigned_to_id is not None:
                alert.triage_status = "in_review"
        elif action == "add_note":
            if not note or not note.strip():
                raise AppError(
                    code="NOTE_CONTENT_REQUIRED",
                    message="Note content cannot be empty.",
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                )
        else:
            raise AppError(
                code="INVALID_TRIAGE_ACTION",
                message=f"Unsupported triage action '{action}'.",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        if note and note.strip():
            cleaned_note = note.strip()
            alert.triage_notes = (
                f"{alert.triage_notes}\n\n[{datetime.now(UTC).isoformat()}] {actor.username}: {cleaned_note}"
                if alert.triage_notes
                else f"[{datetime.now(UTC).isoformat()}] {actor.username}: {cleaned_note}"
            )
            inv_note = InvestigationNote(
                id=uuid.uuid4(),
                alert_id=alert.id,
                author_id=actor.id,
                current_content=cleaned_note,
                revision_count=1,
            )
            db.add(inv_note)
            db.add(
                NoteRevision(
                    note_id=inv_note.id,
                    revision_number=1,
                    content=cleaned_note,
                    edited_by_id=actor.id,
                )
            )

        alert.version += 1

        await AuditService.record(
            db,
            action=f"alert.triage.{action}",
            actor=actor,
            target_type="alert",
            target_id=str(alert.id),
            outcome="success",
            source_ip=source_ip,
            details={
                "before": before,
                "after": {
                    "triage_status": alert.triage_status,
                    "assigned_to_id": str(alert.assigned_to_id) if alert.assigned_to_id else None,
                    "severity": alert.severity,
                },
                "reason": reason,
            },
        )
        await db.commit()
        await db.refresh(alert)

        await publish_realtime_event(
            "alert.triaged",
            {
                "alert_id": str(alert.id),
                "triage_status": alert.triage_status,
                "action": action,
                "actor": actor.username,
            },
            required_permission="alerts:view",
        )
        return alert

