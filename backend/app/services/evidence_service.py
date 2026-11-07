"""Forensic Evidence Service: Streaming SHA-256, Magic-Byte Allowlist, Versioning, Chain of Custody."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import socket
import struct
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.logging import get_correlation_id
from app.models.incident import Incident, IncidentTimeline
from app.models.investigation import Evidence, EvidenceCustodyLog, EvidenceVersion
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.event_bus import publish_realtime_event

STREAM_CHUNK_BYTES = 65_536

# Dangerous binary/executable signatures strictly rejected regardless of file extension
FORBIDDEN_MAGIC_PREFIXES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE executable"),
    (b"\x7fELF", "Linux ELF binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit LE binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit LE binary"),
    (b"\xca\xfe\xba\xbe", "Universal/Java class binary"),
    (b"#!", "Executable interpreter shebang script"),
)

ALLOWED_EXTENSIONS: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".pdf": "application/pdf",
    ".pcap": "application/vnd.tcpdump.pcap",
    ".pcapng": "application/x-pcapng",
    ".json": "application/json",
    ".txt": "text/plain",
    ".log": "text/plain",
    ".csv": "text/csv",
}

VALID_EVIDENCE_TYPES = {
    "file",
    "screenshot",
    "log_excerpt",
    "json_artifact",
    "ioc_record",
    "note",
}

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def sanitize_evidence_filename(raw_filename: str | None) -> str:
    """Strip path traversal components, null bytes, and unsafe characters from untrusted filenames."""
    if not raw_filename:
        raise AppError(
            "INVALID_EVIDENCE_FILENAME",
            "Uploaded evidence file must include a filename.",
            status.HTTP_400_BAD_REQUEST,
        )
    if "\x00" in raw_filename:
        raise AppError(
            "UNSAFE_EVIDENCE_FILENAME",
            "Null bytes are prohibited in filenames.",
            status.HTTP_400_BAD_REQUEST,
        )
    # Reject explicit path traversal attempts before normalization so security logs capture them
    normalized_slashes = raw_filename.replace("\\", "/")
    parts = [p for p in normalized_slashes.split("/") if p]
    if ".." in parts or normalized_slashes.startswith("/") or ":" in raw_filename:
        raise AppError(
            "PATH_TRAVERSAL_REJECTED",
            "Path traversal sequences or directory prefixes are forbidden in evidence filenames.",
            status.HTTP_400_BAD_REQUEST,
        )
    basename = parts[-1] if parts else ""
    cleaned = _SAFE_FILENAME_RE.sub("_", basename).strip("._")
    if not cleaned:
        raise AppError(
            "INVALID_EVIDENCE_FILENAME",
            "Filename contains no valid alphanumeric characters.",
            status.HTTP_400_BAD_REQUEST,
        )
    # Re-attach original extension safely
    dot_idx = basename.rfind(".")
    if dot_idx > 0:
        stem = _SAFE_FILENAME_RE.sub("_", basename[:dot_idx]).strip("._") or "artifact"
        ext = "." + re.sub(r"[^A-Za-z0-9]", "", basename[dot_idx + 1 :]).lower()
        return f"{stem[:180]}{ext}"
    return cleaned[:200]


def detect_and_validate_evidence_mime(filename: str, head_bytes: bytes, full_sample: bytes) -> str:
    """Validate extension allowlist AND magic-byte content sniffing to block disguised executables/HTML."""
    dot_idx = filename.rfind(".")
    ext = filename[dot_idx:].lower() if dot_idx >= 0 else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise AppError(
            "UNSUPPORTED_EVIDENCE_FILE_TYPE",
            f"Extension '{ext or '<none>'}' is not in the forensic evidence allowlist "
            f"({', '.join(sorted(ALLOWED_EXTENSIONS.keys()))}).",
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )

    if len(head_bytes) == 0:
        raise AppError(
            "EMPTY_EVIDENCE_FILE",
            "Empty 0-byte files cannot be preserved as forensic evidence.",
            status.HTTP_400_BAD_REQUEST,
        )

    for magic, reason in FORBIDDEN_MAGIC_PREFIXES:
        if head_bytes.startswith(magic):
            raise AppError(
                "DISGUISED_EXECUTABLE_REJECTED",
                f"Content sniffing detected forbidden executable header ({reason}).",
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )

    if ext == ".png":
        if not head_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            raise AppError(
                "MIME_MAGIC_MISMATCH",
                "File with .png extension lacks valid PNG magic header.",
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
        return "image/png"

    if ext in (".jpg", ".jpeg"):
        if not head_bytes.startswith(b"\xff\xd8\xff"):
            raise AppError(
                "MIME_MAGIC_MISMATCH",
                "File with JPEG extension lacks valid JFIF/EXIF magic header.",
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
        return "image/jpeg"

    if ext == ".pdf":
        if not head_bytes.startswith(b"%PDF-"):
            raise AppError(
                "MIME_MAGIC_MISMATCH",
                "File with .pdf extension lacks '%PDF-' magic header.",
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
        return "application/pdf"

    if ext == ".pcap":
        pcap_magics = (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        )
        if not head_bytes.startswith(pcap_magics):
            raise AppError(
                "MIME_MAGIC_MISMATCH",
                "File with .pcap extension lacks valid libpcap global header.",
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
        return "application/vnd.tcpdump.pcap"

    if ext == ".pcapng":
        if not head_bytes.startswith(b"\x0a\x0d\x0d\x0a"):
            raise AppError(
                "MIME_MAGIC_MISMATCH",
                "File with .pcapng extension lacks Section Header Block magic.",
                status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            )
        return "application/x-pcapng"

    # Text-based formats (.json, .txt, .log, .csv): prohibit binary null bytes and validate UTF-8
    if b"\x00" in full_sample:
        raise AppError(
            "BINARY_CONTENT_IN_TEXT_EVIDENCE",
            f"Binary null bytes detected inside '{ext}' text artifact.",
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        )
    try:
        decoded_sample = full_sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AppError(
            "INVALID_UTF8_EVIDENCE",
            f"Text artifact '{ext}' must be valid UTF-8.",
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
        ) from exc

    if ext == ".json":
        return "application/json"
    if ext == ".csv":
        return "text/csv"
    _ = decoded_sample
    return "text/plain"


def _scan_with_clamav_sync(file_path: Path, host: str, port: int) -> str:
    """Optional ClamAV INSTREAM scanner when `CLAMAV_ENABLED=true`."""
    with socket.create_connection((host, port), timeout=10.0) as sock:
        sock.sendall(b"zINSTREAM\x00")
        with file_path.open("rb") as fh:
            while True:
                chunk = fh.read(STREAM_CHUNK_BYTES)
                if not chunk:
                    break
                sock.sendall(struct.pack("!I", len(chunk)) + chunk)
        sock.sendall(struct.pack("!I", 0))
        resp = sock.recv(1024).decode("utf-8", errors="replace").strip("\x00\r\n ")
    if "FOUND" in resp:
        return f"infected:{resp}"
    if "OK" in resp:
        return "clean"
    return "error"


class EvidenceService:
    @staticmethod
    def storage_root() -> Path:
        root = Path(get_settings().EVIDENCE_STORAGE_DIR).resolve()
        root.mkdir(parents=True, exist_ok=True)
        return root

    @staticmethod
    def resolve_storage_path(storage_key: str) -> Path:
        if "/" in storage_key or "\\" in storage_key or ".." in storage_key:
            raise AppError("INVALID_STORAGE_KEY", "Malformed evidence storage key.", 400)
        root = EvidenceService.storage_root()
        target = (root / storage_key).resolve()
        if target.parent != root:
            raise AppError("STORAGE_PATH_ESCAPE", "Evidence storage path escape blocked.", 400)
        return target

    @staticmethod
    async def _stream_upload_to_vault(upload: UploadFile) -> tuple[str, str, str, int, str]:
        """Stream an UploadFile to disk while computing SHA-256 and enforcing size/MIME guards.

        Returns `(storage_key, safe_filename, detected_mime, total_bytes, sha256_hex)`.
        """
        settings = get_settings()
        safe_filename = sanitize_evidence_filename(upload.filename)
        storage_key = f"{uuid.uuid4().hex}.evd"
        dest_path = EvidenceService.resolve_storage_path(storage_key)

        hasher = hashlib.sha256()
        total_bytes = 0
        sample_buf = bytearray()

        try:
            with dest_path.open("wb") as out_fh:
                while True:
                    chunk = await upload.read(STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > settings.MAX_UPLOAD_BYTES:
                        raise AppError(
                            "EVIDENCE_TOO_LARGE",
                            f"Uploaded file exceeds maximum limit of {settings.MAX_UPLOAD_BYTES} bytes.",
                            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        )
                    if len(sample_buf) < 8192:
                        needed = 8192 - len(sample_buf)
                        sample_buf.extend(chunk[:needed])
                    hasher.update(chunk)
                    out_fh.write(chunk)

            os.chmod(dest_path, 0o600)
            detected_mime = detect_and_validate_evidence_mime(
                safe_filename,
                bytes(sample_buf[:64]),
                bytes(sample_buf),
            )
            if detected_mime == "application/json":
                # Validate complete JSON syntax so corrupt/polyglot JSON files are rejected
                try:
                    with dest_path.open("rb") as jf:
                        json.load(jf)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AppError(
                        "INVALID_JSON_EVIDENCE",
                        "File with .json extension does not contain valid UTF-8 JSON.",
                        status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    ) from exc

            av_status = "skipped"
            if settings.CLAMAV_ENABLED:
                av_res = await asyncio.to_thread(
                    _scan_with_clamav_sync,
                    dest_path,
                    settings.CLAMAV_HOST,
                    settings.CLAMAV_PORT,
                )
                if av_res.startswith("infected:"):
                    raise AppError(
                        "MALWARE_SIGNATURE_DETECTED",
                        "ClamAV rejected infected upload; quarantine policy active.",
                        status.HTTP_422_UNPROCESSABLE_ENTITY,
                    )
                av_status = av_res

            return storage_key, safe_filename, detected_mime, total_bytes, f"{hasher.hexdigest()}|{av_status}"
        except Exception:
            if dest_path.exists():
                dest_path.unlink(missing_ok=True)
            raise

    @staticmethod
    async def upload_evidence(
        db: AsyncSession,
        *,
        incident_id: uuid.UUID,
        title: str,
        description: str,
        evidence_type: str,
        upload: UploadFile,
        actor: User,
        source_ip: str | None = None,
        is_simulated: bool = False,
    ) -> Evidence:
        if evidence_type not in VALID_EVIDENCE_TYPES:
            raise AppError(
                "INVALID_EVIDENCE_TYPE",
                f"evidence_type must be one of {sorted(VALID_EVIDENCE_TYPES)}.",
                422,
            )

        inc_res = await db.execute(select(Incident).where(Incident.id == incident_id))
        incident = inc_res.scalar_one_or_none()
        if incident is None:
            raise AppError("INCIDENT_NOT_FOUND", "Target incident not found.", 404)

        storage_key, safe_filename, detected_mime, size_bytes, hash_and_av = (
            await EvidenceService._stream_upload_to_vault(upload)
        )
        sha256_digest, av_status = hash_and_av.split("|", 1)

        now = datetime.now(UTC)
        ev = Evidence(
            id=uuid.uuid4(),
            incident_id=incident.id,
            title=title.strip(),
            description=description.strip(),
            evidence_type=evidence_type,
            status="active",
            current_version=1,
            uploaded_by_id=actor.id,
            is_simulated=is_simulated or incident.is_simulated,
            created_at=now,
            updated_at=now,
        )
        db.add(ev)
        await db.flush()

        ver = EvidenceVersion(
            id=uuid.uuid4(),
            evidence_id=ev.id,
            version_number=1,
            storage_key=storage_key,
            original_filename=safe_filename,
            detected_mime_type=detected_mime,
            size_bytes=size_bytes,
            sha256_hash=sha256_digest,
            av_scan_status=av_status,
            uploaded_by_id=actor.id,
            notes="Initial forensic artifact preservation",
            created_at=now,
        )
        db.add(ver)

        db.add(
            EvidenceCustodyLog(
                id=uuid.uuid4(),
                evidence_id=ev.id,
                version_number=1,
                actor_id=actor.id,
                actor_label=actor.username,
                action="uploaded",
                sha256_recorded=sha256_digest,
                ip_address=source_ip,
                correlation_id=get_correlation_id(),
                details={
                    "filename": safe_filename,
                    "mime_type": detected_mime,
                    "size_bytes": size_bytes,
                },
                created_at=now,
            )
        )

        db.add(
            IncidentTimeline(
                incident_id=incident.id,
                event_type="evidence_added",
                title=f"Evidence preserved: {ev.title} (v1)",
                description=f"File '{safe_filename}' ({size_bytes} B) SHA-256: {sha256_digest[:16]}…",
                actor_id=actor.id,
                actor_label=actor.username,
                metadata_json={
                    "evidence_id": str(ev.id),
                    "sha256": sha256_digest,
                    "filename": safe_filename,
                },
                occurred_at=now,
            )
        )

        await AuditService.record(
            db,
            action="evidence.uploaded",
            actor=actor,
            target_type="evidence",
            target_id=str(ev.id),
            source_ip=source_ip,
            details={
                "incident_id": str(incident.id),
                "human_id": incident.human_id,
                "filename": safe_filename,
                "sha256": sha256_digest,
                "size_bytes": size_bytes,
            },
        )
        await db.commit()
        await db.refresh(ev)

        await publish_realtime_event(
            "evidence.uploaded",
            {
                "evidence_id": str(ev.id),
                "incident_id": str(incident.id),
                "human_id": incident.human_id,
                "title": ev.title,
                "sha256": sha256_digest,
            },
            required_permission="evidence:read",
        )
        return ev

    @staticmethod
    async def upload_new_version(
        db: AsyncSession,
        *,
        evidence_id: uuid.UUID,
        upload: UploadFile,
        notes: str | None,
        actor: User,
        source_ip: str | None = None,
    ) -> Evidence:
        res = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        ev = res.scalar_one_or_none()
        if ev is None:
            raise AppError("EVIDENCE_NOT_FOUND", "Evidence record not found.", 404)
        if ev.status == "withdrawn":
            raise AppError(
                "EVIDENCE_WITHDRAWN",
                "Cannot append a new version to a withdrawn evidence record.",
                409,
            )

        storage_key, safe_filename, detected_mime, size_bytes, hash_and_av = (
            await EvidenceService._stream_upload_to_vault(upload)
        )
        sha256_digest, av_status = hash_and_av.split("|", 1)

        now = datetime.now(UTC)
        next_ver = ev.current_version + 1
        ev.current_version = next_ver
        ev.updated_at = now

        ver = EvidenceVersion(
            id=uuid.uuid4(),
            evidence_id=ev.id,
            version_number=next_ver,
            storage_key=storage_key,
            original_filename=safe_filename,
            detected_mime_type=detected_mime,
            size_bytes=size_bytes,
            sha256_hash=sha256_digest,
            av_scan_status=av_status,
            uploaded_by_id=actor.id,
            notes=(notes or "").strip() or f"Version {next_ver} preservation",
            created_at=now,
        )
        db.add(ver)

        db.add(
            EvidenceCustodyLog(
                id=uuid.uuid4(),
                evidence_id=ev.id,
                version_number=next_ver,
                actor_id=actor.id,
                actor_label=actor.username,
                action="version_added",
                sha256_recorded=sha256_digest,
                ip_address=source_ip,
                correlation_id=get_correlation_id(),
                details={
                    "filename": safe_filename,
                    "version_number": next_ver,
                    "notes": ver.notes,
                },
                created_at=now,
            )
        )

        db.add(
            IncidentTimeline(
                incident_id=ev.incident_id,
                event_type="evidence_version_added",
                title=f"Evidence updated: {ev.title} (v{next_ver})",
                description=f"Preserved immutable version v{next_ver} ({safe_filename}), prior versions retained.",
                actor_id=actor.id,
                actor_label=actor.username,
                metadata_json={
                    "evidence_id": str(ev.id),
                    "version_number": next_ver,
                    "sha256": sha256_digest,
                },
                occurred_at=now,
            )
        )

        await AuditService.record(
            db,
            action="evidence.version_added",
            actor=actor,
            target_type="evidence",
            target_id=str(ev.id),
            source_ip=source_ip,
            details={
                "version_number": next_ver,
                "filename": safe_filename,
                "sha256": sha256_digest,
            },
        )
        await db.commit()
        await db.refresh(ev)
        return ev

    @staticmethod
    async def verify_integrity(
        db: AsyncSession,
        *,
        evidence_id: uuid.UUID,
        version_number: int | None,
        actor: User,
        source_ip: str | None = None,
    ) -> dict[str, Any]:
        res = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        ev = res.scalar_one_or_none()
        if ev is None:
            raise AppError("EVIDENCE_NOT_FOUND", "Evidence record not found.", 404)

        target_ver_num = version_number or ev.current_version
        ver_obj = next((v for v in ev.versions if v.version_number == target_ver_num), None)
        if ver_obj is None:
            raise AppError("EVIDENCE_VERSION_NOT_FOUND", "Requested evidence version not found.", 404)

        path = EvidenceService.resolve_storage_path(ver_obj.storage_key)
        now = datetime.now(UTC)

        if not path.exists():
            computed = None
            valid = False
            detail = "Stored artifact blob is missing on disk!"
            disk_size = 0
        else:
            hasher = hashlib.sha256()
            disk_size = 0
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    disk_size += len(chunk)
                    hasher.update(chunk)
            computed = hasher.hexdigest()
            valid = computed == ver_obj.sha256_hash and disk_size == ver_obj.size_bytes
            detail = (
                f"Cryptographic SHA-256 match verified ({disk_size} bytes)."
                if valid
                else "SHA-256 hash or byte-length mismatch detected!"
            )

        db.add(
            EvidenceCustodyLog(
                id=uuid.uuid4(),
                evidence_id=ev.id,
                version_number=ver_obj.version_number,
                actor_id=actor.id,
                actor_label=actor.username,
                action="verified_ok" if valid else "verified_mismatch",
                sha256_recorded=computed or "MISSING",
                ip_address=source_ip,
                correlation_id=get_correlation_id(),
                details={"valid": valid, "expected_sha256": ver_obj.sha256_hash},
                created_at=now,
            )
        )
        await AuditService.record(
            db,
            action="evidence.integrity_verified",
            actor=actor,
            target_type="evidence",
            target_id=str(ev.id),
            outcome="success" if valid else "failure",
            source_ip=source_ip,
            details={
                "version_number": ver_obj.version_number,
                "valid": valid,
                "expected_sha256": ver_obj.sha256_hash,
                "computed_sha256": computed,
            },
        )
        await db.commit()

        return {
            "evidence_id": ev.id,
            "version_number": ver_obj.version_number,
            "valid": valid,
            "expected_sha256": ver_obj.sha256_hash,
            "computed_sha256": computed,
            "size_bytes": disk_size,
            "detail": detail,
            "verified_at": now,
        }

    @staticmethod
    async def withdraw_evidence(
        db: AsyncSession,
        *,
        evidence_id: uuid.UUID,
        reason: str,
        actor: User,
        source_ip: str | None = None,
    ) -> Evidence:
        res = await db.execute(select(Evidence).where(Evidence.id == evidence_id))
        ev = res.scalar_one_or_none()
        if ev is None:
            raise AppError("EVIDENCE_NOT_FOUND", "Evidence record not found.", 404)
        if ev.status == "withdrawn":
            raise AppError("EVIDENCE_ALREADY_WITHDRAWN", "Evidence is already withdrawn.", 409)

        now = datetime.now(UTC)
        cleaned_reason = reason.strip()
        ev.status = "withdrawn"
        ev.withdrawn_reason = cleaned_reason
        ev.withdrawn_by_id = actor.id
        ev.withdrawn_at = now
        ev.updated_at = now

        latest_ver = ev.versions[0] if ev.versions else None
        recorded_hash = latest_ver.sha256_hash if latest_ver else ("0" * 64)

        db.add(
            EvidenceCustodyLog(
                id=uuid.uuid4(),
                evidence_id=ev.id,
                version_number=ev.current_version,
                actor_id=actor.id,
                actor_label=actor.username,
                action="withdrawn",
                sha256_recorded=recorded_hash,
                ip_address=source_ip,
                correlation_id=get_correlation_id(),
                details={"reason": cleaned_reason},
                created_at=now,
            )
        )
        db.add(
            IncidentTimeline(
                incident_id=ev.incident_id,
                event_type="evidence_withdrawn",
                title=f"Evidence withdrawn: {ev.title}",
                description=cleaned_reason,
                actor_id=actor.id,
                actor_label=actor.username,
                metadata_json={"evidence_id": str(ev.id)},
                occurred_at=now,
            )
        )
        await AuditService.record(
            db,
            action="evidence.withdrawn",
            actor=actor,
            target_type="evidence",
            target_id=str(ev.id),
            source_ip=source_ip,
            details={"reason": cleaned_reason, "incident_id": str(ev.incident_id)},
        )
        await db.commit()
        await db.refresh(ev)
        return ev

