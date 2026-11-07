"""Incident Reporting Orchestration Service."""

from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path

from fastapi import status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError
from app.models.automation import IncidentReport
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.reporting.collector import IncidentReportCollector
from app.services.reporting.json_generator import JsonReportGenerator
from app.services.reporting.pdf_generator import WeasyPrintPdfGenerator
from app.services.reporting.stix_generator import Stix2BundleGenerator

logger = logging.getLogger("sentinel.reporting")

VALID_REPORT_FORMATS = ("pdf", "json", "stix")
VALID_TLP_LEVELS = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED")


class ReportingService:
    """Enterprise Incident Reporting Service."""

    @staticmethod
    def _get_reports_storage_dir() -> Path:
        settings = get_settings()
        reports_dir = Path(settings.EVIDENCE_STORAGE_DIR).parent / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        return reports_dir

    @classmethod
    async def generate_report(
        cls,
        db: AsyncSession,
        *,
        incident_id: uuid.UUID,
        report_format: str = "pdf",
        tlp_classification: str = "TLP:AMBER",
        actor: User,
    ) -> IncidentReport:
        fmt = report_format.lower().strip()
        tlp = tlp_classification.upper().strip()

        if fmt not in VALID_REPORT_FORMATS:
            raise AppError(
                code="INVALID_REPORT_FORMAT",
                message=f"Report format '{report_format}' must be one of: {', '.join(VALID_REPORT_FORMATS)}.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        if tlp not in VALID_TLP_LEVELS:
            raise AppError(
                code="INVALID_TLP_CLASSIFICATION",
                message=f"TLP classification '{tlp_classification}' must be one of: {', '.join(VALID_TLP_LEVELS)}.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # 1. Collect full immutable incident snapshot
        snapshot = await IncidentReportCollector.collect_snapshot(db, incident_id)

        # 2. Render binary content
        content_bytes: bytes
        ext: str
        if fmt == "pdf":
            generator = WeasyPrintPdfGenerator()
            content_bytes = generator.generate_pdf_bytes(snapshot, tlp=tlp)
            ext = "pdf"
        elif fmt == "json":
            content_bytes = JsonReportGenerator.generate_json_bytes(snapshot, tlp=tlp)
            ext = "json"
        elif fmt == "stix":
            content_bytes = Stix2BundleGenerator.generate_stix_bytes(snapshot, tlp=tlp)
            ext = "stix.json"
        else:
            raise AppError(code="UNSUPPORTED_FORMAT", message="Unsupported format", status_code=400)

        # 3. Compute SHA-256 hash and persist to disk
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        report_id = uuid.uuid4()
        storage_dir = cls._get_reports_storage_dir()
        file_path = storage_dir / f"{incident_id}_{report_id}.{ext}"
        file_path.write_bytes(content_bytes)

        # 4. Save IncidentReport record in database
        report = IncidentReport(
            id=report_id,
            incident_id=incident_id,
            incident_version_snapshot=int(snapshot["incident"].get("version") or 1),
            report_format=fmt,
            tlp_classification=tlp,
            snapshot_json=snapshot,
            storage_key=str(file_path),
            sha256_hash=sha256_hash,
            generated_by_id=actor.id,
            is_simulated=bool(snapshot["incident"].get("is_simulated", False)),
        )
        db.add(report)
        await db.flush()

        await AuditService.record(
            db,
            action="report.generated",
            actor=actor,
            target_type="incident_report",
            target_id=str(report.id),
            outcome="success",
            details={
                "incident_id": str(incident_id),
                "human_id": snapshot["incident"].get("human_id"),
                "report_format": fmt,
                "tlp_classification": tlp,
                "sha256_hash": sha256_hash,
                "file_size_bytes": len(content_bytes),
                "is_simulated": report.is_simulated,
            },
        )
        await db.commit()
        return report

    @classmethod
    async def get_report(
        cls,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> IncidentReport:
        stmt = select(IncidentReport).where(IncidentReport.id == report_id)
        res = await db.execute(stmt)
        report = res.scalar_one_or_none()
        if not report:
            raise AppError(
                code="REPORT_NOT_FOUND",
                message=f"Incident report '{report_id}' does not exist.",
                status_code=status.HTTP_404_NOT_FOUND,
            )
        return report

    @classmethod
    async def get_report_file(
        cls,
        db: AsyncSession,
        report_id: uuid.UUID,
    ) -> tuple[IncidentReport, bytes, str, str]:
        report = await cls.get_report(db, report_id)

        mime_types = {
            "pdf": "application/pdf",
            "json": "application/json",
            "stix": "application/json",
        }
        mime_type = mime_types.get(report.report_format, "application/octet-stream")

        ext = "pdf" if report.report_format == "pdf" else ("stix.json" if report.report_format == "stix" else "json")
        human_id = report.snapshot_json.get("incident", {}).get("human_id", "INCIDENT")
        filename = f"SENTINEL_IR_{human_id}_Report.{ext}"

        # Attempt to read from storage
        if report.storage_key and Path(report.storage_key).exists():
            content_bytes = Path(report.storage_key).read_bytes()
        else:
            # Dynamically regenerate from snapshot if storage file was rotated
            if report.report_format == "pdf":
                content_bytes = WeasyPrintPdfGenerator().generate_pdf_bytes(
                    report.snapshot_json, tlp=report.tlp_classification
                )
            elif report.report_format == "json":
                content_bytes = JsonReportGenerator.generate_json_bytes(
                    report.snapshot_json, tlp=report.tlp_classification
                )
            elif report.report_format == "stix":
                content_bytes = Stix2BundleGenerator.generate_stix_bytes(
                    report.snapshot_json, tlp=report.tlp_classification
                )
            else:
                content_bytes = b""

        return report, content_bytes, mime_type, filename

    @staticmethod
    async def list_reports(
        db: AsyncSession,
        *,
        incident_id: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[IncidentReport]:
        stmt = select(IncidentReport).order_by(IncidentReport.created_at.desc())
        if incident_id:
            stmt = stmt.where(IncidentReport.incident_id == incident_id)
        stmt = stmt.limit(max(1, min(limit, 100))).offset(max(0, offset))
        res = await db.execute(stmt)
        return list(res.scalars().all())

