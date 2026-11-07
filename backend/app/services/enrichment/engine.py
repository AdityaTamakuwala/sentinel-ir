"""Centralized Threat Intelligence Enrichment Engine.

Orchestrates multi-provider enrichment, Redis caching (24h TTL), sliding-window rate limiting,
RFC 1918 internal IP protection, and database synchronization.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.db.session import get_redis_client
from app.models.base import utc_now
from app.models.investigation import EnrichmentResult, IncidentIndicator, Indicator
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.enrichment.abuseipdb import AbuseIPDBAdapter
from app.services.enrichment.base import ThreatIntelProvider, ThreatIntelResult
from app.services.enrichment.internal_guard import is_internal_indicator, make_internal_intel_result
from app.services.enrichment.mock_provider import MockThreatIntelProvider
from app.services.enrichment.otx import AlienVaultOTXAdapter
from app.services.enrichment.rate_limiter import check_provider_rate_limit
from app.services.enrichment.virustotal import VirusTotalAdapter
from app.services.event_bus import publish_realtime_event

CACHE_TTL_SECONDS = 86400  # 24 hours


class EnrichmentService:
    """Orchestrates indicator threat intelligence lookups across active providers."""

    @classmethod
    def get_providers(cls) -> list[ThreatIntelProvider]:
        """Instantiate available threat intelligence adapters."""
        return [
            VirusTotalAdapter(),
            AbuseIPDBAdapter(),
            AlienVaultOTXAdapter(),
        ]

    @classmethod
    async def enrich_indicator(
        cls,
        db: AsyncSession,
        ioc_type: str,
        value: str,
        force_refresh: bool = False,
        actor: User | None = None,
        source_ip: str | None = None,
    ) -> Indicator:
        """Enrich a single IOC, enforcing internal filters, Redis caching, and DB persistence."""
        settings = get_settings()
        clean_type = ioc_type.strip().lower()
        clean_value = value.strip()

        # 1. Check or create base indicator in DB
        ind_stmt = (
            select(Indicator)
            .where(Indicator.ioc_type == clean_type, Indicator.value == clean_value)
            .options(selectinload(Indicator.enrichments))
        )
        indicator = (await db.execute(ind_stmt)).scalar_one_or_none()
        is_new = False
        if indicator is None:
            indicator = Indicator(
                ioc_type=clean_type,
                value=clean_value,
                is_internal=is_internal_indicator(clean_type, clean_value),
                reputation="unknown",
                confidence=0,
                first_seen_at=utc_now(),
                last_seen_at=utc_now(),
                is_simulated=False,
            )
            db.add(indicator)
            await db.flush()
            is_new = True

        indicator.last_seen_at = utc_now()

        # 2. Safety filter: Internal RFC 1918 / Intranet assets are NEVER sent externally
        if is_internal_indicator(clean_type, clean_value):
            indicator.is_internal = True
            indicator.reputation = "internal"
            indicator.confidence = 100

            if is_new:
                safe_res = make_internal_intel_result(clean_type, clean_value)
                er = EnrichmentResult(
                    indicator_id=indicator.id,
                    provider=safe_res.provider,
                    status=safe_res.status,
                    reputation=safe_res.reputation,
                    confidence_score=safe_res.confidence_score,
                    summary=safe_res.summary,
                    raw_data=safe_res.raw_data,
                    source_references=safe_res.source_references,
                    is_mock=False,
                    looked_up_at=utc_now(),
                )
                db.add(er)
            else:
                existing_stmt = select(EnrichmentResult).where(
                    EnrichmentResult.indicator_id == indicator.id,
                    EnrichmentResult.status == "not_applicable_internal",
                )
                existing = (await db.execute(existing_stmt)).scalar_one_or_none()
                if existing is None:
                    safe_res = make_internal_intel_result(clean_type, clean_value)
                    er = EnrichmentResult(
                        indicator_id=indicator.id,
                        provider=safe_res.provider,
                        status=safe_res.status,
                        reputation=safe_res.reputation,
                        confidence_score=safe_res.confidence_score,
                        summary=safe_res.summary,
                        raw_data=safe_res.raw_data,
                        source_references=safe_res.source_references,
                        is_mock=False,
                        looked_up_at=utc_now(),
                    )
                    db.add(er)

            await db.commit()
            out_stmt = (
                select(Indicator)
                .where(Indicator.id == indicator.id)
                .options(selectinload(Indicator.enrichments))
            )
            return (await db.execute(out_stmt)).scalar_one()

        # 3. Check Redis cache if not forced refresh
        redis = get_redis_client()
        cache_key = f"sentinel:enrichment:{clean_type}:{clean_value}"
        if not force_refresh:
            cached_raw = await redis.get(cache_key)
            if cached_raw:
                try:  # noqa: S110
                    await db.commit()
                    out_stmt = (
                        select(Indicator)
                        .where(Indicator.id == indicator.id)
                        .options(selectinload(Indicator.enrichments))
                    )
                    return (await db.execute(out_stmt)).scalar_one()
                except Exception:  # noqa: S110
                    # Stale cache deserialization fallback
                    pass

        # 4. Gather provider results
        results: list[ThreatIntelResult] = []
        providers = cls.get_providers()
        configured_providers = [p for p in providers if p.is_configured() and clean_type in p.supported_ioc_types()]

        if configured_providers:
            for p in configured_providers:
                # Rate limit guard
                limit = (
                    settings.VIRUSTOTAL_RATE_LIMIT_PER_MIN
                    if p.provider_name() == "virustotal"
                    else 30
                )
                allowed = await check_provider_rate_limit(redis, p.provider_name(), limit)
                if not allowed:
                    results.append(
                        ThreatIntelResult(
                            ioc_type=clean_type,
                            value=clean_value,
                            provider=p.provider_name(),
                            status="rate_limited",
                            reputation="unknown",
                            confidence_score=0,
                            summary=f"{p.provider_name()} local rate limit reached.",
                            is_mock=False,
                            looked_up_at=utc_now(),
                        )
                    )
                    continue

                res = await p.lookup(clean_type, clean_value)
                results.append(res)
        elif settings.ENRICHMENT_USE_MOCK_WHEN_UNCONFIGURED:
            # Fall back to high-fidelity Mock provider
            mock_p = MockThreatIntelProvider()
            res = await mock_p.lookup(clean_type, clean_value)
            results.append(res)

        # 5. Persist enrichment results and synthesize indicator overall reputation
        max_confidence = 0
        has_malicious = False
        has_suspicious = False
        has_benign = False

        for r in results:
            er = EnrichmentResult(
                indicator_id=indicator.id,
                provider=r.provider,
                status=r.status,
                reputation=r.reputation,
                malicious_count=r.malicious_count,
                total_engines=r.total_engines,
                confidence_score=r.confidence_score,
                summary=r.summary,
                raw_data=r.raw_data,
                source_references=r.source_references,
                is_mock=r.is_mock,
                looked_up_at=r.looked_up_at,
                expires_at=utc_now() + timedelta(seconds=CACHE_TTL_SECONDS),
            )
            db.add(er)

            if r.status == "success":
                max_confidence = max(max_confidence, r.confidence_score)
                if r.reputation == "malicious":
                    has_malicious = True
                elif r.reputation == "suspicious":
                    has_suspicious = True
                elif r.reputation == "benign":
                    has_benign = True

        if has_malicious:
            indicator.reputation = "malicious"
            indicator.confidence = max(max_confidence, 75)
        elif has_suspicious:
            indicator.reputation = "suspicious"
            indicator.confidence = max(max_confidence, 55)
        elif has_benign:
            indicator.reputation = "benign"
            indicator.confidence = max(max_confidence, 80)

        await db.commit()
        out_stmt = (
            select(Indicator)
            .where(Indicator.id == indicator.id)
            .options(selectinload(Indicator.enrichments))
        )
        indicator = (await db.execute(out_stmt)).scalar_one()

        # Cache summary in Redis
        cache_payload = {
            "reputation": indicator.reputation,
            "confidence": indicator.confidence,
            "updated_at": indicator.last_seen_at.isoformat(),
        }
        await redis.setex(cache_key, CACHE_TTL_SECONDS, json.dumps(cache_payload))

        # Real-time event & audit log
        await publish_realtime_event(
            "indicator.enriched",
            {
                "id": str(indicator.id),
                "ioc_type": indicator.ioc_type,
                "value": indicator.value,
                "reputation": indicator.reputation,
                "confidence": indicator.confidence,
                "providers": [r.provider for r in results],
            },
            required_permission="enrichment:read",
        )

        if actor:
            await AuditService.record(
                db,
                action="enrichment.lookup",
                actor=actor,
                target_type="indicator",
                target_id=str(indicator.id),
                outcome="success",
                source_ip=source_ip,
                details={
                    "ioc_type": clean_type,
                    "value": clean_value,
                    "reputation": indicator.reputation,
                    "force_refresh": force_refresh,
                },
            )
            await db.commit()

        return indicator

    @classmethod
    async def enrich_incident_indicators(
        cls,
        db: AsyncSession,
        incident_id: uuid.UUID,
        actor: User | None = None,
        source_ip: str | None = None,
    ) -> list[Indicator]:
        """Enrich all indicators linked to an incident."""
        stmt = (
            select(IncidentIndicator)
            .where(IncidentIndicator.incident_id == incident_id)
            .options(selectinload(IncidentIndicator.indicator))
        )
        links = (await db.execute(stmt)).scalars().all()
        enriched: list[Indicator] = []

        for link in links:
            if link.indicator:
                ind = await cls.enrich_indicator(
                    db,
                    ioc_type=link.indicator.ioc_type,
                    value=link.indicator.value,
                    actor=actor,
                    source_ip=source_ip,
                )
                enriched.append(ind)

        return enriched

    @classmethod
    async def get_indicators(
        cls,
        db: AsyncSession,
        search: str | None = None,
        ioc_type: str | None = None,
        reputation: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Indicator], int]:
        """Fetch paginated threat indicators with optional filters."""
        filters: list[Any] = []
        if search and search.strip():
            filters.append(Indicator.value.ilike(f"%{search.strip()}%"))
        if ioc_type and ioc_type.strip():
            filters.append(Indicator.ioc_type == ioc_type.strip().lower())
        if reputation and reputation.strip():
            filters.append(Indicator.reputation == reputation.strip().lower())

        count_stmt = select(func.count(Indicator.id))
        if filters:
            count_stmt = count_stmt.where(*filters)
        total = int((await db.execute(count_stmt)).scalar_one())

        stmt = (
            select(Indicator)
            .where(*filters)
            .order_by(Indicator.last_seen_at.desc())
            .options(selectinload(Indicator.enrichments))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        rows = list((await db.execute(stmt)).scalars().all())
        return rows, total

    @classmethod
    async def get_stats(cls, db: AsyncSession) -> dict[str, Any]:
        """Calculate aggregate threat intelligence metrics."""
        rep_counts_stmt = select(Indicator.reputation, func.count(Indicator.id)).group_by(Indicator.reputation)
        rep_rows = (await db.execute(rep_counts_stmt)).all()
        rep_map = {r: count for r, count in rep_rows}

        total = sum(rep_map.values())
        malicious = rep_map.get("malicious", 0)
        suspicious = rep_map.get("suspicious", 0)
        benign = rep_map.get("benign", 0)
        internal = rep_map.get("internal", 0)

        # Top threats
        top_stmt = (
            select(Indicator)
            .where(Indicator.reputation.in_(["malicious", "suspicious"]))
            .order_by(Indicator.confidence.desc(), Indicator.last_seen_at.desc())
            .options(selectinload(Indicator.enrichments))
            .limit(5)
        )
        top_threats = list((await db.execute(top_stmt)).scalars().all())

        return {
            "total_indicators": total,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "benign_count": benign,
            "internal_count": internal,
            "top_threats": top_threats,
        }
