"""Centralized Role-Based Access Control (RBAC) permission matrix and route guards.

Every API route MUST either:
  1. Depend on `require_permission(PermissionCode.XYZ)` (or `require_authenticated_user`), OR
  2. Be decorated with `@public_endpoint(reason="...")`.

An automated security test iterates every route in `app.routes` and fails if any route lacks
an explicit declaration or allows a role outside `ROLE_PERMISSION_MATRIX`.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Coroutine
from enum import StrEnum
from typing import Any

import jwt
from fastapi import Depends, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AppError
from app.core.security import (
    ACCESS_COOKIE_NAME,
    CSRF_COOKIE_NAME,
    decode_access_token,
    verify_csrf_tokens,
)
from app.db.session import get_db_session
from app.models.user import User
from app.services.audit_service import AuditService


class RoleName(StrEnum):
    SOC_L1 = "soc_l1"
    SOC_L2 = "soc_l2"
    SOC_MANAGER = "soc_manager"
    ADMIN = "admin"


class PermissionCode(StrEnum):
    # Dashboard & Analytics
    DASHBOARD_VIEW = "dashboard:view"

    # Alerts & Triage
    ALERTS_VIEW = "alerts:view"
    ALERTS_CREATE = "alerts:create"
    ALERTS_TRIAGE = "alerts:triage"

    # Threat Intelligence & MITRE
    ENRICHMENT_READ = "enrichment:read"
    ENRICHMENT_RUN = "enrichment:run"
    MITRE_READ = "mitre:read"
    MITRE_MAP = "mitre:map"
    MITRE_CONFIRM = "mitre:confirm"

    # Incidents & Investigation
    INCIDENTS_VIEW = "incidents:view"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_ASSIGN = "incidents:assign"
    INCIDENTS_CLOSE = "incidents:close"
    INCIDENTS_REOPEN_CLOSED = "incidents:reopen_closed"
    NOTES_WRITE = "notes:write"
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_UPLOAD = "evidence:upload"
    EVIDENCE_WITHDRAW = "evidence:withdraw"

    # Playbooks & Response Actions
    PLAYBOOKS_VIEW = "playbooks:view"
    PLAYBOOKS_EXECUTE = "playbooks:execute"
    PLAYBOOKS_MANAGE = "playbooks:manage"
    RESPONSE_PROPOSE = "response:propose"
    RESPONSE_APPROVE_LOW = "response:approve_low"
    RESPONSE_APPROVE_ALL = "response:approve_all"
    RESPONSE_EXECUTE = "response:execute"

    # Reports
    REPORTS_VIEW = "reports:view"
    REPORTS_GENERATE = "reports:generate"

    # Simulation
    SIMULATION_RUN = "simulation:run"

    # Governance, Users, Settings, Audit
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    INTEGRATIONS_MANAGE = "integrations:manage"
    SETTINGS_MANAGE = "settings:manage"
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"


PERMISSION_DESCRIPTIONS: dict[PermissionCode, tuple[str, str]] = {
    PermissionCode.DASHBOARD_VIEW: ("analytics", "View SOC Command Centre metrics and SLA status"),
    PermissionCode.ALERTS_VIEW: ("alerts", "View alerts, occurrences, and triage workbench"),
    PermissionCode.ALERTS_CREATE: ("alerts", "Create manual alerts or import JSON alerts"),
    PermissionCode.ALERTS_TRIAGE: ("alerts", "Review, mark false positive, escalate, or assign alerts"),
    PermissionCode.ENRICHMENT_READ: ("enrichment", "View indicator threat intelligence lookups"),
    PermissionCode.ENRICHMENT_RUN: ("enrichment", "Trigger indicator threat intelligence enrichment"),
    PermissionCode.MITRE_READ: ("mitre", "Browse MITRE ATT&CK matrix and incident mappings"),
    PermissionCode.MITRE_MAP: ("mitre", "Suggest or add MITRE ATT&CK mappings on incidents"),
    PermissionCode.MITRE_CONFIRM: ("mitre", "Confirm or reject suggested MITRE ATT&CK techniques"),
    PermissionCode.INCIDENTS_VIEW: ("incidents", "View incidents, timelines, and linked entities"),
    PermissionCode.INCIDENTS_CREATE: ("incidents", "Create incidents from alerts or investigations"),
    PermissionCode.INCIDENTS_UPDATE: ("incidents", "Progress incident lifecycle states and metadata"),
    PermissionCode.INCIDENTS_ASSIGN: ("incidents", "Assign or reassign incidents across analysts"),
    PermissionCode.INCIDENTS_CLOSE: ("incidents", "Transition resolved incidents to CLOSED with justification"),
    PermissionCode.INCIDENTS_REOPEN_CLOSED: ("incidents", "Reopen CLOSED incidents back to INVESTIGATING"),
    PermissionCode.NOTES_WRITE: ("investigation", "Create and revise timestamped investigation notes"),
    PermissionCode.EVIDENCE_READ: ("investigation", "Inspect, verify hash, and download incident evidence"),
    PermissionCode.EVIDENCE_UPLOAD: ("investigation", "Upload evidence artifacts and new evidence versions"),
    PermissionCode.EVIDENCE_WITHDRAW: ("investigation", "Soft-withdraw evidence items with reason"),
    PermissionCode.PLAYBOOKS_VIEW: ("automation", "View declarative playbooks and execution monitor"),
    PermissionCode.PLAYBOOKS_EXECUTE: ("automation", "Run playbooks and dry-run simulations"),
    PermissionCode.PLAYBOOKS_MANAGE: ("automation", "Create, edit, or toggle declarative playbooks"),
    PermissionCode.RESPONSE_PROPOSE: ("response", "Request human-approved containment/response actions"),
    PermissionCode.RESPONSE_APPROVE_LOW: ("response", "Approve low-impact response actions (four-eyes enforced)"),
    PermissionCode.RESPONSE_APPROVE_ALL: ("response", "Approve any response action including high/critical impact"),
    PermissionCode.RESPONSE_EXECUTE: ("response", "Execute approved response actions via adapter"),
    PermissionCode.REPORTS_VIEW: ("reports", "View generated incident reports"),
    PermissionCode.REPORTS_GENERATE: ("reports", "Generate and export PDF, JSON, and STIX incident reports"),
    PermissionCode.SIMULATION_RUN: ("simulation", "Launch realistic SOC attack simulation scenarios"),
    PermissionCode.USERS_READ: ("governance", "View SOC analyst roster and role matrix"),
    PermissionCode.USERS_MANAGE: ("governance", "Create, update, lock/unlock users and assign roles"),
    PermissionCode.INTEGRATIONS_MANAGE: ("governance", "Configure external integrations and webhook sources"),
    PermissionCode.SETTINGS_MANAGE: ("governance", "Configure SLA policies and system settings"),
    PermissionCode.AUDIT_READ: ("audit", "Search and verify tamper-evident audit logs"),
    PermissionCode.AUDIT_EXPORT: ("audit", "Export audit logs as CSV or JSON"),
}


_L1_PERMISSIONS: frozenset[PermissionCode] = frozenset(
    {
        PermissionCode.DASHBOARD_VIEW,
        PermissionCode.ALERTS_VIEW,
        PermissionCode.ALERTS_CREATE,
        PermissionCode.ALERTS_TRIAGE,
        PermissionCode.ENRICHMENT_READ,
        PermissionCode.ENRICHMENT_RUN,
        PermissionCode.MITRE_READ,
        PermissionCode.MITRE_MAP,
        PermissionCode.INCIDENTS_VIEW,
        PermissionCode.INCIDENTS_CREATE,
        PermissionCode.NOTES_WRITE,
        PermissionCode.EVIDENCE_READ,
        PermissionCode.EVIDENCE_UPLOAD,
        PermissionCode.PLAYBOOKS_VIEW,
        PermissionCode.RESPONSE_PROPOSE,
        PermissionCode.REPORTS_VIEW,
        PermissionCode.SIMULATION_RUN,
        PermissionCode.USERS_READ,
    }
)

_L2_PERMISSIONS: frozenset[PermissionCode] = _L1_PERMISSIONS | frozenset(
    {
        PermissionCode.MITRE_CONFIRM,
        PermissionCode.INCIDENTS_UPDATE,
        PermissionCode.INCIDENTS_CLOSE,
        PermissionCode.INCIDENTS_REOPEN_CLOSED,
        PermissionCode.EVIDENCE_WITHDRAW,
        PermissionCode.PLAYBOOKS_EXECUTE,
        PermissionCode.RESPONSE_APPROVE_LOW,
        PermissionCode.RESPONSE_EXECUTE,
        PermissionCode.REPORTS_GENERATE,
    }
)

_MANAGER_PERMISSIONS: frozenset[PermissionCode] = _L2_PERMISSIONS | frozenset(
    {
        PermissionCode.INCIDENTS_ASSIGN,
        PermissionCode.PLAYBOOKS_MANAGE,
        PermissionCode.RESPONSE_APPROVE_ALL,
        PermissionCode.SETTINGS_MANAGE,
        PermissionCode.AUDIT_READ,
    }
)

_ADMIN_PERMISSIONS: frozenset[PermissionCode] = _MANAGER_PERMISSIONS | frozenset(
    {
        PermissionCode.USERS_MANAGE,
        PermissionCode.INTEGRATIONS_MANAGE,
        PermissionCode.AUDIT_EXPORT,
    }
)

# Canonical single-source-of-truth Role -> Permissions Matrix
ROLE_PERMISSION_MATRIX: dict[RoleName, frozenset[PermissionCode]] = {
    RoleName.SOC_L1: _L1_PERMISSIONS,
    RoleName.SOC_L2: _L2_PERMISSIONS,
    RoleName.SOC_MANAGER: _MANAGER_PERMISSIONS,
    RoleName.ADMIN: _ADMIN_PERMISSIONS,
}


def role_has_permission(role_name: str, permission: PermissionCode) -> bool:
    try:
        role_enum = RoleName(role_name)
    except ValueError:
        return False
    return permission in ROLE_PERMISSION_MATRIX.get(role_enum, frozenset())


def public_endpoint(reason: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Explicitly mark a route handler as unauthenticated/custom-authenticated for RBAC audit tests."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        setattr(func, "__public_endpoint_reason__", reason)
        return func

    return decorator


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> User:
    access_token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not access_token:
        raise AppError(
            code="AUTHENTICATION_REQUIRED",
            message="Authentication required.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        claims = decode_access_token(access_token)
        user_uuid = uuid.UUID(str(claims["sub"]))
    except (jwt.PyJWTError, ValueError, KeyError) as exc:
        raise AppError(
            code="INVALID_ACCESS_TOKEN",
            message="Access token is invalid or expired.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from exc

    # Double-submit CSRF enforcement on all state-changing cookie-authenticated requests
    if request.method.upper() not in ("GET", "HEAD", "OPTIONS"):
        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_header = request.headers.get("X-CSRF-Token")
        if not verify_csrf_tokens(csrf_cookie, csrf_header):
            raise AppError(
                code="CSRF_VALIDATION_FAILED",
                message="Missing or invalid CSRF token.",
                status_code=status.HTTP_403_FORBIDDEN,
            )

    result = await db.execute(select(User).where(User.id == user_uuid))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise AppError(
            code="ACCOUNT_INACTIVE",
            message="User account is inactive or no longer exists.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Enforce forced password change in non-dev mode before accessing other endpoints
    if (
        user.must_change_password
        and not request.url.path.endswith(("/auth/me", "/auth/logout", "/auth/change-password"))
    ):
        raise AppError(
            code="PASSWORD_CHANGE_REQUIRED",
            message="You must change your temporary password before accessing SENTINEL IR.",
            status_code=status.HTTP_403_FORBIDDEN,
        )

    request.state.current_user = user
    return user


def require_authenticated_user() -> Callable[..., Coroutine[Any, Any, User]]:
    async def _dep(user: User = Depends(get_current_user)) -> User:
        return user

    setattr(_dep, "__authenticated_only__", True)
    return _dep


def require_permission(
    permission: PermissionCode,
) -> Callable[..., Coroutine[Any, Any, User]]:
    async def _permission_guard(
        request: Request,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db_session),
    ) -> User:
        role_name = user.role.name if user.role else ""
        if not role_has_permission(role_name, permission):
            await AuditService.record(
                db,
                action="rbac.permission_denied",
                actor=user,
                target_type="endpoint",
                target_id=f"{request.method} {request.url.path}",
                outcome="denied",
                source_ip=request.client.host if request.client else None,
                details={
                    "required_permission": permission.value,
                    "actor_role": role_name,
                },
            )
            await db.commit()
            raise AppError(
                code="INSUFFICIENT_PERMISSIONS",
                message=f"Role '{role_name}' lacks required permission '{permission.value}'.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        return user

    setattr(_permission_guard, "__required_permission__", permission)
    return _permission_guard

