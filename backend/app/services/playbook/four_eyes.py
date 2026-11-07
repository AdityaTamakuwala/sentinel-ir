"""Four-Eyes approval verification and policy engine for response actions."""

from __future__ import annotations

from app.core.errors import AppError
from app.core.rbac import PermissionCode
from app.models.automation import ResponseAction
from app.models.base import utc_now
from app.models.user import User


def validate_response_approval(
    action: ResponseAction,
    approver: User,
    approver_permissions: frozenset[PermissionCode],
) -> None:
    """Validate four-eyes rule, expiration, action state, and role authorization.

    Raises AppError on any policy violation.
    """
    # 1. Action State Check
    if action.status != "PENDING_APPROVAL":
        raise AppError(
            code="INVALID_STATE",
            message=f"Response action {action.id} is in status '{action.status}', not 'PENDING_APPROVAL'.",
            status_code=400,
        )

    # 2. Expiration Check
    now = utc_now()
    if action.expires_at and now > action.expires_at:
        raise AppError(
            code="ACTION_EXPIRED",
            message=f"Response action {action.id} expired at {action.expires_at.isoformat()} UTC.",
            status_code=400,
        )

    # 3. Four-Eyes Rule: Requester MUST NOT approve own action
    if action.requested_by_id == approver.id:
        raise AppError(
            code="FOUR_EYES_VIOLATION",
            message="Four-eyes rule violation: You cannot approve or reject an action that you requested.",
            status_code=403,
        )

    # 4. Role Tiering Check
    risk = action.risk_impact.lower()
    if risk in ("high", "critical"):
        # High and critical impact actions strictly require RESPONSE_APPROVE_ALL (Manager or Admin)
        if PermissionCode.RESPONSE_APPROVE_ALL not in approver_permissions:
            raise AppError(
                code="INSUFFICIENT_PERMISSIONS",
                message=f"Action risk impact '{risk}' requires Manager or Admin authorization (response:approve_all).",
                status_code=403,
            )
    else:
        # Low and medium impact actions require at least RESPONSE_APPROVE_LOW (L2, Manager, Admin)
        has_low = PermissionCode.RESPONSE_APPROVE_LOW in approver_permissions
        has_all = PermissionCode.RESPONSE_APPROVE_ALL in approver_permissions
        if not (has_low or has_all):
            raise AppError(
                code="INSUFFICIENT_PERMISSIONS",
                message="Approval requires at least SOC L2 authorization (response:approve_low).",
                status_code=403,
            )
