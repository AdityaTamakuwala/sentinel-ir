"""Analyst Roster, User Lifecycle, and Role Permission Matrix endpoints (`/api/v1/users`)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import _serialize_user
from app.core.errors import AppError
from app.core.rbac import (
    ROLE_PERMISSION_MATRIX,
    PermissionCode,
    RoleName,
    require_permission,
)
from app.core.security import hash_password, validate_password_policy
from app.db.session import get_db_session
from app.models.user import Role, User
from app.schemas.auth import (
    CreateUserRequest,
    RoleMatrixEntryOut,
    UpdateUserRequest,
    UserSummaryOut,
)
from app.services.audit_service import AuditService

router = APIRouter(prefix="/users", tags=["Analyst & Team Management"])

ROLE_LABELS = {
    RoleName.SOC_L1: "SOC Analyst L1",
    RoleName.SOC_L2: "SOC Analyst L2",
    RoleName.SOC_MANAGER: "SOC Manager",
    RoleName.ADMIN: "Platform Administrator",
}


@router.get("", response_model=list[UserSummaryOut])
async def list_users(
    _actor: User = Depends(require_permission(PermissionCode.USERS_READ)),
    db: AsyncSession = Depends(get_db_session),
) -> list[UserSummaryOut]:
    res = await db.execute(select(User).order_by(User.username.asc()))
    return [_serialize_user(u) for u in res.scalars().all()]


@router.get("/roles/matrix", response_model=list[RoleMatrixEntryOut])
async def get_role_matrix(
    _actor: User = Depends(require_permission(PermissionCode.USERS_READ)),
) -> list[RoleMatrixEntryOut]:
    return [
        RoleMatrixEntryOut(
            role=r.value,
            display_name=ROLE_LABELS[r],
            permissions=sorted(p.value for p in perms),
        )
        for r, perms in ROLE_PERMISSION_MATRIX.items()
    ]


@router.post("", response_model=UserSummaryOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.USERS_MANAGE)),
    db: AsyncSession = Depends(get_db_session),
) -> UserSummaryOut:
    policy_errors = validate_password_policy(payload.password)
    if policy_errors:
        raise AppError(
            code="PASSWORD_POLICY_VIOLATION",
            message="Password does not satisfy enterprise complexity requirements.",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details={"violations": policy_errors},
        )

    dup = await db.execute(
        select(User).where(
            or_(
                func.lower(User.username) == payload.username.lower(),
                func.lower(User.email) == payload.email.lower(),
            )
        )
    )
    if dup.scalar_one_or_none() is not None:
        raise AppError(
            code="USER_ALREADY_EXISTS",
            message="A user with that username or email already exists.",
            status_code=status.HTTP_409_CONFLICT,
        )

    role_res = await db.execute(select(Role).where(Role.name == payload.role))
    role = role_res.scalar_one_or_none()
    if role is None:
        raise AppError("ROLE_NOT_FOUND", f"Role '{payload.role}' not provisioned.", 404)

    new_user = User(
        id=uuid.uuid4(),
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role_id=role.id,
        is_active=True,
        is_demo_user=False,
        must_change_password=payload.must_change_password,
    )
    db.add(new_user)
    await db.flush()
    new_user.role = role

    await AuditService.record(
        db,
        action="user.created",
        actor=actor,
        target_type="user",
        target_id=str(new_user.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={"username": new_user.username, "role": role.name},
    )
    await db.commit()
    await db.refresh(new_user)
    return _serialize_user(new_user)


@router.patch("/{user_id}", response_model=UserSummaryOut)
async def update_user(
    user_id: uuid.UUID,
    payload: UpdateUserRequest,
    request: Request,
    actor: User = Depends(require_permission(PermissionCode.USERS_MANAGE)),
    db: AsyncSession = Depends(get_db_session),
) -> UserSummaryOut:
    res = await db.execute(select(User).where(User.id == user_id))
    target = res.scalar_one_or_none()
    if target is None:
        raise AppError("USER_NOT_FOUND", "User not found.", 404)

    before = {
        "role": target.role.name if target.role else None,
        "is_active": target.is_active,
        "full_name": target.full_name,
    }

    if payload.full_name is not None:
        target.full_name = payload.full_name.strip()

    if payload.role is not None:
        if target.id == actor.id and payload.role != "admin":
            raise AppError(
                "SELF_DEMOTION_FORBIDDEN",
                "Administrators cannot demote their own active account.",
                400,
            )
        role_res = await db.execute(select(Role).where(Role.name == payload.role))
        role = role_res.scalar_one_or_none()
        if role is None:
            raise AppError("ROLE_NOT_FOUND", f"Role '{payload.role}' not found.", 404)
        target.role_id = role.id
        target.role = role

    if payload.is_active is not None:
        if target.id == actor.id and not payload.is_active:
            raise AppError(
                "SELF_DEACTIVATION_FORBIDDEN",
                "Administrators cannot deactivate their own account.",
                400,
            )
        target.is_active = payload.is_active

    if payload.unlock_account:
        target.failed_login_attempts = 0
        target.locked_until = None

    await AuditService.record(
        db,
        action="user.updated",
        actor=actor,
        target_type="user",
        target_id=str(target.id),
        outcome="success",
        source_ip=request.client.host if request.client else None,
        details={
            "before": before,
            "after": {
                "role": target.role.name if target.role else None,
                "is_active": target.is_active,
                "full_name": target.full_name,
            },
            "unlocked": payload.unlock_account,
        },
    )
    await db.commit()
    await db.refresh(target)
    return _serialize_user(target)

