"""Authentication service: Argon2id login, lockout, rotating refresh families, reuse detection, TOTP."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import status
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.security import (
    create_access_token,
    decrypt_secret,
    generate_opaque_token,
    hash_password,
    sha256_hex,
    validate_password_policy,
    verify_dummy_password,
    verify_password,
)
from app.models.user import RefreshToken, User
from app.services.audit_service import AuditService

GENERIC_LOGIN_ERROR = "Invalid credentials or account temporarily locked."


class AuthService:
    @staticmethod
    async def authenticate_user(
        db: AsyncSession,
        *,
        identifier: str,
        password: str,
        source_ip: str | None,
        user_agent: str | None,
        totp_code: str | None = None,
    ) -> tuple[User, str, str, str]:
        settings = get_settings()
        normalized = identifier.strip().lower()
        now = datetime.now(UTC)

        stmt = select(User).where(
            or_(
                func.lower(User.username) == normalized,
                func.lower(User.email) == normalized,
            )
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if user is None:
            verify_dummy_password(password)
            await AuditService.record(
                db,
                action="auth.login_failed",
                actor_username_override=normalized[:64] or "unknown",
                target_type="user",
                outcome="failure",
                source_ip=source_ip,
                details={"reason": "unknown_principal"},
            )
            await db.commit()
            raise AppError(
                code="INVALID_CREDENTIALS",
                message=GENERIC_LOGIN_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if not user.is_active:
            verify_dummy_password(password)
            await AuditService.record(
                db,
                action="auth.login_failed",
                actor=user,
                target_type="user",
                target_id=str(user.id),
                outcome="denied",
                source_ip=source_ip,
                details={"reason": "account_inactive"},
            )
            await db.commit()
            raise AppError(
                code="INVALID_CREDENTIALS",
                message=GENERIC_LOGIN_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if user.locked_until and user.locked_until > now:
            verify_dummy_password(password)
            await AuditService.record(
                db,
                action="auth.login_blocked_locked",
                actor=user,
                target_type="user",
                target_id=str(user.id),
                outcome="denied",
                source_ip=source_ip,
                details={"locked_until": user.locked_until.isoformat()},
            )
            await db.commit()
            raise AppError(
                code="INVALID_CREDENTIALS",
                message=GENERIC_LOGIN_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if not verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            locked_now = False
            if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
                locked_now = True

            await AuditService.record(
                db,
                action="auth.account_locked" if locked_now else "auth.login_failed",
                actor=user,
                target_type="user",
                target_id=str(user.id),
                outcome="failure",
                source_ip=source_ip,
                details={
                    "failed_attempts": user.failed_login_attempts,
                    "locked": locked_now,
                },
            )
            await db.commit()
            raise AppError(
                code="INVALID_CREDENTIALS",
                message=GENERIC_LOGIN_ERROR,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if user.totp_enabled and user.totp_secret_encrypted:
            if not totp_code:
                raise AppError(
                    code="MFA_REQUIRED",
                    message="Multi-factor authentication code required.",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )
            totp_secret = decrypt_secret(user.totp_secret_encrypted)
            totp = pyotp.TOTP(totp_secret)
            if not totp.verify(totp_code.strip(), valid_window=1):
                user.failed_login_attempts += 1
                await AuditService.record(
                    db,
                    action="auth.mfa_failed",
                    actor=user,
                    target_type="user",
                    target_id=str(user.id),
                    outcome="failure",
                    source_ip=source_ip,
                )
                await db.commit()
                raise AppError(
                    code="INVALID_MFA_CODE",
                    message="Invalid multi-factor authentication code.",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                )

        # Successful authentication
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now

        role_name = user.role.name if user.role else "soc_l1"
        access_token, _ = create_access_token(
            user_id=user.id,
            username=user.username,
            role=role_name,
            must_change_password=user.must_change_password,
        )

        raw_refresh = generate_opaque_token(48)
        family_id = uuid.uuid4()
        refresh_row = RefreshToken(
            user_id=user.id,
            token_hash=sha256_hex(raw_refresh),
            family_id=family_id,
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            ip_address=source_ip,
            user_agent=(user_agent or "")[:255] or None,
        )
        db.add(refresh_row)

        csrf_token = generate_opaque_token(32)

        await AuditService.record(
            db,
            action="auth.login_succeeded",
            actor=user,
            target_type="user",
            target_id=str(user.id),
            outcome="success",
            source_ip=source_ip,
            details={"family_id": str(family_id)},
        )
        await db.commit()
        return user, access_token, raw_refresh, csrf_token

    @staticmethod
    async def rotate_refresh_token(
        db: AsyncSession,
        *,
        raw_refresh_token: str | None,
        source_ip: str | None,
        user_agent: str | None,
    ) -> tuple[User, str, str, str]:
        if not raw_refresh_token:
            raise AppError(
                code="MISSING_REFRESH_TOKEN",
                message="Refresh token missing.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        settings = get_settings()
        now = datetime.now(UTC)
        token_hash = sha256_hex(raw_refresh_token)

        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        token_row = result.scalar_one_or_none()
        if token_row is None:
            await AuditService.record(
                db,
                action="auth.refresh_unknown_token",
                target_type="session",
                outcome="denied",
                source_ip=source_ip,
            )
            await db.commit()
            raise AppError(
                code="INVALID_REFRESH_TOKEN",
                message="Refresh token invalid.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        user_res = await db.execute(select(User).where(User.id == token_row.user_id))
        user = user_res.scalar_one_or_none()

        # Detect reuse of an already-rotated or revoked refresh token -> revoke whole family!
        if token_row.replaced_by_id is not None or token_row.revoked_at is not None:
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.family_id == token_row.family_id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=now, revoke_reason="reuse_detected")
            )
            await AuditService.record(
                db,
                action="auth.refresh_token_reuse_detected",
                actor=user,
                target_type="session_family",
                target_id=str(token_row.family_id),
                outcome="denied",
                source_ip=source_ip,
                details={
                    "reused_token_id": str(token_row.id),
                    "family_revoked": True,
                },
            )
            await db.commit()
            raise AppError(
                code="REFRESH_TOKEN_REUSE_DETECTED",
                message="Session revoked due to refresh token reuse anomaly.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if token_row.expires_at <= now or user is None or not user.is_active:
            token_row.revoked_at = now
            token_row.revoke_reason = "expired_or_inactive"
            await db.commit()
            raise AppError(
                code="REFRESH_TOKEN_EXPIRED",
                message="Session expired. Please sign in again.",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        new_raw_refresh = generate_opaque_token(48)
        new_row = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=sha256_hex(new_raw_refresh),
            family_id=token_row.family_id,
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            ip_address=source_ip,
            user_agent=(user_agent or "")[:255] or None,
        )
        db.add(new_row)
        token_row.replaced_by_id = new_row.id
        token_row.revoked_at = now
        token_row.revoke_reason = "rotated"

        role_name = user.role.name if user.role else "soc_l1"
        access_token, _ = create_access_token(
            user_id=user.id,
            username=user.username,
            role=role_name,
            must_change_password=user.must_change_password,
        )
        csrf_token = generate_opaque_token(32)

        await db.commit()
        return user, access_token, new_raw_refresh, csrf_token

    @staticmethod
    async def logout_session(
        db: AsyncSession,
        *,
        user: User | None,
        raw_refresh_token: str | None,
        source_ip: str | None,
    ) -> None:
        now = datetime.now(UTC)
        if raw_refresh_token:
            th = sha256_hex(raw_refresh_token)
            res = await db.execute(select(RefreshToken).where(RefreshToken.token_hash == th))
            row = res.scalar_one_or_none()
            if row is not None:
                await db.execute(
                    update(RefreshToken)
                    .where(
                        RefreshToken.family_id == row.family_id,
                        RefreshToken.revoked_at.is_(None),
                    )
                    .values(revoked_at=now, revoke_reason="user_logout")
                )

        if user is not None:
            await AuditService.record(
                db,
                action="auth.logout",
                actor=user,
                target_type="user",
                target_id=str(user.id),
                outcome="success",
                source_ip=source_ip,
            )
        await db.commit()

    @staticmethod
    async def change_password(
        db: AsyncSession,
        *,
        user: User,
        current_password: str,
        new_password: str,
        source_ip: str | None,
    ) -> None:
        if not verify_password(current_password, user.password_hash):
            await AuditService.record(
                db,
                action="auth.password_change_failed",
                actor=user,
                target_type="user",
                target_id=str(user.id),
                outcome="failure",
                source_ip=source_ip,
                details={"reason": "invalid_current_password"},
            )
            await db.commit()
            raise AppError(
                code="INVALID_CURRENT_PASSWORD",
                message="Current password is incorrect.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        policy_errors = validate_password_policy(new_password)
        if policy_errors:
            raise AppError(
                code="PASSWORD_POLICY_VIOLATION",
                message="New password does not meet enterprise security policy.",
                status_code=status.HTTP_400_BAD_REQUEST,
                details={"violations": policy_errors},
            )

        user.password_hash = hash_password(new_password)
        user.must_change_password = False

        now = datetime.now(UTC)
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now, revoke_reason="password_changed")
        )

        await AuditService.record(
            db,
            action="auth.password_changed",
            actor=user,
            target_type="user",
            target_id=str(user.id),
            outcome="success",
            source_ip=source_ip,
        )
        await db.commit()

