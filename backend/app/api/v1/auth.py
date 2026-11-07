"""Authentication & Session Lifecycle endpoints (`/api/v1/auth`)."""

from __future__ import annotations

import pyotp
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.errors import AppError
from app.core.rate_limit import enforce_rate_limit
from app.core.rbac import (
    ROLE_PERMISSION_MATRIX,
    RoleName,
    public_endpoint,
    require_authenticated_user,
)
from app.core.security import (
    CSRF_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
    clear_auth_cookies,
    decrypt_secret,
    encrypt_secret,
    generate_opaque_token,
    set_auth_cookies,
)
from app.db.session import get_db_session
from app.models.user import User
from app.schemas.auth import (
    AuthSessionResponse,
    ChangePasswordRequest,
    LoginRequest,
    TotpSetupResponse,
    TotpVerifyRequest,
    UserSummaryOut,
)
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _serialize_user(user: User) -> UserSummaryOut:
    role_name = user.role.name if user.role else "soc_l1"
    return UserSummaryOut(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=role_name,
        is_active=user.is_active,
        is_demo_user=user.is_demo_user,
        must_change_password=user.must_change_password,
        totp_enabled=user.totp_enabled,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


def _permissions_for_user(user: User) -> list[str]:
    role_name = user.role.name if user.role else "soc_l1"
    try:
        r_enum = RoleName(role_name)
    except ValueError:
        return []
    return sorted(p.value for p in ROLE_PERMISSION_MATRIX.get(r_enum, frozenset()))


@router.post("/login", response_model=AuthSessionResponse)
@public_endpoint(reason="Credential exchange endpoint issuing httpOnly cookies + CSRF token")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db_session),
) -> AuthSessionResponse:
    client_ip = request.client.host if request.client else "unknown"
    await enforce_rate_limit(f"auth_login:{client_ip}", max_requests=20, window_seconds=60)

    user, access_token, refresh_token, csrf_token = await AuthService.authenticate_user(
        db,
        identifier=payload.identifier,
        password=payload.password,
        source_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
        totp_code=payload.totp_code,
    )
    set_auth_cookies(
        response,
        access_token=access_token,
        refresh_token=refresh_token,
        csrf_token=csrf_token,
    )
    settings = get_settings()
    return AuthSessionResponse(
        user=_serialize_user(user),
        permissions=_permissions_for_user(user),
        csrf_token=csrf_token,
        app_env=settings.APP_ENV,
    )


@router.post("/refresh", response_model=AuthSessionResponse)
@public_endpoint(reason="Rotating refresh-token cookie exchange with family reuse detection")
async def refresh_session(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db_session),
) -> AuthSessionResponse:
    client_ip = request.client.host if request.client else "unknown"
    await enforce_rate_limit(f"auth_refresh:{client_ip}", max_requests=30, window_seconds=60)

    raw_refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    try:
        user, access_token, new_refresh, csrf_token = await AuthService.rotate_refresh_token(
            db,
            raw_refresh_token=raw_refresh,
            source_ip=client_ip,
            user_agent=request.headers.get("user-agent"),
        )
    except AppError:
        clear_auth_cookies(response)
        raise

    set_auth_cookies(
        response,
        access_token=access_token,
        refresh_token=new_refresh,
        csrf_token=csrf_token,
    )
    settings = get_settings()
    return AuthSessionResponse(
        user=_serialize_user(user),
        permissions=_permissions_for_user(user),
        csrf_token=csrf_token,
        app_env=settings.APP_ENV,
    )


@router.get("/me", response_model=AuthSessionResponse)
async def get_current_session(
    request: Request,
    response: Response,
    user: User = Depends(require_authenticated_user()),
) -> AuthSessionResponse:
    settings = get_settings()
    csrf = request.cookies.get(CSRF_COOKIE_NAME)
    if not csrf:
        csrf = generate_opaque_token(32)
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf,
            httponly=False,
            secure=settings.effective_cookie_secure,
            samesite="strict",
            path="/",
        )
    return AuthSessionResponse(
        user=_serialize_user(user),
        permissions=_permissions_for_user(user),
        csrf_token=csrf,
        app_env=settings.APP_ENV,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    raw_refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    await AuthService.logout_session(
        db,
        user=user,
        raw_refresh_token=raw_refresh,
        source_ip=request.client.host if request.client else None,
    )
    clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    await AuthService.change_password(
        db,
        user=user,
        current_password=payload.current_password,
        new_password=payload.new_password,
        source_ip=request.client.host if request.client else None,
    )
    clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/mfa/setup", response_model=TotpSetupResponse)
async def setup_totp(
    request: Request,
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> TotpSetupResponse:
    secret = pyotp.random_base32()
    user.totp_secret_encrypted = encrypt_secret(secret)
    user.totp_enabled = False
    await AuditService.record(
        db,
        action="auth.mfa_setup_initiated",
        actor=user,
        target_type="user",
        target_id=str(user.id),
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SENTINEL IR")
    return TotpSetupResponse(secret=secret, provisioning_uri=uri)


@router.post("/mfa/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_totp(
    payload: TotpVerifyRequest,
    request: Request,
    user: User = Depends(require_authenticated_user()),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    if not user.totp_secret_encrypted:
        raise AppError("MFA_NOT_INITIALIZED", "Run /mfa/setup before enabling MFA.", 400)
    secret = decrypt_secret(user.totp_secret_encrypted)
    if not pyotp.TOTP(secret).verify(payload.code.strip(), valid_window=1):
        raise AppError("INVALID_MFA_CODE", "TOTP verification code is invalid.", 400)
    user.totp_enabled = True
    await AuditService.record(
        db,
        action="auth.mfa_enabled",
        actor=user,
        target_type="user",
        target_id=str(user.id),
        source_ip=request.client.host if request.client else None,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

