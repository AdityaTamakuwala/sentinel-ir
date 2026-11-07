"""Cryptographic primitives: Argon2id, JWT, Fernet at-rest encryption, CSRF, and cookies."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from fastapi import Response

from app.core.config import get_settings

ACCESS_COOKIE_NAME = "sentinel_access"
REFRESH_COOKIE_NAME = "sentinel_refresh"
CSRF_COOKIE_NAME = "sentinel_csrf"

JWT_ISSUER = "sentinel-ir"
JWT_AUDIENCE = "sentinel-ir-web"

_ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)
# Precomputed dummy Argon2id hash so unknown-username logins spend identical CPU time
_DUMMY_ARGON2_HASH = _ph.hash("DummyTimingProtection!2026#Sentinel")


def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_dummy_password(plaintext: str) -> None:
    """Spend Argon2id verification time when username does not exist to prevent timing enumeration."""
    verify_password(plaintext, _DUMMY_ARGON2_HASH)


def validate_password_policy(password: str) -> list[str]:
    """Return list of policy violations (empty list means compliant)."""
    issues: list[str] = []
    if len(password) < 12:
        issues.append("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password):
        issues.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        issues.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        issues.append("Password must contain at least one digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        issues.append("Password must contain at least one special character.")
    return issues


def sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def generate_opaque_token(nbytes: int = 48) -> str:
    return secrets.token_urlsafe(nbytes)


def encrypt_secret(plaintext: str) -> str:
    settings = get_settings()
    f = Fernet(settings.ENCRYPTION_KEY.encode("utf-8"))
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    settings = get_settings()
    f = Fernet(settings.ENCRYPTION_KEY.encode("utf-8"))
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def mask_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    if len(secret) <= 8:
        return "••••••••"
    return f"{secret[:4]}••••••••{secret[-4:]}"


def create_access_token(
    *,
    user_id: uuid.UUID,
    username: str,
    role: str,
    must_change_password: bool = False,
) -> tuple[str, datetime]:
    settings = get_settings()
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "mcp": must_change_password,
        "jti": str(uuid.uuid4()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    encoded = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return encoded, expires_at


def decode_access_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    decoded: dict[str, Any] = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=["HS256"],
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        options={"require": ["sub", "role", "exp", "iat", "iss", "aud"]},
    )
    return decoded


def verify_csrf_tokens(cookie_token: str | None, header_token: str | None) -> bool:
    if not cookie_token or not header_token:
        return False
    return hmac.compare_digest(cookie_token, header_token)


def set_auth_cookies(
    response: Response,
    *,
    access_token: str,
    refresh_token: str,
    csrf_token: str,
) -> None:
    settings = get_settings()
    secure = settings.effective_cookie_secure
    access_max_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400

    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=access_token,
        max_age=access_max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=refresh_max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/api/v1/auth",
    )
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=refresh_max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    settings = get_settings()
    secure = settings.effective_cookie_secure
    response.delete_cookie(ACCESS_COOKIE_NAME, path="/", secure=secure, samesite="strict")
    response.delete_cookie(
        REFRESH_COOKIE_NAME, path="/api/v1/auth", secure=secure, samesite="strict"
    )
    response.delete_cookie(CSRF_COOKIE_NAME, path="/", secure=secure, samesite="strict")

