"""Authentication, Session, User, and Role Matrix Pydantic v2 schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginRequest(BaseModel):
    identifier: str = Field(..., min_length=2, max_length=255)
    password: str = Field(..., min_length=1, max_length=256)
    totp_code: str | None = Field(default=None, max_length=12)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=12, max_length=256)


class UserSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    is_demo_user: bool
    must_change_password: bool
    totp_enabled: bool
    last_login_at: datetime | None = None
    created_at: datetime


class AuthSessionResponse(BaseModel):
    user: UserSummaryOut
    permissions: list[str]
    csrf_token: str
    app_env: str


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=128)
    password: str = Field(..., min_length=12, max_length=256)
    role: Literal["soc_l1", "soc_l2", "soc_manager", "admin"]
    must_change_password: bool = True


class UpdateUserRequest(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=128)
    role: Literal["soc_l1", "soc_l2", "soc_manager", "admin"] | None = None
    is_active: bool | None = None
    unlock_account: bool = False


class RoleMatrixEntryOut(BaseModel):
    role: str
    display_name: str
    permissions: list[str]


class TotpSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TotpVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

