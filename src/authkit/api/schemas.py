"""Request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Email = Field(min_length=3, max_length=254, examples=["amina@example.com"])
# Upper bound on input size only; the real length policy is enforced by the service.
Secret = Field(min_length=1, max_length=1024)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterIn(Strict):
    email: str = Email
    password: str = Secret


class AcceptedOut(BaseModel):
    status: Literal["accepted"] = "accepted"
    message: str


class LoginIn(Strict):
    email: str = Email
    password: str = Secret


class MfaLoginIn(Strict):
    mfa_token: str = Field(min_length=10, max_length=2048)
    code: str = Field(min_length=6, max_length=32, description="6-digit TOTP or a recovery code")


class RefreshIn(Strict):
    refresh_token: str | None = Field(default=None, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    refresh_token: str | None = Field(
        default=None, description="Omitted when the X-Auth-Mode: cookie header is sent."
    )


class LoginOut(BaseModel):
    status: Literal["ok", "mfa_required"]
    access_token: str | None = None
    token_type: Literal["Bearer"] | None = None
    expires_in: int | None = None
    refresh_token: str | None = None
    mfa_token: str | None = None


class TokenIn(Strict):
    token: str = Field(min_length=10, max_length=256)


class ForgotIn(Strict):
    email: str = Email


class ResetIn(Strict):
    token: str = Field(min_length=10, max_length=256)
    new_password: str = Secret


class ChangePasswordIn(Strict):
    current_password: str = Secret
    new_password: str = Secret


class DeleteAccountIn(Strict):
    password: str = Secret
    code: str | None = Field(default=None, max_length=32)


class UserOut(BaseModel):
    id: str
    email: str
    role: Literal["user", "admin"]
    email_verified: bool
    totp_enabled: bool
    created_at: datetime


class SessionOut(BaseModel):
    id: str
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    ip: str | None
    user_agent: str | None
    used_2fa: bool
    current: bool


class SessionsOut(BaseModel):
    sessions: list[SessionOut]


class RevokedOut(BaseModel):
    revoked: int


class MfaSetupOut(BaseModel):
    secret: str = Field(description="Base32 secret for manual entry")
    otpauth_uri: str
    qr_svg: str = Field(description="Inline SVG of the QR code, generated on the server")


class CodeIn(Strict):
    code: str = Field(min_length=6, max_length=32)


class MfaReauthIn(Strict):
    password: str = Secret
    code: str = Field(min_length=6, max_length=32)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


class AuditOut(BaseModel):
    id: int
    at: datetime
    event: str
    user_id: str | None
    session_id: str | None
    ip: str | None
    user_agent: str | None
    detail: dict[str, object] | None


class AuditPage(BaseModel):
    items: list[AuditOut]
    next_before: int | None


class AdminUserOut(UserOut):
    is_active: bool


class AdminUsersOut(BaseModel):
    users: list[AdminUserOut]


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorOut(BaseModel):
    error: ErrorBody
