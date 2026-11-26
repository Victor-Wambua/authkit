"""Append-only audit trail."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from authkit.context import AppContext
from authkit.models import AuditEvent

# Every event name that can be written. Kept as constants so typos fail at import time.
REGISTER = "register"
REGISTER_DUPLICATE = "register_duplicate"
LOGIN_SUCCESS = "login_success"
LOGIN_FAILURE = "login_failure"
LOGIN_BLOCKED = "login_blocked"
LOGIN_PASSWORD_OK_MFA_PENDING = "login_password_ok_mfa_pending"
MFA_FAILURE = "mfa_failure"
MFA_BLOCKED = "mfa_blocked"
LOGOUT = "logout"
PASSWORD_CHANGED = "password_changed"
PASSWORD_REHASHED = "password_rehashed"
PASSWORD_RESET_REQUESTED = "password_reset_requested"
PASSWORD_RESET_COMPLETED = "password_reset_completed"
EMAIL_VERIFIED = "email_verified"
TOTP_ENABLED = "totp_enabled"
TOTP_DISABLED = "totp_disabled"
RECOVERY_CODE_USED = "recovery_code_used"
RECOVERY_CODES_REGENERATED = "recovery_codes_regenerated"
TOKEN_REUSE_DETECTED = "token_reuse_detected"
SESSION_REVOKED = "session_revoked"
OTHER_SESSIONS_REVOKED = "other_sessions_revoked"
ACCOUNT_DELETED = "account_deleted"


@dataclass(frozen=True)
class RequestInfo:
    ip: str | None = None
    user_agent: str | None = None


def record(
    ctx: AppContext,
    db: Session,
    event: str,
    req: RequestInfo,
    *,
    user_id: str | None = None,
    session_id: str | None = None,
    **detail: Any,
) -> None:
    """Add an audit row to the caller's transaction. ``detail`` must never hold secrets."""
    db.add(
        AuditEvent(
            at=ctx.clock.now(),
            event=event,
            user_id=user_id,
            session_id=session_id,
            ip=req.ip,
            user_agent=(req.user_agent or "")[:256] or None,
            detail=json.dumps(detail, sort_keys=True) if detail else None,
        )
    )
