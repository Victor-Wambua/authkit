"""TOTP enrolment and verification, plus single-use recovery codes."""

from __future__ import annotations

import io
import re
import secrets

import segno
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from authkit.context import AppContext
from authkit.errors import ApiError
from authkit.models import RecoveryCode, User
from authkit.security import totp
from authkit.services import audit
from authkit.services.audit import RequestInfo

RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
RECOVERY_COUNT = 10
_TOTP_RE = re.compile(r"\d{6}")


def new_recovery_code() -> str:
    """16 symbols x 5 bits = 80 bits, shown as XXXX-XXXX-XXXX-XXXX."""
    raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(16))
    return "-".join(raw[i : i + 4] for i in range(0, 16, 4))


def normalize_recovery(code: str) -> str:
    return re.sub(r"[\s-]", "", code).upper()


def qr_svg(uri: str) -> str:
    """Server-side QR as an inline SVG string. Nothing is sent to a third party."""
    buffer = io.BytesIO()
    segno.make(uri, error="m").save(
        buffer,
        kind="svg",
        scale=1,
        border=2,
        dark="#111111",
        light="#ffffff",
        omitsize=True,  # viewBox only, so CSS decides the rendered size
        xmldecl=False,
        svgns=True,
        nl=False,
        svgclass="qr",
    )
    out = buffer.getvalue().decode()
    return out


def begin_setup(ctx: AppContext, db: Session, user: User) -> tuple[str, str]:
    if user.totp_enabled:
        raise ApiError(409, "totp_already_enabled", "Two-factor authentication is already on.")
    secret = totp.generate_secret()
    user.totp_secret_enc = ctx.secrets.encrypt(secret)
    user.totp_last_step = 0
    uri = totp.provisioning_uri(secret, user.email, ctx.settings.totp_issuer)
    db.commit()
    return totp.b32(secret), uri


def verify_user_code(ctx: AppContext, db: Session, user: User, code: str) -> bool:
    """Check a TOTP code once. A code (or an earlier one) can never be accepted twice."""
    if user.totp_secret_enc is None:
        return False
    secret = ctx.secrets.decrypt(user.totp_secret_enc)
    step = totp.verify(
        secret, code, ctx.clock.now().timestamp(), last_used_step=user.totp_last_step
    )
    if step is None:
        return False
    claimed = db.execute(
        update(User)
        .where(User.id == user.id, User.totp_last_step < step)
        .values(totp_last_step=step)
    )
    if claimed.rowcount != 1:  # type: ignore[attr-defined]
        return False
    user.totp_last_step = step
    return True


def consume_recovery(ctx: AppContext, db: Session, user: User, code: str) -> bool:
    digest = ctx.secrets.keyed_hash(normalize_recovery(code))
    row = db.scalar(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == digest,
            RecoveryCode.used_at.is_(None),
        )
    )
    if row is None:
        return False
    claimed = db.execute(
        update(RecoveryCode)
        .where(RecoveryCode.id == row.id, RecoveryCode.used_at.is_(None))
        .values(used_at=ctx.clock.now())
    )
    return bool(claimed.rowcount == 1)  # type: ignore[attr-defined]


def check_second_factor(ctx: AppContext, db: Session, user: User, code: str) -> str | None:
    """Return 'totp', 'recovery' or None. Six digits is TOTP, anything else a recovery code."""
    candidate = code.strip()
    if _TOTP_RE.fullmatch(candidate):
        return "totp" if verify_user_code(ctx, db, user, candidate) else None
    return "recovery" if consume_recovery(ctx, db, user, candidate) else None


def remaining_recovery_codes(db: Session, user_id: str) -> int:
    return int(
        db.scalar(
            select(func.count(RecoveryCode.id)).where(
                RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None)
            )
        )
        or 0
    )


def _replace_codes(ctx: AppContext, db: Session, user_id: str) -> list[str]:
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    codes = [new_recovery_code() for _ in range(RECOVERY_COUNT)]
    for c in codes:
        db.add(
            RecoveryCode(user_id=user_id, code_hash=ctx.secrets.keyed_hash(normalize_recovery(c)))
        )
    return codes


def enable(ctx: AppContext, db: Session, user: User, code: str, req: RequestInfo) -> list[str]:
    if user.totp_enabled:
        raise ApiError(409, "totp_already_enabled", "Two-factor authentication is already on.")
    if user.totp_secret_enc is None:
        raise ApiError(409, "totp_not_started", "Start setup first.")
    if not _TOTP_RE.fullmatch(code.strip()) or not verify_user_code(ctx, db, user, code.strip()):
        db.commit()
        raise ApiError(400, "invalid_code", "The code is incorrect or expired.")
    user.totp_enabled_at = ctx.clock.now()
    codes = _replace_codes(ctx, db, user.id)
    audit.record(ctx, db, audit.TOTP_ENABLED, req, user_id=user.id)
    db.commit()
    return codes


def disable(ctx: AppContext, db: Session, user: User) -> None:
    user.totp_enabled_at = None
    user.totp_secret_enc = None
    user.totp_last_step = 0
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))


def regenerate_codes(ctx: AppContext, db: Session, user: User, req: RequestInfo) -> list[str]:
    codes = _replace_codes(ctx, db, user.id)
    audit.record(ctx, db, audit.RECOVERY_CODES_REGENERATED, req, user_id=user.id)
    db.commit()
    return codes
