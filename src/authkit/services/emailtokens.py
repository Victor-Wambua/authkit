"""Single-use, expiring, hashed tokens for e-mail verification and password reset."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from authkit.context import AppContext
from authkit.models import EmailToken
from authkit.security.tokens import EMAIL_PREFIX, hash_token, new_opaque_token

VERIFY = "verify"
RESET = "reset"


def issue(ctx: AppContext, db: Session, user_id: str, purpose: str, ttl_seconds: int) -> str:
    """Create a token. Older unused tokens for the same purpose stop working."""
    now = ctx.clock.now()
    db.execute(
        update(EmailToken)
        .where(
            EmailToken.user_id == user_id,
            EmailToken.purpose == purpose,
            EmailToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    raw = new_opaque_token(EMAIL_PREFIX)
    db.add(
        EmailToken(
            user_id=user_id,
            purpose=purpose,
            token_hash=hash_token(raw),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
    )
    return raw


def peek(ctx: AppContext, db: Session, raw: str, purpose: str) -> EmailToken | None:
    """The row for a still-valid token, without using it up."""
    row = db.scalar(
        select(EmailToken).where(
            EmailToken.token_hash == hash_token(raw), EmailToken.purpose == purpose
        )
    )
    if row is None or row.used_at is not None or row.expires_at <= ctx.clock.now():
        return None
    return row


def consume(ctx: AppContext, db: Session, raw: str, purpose: str) -> str | None:
    """Atomically use a token. Returns the user id, or None if invalid, expired or used."""
    row = db.scalar(
        select(EmailToken).where(
            EmailToken.token_hash == hash_token(raw), EmailToken.purpose == purpose
        )
    )
    if row is None:
        return None
    now = ctx.clock.now()
    claimed = db.execute(
        update(EmailToken)
        .where(EmailToken.id == row.id, EmailToken.used_at.is_(None), EmailToken.expires_at > now)
        .values(used_at=now)
    )
    return row.user_id if claimed.rowcount == 1 else None  # type: ignore[attr-defined]
