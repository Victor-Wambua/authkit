"""Housekeeping: delete rows that can no longer matter."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from authkit.context import AppContext
from authkit.models import AuthSession, EmailToken, RefreshToken, ThrottleEvent


def purge(ctx: AppContext, db: Session) -> dict[str, int]:
    """Remove expired tokens, dead sessions and old throttle rows.

    Used refresh tokens are kept until their own expiry so reuse can still be detected.
    """
    now = ctx.clock.now()
    grace = now - timedelta(days=1)
    counts = {
        "refresh_tokens": db.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < now)
        ).rowcount,  # type: ignore[attr-defined]
        "sessions": db.execute(delete(AuthSession).where(AuthSession.expires_at < grace)).rowcount,  # type: ignore[attr-defined]
        "email_tokens": db.execute(
            delete(EmailToken).where(EmailToken.expires_at < grace)
        ).rowcount,  # type: ignore[attr-defined]
        "throttle_events": db.execute(
            delete(ThrottleEvent).where(
                ThrottleEvent.at < now - timedelta(seconds=ctx.settings.throttle_window_seconds * 2)
            )
        ).rowcount,  # type: ignore[attr-defined]
    }
    db.commit()
    return counts
