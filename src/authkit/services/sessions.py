"""Sessions, access tokens and refresh-token rotation with reuse detection.

Each sign-in creates one ``AuthSession`` (the refresh-token *family*). Every refresh
token can be used exactly once. Presenting a token that was already used means two
parties hold the same secret, so the whole family is revoked and the user is audited.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from authkit.context import AppContext
from authkit.errors import ApiError, invalid_token, unauthorized
from authkit.models import AuthSession, RefreshToken, User
from authkit.security.keys import TokenError
from authkit.security.tokens import REFRESH_PREFIX, hash_token, new_opaque_token
from authkit.services import audit
from authkit.services.audit import RequestInfo


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    session_id: str


def _issue_refresh(ctx: AppContext, db: Session, session: AuthSession) -> str:
    now = ctx.clock.now()
    raw = new_opaque_token(REFRESH_PREFIX)
    expires = min(now + timedelta(seconds=ctx.settings.refresh_ttl_seconds), session.expires_at)
    db.add(
        RefreshToken(
            session_id=session.id, token_hash=hash_token(raw), created_at=now, expires_at=expires
        )
    )
    return raw


def _access(ctx: AppContext, user: User, session: AuthSession) -> str:
    amr = ["pwd", "otp"] if session.used_2fa else ["pwd"]
    return ctx.jwt.access_token(
        user.id, session.id, user.role, amr, ctx.settings.access_ttl_seconds
    )


def start_session(
    ctx: AppContext, db: Session, user: User, req: RequestInfo, *, used_2fa: bool
) -> IssuedTokens:
    """Create a session and its first refresh token. The caller commits."""
    now = ctx.clock.now()
    session = AuthSession(
        user_id=user.id,
        created_at=now,
        last_used_at=now,
        expires_at=now + timedelta(seconds=ctx.settings.session_max_age_seconds),
        ip=req.ip,
        user_agent=(req.user_agent or "")[:256] or None,
        used_2fa=used_2fa,
    )
    db.add(session)
    db.flush()
    refresh = _issue_refresh(ctx, db, session)
    return IssuedTokens(
        _access(ctx, user, session), refresh, ctx.settings.access_ttl_seconds, session.id
    )


def rotate_refresh(ctx: AppContext, db: Session, raw_token: str, req: RequestInfo) -> IssuedTokens:
    now = ctx.clock.now()
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw_token)))
    if row is None:
        raise invalid_token()
    session = db.get(AuthSession, row.session_id)
    if session is None or session.revoked_at is not None or session.expires_at <= now:
        raise invalid_token()
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise invalid_token()

    if row.used_at is None and row.expires_at <= now:
        raise invalid_token()  # simply expired, nothing suspicious

    reused = row.used_at is not None
    if not reused:
        # Compare-and-swap: only one caller can flip used_at from NULL. A concurrent loser
        # sees rowcount 0 and is treated exactly like a replay.
        claimed = db.execute(
            update(RefreshToken)
            .where(RefreshToken.id == row.id, RefreshToken.used_at.is_(None))
            .values(used_at=now)
        )
        reused = claimed.rowcount != 1  # type: ignore[attr-defined]

    if reused:
        revoke_session(ctx, db, session, "token_reuse")
        audit.record(
            ctx, db, audit.TOKEN_REUSE_DETECTED, req, user_id=user.id, session_id=session.id
        )
        db.commit()
        raise invalid_token()

    new_refresh = _issue_refresh(ctx, db, session)
    session.last_used_at = now
    session.ip = req.ip or session.ip
    session.user_agent = (req.user_agent or session.user_agent or "")[:256] or None
    tokens = IssuedTokens(
        _access(ctx, user, session), new_refresh, ctx.settings.access_ttl_seconds, session.id
    )
    db.commit()
    return tokens


def revoke_session(ctx: AppContext, db: Session, session: AuthSession, reason: str) -> None:
    if session.revoked_at is None:
        session.revoked_at = ctx.clock.now()
        session.revoked_reason = reason


def revoke_user_sessions(
    ctx: AppContext, db: Session, user_id: str, *, reason: str, except_id: str | None = None
) -> int:
    stmt = (
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=ctx.clock.now(), revoked_reason=reason)
    )
    if except_id:
        stmt = stmt.where(AuthSession.id != except_id)
    result = db.execute(stmt)
    return int(result.rowcount)  # type: ignore[attr-defined]


def authenticate(ctx: AppContext, db: Session, token: str) -> tuple[User, AuthSession]:
    """Verify an access token AND that its session is still live.

    Checking the session row makes "sign out other devices" take effect immediately
    on this service, instead of after the 15-minute access-token expiry.
    """
    try:
        claims = ctx.jwt.decode(token, use="access")
    except TokenError:
        raise unauthorized() from None
    session = db.get(AuthSession, str(claims.get("sid")))
    now = ctx.clock.now()
    if (
        session is None
        or session.user_id != claims["sub"]
        or session.revoked_at is not None
        or session.expires_at <= now
    ):
        raise unauthorized()
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise unauthorized()
    return user, session


def list_sessions(ctx: AppContext, db: Session, user_id: str) -> list[AuthSession]:
    now = ctx.clock.now()
    return list(
        db.scalars(
            select(AuthSession)
            .where(
                AuthSession.user_id == user_id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
            )
            .order_by(AuthSession.last_used_at.desc())
        )
    )


def revoke_by_refresh_token(ctx: AppContext, db: Session, raw: str, req: RequestInfo) -> None:
    """Logout with just the refresh token (the access token may have expired)."""
    row = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
    if row is None:
        return
    session = db.get(AuthSession, row.session_id)
    if session is not None and session.revoked_at is None:
        revoke_session(ctx, db, session, "logout")
        audit.record(ctx, db, audit.LOGOUT, req, user_id=session.user_id, session_id=session.id)
        db.commit()


def ensure_owner(session: AuthSession | None, user_id: str) -> AuthSession:
    if session is None or session.user_id != user_id:
        raise ApiError(404, "not_found", "Session not found.")
    return session
