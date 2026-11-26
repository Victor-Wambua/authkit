"""The signed-in user: profile, password, sessions, activity and account deletion."""

from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Query, Response
from sqlalchemy import select

from authkit.api.schemas import (
    AuditOut,
    AuditPage,
    ChangePasswordIn,
    DeleteAccountIn,
    RevokedOut,
    SessionOut,
    SessionsOut,
    UserOut,
)
from authkit.http import Ctx, CurrentAuth, Db, ReqInfo
from authkit.models import AuditEvent, AuthSession, User
from authkit.services import accounts, audit, sessions

router = APIRouter(prefix="/api/me", tags=["me"])


def user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        role="admin" if user.role == "admin" else "user",
        email_verified=user.email_verified_at is not None,
        totp_enabled=user.totp_enabled,
        created_at=user.created_at,
    )


def audit_out(row: AuditEvent) -> AuditOut:
    return AuditOut(
        id=row.id,
        at=row.at,
        event=row.event,
        user_id=row.user_id,
        session_id=row.session_id,
        ip=row.ip,
        user_agent=row.user_agent,
        detail=json.loads(row.detail) if row.detail else None,
    )


@router.get("", response_model=UserOut, summary="Who am I")
def whoami(auth: CurrentAuth) -> UserOut:
    return user_out(auth.user)


@router.post("/password", response_model=RevokedOut, summary="Change password")
def change_password(
    body: ChangePasswordIn,
    auth: CurrentAuth,
    ctx: Ctx,
    db: Db,
    req: ReqInfo,
    tasks: BackgroundTasks,
) -> RevokedOut:
    """Requires the current password. Every *other* session is signed out."""
    n = accounts.change_password(
        ctx, db, auth.user, auth.session, body.current_password, body.new_password, req, tasks
    )
    return RevokedOut(revoked=n)


@router.delete("", status_code=204, summary="Delete my account")
def delete_account(
    body: DeleteAccountIn, auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo
) -> Response:
    """Requires the password (and a 2FA code if enabled). Deletes the user and all sessions."""
    accounts.delete_account(ctx, db, auth.user, body.password, body.code, req)
    return Response(status_code=204)


@router.get("/sessions", response_model=SessionsOut, summary="List signed-in devices")
def list_sessions(auth: CurrentAuth, ctx: Ctx, db: Db) -> SessionsOut:
    rows = sessions.list_sessions(ctx, db, auth.user.id)
    return SessionsOut(
        sessions=[
            SessionOut(
                id=s.id,
                created_at=s.created_at,
                last_used_at=s.last_used_at,
                expires_at=s.expires_at,
                ip=s.ip,
                user_agent=s.user_agent,
                used_2fa=s.used_2fa,
                current=s.id == auth.session.id,
            )
            for s in rows
        ]
    )


@router.post("/sessions/revoke-others", response_model=RevokedOut, summary="Sign out other devices")
def revoke_others(auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo) -> RevokedOut:
    n = sessions.revoke_user_sessions(
        ctx, db, auth.user.id, reason="revoked_by_user", except_id=auth.session.id
    )
    audit.record(
        ctx,
        db,
        audit.OTHER_SESSIONS_REVOKED,
        req,
        user_id=auth.user.id,
        session_id=auth.session.id,
        count=n,
    )
    db.commit()
    return RevokedOut(revoked=n)


@router.delete("/sessions/{session_id}", status_code=204, summary="Revoke one session")
def revoke_one(session_id: str, auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo) -> Response:
    target = sessions.ensure_owner(db.get(AuthSession, session_id), auth.user.id)
    sessions.revoke_session(ctx, db, target, "revoked_by_user")
    audit.record(
        ctx,
        db,
        audit.SESSION_REVOKED,
        req,
        user_id=auth.user.id,
        session_id=target.id,
        by_session=auth.session.id,
    )
    db.commit()
    return Response(status_code=204)


@router.get("/activity", response_model=AuditPage, summary="My recent security activity")
def my_activity(
    auth: CurrentAuth, db: Db, limit: int = Query(30, ge=1, le=100), before: int | None = None
) -> AuditPage:
    stmt = select(AuditEvent).where(AuditEvent.user_id == auth.user.id)
    if before is not None:
        stmt = stmt.where(AuditEvent.id < before)
    rows = list(db.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit + 1)))
    page, more = rows[:limit], len(rows) > limit
    return AuditPage(items=[audit_out(r) for r in page], next_before=page[-1].id if more else None)
