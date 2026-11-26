"""Admin-only endpoints: audit log and user list."""

from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from authkit.api.me import audit_out
from authkit.api.schemas import AdminUserOut, AdminUsersOut, AuditPage
from authkit.http import AdminAuth, Db
from authkit.models import AuditEvent, User

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/audit", response_model=AuditPage, summary="Read the audit log (admin only)")
def read_audit(
    _: AdminAuth,
    db: Db,
    event: str | None = Query(None, max_length=48),
    user_id: str | None = Query(None, max_length=36),
    limit: int = Query(50, ge=1, le=200),
    before: int | None = Query(None, description="Return rows with id below this (paging)"),
) -> AuditPage:
    stmt = select(AuditEvent)
    if event:
        stmt = stmt.where(AuditEvent.event == event)
    if user_id:
        stmt = stmt.where(AuditEvent.user_id == user_id)
    if before is not None:
        stmt = stmt.where(AuditEvent.id < before)
    rows = list(db.scalars(stmt.order_by(AuditEvent.id.desc()).limit(limit + 1)))
    page, more = rows[:limit], len(rows) > limit
    return AuditPage(items=[audit_out(r) for r in page], next_before=page[-1].id if more else None)


@router.get("/users", response_model=AdminUsersOut, summary="List accounts (admin only)")
def list_users(_: AdminAuth, db: Db, limit: int = Query(100, ge=1, le=500)) -> AdminUsersOut:
    rows = db.scalars(select(User).order_by(User.created_at.desc()).limit(limit))
    return AdminUsersOut(
        users=[
            AdminUserOut(
                id=u.id,
                email=u.email,
                role="admin" if u.role == "admin" else "user",
                email_verified=u.email_verified_at is not None,
                totp_enabled=u.totp_enabled,
                created_at=u.created_at,
                is_active=u.is_active,
            )
            for u in rows
        ]
    )
