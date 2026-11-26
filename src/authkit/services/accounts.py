"""Registration, login, password management and account deletion."""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.background import BackgroundTasks

from authkit.context import AppContext
from authkit.errors import ApiError, invalid_credentials, invalid_token, throttled
from authkit.mailer import Message
from authkit.models import AuthSession, User
from authkit.security.breach import BreachCheckUnavailable
from authkit.security.keys import TokenError
from authkit.security.throttle import account_key
from authkit.services import audit, emailtokens, mfa, sessions
from authkit.services.audit import RequestInfo
from authkit.services.sessions import IssuedTokens

log = logging.getLogger("authkit.accounts")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


Tasks = BackgroundTasks


@dataclass(frozen=True)
class LoginResult:
    tokens: IssuedTokens | None = None
    mfa_token: str | None = None


def normalize_email(raw: str) -> str:
    email = unicodedata.normalize("NFKC", raw).strip().lower()
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise ApiError(422, "invalid_email", "Enter a valid email address.")
    return email


def check_new_password(ctx: AppContext, password: str, email: str) -> None:
    """Policy plus breach check. Raises 422 with machine-readable reasons."""
    reasons = ctx.policy.problems(password, email)
    if not reasons:
        try:
            if ctx.breach.pwned_count(password) > 0:
                reasons = ["breached"]
        except BreachCheckUnavailable:
            raise ApiError(
                503, "password_check_unavailable", "Cannot check the password right now."
            ) from None
    if reasons:
        raise ApiError(
            422,
            "password_rejected",
            "That password cannot be used.",
            extra={"reasons": reasons},
        )


def _mail(ctx: AppContext, tasks: Tasks, to: str, subject: str, text: str) -> None:
    tasks.add_task(ctx.send_mail, Message(to=to, subject=subject, text=text))


def _link(ctx: AppContext, route: str, token: str) -> str:
    # The token goes in the URL fragment: browsers never send it to the server or in Referer.
    return f"{ctx.settings.base_url.rstrip('/')}/#/{route}?token={token}"


def _ip(req: RequestInfo) -> str:
    return req.ip or "-"


def _throttle_wait(ctx: AppContext, db: Session, email: str, req: RequestInfo) -> int:
    return max(
        ctx.throttle.wait_seconds(db, "acct", account_key(email), ctx.account_policy),
        ctx.throttle.wait_seconds(db, "ip", _ip(req), ctx.ip_policy),
    )


def _record_failure(ctx: AppContext, db: Session, email: str, req: RequestInfo) -> None:
    ctx.throttle.record_failure(db, "acct", account_key(email), ctx.account_policy)
    ctx.throttle.record_failure(db, "ip", _ip(req), ctx.ip_policy)


# --- registration ---------------------------------------------------------


def register(
    ctx: AppContext, db: Session, raw_email: str, password: str, req: RequestInfo, tasks: Tasks
) -> None:
    """Always answers the same way, whether or not the address is already registered."""
    if not ctx.settings.registration_open:
        raise ApiError(403, "registration_closed", "Registration is closed.")
    email = normalize_email(raw_email)
    s = ctx.settings
    if not ctx.throttle.allow(db, "register", _ip(req), s.register_per_ip_per_hour, 3600):
        db.commit()
        raise throttled(600)
    check_new_password(ctx, password, email)
    pw_hash = ctx.hasher.hash(password)  # computed on both paths so timing matches
    now = ctx.clock.now()
    existing = db.scalar(select(User).where(User.email == email))
    try:
        if existing is not None:
            audit.record(ctx, db, audit.REGISTER_DUPLICATE, req, user_id=existing.id)
            _mail(
                ctx,
                tasks,
                email,
                "You already have an Authkit account",
                "Someone (hopefully you) tried to register with this address, but an account "
                f"already exists.\n\nSign in at {s.base_url}\nForgot your password? Use the "
                "reset link on the sign-in page.\n\nIf this was not you, ignore this message.",
            )
        else:
            user = User(email=email, password_hash=pw_hash, password_changed_at=now, created_at=now)
            db.add(user)
            db.flush()
            token = emailtokens.issue(
                ctx, db, user.id, emailtokens.VERIFY, s.email_verify_ttl_seconds
            )
            audit.record(ctx, db, audit.REGISTER, req, user_id=user.id)
            _mail(
                ctx,
                tasks,
                email,
                "Confirm your email address",
                f"Welcome to Authkit.\n\nConfirm your address: {_link(ctx, 'verify', token)}\n\n"
                "The link works once and expires in 24 hours.",
            )
        db.commit()
    except IntegrityError:
        db.rollback()  # lost a race with a parallel registration: same outcome as a duplicate


# --- login ----------------------------------------------------------------


def login(
    ctx: AppContext, db: Session, raw_email: str, password: str, req: RequestInfo
) -> LoginResult:
    try:
        email = normalize_email(raw_email)
    except ApiError:
        ctx.hasher.dummy_verify(password)
        raise invalid_credentials() from None

    wait = _throttle_wait(ctx, db, email, req)
    if wait:
        audit.record(ctx, db, audit.LOGIN_BLOCKED, req, email=email, retry_after=wait)
        db.commit()
        raise throttled(wait)

    user = db.scalar(select(User).where(User.email == email))
    if user is None or not user.is_active:
        ctx.hasher.dummy_verify(password)  # same CPU cost as a real check
        ok = False
    else:
        ok = ctx.hasher.verify(user.password_hash, password)

    if not ok or user is None:
        _record_failure(ctx, db, email, req)
        audit.record(
            ctx,
            db,
            audit.LOGIN_FAILURE,
            req,
            user_id=user.id if user else None,
            email=email,
        )
        db.commit()
        raise invalid_credentials()

    if ctx.hasher.needs_rehash(user.password_hash):
        user.password_hash = ctx.hasher.hash(password)  # transparent parameter upgrade
        audit.record(ctx, db, audit.PASSWORD_REHASHED, req, user_id=user.id)
    ctx.throttle.clear(db, "acct", account_key(email))

    if ctx.settings.require_verified_email and user.email_verified_at is None:
        db.commit()
        raise ApiError(403, "email_not_verified", "Confirm your email address first.")

    if user.totp_enabled:
        audit.record(ctx, db, audit.LOGIN_PASSWORD_OK_MFA_PENDING, req, user_id=user.id)
        db.commit()
        return LoginResult(mfa_token=ctx.jwt.mfa_token(user.id, ctx.settings.mfa_token_ttl_seconds))

    tokens = sessions.start_session(ctx, db, user, req, used_2fa=False)
    audit.record(
        ctx,
        db,
        audit.LOGIN_SUCCESS,
        req,
        user_id=user.id,
        session_id=tokens.session_id,
        method="password",
    )
    db.commit()
    return LoginResult(tokens=tokens)


def complete_mfa_login(
    ctx: AppContext, db: Session, mfa_token: str, code: str, req: RequestInfo
) -> IssuedTokens:
    try:
        claims = ctx.jwt.decode(mfa_token, use="mfa")
    except TokenError:
        raise invalid_token() from None
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active or not user.totp_enabled:
        raise invalid_token()

    wait = ctx.throttle.wait_seconds(db, "mfa", user.id, ctx.account_policy)
    if wait:
        audit.record(ctx, db, audit.MFA_BLOCKED, req, user_id=user.id)
        db.commit()
        raise throttled(wait)

    method = mfa.check_second_factor(ctx, db, user, code)
    if method is None:
        ctx.throttle.record_failure(db, "mfa", user.id, ctx.account_policy)
        audit.record(ctx, db, audit.MFA_FAILURE, req, user_id=user.id)
        db.commit()
        raise ApiError(401, "invalid_code", "The code is incorrect or expired.")

    ctx.throttle.clear(db, "mfa", user.id)
    if method == "recovery":
        audit.record(
            ctx,
            db,
            audit.RECOVERY_CODE_USED,
            req,
            user_id=user.id,
            remaining=mfa.remaining_recovery_codes(db, user.id),
        )
    tokens = sessions.start_session(ctx, db, user, req, used_2fa=True)
    audit.record(
        ctx,
        db,
        audit.LOGIN_SUCCESS,
        req,
        user_id=user.id,
        session_id=tokens.session_id,
        method=f"password+{method}",
    )
    db.commit()
    return tokens


def logout(ctx: AppContext, db: Session, session: AuthSession, req: RequestInfo) -> None:
    sessions.revoke_session(ctx, db, session, "logout")
    audit.record(ctx, db, audit.LOGOUT, req, user_id=session.user_id, session_id=session.id)
    db.commit()


# --- verified re-authentication for sensitive actions ----------------------


def confirm_password(
    ctx: AppContext, db: Session, user: User, password: str, req: RequestInfo
) -> None:
    """Throttled password check for logged-in users (a stolen access token is not enough)."""
    key = account_key(user.email)
    wait = ctx.throttle.wait_seconds(db, "acct", key, ctx.account_policy)
    if wait:
        audit.record(ctx, db, audit.LOGIN_BLOCKED, req, user_id=user.id, via="reauth")
        db.commit()
        raise throttled(wait)
    if not ctx.hasher.verify(user.password_hash, password):
        ctx.throttle.record_failure(db, "acct", key, ctx.account_policy)
        audit.record(ctx, db, audit.LOGIN_FAILURE, req, user_id=user.id, via="reauth")
        db.commit()
        raise ApiError(403, "wrong_password", "The current password is incorrect.")


def change_password(
    ctx: AppContext,
    db: Session,
    user: User,
    current_session: AuthSession,
    current_password: str,
    new_password: str,
    req: RequestInfo,
    tasks: Tasks,
) -> int:
    """Returns how many other sessions were signed out."""
    confirm_password(ctx, db, user, current_password, req)
    check_new_password(ctx, new_password, user.email)
    user.password_hash = ctx.hasher.hash(new_password)
    user.password_changed_at = ctx.clock.now()
    revoked = sessions.revoke_user_sessions(
        ctx, db, user.id, reason="password_changed", except_id=current_session.id
    )
    audit.record(
        ctx,
        db,
        audit.PASSWORD_CHANGED,
        req,
        user_id=user.id,
        session_id=current_session.id,
        other_sessions_revoked=revoked,
    )
    _mail(
        ctx,
        tasks,
        user.email,
        "Your Authkit password was changed",
        "Your password was just changed and your other devices were signed out. "
        "If this was not you, reset your password immediately.",
    )
    db.commit()
    return revoked


def delete_account(
    ctx: AppContext, db: Session, user: User, password: str, code: str | None, req: RequestInfo
) -> None:
    confirm_password(ctx, db, user, password, req)
    if user.totp_enabled and (not code or mfa.check_second_factor(ctx, db, user, code) is None):
        db.commit()
        raise ApiError(403, "invalid_code", "A valid two-factor code is required.")
    if user.role == "admin":
        admins = db.scalar(
            select(func.count(User.id)).where(User.role == "admin", User.is_active.is_(True))
        )
        if (admins or 0) <= 1:
            raise ApiError(409, "last_admin", "The last administrator cannot be deleted.")
    audit.record(ctx, db, audit.ACCOUNT_DELETED, req, user_id=user.id, email=user.email)
    db.delete(user)  # sessions, tokens, recovery codes go with it (ON DELETE CASCADE)
    db.commit()


# --- e-mail verification and password reset ---------------------------------


def request_password_reset(
    ctx: AppContext, db: Session, raw_email: str, req: RequestInfo, tasks: Tasks
) -> None:
    """Silent about whether the address exists. The caller always answers 202."""
    try:
        email = normalize_email(raw_email)
    except ApiError:
        return
    allowed = ctx.throttle.allow(
        db, "reset", account_key(email), ctx.settings.reset_per_email_per_hour, 3600
    )
    user = db.scalar(select(User).where(User.email == email))
    if user is not None and user.is_active and allowed:
        token = emailtokens.issue(
            ctx, db, user.id, emailtokens.RESET, ctx.settings.password_reset_ttl_seconds
        )
        audit.record(ctx, db, audit.PASSWORD_RESET_REQUESTED, req, user_id=user.id)
        _mail(
            ctx,
            tasks,
            email,
            "Reset your Authkit password",
            f"Reset your password: {_link(ctx, 'reset', token)}\n\nThe link works once and "
            "expires in 1 hour. If you did not ask for this, ignore this message.",
        )
    db.commit()


def reset_password(
    ctx: AppContext, db: Session, token: str, new_password: str, req: RequestInfo, tasks: Tasks
) -> None:
    row = emailtokens.peek(ctx, db, token, emailtokens.RESET)
    user = db.get(User, row.user_id) if row else None
    if row is None or user is None or not user.is_active:
        raise ApiError(400, "invalid_token", "The link is invalid, expired or already used.")
    # Validate the new password before burning the token, so a typo does not waste the link.
    check_new_password(ctx, new_password, user.email)
    if emailtokens.consume(ctx, db, token, emailtokens.RESET) is None:
        db.commit()
        raise ApiError(400, "invalid_token", "The link is invalid, expired or already used.")
    now = ctx.clock.now()
    user.password_hash = ctx.hasher.hash(new_password)
    user.password_changed_at = now
    if user.email_verified_at is None:
        user.email_verified_at = now  # reading the mailbox proves control of the address
    revoked = sessions.revoke_user_sessions(ctx, db, user.id, reason="password_reset")
    ctx.throttle.clear(db, "acct", account_key(user.email))
    audit.record(
        ctx, db, audit.PASSWORD_RESET_COMPLETED, req, user_id=user.id, sessions_revoked=revoked
    )
    _mail(
        ctx,
        tasks,
        user.email,
        "Your Authkit password was reset",
        "Your password was reset and all devices were signed out. If this was not you, "
        "contact your administrator.",
    )
    db.commit()


def verify_email(ctx: AppContext, db: Session, token: str, req: RequestInfo) -> None:
    user_id = emailtokens.consume(ctx, db, token, emailtokens.VERIFY)
    if user_id is None:
        db.commit()
        raise ApiError(400, "invalid_token", "The link is invalid, expired or already used.")
    user = db.get(User, user_id)
    if user is not None and user.email_verified_at is None:
        user.email_verified_at = ctx.clock.now()
    audit.record(ctx, db, audit.EMAIL_VERIFIED, req, user_id=user_id)
    db.commit()


def resend_verification(
    ctx: AppContext, db: Session, user: User, req: RequestInfo, tasks: Tasks
) -> None:
    if user.email_verified_at is not None:
        return
    if not ctx.throttle.allow(db, "verify", user.id, 3, 3600):
        db.commit()
        raise throttled(600)
    token = emailtokens.issue(
        ctx, db, user.id, emailtokens.VERIFY, ctx.settings.email_verify_ttl_seconds
    )
    _mail(
        ctx,
        tasks,
        user.email,
        "Confirm your email address",
        f"Confirm your address: {_link(ctx, 'verify', token)}",
    )
    db.commit()
