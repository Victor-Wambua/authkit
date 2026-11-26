"""Registration, sign-in, token refresh, sign-out, e-mail verification and password reset."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Request, Response

from authkit.api.schemas import (
    AcceptedOut,
    ErrorOut,
    ForgotIn,
    LoginIn,
    LoginOut,
    MfaLoginIn,
    RefreshIn,
    RegisterIn,
    ResetIn,
    TokenIn,
    TokenOut,
)
from authkit.errors import ApiError, invalid_token
from authkit.http import Ctx, CurrentAuth, Db, ReqInfo
from authkit.services import accounts, sessions
from authkit.services.sessions import IssuedTokens

router = APIRouter(prefix="/api/auth", tags=["auth"])

COOKIE_NAME = "authkit_rt"
COOKIE_PATH = "/api/auth"
_ERR: dict[int | str, dict[str, Any]] = {429: {"model": ErrorOut}, 401: {"model": ErrorOut}}


def _cookie_mode(request: Request) -> bool:
    """Browsers opt in with a custom header; cross-site forms cannot set it."""
    return request.headers.get("x-auth-mode", "").lower() == "cookie"


def _token_body(
    ctx: Ctx, request: Request, response: Response, tokens: IssuedTokens
) -> dict[str, object]:
    body: dict[str, object] = {
        "access_token": tokens.access_token,
        "token_type": "Bearer",
        "expires_in": tokens.expires_in,
    }
    if _cookie_mode(request):
        response.set_cookie(
            COOKIE_NAME,
            tokens.refresh_token,
            max_age=ctx.settings.refresh_ttl_seconds,
            httponly=True,
            secure=ctx.settings.secure_cookies,
            samesite="strict",
            path=COOKIE_PATH,
        )
    else:
        body["refresh_token"] = tokens.refresh_token
    return body


@router.post(
    "/register",
    status_code=202,
    response_model=AcceptedOut,
    summary="Create an account",
    description="Always answers 202 with the same body, whether or not the address is "
    "already registered, so the endpoint cannot be used to find out who has an account. "
    "Password problems are reported as 422 with reasons.",
)
def register(
    body: RegisterIn, ctx: Ctx, db: Db, req: ReqInfo, tasks: BackgroundTasks
) -> AcceptedOut:
    accounts.register(ctx, db, body.email, body.password, req, tasks)
    return AcceptedOut(message="If this address can be registered, an email is on its way.")


@router.post(
    "/login",
    response_model=LoginOut,
    response_model_exclude_none=True,
    responses=_ERR,
    summary="Sign in with email and password",
    description="Returns tokens, or `status: mfa_required` with a short-lived `mfa_token` "
    "when the account has two-factor authentication enabled.",
)
def login(
    body: LoginIn, request: Request, response: Response, ctx: Ctx, db: Db, req: ReqInfo
) -> dict[str, object]:
    result = accounts.login(ctx, db, body.email, body.password, req)
    if result.tokens is None:
        return {"status": "mfa_required", "mfa_token": result.mfa_token}
    return {"status": "ok", **_token_body(ctx, request, response, result.tokens)}


@router.post(
    "/login/mfa",
    response_model=LoginOut,
    response_model_exclude_none=True,
    responses=_ERR,
    summary="Finish sign-in with a TOTP or recovery code",
)
def login_mfa(
    body: MfaLoginIn, request: Request, response: Response, ctx: Ctx, db: Db, req: ReqInfo
) -> dict[str, object]:
    tokens = accounts.complete_mfa_login(ctx, db, body.mfa_token, body.code, req)
    return {"status": "ok", **_token_body(ctx, request, response, tokens)}


@router.post(
    "/refresh",
    response_model=TokenOut,
    response_model_exclude_none=True,
    responses=_ERR,
    summary="Rotate the refresh token",
    description="Each refresh token works once. Presenting one that was already used revokes "
    "the whole session (token family) and records `token_reuse_detected` in the audit log.",
)
def refresh(
    body: RefreshIn, request: Request, response: Response, ctx: Ctx, db: Db, req: ReqInfo
) -> dict[str, object]:
    raw = body.refresh_token or (
        request.cookies.get(COOKIE_NAME) if _cookie_mode(request) else None
    )
    if not raw:
        raise invalid_token()
    tokens = sessions.rotate_refresh(ctx, db, raw, req)
    return _token_body(ctx, request, response, tokens)


@router.post("/logout", status_code=204, summary="Sign out the current session")
def logout(
    request: Request,
    response: Response,
    ctx: Ctx,
    db: Db,
    req: ReqInfo,
    body: RefreshIn | None = None,
) -> Response:
    """Works with a bearer token, or with just a refresh token if the access token expired."""
    out = Response(status_code=204)
    if _cookie_mode(request):
        out.delete_cookie(COOKIE_NAME, path=COOKIE_PATH)
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        try:
            _, session = sessions.authenticate(ctx, db, header[7:].strip())
        except ApiError:
            session = None  # an invalid token just means there is nothing to revoke by it
        if session is not None:
            accounts.logout(ctx, db, session, req)
            return out
    raw = (body.refresh_token if body else None) or (
        request.cookies.get(COOKIE_NAME) if _cookie_mode(request) else None
    )
    if raw:
        sessions.revoke_by_refresh_token(ctx, db, raw, req)
    return out


@router.post("/email/verify", status_code=204, summary="Confirm an email address")
def verify_email(body: TokenIn, ctx: Ctx, db: Db, req: ReqInfo) -> Response:
    accounts.verify_email(ctx, db, body.token, req)
    return Response(status_code=204)


@router.post(
    "/email/resend",
    status_code=202,
    response_model=AcceptedOut,
    summary="Resend the verification email",
)
def resend_verification(
    auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo, tasks: BackgroundTasks
) -> AcceptedOut:
    accounts.resend_verification(ctx, db, auth.user, req, tasks)
    return AcceptedOut(message="If the address still needs confirming, an email is on its way.")


@router.post(
    "/password/forgot",
    status_code=202,
    response_model=AcceptedOut,
    summary="Ask for a password-reset email",
    description="Always 202 with the same body for known and unknown addresses.",
)
def forgot_password(
    body: ForgotIn, ctx: Ctx, db: Db, req: ReqInfo, tasks: BackgroundTasks
) -> AcceptedOut:
    accounts.request_password_reset(ctx, db, body.email, req, tasks)
    return AcceptedOut(message="If that address has an account, a reset link is on its way.")


@router.post(
    "/password/reset",
    status_code=204,
    summary="Set a new password with a reset token",
    description="Single use. Signs out every session of the account.",
)
def reset_password(
    body: ResetIn, ctx: Ctx, db: Db, req: ReqInfo, tasks: BackgroundTasks
) -> Response:
    accounts.reset_password(ctx, db, body.token, body.new_password, req, tasks)
    return Response(status_code=204)
