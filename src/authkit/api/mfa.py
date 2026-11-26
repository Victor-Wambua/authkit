"""Two-factor authentication (TOTP) management."""

from __future__ import annotations

from fastapi import APIRouter, Response

from authkit.api.schemas import CodeIn, MfaReauthIn, MfaSetupOut, RecoveryCodesOut
from authkit.errors import ApiError
from authkit.http import Ctx, CurrentAuth, Db, ReqInfo
from authkit.services import accounts, audit, mfa

router = APIRouter(prefix="/api/mfa", tags=["two-factor"])


@router.post("/setup", response_model=MfaSetupOut, summary="Start TOTP enrolment")
def setup(auth: CurrentAuth, ctx: Ctx, db: Db) -> MfaSetupOut:
    """Creates a pending secret and returns the otpauth URI plus a server-rendered QR (SVG).

    Two-factor stays off until `/mfa/enable` is called with a valid code.
    """
    secret, uri = mfa.begin_setup(ctx, db, auth.user)
    return MfaSetupOut(secret=secret, otpauth_uri=uri, qr_svg=mfa.qr_svg(uri))


@router.post("/enable", response_model=RecoveryCodesOut, summary="Confirm enrolment")
def enable(body: CodeIn, auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo) -> RecoveryCodesOut:
    """Returns ten single-use recovery codes. They are shown once and stored only as hashes."""
    return RecoveryCodesOut(recovery_codes=mfa.enable(ctx, db, auth.user, body.code, req))


def _reauth(ctx: Ctx, db: Db, auth: CurrentAuth, password: str, code: str, req: ReqInfo) -> None:
    accounts.confirm_password(ctx, db, auth.user, password, req)
    if mfa.check_second_factor(ctx, db, auth.user, code) is None:
        db.commit()
        raise ApiError(403, "invalid_code", "The code is incorrect or expired.")


@router.post("/disable", status_code=204, summary="Turn two-factor off")
def disable(body: MfaReauthIn, auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo) -> Response:
    """Needs the password and a current code, so a stolen access token cannot remove 2FA."""
    if not auth.user.totp_enabled:
        raise ApiError(409, "totp_not_enabled", "Two-factor authentication is not on.")
    _reauth(ctx, db, auth, body.password, body.code, req)
    mfa.disable(ctx, db, auth.user)
    audit.record(ctx, db, audit.TOTP_DISABLED, req, user_id=auth.user.id)
    db.commit()
    return Response(status_code=204)


@router.post("/recovery-codes", response_model=RecoveryCodesOut, summary="Replace recovery codes")
def regenerate(
    body: MfaReauthIn, auth: CurrentAuth, ctx: Ctx, db: Db, req: ReqInfo
) -> RecoveryCodesOut:
    if not auth.user.totp_enabled:
        raise ApiError(409, "totp_not_enabled", "Two-factor authentication is not on.")
    _reauth(ctx, db, auth, body.password, body.code, req)
    return RecoveryCodesOut(recovery_codes=mfa.regenerate_codes(ctx, db, auth.user, req))
