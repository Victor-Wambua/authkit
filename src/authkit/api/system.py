"""Health, key discovery and the dev-only mailbox."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from authkit import __version__
from authkit.errors import not_found
from authkit.http import Ctx
from authkit.mailer import FileMailer

router = APIRouter(tags=["system"])


@router.get("/healthz", summary="Liveness check")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@router.get("/.well-known/jwks.json", summary="Public signing keys (EdDSA only)")
def jwks(ctx: Ctx) -> dict[str, Any]:
    """Lets other services verify access tokens locally. HS256 secrets are never published."""
    return ctx.secrets.keyring.jwks()


@router.get("/api/dev/outbox", summary="Dev only: emails written by the file mailer")
def dev_outbox(ctx: Ctx) -> dict[str, Any]:
    if ctx.settings.env != "dev" or not isinstance(ctx.mailer, FileMailer):
        raise not_found()
    return {"messages": ctx.mailer.list_messages()}
