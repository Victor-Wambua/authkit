"""Shared HTTP plumbing: client IP, error handlers and FastAPI dependencies."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from authkit.context import AppContext
from authkit.errors import ApiError, forbidden, unauthorized
from authkit.models import AuthSession, User
from authkit.services import sessions
from authkit.services.audit import RequestInfo


def client_ip(request: Request, trusted_hops: int) -> str | None:
    """The caller's address. X-Forwarded-For is only believed for N trusted proxy hops.

    With hops=0 (the default) the header is ignored entirely, because anyone can forge it.
    With hops=N the address N entries from the right is used: that is the one appended
    by the outermost proxy you control.
    """
    peer = request.client.host if request.client else None
    if trusted_hops > 0:
        parts = [
            p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()
        ]
        if len(parts) >= trusted_hops:
            candidate = parts[-trusted_hops]
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                return peer
    return peer


def get_ctx(request: Request) -> AppContext:
    ctx: AppContext = request.app.state.ctx
    return ctx


Ctx = Annotated[AppContext, Depends(get_ctx)]


def get_db(ctx: Ctx) -> Iterator[Session]:
    with ctx.sessions() as session:
        yield session


Db = Annotated[Session, Depends(get_db)]


def get_req_info(request: Request, ctx: Ctx) -> RequestInfo:
    return RequestInfo(
        ip=client_ip(request, ctx.settings.trusted_proxy_hops),
        user_agent=request.headers.get("user-agent"),
    )


ReqInfo = Annotated[RequestInfo, Depends(get_req_info)]


@dataclass(frozen=True)
class Auth:
    user: User
    session: AuthSession


def current_auth(request: Request, ctx: Ctx, db: Db) -> Auth:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise unauthorized()
    user, session = sessions.authenticate(ctx, db, token.strip())
    return Auth(user, session)


CurrentAuth = Annotated[Auth, Depends(current_auth)]


def require_admin(auth: CurrentAuth) -> Auth:
    if auth.user.role != "admin":
        raise forbidden()
    return auth


AdminAuth = Annotated[Auth, Depends(require_admin)]


def _error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, **extra}}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            _error_body(exc.code, exc.message, **exc.extra), exc.status, headers=exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default body echoes the submitted values (including passwords). Drop them.
        fields = [
            {"field": ".".join(str(p) for p in e["loc"][1:]), "problem": e["type"]}
            for e in exc.errors()
        ]
        return JSONResponse(
            _error_body("validation_error", "The request is not valid.", fields=fields), 422
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "not_found", 405: "method_not_allowed", 413: "payload_too_large"}
        return JSONResponse(
            _error_body(codes.get(exc.status_code, "http_error"), str(exc.detail)),
            exc.status_code,
            headers=getattr(exc, "headers", None),
        )
