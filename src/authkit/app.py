"""Application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import Engine

from authkit import __version__
from authkit.api import admin, auth, me, system
from authkit.api import mfa as mfa_api
from authkit.clock import Clock, SystemClock
from authkit.config import ConfigError, Settings
from authkit.context import AppContext
from authkit.db import create_schema, make_engine, make_session_factory
from authkit.http import install_error_handlers
from authkit.logging_setup import configure_logging
from authkit.mailer import FileMailer, Mailer, SmtpMailer
from authkit.middleware import RequestLog, RequestSizeLimit, SecurityHeaders
from authkit.security.breach import (
    BreachChecker,
    FailOpenChecker,
    HibpHttpSource,
    NullChecker,
    RangeBreachChecker,
    SortedHashFile,
)
from authkit.security.keys import Secrets, load_secrets
from authkit.security.passwords import Argon2Hasher, PasswordPolicy
from authkit.security.throttle import Throttle
from authkit.security.tokens import JwtIssuer

PACKAGE_DIR = Path(__file__).parent
WEB_DIR = PACKAGE_DIR / "web"
SAMPLE_BREACH_FILE = PACKAGE_DIR / "data" / "breached-sample.txt"

log = logging.getLogger("authkit")


def build_breach_checker(settings: Settings) -> BreachChecker:
    if settings.breach_mode == "off":
        return NullChecker()
    if settings.breach_mode == "hibp":
        return FailOpenChecker(RangeBreachChecker(HibpHttpSource()), settings.hibp_fail_open)
    path = settings.breach_file or SAMPLE_BREACH_FILE
    if not path.is_file():
        raise ConfigError(f"breach file {path} not found")
    return RangeBreachChecker(SortedHashFile(path))


def build_mailer(settings: Settings, clock: Clock) -> Mailer:
    if settings.mailer == "smtp":
        return SmtpMailer(
            settings.smtp_host,
            settings.smtp_port,
            settings.smtp_username,
            settings.smtp_password,
            settings.smtp_from,
            settings.smtp_starttls,
        )
    if not settings.is_dev:
        raise ConfigError(
            "the file mailer writes tokens to disk and is for development only; "
            "set AUTHKIT_MAILER=smtp"
        )
    return FileMailer(settings.outbox_dir, clock)


def build_context(
    settings: Settings,
    engine: Engine,
    *,
    clock: Clock | None = None,
    mailer: Mailer | None = None,
    breach: BreachChecker | None = None,
    secrets: Secrets | None = None,
) -> AppContext:
    clock = clock or SystemClock()
    secrets = secrets or load_secrets(settings.keys_file, create_if_missing=settings.is_dev)
    return AppContext(
        settings=settings,
        clock=clock,
        secrets=secrets,
        sessions=make_session_factory(engine),
        hasher=Argon2Hasher(
            settings.argon2_memory_kib, settings.argon2_time_cost, settings.argon2_parallelism
        ),
        policy=PasswordPolicy(settings.password_min_length, settings.password_max_length),
        breach=breach if breach is not None else build_breach_checker(settings),
        throttle=Throttle(clock),
        mailer=mailer if mailer is not None else build_mailer(settings, clock),
        jwt=JwtIssuer(secrets.keyring, clock, settings.jwt_issuer, settings.jwt_audience),
    )


def create_app(
    settings: Settings | None = None,
    *,
    clock: Clock | None = None,
    mailer: Mailer | None = None,
    breach: BreachChecker | None = None,
    secrets: Secrets | None = None,
) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    if settings.database_url.startswith("sqlite:///") and ":memory:" not in settings.database_url:
        Path(settings.database_url.removeprefix("sqlite:///")).parent.mkdir(
            parents=True, exist_ok=True
        )
    engine = make_engine(settings.database_url)
    create_schema(engine)
    ctx = build_context(
        settings, engine, clock=clock, mailer=mailer, breach=breach, secrets=secrets
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        log.info("authkit started", extra={"env": settings.env, "version": __version__})
        yield
        engine.dispose()

    app = FastAPI(
        title="Authkit",
        version=__version__,
        summary="A small, self-hostable authentication service.",
        description=(
            "Argon2id passwords, 15-minute access tokens, rotating refresh tokens with reuse "
            "detection, TOTP two-factor authentication, e-mail verification, password reset, "
            "login throttling and an audit log.\n\n"
            "Authenticate with `Authorization: Bearer <access_token>`."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_on else None,
        lifespan=lifespan,
    )
    app.state.ctx = ctx
    app.state.engine = engine
    install_error_handlers(app)

    for router in (auth.router, me.router, mfa_api.router, admin.router, system.router):
        app.include_router(router)

    # Innermost first: the last middleware added is the outermost one.
    app.add_middleware(RequestSizeLimit, max_bytes=settings.max_body_bytes)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Auth-Mode", "X-Request-ID"],
            max_age=600,
        )
    app.add_middleware(SecurityHeaders, hsts=not settings.is_dev)
    app.add_middleware(RequestLog)

    _mount_docs(app, settings)
    _mount_ui(app)
    return app


def _mount_docs(app: FastAPI, settings: Settings) -> None:
    if not settings.docs_on:
        return
    from swagger_ui_bundle import swagger_ui_path

    app.mount("/docs-assets", StaticFiles(directory=swagger_ui_path), name="docs-assets")

    @app.get("/docs", include_in_schema=False)
    def docs() -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><html lang=en><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            "<title>Authkit API</title>"
            "<link rel=stylesheet href=/docs-assets/swagger-ui.css></head><body>"
            "<div id=swagger-ui></div>"
            "<script src=/docs-assets/swagger-ui-bundle.js></script>"
            "<script src=/docs/init.js></script></body></html>"
        )

    @app.get("/docs/init.js", include_in_schema=False)
    def docs_init() -> Response:
        js = (
            "window.ui = SwaggerUIBundle({url: '/openapi.json', dom_id: '#swagger-ui', "
            "deepLinking: true, persistAuthorization: false});"
        )
        return Response(js, media_type="application/javascript")


def _mount_ui(app: FastAPI) -> None:
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})
