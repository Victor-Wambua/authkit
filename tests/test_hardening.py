"""HTTP-level hardening: headers, body limits, CORS, client IP, dev-only routes, error shape."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from sqlalchemy import select

from authkit.config import ConfigError, Settings
from authkit.mailer import MemoryMailer
from authkit.models import AuthSession
from tests.conftest import PASSWORD, Harness

EMAIL = "amina@example.com"


def test_security_headers_on_api_and_ui_responses(h: Harness) -> None:
    for path in ("/healthz", "/api/me", "/", "/static/app.css"):
        r = h.client.get(path)
        assert r.headers["x-content-type-options"] == "nosniff", path
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert "camera=()" in r.headers["permissions-policy"]


def test_csp_for_the_app_has_no_inline_or_eval_allowance(h: Harness) -> None:
    csp = h.client.get("/").headers["content-security-policy"]
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "script-src 'self'" in csp and "default-src 'none'" in csp


def test_api_responses_are_not_cacheable(h: Harness) -> None:
    r = h.client.get("/api/me")
    assert r.headers["cache-control"] == "no-store"


def test_hsts_is_only_sent_outside_dev(tmp_path, make_harness: Callable[..., Harness]) -> None:  # type: ignore[no-untyped-def]
    assert "strict-transport-security" not in make_harness().client.get("/healthz").headers
    prod = make_harness(env="production", mailer="smtp", docs_enabled=False)
    assert "max-age=" in prod.client.get("/healthz").headers["strict-transport-security"]


def test_request_ids_are_assigned_and_untrusted_ones_replaced(h: Harness) -> None:
    assert len(h.client.get("/healthz").headers["x-request-id"]) == 32
    assert (
        h.client.get("/healthz", headers={"X-Request-ID": "trace-12345678"}).headers["x-request-id"]
        == "trace-12345678"
    )
    evil = h.client.get("/healthz", headers={"X-Request-ID": "a b\tc<script>"})
    assert evil.headers["x-request-id"] != "a b\tc<script>"


def test_oversized_bodies_are_rejected_by_content_length(
    make_harness: Callable[..., Harness],
) -> None:
    h = make_harness(max_body_bytes=2048)
    r = h.post("/api/auth/login", {"email": EMAIL, "password": "x" * 5000})
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


def test_oversized_streamed_bodies_are_rejected_too(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(max_body_bytes=2048)

    def chunks() -> Iterator[bytes]:
        for _ in range(10):
            yield b'{"email": "' + b"a" * 400 + b'"' + b" " * 10

    r = h.client.post(
        "/api/auth/login", content=chunks(), headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413


def test_normal_sized_bodies_pass(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(max_body_bytes=2048)
    assert h.post("/api/auth/login", {"email": EMAIL, "password": "x" * 100}).status_code == 401


def test_no_cors_headers_by_default(h: Harness) -> None:
    r = h.client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_allows_only_the_configured_origins(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(cors_origins="https://app.example.org, https://admin.example.org")
    ok = h.client.get("/healthz", headers={"Origin": "https://app.example.org"})
    assert ok.headers["access-control-allow-origin"] == "https://app.example.org"
    assert ok.headers["access-control-allow-credentials"] == "true"
    bad = h.client.get("/healthz", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in bad.headers
    pre = h.client.options(
        "/api/auth/login",
        headers={
            "Origin": "https://app.example.org",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-auth-mode,content-type",
        },
    )
    assert (
        pre.status_code == 200
        and "x-auth-mode" in pre.headers["access-control-allow-headers"].lower()
    )


def test_wildcard_cors_is_refused_at_startup() -> None:
    with pytest.raises(ValueError, match="explicit origins"):
        Settings(_env_file=None, cors_origins="*")


def test_x_forwarded_for_is_ignored_unless_proxies_are_trusted(h: Harness) -> None:
    h.login(EMAIL, "wrong wrong wrong", headers={"X-Forwarded-For": "198.51.100.77"})
    with h.db() as db:
        from authkit.models import AuditEvent

        assert db.scalars(select(AuditEvent.ip)).first() == "testclient"


def test_x_forwarded_for_uses_the_entry_added_by_the_trusted_proxy(
    make_harness: Callable[..., Harness],
) -> None:
    h = make_harness(trusted_proxy_hops=1)
    # A client forges the left side; our proxy appended the real address on the right.
    h.login(EMAIL, "wrong wrong wrong", headers={"X-Forwarded-For": "6.6.6.6, 198.51.100.77"})
    h.login(EMAIL, "wrong wrong wrong", headers={"X-Forwarded-For": "not-an-ip"})
    h.login(EMAIL, "wrong wrong wrong")
    from authkit.models import AuditEvent

    with h.db() as db:
        ips = list(db.scalars(select(AuditEvent.ip).order_by(AuditEvent.id)))
    assert ips == ["198.51.100.77", "testclient", "testclient"]


def test_session_records_the_client_address_and_agent(h: Harness) -> None:
    h.register(EMAIL)
    h.client.post(
        "/api/auth/login",
        json={"email": EMAIL, "password": PASSWORD},
        headers={"User-Agent": "Mozilla/5.0 (Test)"},
    )
    with h.db() as db:
        s = db.scalar(select(AuthSession))
    assert s is not None and s.user_agent == "Mozilla/5.0 (Test)" and s.ip == "testclient"


def test_dev_outbox_is_hidden_outside_dev_env(h: Harness) -> None:
    assert h.client.get("/api/dev/outbox").status_code == 404


def test_dev_outbox_lists_file_mailer_messages_in_dev(
    tmp_path, make_harness: Callable[..., Harness]
) -> None:  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from authkit.app import create_app
    from authkit.mailer import FileMailer
    from authkit.security.keys import Secrets

    settings = Settings(
        _env_file=None,
        env="dev",
        database_url=f"sqlite:///{tmp_path / 'dev.db'}",
        keys_file=tmp_path / "k.json",
        outbox_dir=tmp_path / "box",
        argon2_memory_kib=64,
        argon2_time_cost=1,
        log_level="WARNING",
    )
    app = create_app(settings, secrets=Secrets.ephemeral())
    assert isinstance(app.state.ctx.mailer, FileMailer)
    client = TestClient(app)
    client.post("/api/auth/register", json={"email": EMAIL, "password": PASSWORD})
    messages = client.get("/api/dev/outbox").json()["messages"]
    assert messages and messages[0]["to"] == EMAIL and "token=" in messages[0]["text"]


def test_production_refuses_the_file_mailer_and_missing_keys(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from authkit.app import create_app
    from authkit.security.keys import Secrets

    def prod(**kw: Any) -> Settings:
        return Settings(
            _env_file=None,
            env="production",
            database_url=f"sqlite:///{tmp_path / 'p.db'}",
            keys_file=tmp_path / "none.json",
            **kw,
        )

    with pytest.raises(ConfigError, match="init-keys"):
        create_app(prod(mailer="smtp"), mailer=MemoryMailer())
    with pytest.raises(ConfigError, match="development only"):
        create_app(prod(), secrets=Secrets.ephemeral())


def test_docs_are_served_in_dev_and_off_in_production(
    h: Harness, make_harness: Callable[..., Harness]
) -> None:
    assert h.client.get("/openapi.json").status_code == 200
    docs = h.client.get("/docs")
    assert (
        docs.status_code == 200 and "script-src 'self'" in docs.headers["content-security-policy"]
    )
    assert "cdn" not in docs.text.lower()
    assert h.client.get("/docs-assets/swagger-ui-bundle.js").status_code == 200
    prod = make_harness(env="production", mailer="smtp")
    assert prod.client.get("/openapi.json").status_code == 404
    assert prod.client.get("/docs").status_code == 404


def test_openapi_documents_the_public_surface(h: Harness) -> None:
    spec = h.client.get("/openapi.json").json()
    paths = set(spec["paths"])
    for p in (
        "/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/api/auth/logout",
        "/api/auth/password/forgot", "/api/auth/password/reset", "/api/auth/login/mfa",
        "/api/me", "/api/me/sessions", "/api/mfa/setup", "/api/mfa/enable", "/api/admin/audit",
    ):  # fmt: skip
        assert p in paths, p
    assert all(op.get("summary") for item in spec["paths"].values() for op in item.values())


def test_error_bodies_have_one_shape(h: Harness) -> None:
    for r in (h.client.get("/nope"), h.client.delete("/healthz"), h.login("x", "y")):
        body = r.json()
        assert set(body) == {"error"} and {"code", "message"} <= set(body["error"])


def test_health_and_jwks(h: Harness) -> None:
    assert h.client.get("/healthz").json()["status"] == "ok"
    keys = h.client.get("/.well-known/jwks.json").json()["keys"]
    assert keys and all("d" not in k and "private_pem" not in k for k in keys)


def test_the_ui_is_served_and_has_no_external_references(h: Harness) -> None:
    page = h.client.get("/")
    assert page.status_code == 200 and "text/html" in page.headers["content-type"]
    for path in ("/static/app.css", "/static/js/app.js", "/static/js/api.js", "/static/js/dom.js"):
        response = h.client.get(path)
        assert response.status_code == 200, path
        body = response.text
        assert "http://" not in body.replace("http://www.w3.org", "") and "https://" not in body, (
            path
        )
    assert "https://" not in page.text
