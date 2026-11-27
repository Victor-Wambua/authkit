"""Browser host for the real authkit package (runs under Pyodide, inside a Web Worker).

Everything under ``authkit`` is the unmodified service: the FastAPI app, the SQLAlchemy models,
Argon2id hashing, the JWT key ring, refresh rotation, TOTP and the audit log. This file only
supplies what a server process would normally provide:

* an ASGI driver, so a ``fetch()`` call in the page becomes a request to the FastAPI app;
* an in-memory SQLite database and a throw-away key file in Pyodide's virtual filesystem;
* a clock that can be moved forward, so token expiry and lockout windows can be shown;
* read-only inspection helpers for the demo's audit and token panels.

There are no threads in WebAssembly, so ``anyio.to_thread.run_sync`` is replaced by a direct
call. Requests are therefore handled one at a time, which is also what the single SQLite
connection did before.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio.to_thread
from sqlalchemy import select

from authkit.app import create_app
from authkit.cli import DEMO_USERS, seed_demo
from authkit.config import Settings
from authkit.models import AuditEvent, AuthSession, RefreshToken, User
from authkit.security import totp


async def _run_inline(func: Any, *args: Any, **_kwargs: Any) -> Any:
    return func(*args)


anyio.to_thread.run_sync = _run_inline  # type: ignore[assignment]

# 198.51.100.0/24 is reserved for documentation (RFC 5737): a stand-in for the visitor's address.
CLIENT_IP = "198.51.100.23"
WORK_DIR = Path("/tmp/authkit-demo")  # noqa: S108 (Pyodide virtual filesystem, not the host)


class DemoClock:
    """Real time plus an offset the visitor can advance. Used for JWTs, lockouts and TOTP."""

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def now(self) -> datetime:
        return datetime.now(UTC) + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += timedelta(seconds=seconds)


class _State:
    app: Any = None
    ctx: Any = None
    clock: DemoClock


state = _State()


def boot() -> str:
    """Create a fresh service: new keys, empty database, seed accounts."""
    if state.app is not None:
        state.app.state.engine.dispose()
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    WORK_DIR.mkdir(parents=True)
    state.clock = DemoClock()
    settings = Settings(
        env="dev",
        log_level="WARNING",
        docs_enabled=False,  # the Swagger UI bundle is not shipped with the demo
        database_url="sqlite://",
        keys_file=WORK_DIR / "keys.json",
        outbox_dir=WORK_DIR / "outbox",
        base_url="https://victor-wambua.github.io/authkit",
    )
    state.app = create_app(settings, clock=state.clock)
    state.ctx = state.app.state.ctx
    seed_demo(state.ctx)
    return json.dumps(
        {
            "accounts": [{"email": e, "role": r, "password": p} for e, r, p in DEMO_USERS],
            "argon2": {
                "memory_kib": settings.argon2_memory_kib,
                "time_cost": settings.argon2_time_cost,
                "parallelism": settings.argon2_parallelism,
            },
            "access_ttl": settings.access_ttl_seconds,
        }
    )


async def handle(method: str, path: str, query: str, headers_json: str, body: str) -> str:
    """Run one HTTP request through the real ASGI app and return status, headers and body."""
    headers = json.loads(headers_json)
    payload = body.encode() if body else b""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "root_path": "",
        "headers": [(k.lower().encode(), str(v).encode()) for k, v in headers.items()],
        "client": (CLIENT_IP, 49152),
        "server": ("authkit.demo", 443),
    }
    sent: list[dict[str, Any]] = []
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": payload, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await state.app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    chunks = [m.get("body", b"") for m in sent if m["type"] == "http.response.body"]
    return json.dumps(
        {
            "status": start["status"],
            "headers": [[k.decode(), v.decode()] for k, v in start["headers"]],
            "body": b"".join(chunks).decode("utf-8", "replace"),
            "clock_offset": state.clock.offset.total_seconds(),
        }
    )


def advance_clock(seconds: float) -> str:
    state.clock.advance(seconds)
    return json.dumps(
        {"now": state.clock.now().isoformat(), "offset": state.clock.offset.total_seconds()}
    )


def totp_code(secret_b32: str) -> str:
    """The code an authenticator app would show right now, using the server's clock."""
    now = state.clock.now().timestamp()
    code = totp.totp_at(totp.from_b32(secret_b32), now)
    return json.dumps({"code": code, "remaining": 30 - int(now % 30)})


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def snapshot() -> str:
    """Read-only view of the audit table and the refresh-token chains, newest first."""
    now = state.clock.now()
    with state.ctx.sessions() as db:
        emails = {u.id: u.email for u in db.scalars(select(User))}
        audit_rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(150))
        audit = []
        for row in audit_rows:
            detail = json.loads(row.detail) if row.detail else {}
            audit.append(
                {
                    "id": row.id,
                    "at": _iso(row.at),
                    "event": row.event,
                    "who": emails.get(row.user_id or "") or detail.get("email"),
                    "session_id": row.session_id,
                    "ip": row.ip,
                    "detail": detail,
                }
            )
        tokens: dict[str, list[dict[str, Any]]] = {}
        for tok in db.scalars(
            select(RefreshToken).order_by(RefreshToken.created_at, RefreshToken.id)
        ):
            state_name = "used" if tok.used_at else ("expired" if tok.expires_at <= now else "live")
            tokens.setdefault(tok.session_id, []).append(
                {"hash": tok.token_hash, "state": state_name, "created_at": _iso(tok.created_at)}
            )
        sessions = []
        for s in db.scalars(select(AuthSession).order_by(AuthSession.created_at.desc())):
            sessions.append(
                {
                    "id": s.id,
                    "who": emails.get(s.user_id),
                    "created_at": _iso(s.created_at),
                    "revoked_at": _iso(s.revoked_at),
                    "revoked_reason": s.revoked_reason,
                    "used_2fa": s.used_2fa,
                    "tokens": tokens.get(s.id, []),
                }
            )
    return json.dumps({"now": now.isoformat(), "audit": audit, "sessions": sessions})
