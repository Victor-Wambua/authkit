"""Shared fixtures. Every test gets its own SQLite file, key set, mailer and fake clock."""

from __future__ import annotations

import re
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from authkit.app import create_app
from authkit.clock import FakeClock
from authkit.config import Settings
from authkit.context import AppContext
from authkit.mailer import MemoryMailer
from authkit.models import User
from authkit.security import totp
from authkit.security.keys import Secrets

warnings.filterwarnings("ignore", message=".*httpx.*starlette.testclient.*")

PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a different long passphrase 42"


@dataclass
class Tokens:
    access: str
    refresh: str
    session_id: str | None = None

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access}"}


class Harness:
    def __init__(self, tmp_path: Path, **overrides: Any) -> None:
        base: dict[str, Any] = {
            "env": "test",
            "database_url": f"sqlite:///{tmp_path / 'authkit-test.db'}",
            "keys_file": tmp_path / "keys.json",
            "outbox_dir": tmp_path / "outbox",
            "argon2_memory_kib": 64,
            "argon2_time_cost": 1,
            "argon2_parallelism": 1,
            "log_level": "WARNING",
        }
        base.update(overrides)
        self.settings = Settings(_env_file=None, **base)
        self.clock = FakeClock()
        self.mailer = MemoryMailer()
        self.secrets = Secrets.ephemeral()
        self.app = create_app(
            self.settings, clock=self.clock, mailer=self.mailer, secrets=self.secrets
        )
        self.client = TestClient(self.app)
        self.ctx: AppContext = self.app.state.ctx

    # -- low level -------------------------------------------------------
    def db(self) -> Session:
        return self.ctx.sessions()

    def post(self, path: str, json: Any = None, **kw: Any) -> Response:
        return self.client.post(path, json=json, **kw)

    def new_client(self) -> TestClient:
        return TestClient(self.app)

    # -- accounts --------------------------------------------------------
    def register(self, email: str, password: str = PASSWORD) -> Response:
        return self.post("/api/auth/register", {"email": email, "password": password})

    def mail_token(self, to: str, subject_contains: str) -> str:
        for msg in reversed(self.mailer.messages):
            if msg.to == to and subject_contains.lower() in msg.subject.lower():
                match = re.search(r"token=([A-Za-z0-9_\-]+)", msg.text)
                assert match, msg.text
                return match.group(1)
        raise AssertionError(f"no mail to {to} matching {subject_contains!r}")

    def verify_email(self, email: str) -> None:
        token = self.mail_token(email, "confirm")
        assert self.post("/api/auth/email/verify", {"token": token}).status_code == 204

    def login(self, email: str, password: str = PASSWORD, **kw: Any) -> Response:
        return self.post("/api/auth/login", {"email": email, "password": password}, **kw)

    def signup(self, email: str = "amina@example.com", password: str = PASSWORD) -> Tokens:
        assert self.register(email, password).status_code == 202
        self.verify_email(email)
        r = self.login(email, password)
        assert r.status_code == 200, r.text
        return self.tokens(r)

    @staticmethod
    def tokens(r: Response) -> Tokens:
        body = r.json()
        return Tokens(body["access_token"], body["refresh_token"])

    def refresh(self, refresh_token: str, client: TestClient | None = None) -> Response:
        return (client or self.client).post(
            "/api/auth/refresh", json={"refresh_token": refresh_token}
        )

    def make_admin(self, email: str) -> None:
        with self.db() as db:
            user = db.scalar(select(User).where(User.email == email))
            assert user is not None
            user.role = "admin"
            db.commit()

    def get_user(self, email: str) -> User:
        with self.db() as db:
            user = db.scalar(select(User).where(User.email == email))
            assert user is not None
            return user

    # -- two-factor ------------------------------------------------------
    def enable_totp(self, tokens: Tokens) -> tuple[bytes, list[str]]:
        r = self.post("/api/mfa/setup", headers=tokens.headers)
        assert r.status_code == 200, r.text
        secret = totp.from_b32(r.json()["secret"])
        r = self.post("/api/mfa/enable", {"code": self.code(secret)}, headers=tokens.headers)
        assert r.status_code == 200, r.text
        return secret, r.json()["recovery_codes"]

    def code(self, secret: bytes, offset_steps: int = 0) -> str:
        return totp.totp_at(secret, self.clock.now().timestamp() + offset_steps * 30)


@pytest.fixture
def make_harness(tmp_path: Path) -> Iterator[Callable[..., Harness]]:
    created: list[Harness] = []

    def factory(**overrides: Any) -> Harness:
        h = Harness(tmp_path, **overrides)
        created.append(h)
        return h

    yield factory
    for h in created:
        h.client.close()
        h.app.state.engine.dispose()


@pytest.fixture
def h(make_harness: Callable[..., Harness]) -> Harness:
    return make_harness()
