"""Config validation, mailers, CLI, maintenance, logging redaction and small utilities."""

from __future__ import annotations

import json
import logging
import smtplib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from authkit import cli
from authkit.clock import FakeClock, SystemClock
from authkit.config import ConfigError, Settings
from authkit.db import UTCDateTime
from authkit.logging_setup import REDACTED, JsonFormatter, redact
from authkit.mailer import FileMailer, Message, SmtpMailer
from authkit.models import AuthSession, EmailToken, RefreshToken, ThrottleEvent, User
from authkit.services import maintenance
from tests.conftest import PASSWORD, Harness

# --- config -----------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"throttle_lockout_seconds": 1000, "throttle_window_seconds": 900},
        {"account_free_attempts": 10, "account_lockout_threshold": 10},
        {"ip_free_attempts": 30, "ip_lockout_threshold": 20},
        {"password_min_length": 200, "password_max_length": 100},
    ],
)
def test_inconsistent_settings_are_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        Settings(_env_file=None, **overrides)


def test_settings_read_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTHKIT_ENV", "dev")
    monkeypatch.setenv("AUTHKIT_ACCESS_TTL_SECONDS", "600")
    s = Settings(_env_file=None)
    assert s.is_dev and s.access_ttl_seconds == 600 and not s.secure_cookies
    assert Settings(_env_file=None, env="production").secure_cookies


def test_production_is_the_default_environment() -> None:
    assert Settings(_env_file=None).env == "production"


# --- clock and db types --------------------------------------------------------


def test_fake_clock_advances_and_system_clock_is_utc() -> None:
    c = FakeClock(datetime(2026, 1, 1, tzinfo=UTC))
    c.advance(seconds=30, minutes=1)
    assert c.now() == datetime(2026, 1, 1, 0, 1, 30, tzinfo=UTC)
    assert SystemClock().now().tzinfo is UTC


def test_utc_datetime_roundtrips_and_refuses_naive_values() -> None:
    t = UTCDateTime()
    aware = datetime(2026, 5, 1, 12, tzinfo=timezone_plus3())
    stored = t.process_bind_param(aware, None)
    assert stored == datetime(2026, 5, 1, 9) and stored.tzinfo is None
    assert t.process_result_value(stored, None) == aware
    assert t.process_bind_param(None, None) is None and t.process_result_value(None, None) is None
    with pytest.raises(ValueError):
        t.process_bind_param(datetime(2026, 1, 1), None)


def timezone_plus3():  # type: ignore[no-untyped-def]
    from datetime import timezone

    return timezone(timedelta(hours=3))


# --- mailers ----------------------------------------------------------------


def test_file_mailer_writes_one_json_file_per_message(tmp_path: Path) -> None:
    m = FileMailer(tmp_path / "box", FakeClock())
    m.send(Message("a@example.com", "Hello", "body one"))
    m.send(Message("b@example.com", "Again", "body two"))
    files = list((tmp_path / "box").glob("*.json"))
    assert len(files) == 2
    listed = m.list_messages()
    assert {x["to"] for x in listed} == {"a@example.com", "b@example.com"}
    assert json.loads(files[0].read_text())["subject"] in {"Hello", "Again"}


def test_smtp_mailer_uses_starttls_and_login_without_a_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            calls.append(f"connect {host}:{port}")

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *a: object) -> None:
            calls.append("quit")

        def starttls(self) -> None:
            calls.append("starttls")

        def login(self, user: str, password: str) -> None:
            calls.append(f"login {user}")

        def send_message(self, msg: Any) -> None:
            calls.append(f"send to={msg['To']} subject={msg['Subject']}")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    SmtpMailer("smtp.example.org", 587, "robot", "pw", "Authkit <no-reply@example.org>").send(
        Message("amina@example.com", "Hi", "text")
    )
    assert calls == [
        "connect smtp.example.org:587",
        "starttls",
        "login robot",
        "send to=amina@example.com subject=Hi",
        "quit",
    ]


def test_a_failing_mailer_never_breaks_the_api_response(h: Harness) -> None:
    class Broken:
        def send(self, message: Message) -> None:
            raise smtplib.SMTPException("relay down")

    h.ctx.mailer = Broken()
    r = h.register("amina@example.com")
    assert r.status_code == 202
    assert h.login("amina@example.com").status_code == 200


# --- logging ----------------------------------------------------------------


def test_redact_hides_sensitive_keys_and_token_shapes() -> None:
    out = redact(
        {
            "email": "amina@example.com",
            "password": "hunter2hunter2",
            "refresh_token": "rt_" + "a" * 43,
            "nested": {"Authorization": "Bearer abc.def.ghi", "ok": 1},
            "note": "token=abc123secret and a JWT eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.sig12345",
            "codes": ["ABCD-EFGH-JKLM-NPQR"],
            "status_code": 200,
        }
    )
    assert out["password"] == REDACTED and out["refresh_token"] == REDACTED
    assert out["nested"]["Authorization"] == REDACTED and out["nested"]["ok"] == 1
    assert "abc123secret" not in out["note"] and "eyJhbGci" not in out["note"]
    assert out["codes"] == [REDACTED]
    assert out["status_code"] == 200 and out["email"] == "amina@example.com"


def test_json_formatter_emits_one_json_object_with_extras_redacted() -> None:
    rec = logging.LogRecord(
        "authkit.test", logging.INFO, __file__, 1, "login with %s", ("Bearer abc.def",), None
    )
    rec.password = "hunter2hunter2"  # type: ignore[attr-defined]
    rec.request_id = "r-1"  # type: ignore[attr-defined]
    doc = json.loads(JsonFormatter().format(rec))
    assert doc["level"] == "INFO" and doc["logger"] == "authkit.test" and doc["request_id"] == "r-1"
    assert doc["password"] == REDACTED and "abc.def" not in doc["msg"]


def test_json_formatter_includes_redacted_exceptions() -> None:
    try:
        raise RuntimeError("failed for token=supersecretvalue")
    except RuntimeError:
        import sys

        rec = logging.LogRecord("authkit", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
    assert "supersecretvalue" not in json.loads(JsonFormatter().format(rec))["exc"]


# --- maintenance --------------------------------------------------------------


def test_purge_removes_only_rows_that_no_longer_matter(h: Harness) -> None:
    h.register("amina@example.com")
    h.signup("kamau@example.com")
    h.login("amina@example.com", "wrong wrong wrong")
    h.clock.advance(15 * 86400)  # refresh tokens expire (14 d), sessions and tokens do not
    with h.db() as db:
        counts = maintenance.purge(h.ctx, db)
        assert counts["refresh_tokens"] == 1 and counts["sessions"] == 0
        assert counts["email_tokens"] == 2  # both verification links expired a day ago
        assert counts["throttle_events"] == 4  # 2 register hits + the failed login (account, IP)
        assert db.scalar(select(AuthSession)) is not None
    h.clock.advance(20 * 86400)
    with h.db() as db:
        counts = maintenance.purge(h.ctx, db)
        assert counts["sessions"] == 1
        assert db.scalar(select(RefreshToken)) is None and db.scalar(select(EmailToken)) is None
        assert db.scalar(select(ThrottleEvent)) is None and db.scalar(select(User)) is not None


# --- CLI --------------------------------------------------------------------------


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("AUTHKIT_ENV", "dev")
    monkeypatch.setenv("AUTHKIT_DATABASE_URL", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setenv("AUTHKIT_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.setenv("AUTHKIT_OUTBOX_DIR", str(tmp_path / "outbox"))
    monkeypatch.setenv("AUTHKIT_ARGON2_MEMORY_KIB", "64")
    monkeypatch.setenv("AUTHKIT_ARGON2_TIME_COST", "1")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_cli_key_lifecycle(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["init-keys"]) == 0
    assert cli.main(["init-keys"]) == 1  # refuses to overwrite
    assert "already exists" in capsys.readouterr().err
    assert cli.main(["rotate-key"]) == 0
    assert len(json.loads((cli_env / "keys.json").read_text())["jwt"]["keys"]) == 2
    assert cli.main(["prune-keys", "--keep", "1"]) == 0
    assert len(json.loads((cli_env / "keys.json").read_text())["jwt"]["keys"]) == 1


def test_cli_create_admin_and_duplicate(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTHKIT_ADMIN_PASSWORD", PASSWORD)
    assert cli.main(["create-admin", "--email", "boss@example.com"]) == 0
    assert cli.main(["create-admin", "--email", "boss@example.com"]) == 1
    monkeypatch.setenv("AUTHKIT_ADMIN_PASSWORD", "short")
    assert (
        cli.main(["create-admin", "--email", "other@example.com"]) == 1
    )  # policy applies here too


def test_cli_seed_demo_is_idempotent_and_refuses_production(
    cli_env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["seed-demo"]) == 0
    assert cli.main(["seed-demo"]) == 0
    out = capsys.readouterr().out
    assert "admin@example.com" in out and "amina@example.com" in out
    monkeypatch.setenv("AUTHKIT_ENV", "production")
    assert cli.main(["seed-demo"]) == 1


def test_cli_breach_build_and_purge(cli_env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    words = cli_env / "words.txt"
    words.write_text("hunter2hunter2\nletmein12345\n\n")
    out = cli_env / "out.txt"
    assert cli.main(["breach-build", str(words), str(out)]) == 0
    assert len(out.read_text().splitlines()) == 2
    assert cli.main(["purge"]) == 0
    assert "refresh_tokens" in capsys.readouterr().out


def test_config_error_is_reported_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("AUTHKIT_ENV", "production")
    monkeypatch.setenv("AUTHKIT_KEYS_FILE", str(tmp_path / "missing.json"))
    monkeypatch.setenv("AUTHKIT_DATABASE_URL", f"sqlite:///{tmp_path / 'x.db'}")
    assert cli.main(["purge"]) == 1
    assert "init-keys" in capsys.readouterr().err
    assert isinstance(ConfigError("x"), RuntimeError)
