"""TOTP enrolment and login, replay protection, recovery codes."""

from __future__ import annotations

import re
from collections.abc import Callable

from sqlalchemy import select

from authkit.models import AuditEvent, RecoveryCode
from authkit.security import totp
from tests.conftest import PASSWORD, Harness, Tokens

EMAIL = "amina@example.com"


def login_to_mfa(h: Harness) -> str:
    r = h.login(EMAIL)
    assert r.status_code == 200 and r.json()["status"] == "mfa_required"
    assert "access_token" not in r.json() and "refresh_token" not in r.json()
    return str(r.json()["mfa_token"])


def finish(h: Harness, mfa_token: str, code: str):  # type: ignore[no-untyped-def]
    return h.post("/api/auth/login/mfa", {"mfa_token": mfa_token, "code": code})


def with_2fa(h: Harness) -> tuple[Tokens, bytes, list[str]]:
    t = h.signup(EMAIL)
    secret, codes = h.enable_totp(t)
    h.clock.advance(30)  # the enrolment code is spent; move on to the next step
    return t, secret, codes


def test_setup_returns_uri_secret_and_an_inline_svg_qr(h: Harness) -> None:
    t = h.signup(EMAIL)
    body = h.post("/api/mfa/setup", headers=t.headers).json()
    assert body["otpauth_uri"].startswith("otpauth://totp/Authkit:amina%40example.com?")
    assert body["secret"] in body["otpauth_uri"]
    svg = body["qr_svg"]
    assert svg.lstrip().startswith("<svg") and "<path" in svg
    assert "<script" not in svg.lower() and "http://" not in svg.replace("http://www.w3.org", "")


def test_two_factor_is_not_active_until_a_code_is_confirmed(h: Harness) -> None:
    t = h.signup(EMAIL)
    h.post("/api/mfa/setup", headers=t.headers)
    assert h.client.get("/api/me", headers=t.headers).json()["totp_enabled"] is False
    assert h.login(EMAIL).json()["status"] == "ok"


def test_the_totp_secret_is_encrypted_at_rest(h: Harness) -> None:
    t = h.signup(EMAIL)
    secret_b32 = h.post("/api/mfa/setup", headers=t.headers).json()["secret"]
    stored = h.get_user(EMAIL).totp_secret_enc
    assert stored is not None and secret_b32 not in stored
    assert totp.b32(h.ctx.secrets.decrypt(stored)) == secret_b32


def test_enable_with_a_wrong_code_fails_and_with_the_right_one_returns_ten_codes(
    h: Harness,
) -> None:
    t = h.signup(EMAIL)
    secret = totp.from_b32(h.post("/api/mfa/setup", headers=t.headers).json()["secret"])
    bad = h.post("/api/mfa/enable", {"code": "000000"}, headers=t.headers)
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "invalid_code"
    ok = h.post("/api/mfa/enable", {"code": h.code(secret)}, headers=t.headers)
    codes = ok.json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(re.fullmatch(r"[A-Z2-9]{4}(-[A-Z2-9]{4}){3}", c) for c in codes)
    assert h.client.get("/api/me", headers=t.headers).json()["totp_enabled"] is True


def test_enable_without_setup_and_double_enable_are_conflicts(h: Harness) -> None:
    t = h.signup(EMAIL)
    assert h.post("/api/mfa/enable", {"code": "123456"}, headers=t.headers).status_code == 409
    h.enable_totp(t)
    assert h.post("/api/mfa/setup", headers=t.headers).status_code == 409


def test_recovery_codes_are_stored_hashed_with_the_pepper(h: Harness) -> None:
    t = h.signup(EMAIL)
    _, codes = h.enable_totp(t)
    with h.db() as db:
        rows = list(db.scalars(select(RecoveryCode)))
    assert len(rows) == 10
    stored = {r.code_hash for r in rows}
    assert not any(c.replace("-", "") in " ".join(stored) for c in codes)
    assert h.ctx.secrets.keyed_hash(codes[0].replace("-", "")) in stored


def test_login_with_totp_issues_tokens_marked_as_two_factor(h: Harness) -> None:
    _, secret, _ = with_2fa(h)
    mfa_token = login_to_mfa(h)
    r = finish(h, mfa_token, h.code(secret))
    assert r.status_code == 200 and r.json()["status"] == "ok"
    t = h.tokens(r)
    assert (
        h.client.get("/api/me/sessions", headers=t.headers).json()["sessions"][0]["used_2fa"]
        is True
    )
    import jwt

    assert jwt.decode(t.access, options={"verify_signature": False})["amr"] == ["pwd", "otp"]


def test_a_totp_code_cannot_be_replayed(h: Harness) -> None:
    _, secret, _ = with_2fa(h)
    code = h.code(secret)
    assert finish(h, login_to_mfa(h), code).status_code == 200
    again = finish(h, login_to_mfa(h), code)  # same 30-second step
    assert again.status_code == 401 and again.json()["error"]["code"] == "invalid_code"
    h.clock.advance(30)
    assert finish(h, login_to_mfa(h), h.code(secret)).status_code == 200


def test_codes_from_the_adjacent_steps_are_accepted_but_not_further(h: Harness) -> None:
    _, secret, _ = with_2fa(h)
    h.clock.advance(30)  # the enrolment step is spent; the step before "now" is a fresh one
    assert finish(h, login_to_mfa(h), h.code(secret, -1)).status_code == 200  # a step behind
    h.clock.advance(60)
    assert finish(h, login_to_mfa(h), h.code(secret, +1)).status_code == 200  # a step ahead
    h.clock.advance(120)
    assert finish(h, login_to_mfa(h), h.code(secret, -2)).status_code == 401  # too old
    assert finish(h, login_to_mfa(h), h.code(secret, +2)).status_code == 401  # too new


def test_wrong_code_is_rejected_and_audited(h: Harness) -> None:
    with_2fa(h)
    r = finish(h, login_to_mfa(h), "000000")
    assert r.status_code == 401
    with h.db() as db:
        assert "mfa_failure" in [e.event for e in db.scalars(select(AuditEvent))]


def test_recovery_code_works_exactly_once(h: Harness) -> None:
    _, _, codes = with_2fa(h)
    assert finish(h, login_to_mfa(h), codes[0]).status_code == 200
    assert finish(h, login_to_mfa(h), codes[0]).status_code == 401
    assert (
        finish(h, login_to_mfa(h), codes[1].lower().replace("-", " ")).status_code == 200
    )  # forgiving input
    with h.db() as db:
        used = [e for e in db.scalars(select(AuditEvent)) if e.event == "recovery_code_used"]
    assert len(used) == 2 and '"remaining": 8' in (used[-1].detail or "")


def test_mfa_guessing_is_throttled(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(account_free_attempts=2, account_lockout_threshold=4)
    _, secret, _ = with_2fa(h)
    mfa_token = login_to_mfa(h)
    for _ in range(4):
        assert finish(h, mfa_token, "000000").status_code == 401
        h.clock.advance(5)
    blocked = finish(h, mfa_token, h.code(secret))  # even the right code is refused now
    assert blocked.status_code == 429 and "retry-after" in blocked.headers


def test_mfa_token_is_not_an_access_token_and_expires_in_five_minutes(h: Harness) -> None:
    _, secret, _ = with_2fa(h)
    mfa_token = login_to_mfa(h)
    assert (
        h.client.get("/api/me", headers={"Authorization": f"Bearer {mfa_token}"}).status_code == 401
    )
    h.clock.advance(301)
    assert finish(h, mfa_token, h.code(secret)).status_code == 401


def test_an_access_token_cannot_stand_in_for_an_mfa_token(h: Harness) -> None:
    t, secret, _ = with_2fa(h)
    assert finish(h, t.access, h.code(secret)).status_code == 401


def test_password_is_still_checked_first_and_looks_the_same_for_2fa_accounts(h: Harness) -> None:
    with_2fa(h)
    wrong = h.login(EMAIL, "not the right password at all")
    unknown = h.login("ghost@example.com", "not the right password at all")
    assert (wrong.status_code, wrong.json()) == (unknown.status_code, unknown.json())


def test_disable_requires_password_and_a_current_code(h: Harness) -> None:
    t, secret, _ = with_2fa(h)
    bad_pw = h.post(
        "/api/mfa/disable",
        {"password": "nope nope nope nope", "code": h.code(secret)},
        headers=t.headers,
    )
    assert bad_pw.status_code == 403
    bad_code = h.post(
        "/api/mfa/disable", {"password": PASSWORD, "code": "000000"}, headers=t.headers
    )
    assert bad_code.status_code == 403
    ok = h.post(
        "/api/mfa/disable", {"password": PASSWORD, "code": h.code(secret)}, headers=t.headers
    )
    assert ok.status_code == 204
    assert h.login(EMAIL).json()["status"] == "ok"
    assert h.get_user(EMAIL).totp_secret_enc is None
    with h.db() as db:
        assert db.scalar(select(RecoveryCode)) is None


def test_disable_when_not_enabled_is_a_conflict(h: Harness) -> None:
    t = h.signup(EMAIL)
    r = h.post("/api/mfa/disable", {"password": PASSWORD, "code": "123456"}, headers=t.headers)
    assert r.status_code == 409


def test_regenerating_recovery_codes_invalidates_the_old_ones(h: Harness) -> None:
    t, secret, old = with_2fa(h)
    r = h.post(
        "/api/mfa/recovery-codes", {"password": PASSWORD, "code": h.code(secret)}, headers=t.headers
    )
    new = r.json()["recovery_codes"]
    assert len(new) == 10 and not set(new) & set(old)
    assert finish(h, login_to_mfa(h), old[0]).status_code == 401
    assert finish(h, login_to_mfa(h), new[0]).status_code == 200


def test_deleting_an_account_with_2fa_needs_a_code(h: Harness) -> None:
    t, secret, _ = with_2fa(h)
    no_code = h.client.request("DELETE", "/api/me", json={"password": PASSWORD}, headers=t.headers)
    assert no_code.status_code == 403
    ok = h.client.request(
        "DELETE", "/api/me", json={"password": PASSWORD, "code": h.code(secret)}, headers=t.headers
    )
    assert ok.status_code == 204


def test_secret_rotation_on_a_fresh_setup_restarts_replay_tracking(h: Harness) -> None:
    t = h.signup(EMAIL)
    first = totp.from_b32(h.post("/api/mfa/setup", headers=t.headers).json()["secret"])
    second = totp.from_b32(h.post("/api/mfa/setup", headers=t.headers).json()["secret"])
    assert first != second
    assert h.post("/api/mfa/enable", {"code": h.code(first)}, headers=t.headers).status_code == 400
    assert h.post("/api/mfa/enable", {"code": h.code(second)}, headers=t.headers).status_code == 200
