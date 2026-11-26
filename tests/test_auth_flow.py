"""Registration, login, logout, verification, password change/reset and deletion."""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import select

from authkit.models import AuditEvent, AuthSession, RefreshToken, User
from authkit.security.passwords import Argon2Hasher
from tests.conftest import NEW_PASSWORD, PASSWORD, Harness

EMAIL = "amina@example.com"


def shape(r) -> tuple[int, dict]:  # type: ignore[no-untyped-def]
    """Status plus the JSON body, which is what an enumeration attacker gets to see."""
    return r.status_code, r.json()


# --- the happy path --------------------------------------------------------


def test_full_flow_register_verify_login_me_refresh_logout(h: Harness) -> None:
    assert h.register(EMAIL).status_code == 202
    assert h.client.get("/api/me").status_code == 401
    h.verify_email(EMAIL)

    login = h.login(EMAIL)
    assert login.status_code == 200 and login.json()["status"] == "ok"
    assert login.json()["token_type"] == "Bearer" and login.json()["expires_in"] == 900
    t = h.tokens(login)

    me = h.client.get("/api/me", headers=t.headers).json()
    assert me["email"] == EMAIL and me["role"] == "user" and me["email_verified"] is True
    assert "password" not in str(me)

    rotated = h.refresh(t.refresh)
    assert rotated.status_code == 200
    t2 = h.tokens(rotated)
    assert t2.refresh != t.refresh

    assert h.client.post("/api/auth/logout", headers=t2.headers).status_code == 204
    assert h.client.get("/api/me", headers=t2.headers).status_code == 401
    assert h.refresh(t2.refresh).status_code == 401


def test_password_is_stored_as_an_argon2id_hash(h: Harness) -> None:
    h.signup(EMAIL)
    stored = h.get_user(EMAIL).password_hash
    assert stored.startswith("$argon2id$") and PASSWORD not in stored


def test_email_is_normalised(h: Harness) -> None:
    assert h.register("  Amina@Example.COM ").status_code == 202
    assert h.login("amina@example.com").status_code == 200


# --- registration ----------------------------------------------------------


def test_register_is_uniform_for_new_and_existing_addresses(h: Harness) -> None:
    first = h.register(EMAIL)
    second = h.register(EMAIL)
    assert shape(first) == shape(second)
    assert first.status_code == 202
    subjects = [m.subject for m in h.mailer.messages if m.to == EMAIL]
    assert subjects == ["Confirm your email address", "You already have an Authkit account"]
    with h.db() as db:
        assert len(list(db.scalars(select(User)))) == 1


def test_register_rejects_weak_passwords_with_reasons(h: Harness) -> None:
    r = h.register(EMAIL, "short")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "password_rejected"
    assert r.json()["error"]["reasons"] == ["too_short"]


def test_register_rejects_breached_passwords(h: Harness) -> None:
    r = h.register(EMAIL, "password123456")
    assert r.status_code == 422 and r.json()["error"]["reasons"] == ["breached"]


def test_register_rejects_password_containing_the_email_name(h: Harness) -> None:
    r = h.register("wanjiru@example.com", "my-wanjiru-passphrase")
    assert r.json()["error"]["reasons"] == ["contains_email"]


def test_register_validates_the_email(h: Harness) -> None:
    for bad in ("nope", "a@b", "@example.com", "two@@example.com", "x" * 300 + "@example.com"):
        assert h.register(bad).status_code == 422, bad


def test_validation_errors_do_not_echo_submitted_values(h: Harness) -> None:
    r = h.post("/api/auth/register", {"email": EMAIL, "password": PASSWORD, "admin": True})
    assert r.status_code == 422
    assert PASSWORD not in r.text and r.json()["error"]["code"] == "validation_error"


def test_extra_fields_cannot_escalate_privileges(h: Harness) -> None:
    r = h.post("/api/auth/register", {"email": EMAIL, "password": PASSWORD, "role": "admin"})
    assert r.status_code == 422
    assert h.register(EMAIL).status_code == 202
    assert h.get_user(EMAIL).role == "user"


def test_registration_can_be_closed(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(registration_open=False)
    r = h.register(EMAIL)
    assert r.status_code == 403 and r.json()["error"]["code"] == "registration_closed"


def test_register_is_rate_limited_per_ip(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(register_per_ip_per_hour=3)
    codes = [h.register(f"user{i}@example.com").status_code for i in range(5)]
    assert codes == [202, 202, 202, 429, 429]
    h.clock.advance(3601)
    assert h.register("later@example.com").status_code == 202


# --- login: enumeration resistance and failure paths ------------------------


def test_unknown_user_and_wrong_password_are_indistinguishable(h: Harness) -> None:
    h.signup(EMAIL)
    wrong = h.login(EMAIL, "this is definitely not right")
    unknown = h.login("nobody@example.com", "this is definitely not right")
    assert shape(wrong) == shape(unknown)
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "invalid_credentials"
    assert set(wrong.headers) - {"content-length"} == set(unknown.headers) - {"content-length"}


def test_unknown_and_known_users_cost_the_same_hashing_work(h: Harness, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Both paths run exactly one Argon2 verification (the dummy hash stands in)."""
    h.signup(EMAIL)
    calls: list[str] = []
    real_verify = Argon2Hasher.verify
    monkeypatch.setattr(
        Argon2Hasher,
        "verify",
        lambda self, hsh, pw: calls.append("verify") or real_verify(self, hsh, pw),
    )
    h.login(EMAIL, "wrong password entirely")
    h.login("ghost@example.com", "wrong password entirely")
    h.login("not-an-email", "wrong password entirely")
    # known user: 1 verify. unknown user and malformed email: dummy_verify -> 1 verify each.
    assert calls == ["verify", "verify", "verify"]


def test_inactive_accounts_cannot_log_in_and_look_like_wrong_password(h: Harness) -> None:
    h.signup(EMAIL)
    with h.db() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        assert user is not None
        user.is_active = False
        db.commit()
    r = h.login(EMAIL)
    assert shape(r) == shape(h.login("ghost@example.com"))


def test_login_requires_verified_email_when_configured(
    make_harness: Callable[..., Harness],
) -> None:
    h = make_harness(require_verified_email=True)
    h.register(EMAIL)
    blocked = h.login(EMAIL)
    assert blocked.status_code == 403 and blocked.json()["error"]["code"] == "email_not_verified"
    h.verify_email(EMAIL)
    assert h.login(EMAIL).status_code == 200


def test_transparent_rehash_on_login(h: Harness) -> None:
    h.signup(EMAIL)
    weak = Argon2Hasher(memory_kib=16, time_cost=1, parallelism=1).hash(PASSWORD)
    with h.db() as db:
        user = db.scalar(select(User).where(User.email == EMAIL))
        assert user is not None
        user.password_hash = weak
        db.commit()
    assert h.login(EMAIL).status_code == 200
    upgraded = h.get_user(EMAIL).password_hash
    assert upgraded != weak and "m=64,t=1,p=1" in upgraded
    assert h.ctx.hasher.verify(upgraded, PASSWORD)
    with h.db() as db:
        events = [e.event for e in db.scalars(select(AuditEvent))]
    assert "password_rehashed" in events
    # And a second login does not rehash again.
    h.login(EMAIL)
    assert h.get_user(EMAIL).password_hash == upgraded


# --- tokens and sessions ----------------------------------------------------


def test_access_token_lifetime_is_fifteen_minutes(h: Harness) -> None:
    t = h.signup(EMAIL)
    h.clock.advance(14 * 60 + 59)
    assert h.client.get("/api/me", headers=t.headers).status_code == 200
    h.clock.advance(2)
    assert h.client.get("/api/me", headers=t.headers).status_code == 401


def test_missing_and_malformed_bearer_headers_are_401(h: Harness) -> None:
    for headers in (
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic abc"},
        {"Authorization": "Bearer junk"},
    ):
        r = h.client.get("/api/me", headers=headers)
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_logout_with_only_a_refresh_token(h: Harness) -> None:
    t = h.signup(EMAIL)
    assert h.post("/api/auth/logout", {"refresh_token": t.refresh}).status_code == 204
    assert h.client.get("/api/me", headers=t.headers).status_code == 401


def test_logout_is_quiet_for_unknown_tokens(h: Harness) -> None:
    assert h.post("/api/auth/logout", {"refresh_token": "rt_unknown"}).status_code == 204
    assert h.post("/api/auth/logout").status_code == 204


def test_cookie_mode_keeps_the_refresh_token_out_of_the_body(h: Harness) -> None:
    h.register(EMAIL)
    r = h.login(EMAIL, headers={"X-Auth-Mode": "cookie"})
    assert "refresh_token" not in r.json()
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api/auth" in cookie
    assert (
        h.client.post("/api/auth/refresh", json={}, headers={"X-Auth-Mode": "cookie"}).status_code
        == 200
    )
    # Without the opt-in header the cookie is ignored, which blocks cross-site form posts.
    assert h.client.post("/api/auth/refresh", json={}).status_code == 401


def test_logout_in_cookie_mode_clears_the_cookie_and_revokes(h: Harness) -> None:
    h.register(EMAIL)
    h.login(EMAIL, headers={"X-Auth-Mode": "cookie"})
    r = h.client.post("/api/auth/logout", headers={"X-Auth-Mode": "cookie"})
    assert r.status_code == 204 and "max-age=0" in r.headers["set-cookie"].lower()
    assert (
        h.client.post("/api/auth/refresh", json={}, headers={"X-Auth-Mode": "cookie"}).status_code
        == 401
    )


def test_refresh_tokens_are_stored_only_as_sha256_hashes(h: Harness) -> None:
    t = h.signup(EMAIL)
    with h.db() as db:
        rows = list(db.scalars(select(RefreshToken)))
    assert len(rows) == 1
    assert rows[0].token_hash != t.refresh and len(rows[0].token_hash) == 64
    import hashlib

    assert rows[0].token_hash == hashlib.sha256(t.refresh.encode()).hexdigest()


# --- e-mail verification ----------------------------------------------------


def test_verification_token_is_single_use(h: Harness) -> None:
    h.register(EMAIL)
    token = h.mail_token(EMAIL, "confirm")
    assert h.post("/api/auth/email/verify", {"token": token}).status_code == 204
    again = h.post("/api/auth/email/verify", {"token": token})
    assert again.status_code == 400 and again.json()["error"]["code"] == "invalid_token"


def test_verification_token_expires(h: Harness) -> None:
    h.register(EMAIL)
    token = h.mail_token(EMAIL, "confirm")
    h.clock.advance(24 * 3600 + 1)
    assert h.post("/api/auth/email/verify", {"token": token}).status_code == 400
    assert h.get_user(EMAIL).email_verified_at is None


def test_unknown_verification_token_gives_the_same_error(h: Harness) -> None:
    r = h.post("/api/auth/email/verify", {"token": "et_" + "x" * 40})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_token"


def test_verification_token_cannot_be_used_to_reset_a_password(h: Harness) -> None:
    h.register(EMAIL)
    token = h.mail_token(EMAIL, "confirm")
    r = h.post("/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD})
    assert r.status_code == 400


def test_resend_verification_replaces_the_old_link(h: Harness) -> None:
    h.register(EMAIL)
    old = h.mail_token(EMAIL, "confirm")
    # Sign in without verifying (not required by default) and ask for a new link.
    t = h.tokens(h.login(EMAIL))
    assert h.client.post("/api/auth/email/resend", headers=t.headers).status_code == 202
    new = h.mail_token(EMAIL, "confirm")
    assert new != old
    assert h.post("/api/auth/email/verify", {"token": old}).status_code == 400
    assert h.post("/api/auth/email/verify", {"token": new}).status_code == 204
    n = len(h.mailer.messages)
    h.client.post("/api/auth/email/resend", headers=t.headers)  # already verified: no mail
    assert len(h.mailer.messages) == n


# --- change password --------------------------------------------------------


def test_change_password_signs_out_other_devices_but_not_this_one(h: Harness) -> None:
    here = h.signup(EMAIL)
    there = h.tokens(h.login(EMAIL))
    r = h.post(
        "/api/me/password",
        {"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        headers=here.headers,
    )
    assert r.status_code == 200 and r.json() == {"revoked": 1}
    assert h.client.get("/api/me", headers=here.headers).status_code == 200
    assert h.client.get("/api/me", headers=there.headers).status_code == 401
    assert h.refresh(there.refresh).status_code == 401
    assert h.login(EMAIL, PASSWORD).status_code == 401
    assert h.login(EMAIL, NEW_PASSWORD).status_code == 200
    assert any("password was changed" in m.subject for m in h.mailer.messages)


def test_change_password_needs_the_current_password(h: Harness) -> None:
    t = h.signup(EMAIL)
    r = h.post(
        "/api/me/password",
        {"current_password": "wrong wrong wrong", "new_password": NEW_PASSWORD},
        headers=t.headers,
    )
    assert r.status_code == 403 and r.json()["error"]["code"] == "wrong_password"
    assert h.login(EMAIL, PASSWORD).status_code == 200


def test_change_password_applies_the_policy(h: Harness) -> None:
    t = h.signup(EMAIL)
    r = h.post(
        "/api/me/password",
        {"current_password": PASSWORD, "new_password": "short"},
        headers=t.headers,
    )
    assert r.status_code == 422 and r.json()["error"]["reasons"] == ["too_short"]


def test_change_password_current_password_guessing_is_throttled(
    make_harness: Callable[..., Harness],
) -> None:
    h = make_harness(account_free_attempts=2, account_lockout_threshold=4)
    t = h.signup(EMAIL)
    body = {"current_password": "wrong wrong wrong", "new_password": NEW_PASSWORD}

    def attempt() -> int:
        return h.post("/api/me/password", body, headers=t.headers).status_code

    assert [attempt(), attempt()] == [403, 403]  # free attempts used up
    assert attempt() == 429  # 1 s backoff
    h.clock.advance(1)
    assert attempt() == 403  # third failure: 2 s backoff
    h.clock.advance(2)
    assert attempt() == 403  # fourth failure reaches the lockout threshold
    h.clock.advance(60)
    assert attempt() == 429  # locked out, even though a minute has passed


# --- password reset ---------------------------------------------------------


def test_forgot_password_is_uniform_for_known_and_unknown_addresses(h: Harness) -> None:
    h.signup(EMAIL)
    known = h.post("/api/auth/password/forgot", {"email": EMAIL})
    unknown = h.post("/api/auth/password/forgot", {"email": "ghost@example.com"})
    junk = h.post("/api/auth/password/forgot", {"email": "not-an-email"})
    assert shape(known) == shape(unknown) == shape(junk)
    assert known.status_code == 202
    assert [m.to for m in h.mailer.messages if "Reset" in m.subject] == [EMAIL]


def test_password_reset_flow_revokes_every_session(h: Harness) -> None:
    a = h.signup(EMAIL)
    b = h.tokens(h.login(EMAIL))
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    token = h.mail_token(EMAIL, "reset")
    r = h.post("/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD})
    assert r.status_code == 204
    for t in (a, b):
        assert h.client.get("/api/me", headers=t.headers).status_code == 401
        assert h.refresh(t.refresh).status_code == 401
    assert h.login(EMAIL, PASSWORD).status_code == 401
    assert h.login(EMAIL, NEW_PASSWORD).status_code == 200


def test_reset_token_is_single_use(h: Harness) -> None:
    h.signup(EMAIL)
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    token = h.mail_token(EMAIL, "reset")
    assert (
        h.post(
            "/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD}
        ).status_code
        == 204
    )
    again = h.post(
        "/api/auth/password/reset", {"token": token, "new_password": "another long passphrase 9"}
    )
    assert again.status_code == 400


def test_reset_token_expires_after_an_hour(h: Harness) -> None:
    h.signup(EMAIL)
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    token = h.mail_token(EMAIL, "reset")
    h.clock.advance(3601)
    assert (
        h.post(
            "/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD}
        ).status_code
        == 400
    )


def test_a_new_reset_request_invalidates_the_previous_link(h: Harness) -> None:
    h.signup(EMAIL)
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    first = h.mail_token(EMAIL, "reset")
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    second = h.mail_token(EMAIL, "reset")
    assert first != second
    assert (
        h.post(
            "/api/auth/password/reset", {"token": first, "new_password": NEW_PASSWORD}
        ).status_code
        == 400
    )
    assert (
        h.post(
            "/api/auth/password/reset", {"token": second, "new_password": NEW_PASSWORD}
        ).status_code
        == 204
    )


def test_a_rejected_new_password_does_not_burn_the_reset_token(h: Harness) -> None:
    h.signup(EMAIL)
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    token = h.mail_token(EMAIL, "reset")
    bad = h.post("/api/auth/password/reset", {"token": token, "new_password": "short"})
    assert bad.status_code == 422
    assert (
        h.post(
            "/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD}
        ).status_code
        == 204
    )


def test_reset_requests_are_rate_limited_silently(h: Harness) -> None:
    h.signup(EMAIL)
    responses = [h.post("/api/auth/password/forgot", {"email": EMAIL}) for _ in range(5)]
    assert len({str(shape(r)) for r in responses}) == 1  # same answer every time
    assert len([m for m in h.mailer.messages if "Reset" in m.subject]) == 3


def test_reset_clears_an_account_lockout(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(account_free_attempts=2, account_lockout_threshold=3)
    h.signup(EMAIL)
    for _ in range(3):
        h.login(EMAIL, "wrong wrong wrong")
    assert h.login(EMAIL).status_code == 429
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    token = h.mail_token(EMAIL, "reset")
    h.post("/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD})
    assert h.login(EMAIL, NEW_PASSWORD).status_code == 200


def test_reset_marks_the_email_as_verified(h: Harness) -> None:
    h.register(EMAIL)
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    token = h.mail_token(EMAIL, "reset")
    h.post("/api/auth/password/reset", {"token": token, "new_password": NEW_PASSWORD})
    assert h.get_user(EMAIL).email_verified_at is not None


# --- account deletion -------------------------------------------------------


def test_delete_account_removes_the_user_and_everything_hanging_off_it(h: Harness) -> None:
    t = h.signup(EMAIL)
    h.tokens(h.login(EMAIL))
    r = h.client.request("DELETE", "/api/me", json={"password": PASSWORD}, headers=t.headers)
    assert r.status_code == 204
    assert h.login(EMAIL).status_code == 401
    assert h.client.get("/api/me", headers=t.headers).status_code == 401
    with h.db() as db:
        assert db.scalar(select(User)) is None
        assert db.scalar(select(AuthSession)) is None
        assert db.scalar(select(RefreshToken)) is None
        assert any(e.event == "account_deleted" for e in db.scalars(select(AuditEvent)))


def test_delete_account_needs_the_password(h: Harness) -> None:
    t = h.signup(EMAIL)
    r = h.client.request(
        "DELETE", "/api/me", json={"password": "nope nope nope nope"}, headers=t.headers
    )
    assert r.status_code == 403
    assert h.login(EMAIL).status_code == 200


def test_the_last_admin_cannot_delete_themselves(h: Harness) -> None:
    t = h.signup(EMAIL)
    h.make_admin(EMAIL)
    r = h.client.request("DELETE", "/api/me", json={"password": PASSWORD}, headers=t.headers)
    assert r.status_code == 409 and r.json()["error"]["code"] == "last_admin"
