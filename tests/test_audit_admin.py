"""Audit trail contents, access control on the admin endpoints, secret hygiene."""

from __future__ import annotations

import logging

from sqlalchemy import select

from authkit.models import AuditEvent
from tests.conftest import PASSWORD, Harness

EMAIL = "amina@example.com"
ADMIN = "admin@example.com"


def events(h: Harness) -> list[AuditEvent]:
    with h.db() as db:
        return list(db.scalars(select(AuditEvent).order_by(AuditEvent.id)))


def test_the_main_security_events_are_recorded_with_ip_and_user_agent(h: Harness) -> None:
    h.register(EMAIL)
    h.verify_email(EMAIL)
    h.login(EMAIL, "wrong wrong wrong", headers={"User-Agent": "TestAgent/1"})
    t = h.tokens(h.login(EMAIL, headers={"User-Agent": "TestAgent/1"}))
    h.post(
        "/api/me/password",
        {"current_password": PASSWORD, "new_password": "brand new long passphrase 7"},
        headers=t.headers,
    )
    h.enable_totp(t)
    names = [e.event for e in events(h)]
    expected = {
        "register", "email_verified", "login_failure",
        "login_success", "password_changed", "totp_enabled",
    }  # fmt: skip
    assert expected <= set(names)
    failure = next(e for e in events(h) if e.event == "login_failure")
    assert failure.ip == "testclient" and failure.user_agent == "TestAgent/1"
    assert failure.user_id is not None


def test_failed_logins_for_unknown_accounts_are_audited_without_a_user_id(h: Harness) -> None:
    h.login("ghost@example.com", "wrong wrong wrong")
    (e,) = events(h)
    assert e.event == "login_failure" and e.user_id is None


def test_logout_and_session_revocation_are_audited(h: Harness) -> None:
    a = h.signup(EMAIL)
    b = h.tokens(h.login(EMAIL))
    h.client.post("/api/me/sessions/revoke-others", headers=a.headers)
    h.client.post("/api/auth/logout", headers=a.headers)
    names = [e.event for e in events(h)]
    assert "other_sessions_revoked" in names and "logout" in names and b.access


def test_audit_rows_never_contain_secrets(h: Harness) -> None:
    t = h.signup(EMAIL)
    _, codes = h.enable_totp(t)
    h.post("/api/auth/password/forgot", {"email": EMAIL})
    reset = h.mail_token(EMAIL, "reset")
    h.login(EMAIL, "wrong passphrase here")
    blob = " ".join(f"{e.event} {e.detail} {e.user_agent} {e.ip}" for e in events(h))
    for secret_value in (PASSWORD, "wrong passphrase here", t.access, t.refresh, reset, *codes):
        assert secret_value not in blob


def test_audit_survives_account_deletion(h: Harness) -> None:
    t = h.signup(EMAIL)
    h.client.request("DELETE", "/api/me", json={"password": PASSWORD}, headers=t.headers)
    names = [e.event for e in events(h)]
    assert "login_success" in names and "account_deleted" in names


# --- admin endpoints -------------------------------------------------------


def test_audit_endpoint_requires_authentication_and_the_admin_role(h: Harness) -> None:
    user = h.signup(EMAIL)
    assert h.client.get("/api/admin/audit").status_code == 401
    forbidden = h.client.get("/api/admin/audit", headers=user.headers)
    assert forbidden.status_code == 403 and forbidden.json()["error"]["code"] == "forbidden"
    assert h.client.get("/api/admin/users", headers=user.headers).status_code == 403


def test_the_role_is_read_from_the_database_not_trusted_from_the_token(h: Harness) -> None:
    """The role comes from the database on every request, not from the token."""
    user = h.signup(EMAIL)
    import jwt

    claims = jwt.decode(user.access, options={"verify_signature": False})
    assert claims["role"] == "user"
    assert h.client.get("/api/admin/audit", headers=user.headers).status_code == 403
    h.make_admin(EMAIL)  # promoted in the DB: the same token (still saying "user") now works
    assert h.client.get("/api/admin/audit", headers=user.headers).status_code == 200


def test_admin_can_read_and_filter_the_audit_log(h: Harness) -> None:
    h.signup(EMAIL)
    h.login(EMAIL, "wrong wrong wrong")
    admin = h.signup(ADMIN)
    h.make_admin(ADMIN)
    everything = h.client.get("/api/admin/audit", headers=admin.headers).json()
    assert len(everything["items"]) >= 6
    ids = [i["id"] for i in everything["items"]]
    assert ids == sorted(ids, reverse=True)  # newest first
    failures = h.client.get("/api/admin/audit?event=login_failure", headers=admin.headers).json()[
        "items"
    ]
    assert [i["event"] for i in failures] == ["login_failure"]
    uid = failures[0]["user_id"]
    mine = h.client.get(f"/api/admin/audit?user_id={uid}", headers=admin.headers).json()["items"]
    assert mine and all(i["user_id"] == uid for i in mine)


def test_audit_paging(h: Harness) -> None:
    admin = h.signup(ADMIN)
    h.make_admin(ADMIN)
    for _ in range(4):
        h.login(ADMIN, "wrong wrong wrong")
        h.clock.advance(61)
    page1 = h.client.get("/api/admin/audit?limit=3", headers=admin.headers).json()
    assert len(page1["items"]) == 3 and page1["next_before"] is not None
    page2 = h.client.get(
        f"/api/admin/audit?limit=3&before={page1['next_before']}", headers=admin.headers
    ).json()
    assert page2["items"] and page2["items"][0]["id"] < page1["items"][-1]["id"]
    assert h.client.get("/api/admin/audit?limit=0", headers=admin.headers).status_code == 422
    assert h.client.get("/api/admin/audit?limit=201", headers=admin.headers).status_code == 422


def test_admin_user_list_exposes_no_credentials(h: Harness) -> None:
    h.signup(EMAIL)
    admin = h.signup(ADMIN)
    h.make_admin(ADMIN)
    r = h.client.get("/api/admin/users", headers=admin.headers)
    assert {u["email"] for u in r.json()["users"]} == {EMAIL, ADMIN}
    assert "password" not in r.text and "totp_secret" not in r.text


def test_users_see_only_their_own_activity(h: Harness) -> None:
    mine = h.signup(EMAIL)
    h.signup("kamau@example.com")
    items = h.client.get("/api/me/activity", headers=mine.headers).json()["items"]
    me = h.client.get("/api/me", headers=mine.headers).json()["id"]
    assert items and all(i["user_id"] == me for i in items)


# --- secrets in logs --------------------------------------------------------


def test_logs_do_not_contain_passwords_or_tokens(h: Harness, caplog) -> None:  # type: ignore[no-untyped-def]
    logger = logging.getLogger("authkit")
    logger.propagate = True  # let caplog see records
    try:
        with caplog.at_level(logging.DEBUG, logger="authkit"):
            t = h.signup(EMAIL)
            h.login(EMAIL, "wrong passphrase here")
            h.refresh(t.refresh)
    finally:
        logger.propagate = False
    text = "\n".join(r.getMessage() + str(r.__dict__) for r in caplog.records)
    assert text  # something was logged
    assert PASSWORD not in text and "wrong passphrase here" not in text
