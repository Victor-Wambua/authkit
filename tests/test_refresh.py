"""Refresh-token rotation, reuse detection, session management and concurrency."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from authkit.models import AuditEvent, AuthSession, RefreshToken
from tests.conftest import Harness

EMAIL = "amina@example.com"


def session_rows(h: Harness) -> list[AuthSession]:
    with h.db() as db:
        return list(db.scalars(select(AuthSession).order_by(AuthSession.created_at)))


def test_each_refresh_token_works_once_and_returns_a_new_pair(h: Harness) -> None:
    t0 = h.signup(EMAIL)
    t1 = h.tokens(h.refresh(t0.refresh))
    t2 = h.tokens(h.refresh(t1.refresh))
    assert len({t0.refresh, t1.refresh, t2.refresh}) == 3
    assert len(session_rows(h)) == 1  # same session (family) throughout
    with h.db() as db:
        used = [
            r.used_at is not None
            for r in db.scalars(select(RefreshToken).order_by(RefreshToken.created_at))
        ]
    assert used == [True, True, False]


def test_reusing_a_rotated_token_revokes_the_whole_family(h: Harness) -> None:
    t0 = h.signup(EMAIL)
    t1 = h.tokens(h.refresh(t0.refresh))  # the legitimate client rotates
    attacker = h.refresh(t0.refresh)  # someone replays the stolen, now-stale token
    assert attacker.status_code == 401
    assert attacker.json()["error"]["code"] == "invalid_token"
    # The newest token held by the real client is dead too, and so is its access token.
    assert h.refresh(t1.refresh).status_code == 401
    assert h.client.get("/api/me", headers=t1.headers).status_code == 401
    (session,) = session_rows(h)
    assert session.revoked_at is not None and session.revoked_reason == "token_reuse"


def test_reuse_is_written_to_the_audit_log_with_ip_and_agent(h: Harness) -> None:
    t0 = h.signup(EMAIL)
    h.refresh(t0.refresh)
    h.client.post(
        "/api/auth/refresh",
        json={"refresh_token": t0.refresh},
        headers={"User-Agent": "stolen-client/1.0"},
    )
    with h.db() as db:
        (event,) = [e for e in db.scalars(select(AuditEvent)) if e.event == "token_reuse_detected"]
    assert event.user_agent == "stolen-client/1.0" and event.ip == "testclient"
    assert event.session_id is not None and event.user_id is not None


def test_reuse_in_one_session_leaves_the_users_other_sessions_alone(h: Harness) -> None:
    laptop = h.signup(EMAIL)
    phone = h.tokens(h.login(EMAIL))
    h.refresh(laptop.refresh)
    assert h.refresh(laptop.refresh).status_code == 401  # reuse on the laptop family
    assert h.client.get("/api/me", headers=phone.headers).status_code == 200
    assert h.refresh(phone.refresh).status_code == 200


def test_after_a_family_is_revoked_every_later_attempt_is_a_plain_401(h: Harness) -> None:
    t0 = h.signup(EMAIL)
    h.refresh(t0.refresh)
    h.refresh(t0.refresh)
    for _ in range(3):
        assert h.refresh(t0.refresh).status_code == 401
    with h.db() as db:
        n = len([e for e in db.scalars(select(AuditEvent)) if e.event == "token_reuse_detected"])
    assert n == 1  # one incident, not one per retry


def test_expired_refresh_token_is_rejected_without_revoking_the_family(h: Harness) -> None:
    t0 = h.signup(EMAIL)
    h.clock.advance(14 * 86400 + 1)
    assert h.refresh(t0.refresh).status_code == 401
    (session,) = session_rows(h)
    assert session.revoked_at is None  # expiry is not an attack signal


def test_each_rotation_restarts_the_idle_clock_until_the_session_cap(h: Harness) -> None:
    t = h.signup(EMAIL)
    for _ in range(2):
        h.clock.advance(13 * 86400)  # just inside the 14-day refresh lifetime, every time
        r = h.refresh(t.refresh)
        assert r.status_code == 200
        t = h.tokens(r)
    # 26 days in. The next token was issued on day 26 and would last 14 more days,
    # but the session itself is capped at 30 days, so it stops working on day 30.
    h.clock.advance(3 * 86400)
    assert h.refresh(t.refresh).status_code == 200  # day 29: still inside the cap
    h.clock.advance(2 * 86400)  # day 31
    assert h.refresh(t.refresh).status_code == 401


def test_unknown_and_malformed_refresh_tokens(h: Harness) -> None:
    for body in ({"refresh_token": "rt_does-not-exist"}, {"refresh_token": ""}, {}):
        r = h.post("/api/auth/refresh", body)
        assert r.status_code == 401


def test_a_deactivated_user_cannot_refresh(h: Harness) -> None:
    from authkit.models import User

    t = h.signup(EMAIL)
    with h.db() as db:
        user = db.scalar(select(User))
        assert user is not None
        user.is_active = False
        db.commit()
    assert h.refresh(t.refresh).status_code == 401
    assert h.client.get("/api/me", headers=t.headers).status_code == 401


def test_concurrent_rotation_of_one_token_has_exactly_one_winner(h: Harness) -> None:
    t0 = h.signup(EMAIL)
    n = 8
    barrier = threading.Barrier(n)

    def attempt(_: int) -> int:
        client = h.new_client()
        barrier.wait()
        return h.refresh(t0.refresh, client).status_code

    with ThreadPoolExecutor(max_workers=n) as pool:
        codes = list(pool.map(attempt, range(n)))
    assert codes.count(200) == 1, codes
    assert codes.count(401) == n - 1
    # The losers were indistinguishable from a replay, so the family is now revoked.
    (session,) = session_rows(h)
    assert session.revoked_reason == "token_reuse"
    with h.db() as db:
        assert (
            len([e for e in db.scalars(select(AuditEvent)) if e.event == "token_reuse_detected"])
            >= 1
        )
        used = [r for r in db.scalars(select(RefreshToken)) if r.used_at is not None]
    assert len(used) == 1  # only one rotation ever happened


def test_concurrent_rotation_of_different_sessions_does_not_interfere(h: Harness) -> None:
    h.register(EMAIL)
    h.verify_email(EMAIL)
    sessions = [h.tokens(h.login(EMAIL)) for _ in range(6)]
    barrier = threading.Barrier(len(sessions))

    def rotate(t):  # type: ignore[no-untyped-def]
        client = h.new_client()
        barrier.wait()
        return h.refresh(t.refresh, client).status_code

    with ThreadPoolExecutor(max_workers=len(sessions)) as pool:
        codes = list(pool.map(rotate, sessions))
    assert codes == [200] * len(sessions)


# --- the session list -----------------------------------------------------


def test_session_list_marks_the_current_device(h: Harness) -> None:
    here = h.signup(EMAIL)
    h.client.post(
        "/api/auth/login",
        json={"email": EMAIL, "password": "correct horse battery staple"},
        headers={"User-Agent": "Firefox on Android"},
    )
    body = h.client.get("/api/me/sessions", headers=here.headers).json()["sessions"]
    assert len(body) == 2
    assert [s["current"] for s in body].count(True) == 1
    assert {s["user_agent"] for s in body} >= {"Firefox on Android"}
    assert all("refresh" not in json.dumps(s) for s in body)


def test_revoke_a_single_session(h: Harness) -> None:
    here = h.signup(EMAIL)
    other = h.tokens(h.login(EMAIL))
    sessions = h.client.get("/api/me/sessions", headers=here.headers).json()["sessions"]
    target = next(s for s in sessions if not s["current"])
    assert (
        h.client.delete(f"/api/me/sessions/{target['id']}", headers=here.headers).status_code == 204
    )
    assert h.client.get("/api/me", headers=other.headers).status_code == 401  # immediate
    assert h.refresh(other.refresh).status_code == 401
    assert len(h.client.get("/api/me/sessions", headers=here.headers).json()["sessions"]) == 1


def test_sign_out_other_devices(h: Harness) -> None:
    here = h.signup(EMAIL)
    others = [h.tokens(h.login(EMAIL)) for _ in range(3)]
    r = h.client.post("/api/me/sessions/revoke-others", headers=here.headers)
    assert r.json() == {"revoked": 3}
    assert h.client.get("/api/me", headers=here.headers).status_code == 200
    assert all(h.client.get("/api/me", headers=o.headers).status_code == 401 for o in others)


def test_you_cannot_revoke_someone_elses_session(h: Harness) -> None:
    mine = h.signup(EMAIL)
    theirs = h.signup("kamau@example.com")
    their_session = h.client.get("/api/me/sessions", headers=theirs.headers).json()["sessions"][0][
        "id"
    ]
    r = h.client.delete(f"/api/me/sessions/{their_session}", headers=mine.headers)
    assert r.status_code == 404
    assert h.client.get("/api/me", headers=theirs.headers).status_code == 200
    assert (
        h.client.delete("/api/me/sessions/does-not-exist", headers=mine.headers).status_code == 404
    )


def test_expired_sessions_drop_out_of_the_list(h: Harness) -> None:
    here = h.signup(EMAIL)
    h.login(EMAIL)
    h.clock.advance(14 * 60)
    here = h.tokens(h.login(EMAIL))
    h.clock.advance(20 * 86400)  # access tokens expired long ago, sessions are still live
    fresh = h.tokens(h.login(EMAIL))
    listed = h.client.get("/api/me/sessions", headers=fresh.headers).json()["sessions"]
    assert len(listed) == 4
    h.clock.advance(11 * 86400)  # now the older ones pass the 30-day cap
    fresh = h.tokens(h.login(EMAIL))
    listed = h.client.get("/api/me/sessions", headers=fresh.headers).json()["sessions"]
    assert len(listed) == 2 and here.access
