"""Login throttling: progressive backoff, temporary lockout, sliding window, per-IP limits."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from authkit.security.throttle import ThrottlePolicy
from tests.conftest import PASSWORD, Harness

EMAIL = "amina@example.com"
BAD = "definitely the wrong passphrase"

POLICY = ThrottlePolicy(
    window_seconds=900,
    free_attempts=5,
    lockout_threshold=10,
    backoff_base_seconds=1,
    backoff_max_seconds=60,
    lockout_seconds=900,
)


@pytest.mark.parametrize(
    "failures,delay",
    [(0, 0), (4, 0), (5, 1), (6, 2), (7, 4), (8, 8), (9, 16), (10, 900), (50, 900)],
)
def test_delay_schedule(failures: int, delay: float) -> None:
    assert POLICY.delay_for(failures) == delay


def test_backoff_is_capped() -> None:
    capped = ThrottlePolicy(900, 1, 40, 1, 60, 900)
    assert capped.delay_for(20) == 60


def test_five_free_failures_then_progressive_backoff(h: Harness) -> None:
    h.signup(EMAIL)
    for _ in range(5):
        assert h.login(EMAIL, BAD).status_code == 401
    blocked = h.login(EMAIL, BAD)
    assert blocked.status_code == 429
    assert blocked.headers["retry-after"] == "1"
    assert blocked.json()["error"]["code"] == "too_many_attempts"
    h.clock.advance(1)
    assert h.login(EMAIL, BAD).status_code == 401  # sixth failure
    assert h.login(EMAIL, BAD).headers["retry-after"] == "2"  # delay doubled


def test_correct_password_is_refused_while_blocked(h: Harness) -> None:
    h.signup(EMAIL)
    for _ in range(5):
        h.login(EMAIL, BAD)
    assert h.login(EMAIL, PASSWORD).status_code == 429
    h.clock.advance(1)
    assert h.login(EMAIL, PASSWORD).status_code == 200


def test_ten_failures_lock_the_account_for_fifteen_minutes(h: Harness) -> None:
    h.signup(EMAIL)
    for _ in range(10):  # a patient attacker who always outwaits the backoff
        assert h.login(EMAIL, BAD).status_code == 401
        h.clock.advance(61)
    locked = h.login(EMAIL, PASSWORD)
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 600


def test_lockout_lifts_after_the_lockout_period(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(account_free_attempts=2, account_lockout_threshold=4)
    h.signup(EMAIL)
    for _ in range(4):
        assert h.login(EMAIL, BAD).status_code == 401
        h.clock.advance(5)  # waits out each backoff, so all four failures are recorded
    assert h.login(EMAIL, PASSWORD).status_code == 429
    h.clock.advance(600)
    assert h.login(EMAIL, PASSWORD).status_code == 429  # ten minutes in: still locked
    h.clock.advance(300)  # 15 minutes after the burst
    assert h.login(EMAIL, PASSWORD).status_code == 200


def test_blocked_attempts_do_not_extend_the_lockout(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(account_free_attempts=2, account_lockout_threshold=3)
    h.signup(EMAIL)
    for _ in range(3):
        h.login(EMAIL, BAD)
        h.clock.advance(5)
    for _ in range(50):  # hammering during the lockout...
        assert h.login(EMAIL, BAD).status_code == 429
    h.clock.advance(900)  # ...changes nothing: it still ends 15 minutes after the last real failure
    assert h.login(EMAIL, PASSWORD).status_code == 200


def test_sliding_window_forgets_old_failures(h: Harness) -> None:
    h.signup(EMAIL)
    for _ in range(4):
        h.login(EMAIL, BAD)
    h.clock.advance(901)  # the four failures age out of the 15-minute window
    for _ in range(4):
        assert h.login(EMAIL, BAD).status_code == 401  # would be blocked if they still counted
    assert h.login(EMAIL, PASSWORD).status_code == 200


def test_success_clears_the_account_counter(h: Harness) -> None:
    h.signup(EMAIL)
    for _ in range(4):
        h.login(EMAIL, BAD)
    assert h.login(EMAIL, PASSWORD).status_code == 200
    for _ in range(5):
        assert h.login(EMAIL, BAD).status_code == 401  # a fresh allowance


def test_unknown_accounts_are_throttled_exactly_like_real_ones(h: Harness) -> None:
    h.signup(EMAIL)
    seen = []
    for target in (EMAIL, "ghost@example.com"):
        codes = [h.login(target, BAD).status_code for _ in range(7)]
        seen.append(codes)
    assert seen[0] == seen[1] == [401] * 5 + [429] * 2


def test_throttle_is_per_account_not_global(h: Harness) -> None:
    h.signup(EMAIL)
    h.signup("kamau@example.com")
    for _ in range(6):
        h.login(EMAIL, BAD)
    assert h.login("kamau@example.com", PASSWORD).status_code == 200


def test_per_ip_limit_applies_across_many_accounts(make_harness: Callable[..., Harness]) -> None:
    h = make_harness(ip_free_attempts=4, ip_lockout_threshold=8, trusted_proxy_hops=1)
    h.signup(EMAIL)
    noisy = {"X-Forwarded-For": "203.0.113.50"}
    quiet = {"X-Forwarded-For": "203.0.113.51"}
    for i in range(4):  # 4 different accounts, one failure each: no account limit hit
        assert h.login(f"victim{i}@example.com", BAD, headers=noisy).status_code == 401
    assert h.login("victim9@example.com", BAD, headers=noisy).status_code == 429
    assert h.login(EMAIL, PASSWORD, headers=noisy).status_code == 429  # even valid credentials
    assert h.login(EMAIL, PASSWORD, headers=quiet).status_code == 200  # another IP is unaffected


def test_forged_forwarded_for_does_not_dodge_the_ip_limit_by_default(
    make_harness: Callable[..., Harness],
) -> None:
    h = make_harness(ip_free_attempts=3, ip_lockout_threshold=6)
    for i in range(3):
        h.login(f"v{i}@example.com", BAD, headers={"X-Forwarded-For": f"10.0.0.{i}"})
    r = h.login("v9@example.com", BAD, headers={"X-Forwarded-For": "10.9.9.9"})
    assert r.status_code == 429  # header ignored: the real peer address is what counts


def test_blocked_and_failed_logins_are_audited(h: Harness) -> None:
    h.signup(EMAIL)
    for _ in range(6):
        h.login(EMAIL, BAD)
    from sqlalchemy import select

    from authkit.models import AuditEvent

    with h.db() as db:
        events = [e.event for e in db.scalars(select(AuditEvent))]
    assert events.count("login_failure") == 5 and events.count("login_blocked") == 1
