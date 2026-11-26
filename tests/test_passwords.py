from __future__ import annotations

import re
import unicodedata

import pytest

from authkit.config import Settings
from authkit.security.passwords import Argon2Hasher, PasswordPolicy


@pytest.fixture(scope="module")
def hasher() -> Argon2Hasher:
    return Argon2Hasher(memory_kib=64, time_cost=1, parallelism=1)


def test_hash_is_argon2id_with_configured_parameters(hasher: Argon2Hasher) -> None:
    h = hasher.hash("correct horse battery staple")
    assert re.match(r"^\$argon2id\$v=19\$m=64,t=1,p=1\$", h)


def test_hashes_are_salted(hasher: Argon2Hasher) -> None:
    assert hasher.hash("same password here") != hasher.hash("same password here")


def test_verify_accepts_right_and_rejects_wrong_password(hasher: Argon2Hasher) -> None:
    h = hasher.hash("correct horse battery staple")
    assert hasher.verify(h, "correct horse battery staple")
    assert not hasher.verify(h, "correct horse battery stapl")


@pytest.mark.parametrize("junk", ["", "not-a-hash", "$argon2id$garbage", "$2b$12$abcdefghijklmnop"])
def test_verify_returns_false_for_garbage_hashes(hasher: Argon2Hasher, junk: str) -> None:
    assert hasher.verify(junk, "anything") is False


def test_needs_rehash_detects_old_parameters() -> None:
    weak = Argon2Hasher(memory_kib=32, time_cost=1, parallelism=1)
    strong = Argon2Hasher(memory_kib=64, time_cost=2, parallelism=1)
    old = weak.hash("a long enough passphrase")
    assert strong.needs_rehash(old)
    assert not strong.needs_rehash(strong.hash("a long enough passphrase"))


def test_unicode_normalisation_makes_equivalent_forms_match(hasher: Argon2Hasher) -> None:
    composed = "café au lait 2026!"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed
    assert hasher.verify(hasher.hash(composed), decomposed)


def test_dummy_verify_runs_without_error(hasher: Argon2Hasher) -> None:
    hasher.dummy_verify("whatever")


def test_default_argon2_parameters_meet_owasp_minimums() -> None:
    s = Settings(_env_file=None)
    # OWASP floor: m=19 MiB, t=2, p=1. We are well above it.
    assert s.argon2_memory_kib >= 19 * 1024
    assert s.argon2_time_cost >= 2


POLICY = PasswordPolicy(min_length=12, max_length=128)


def test_policy_is_length_first_not_composition_based() -> None:
    assert POLICY.problems("all lowercase words only") == []


def test_policy_rejects_short_passwords() -> None:
    assert POLICY.problems("Tr0ub4d&3!") == ["too_short"]


def test_policy_rejects_overlong_passwords() -> None:
    assert POLICY.problems("x" * 129) == ["too_long"]


def test_policy_counts_code_points_not_bytes() -> None:
    # 12 accented characters are 24 bytes in UTF-8 but 12 code points: long enough.
    assert (
        POLICY.problems("\u00e9\u00e8\u00ea\u00eb\u00e0\u00e2\u00e4\u00e7\u00f9\u00fb\u00ee\u00ef")
        == []
    )
    assert POLICY.problems("\u00e9\u00e8\u00ea") == ["too_short"]


def test_policy_allows_spaces_and_emoji() -> None:
    assert POLICY.problems("my dog \U0001f415 eats toast daily") == []


@pytest.mark.parametrize(
    "pw",
    [
        "aaaaaaaaaaaa",
        "123456789012",
        "987654321098",
        "abcdefghijkl",
        "abababababab",
        "abcdabcdabcd",
    ],
)
def test_policy_rejects_repetitive_and_sequential(pw: str) -> None:
    assert "repetitive_or_sequential" in POLICY.problems(pw)


def test_policy_rejects_passwords_containing_the_email_local_part() -> None:
    assert "contains_email" in POLICY.problems("xx-wanjiru-2026-x", "wanjiru@example.com")
    assert "contains_email" in POLICY.problems("wanjiru@example.com", "wanjiru@example.com")


def test_policy_ignores_very_short_email_local_parts() -> None:
    assert POLICY.problems("a delightfully unrelated phrase", "al@example.com") == []
