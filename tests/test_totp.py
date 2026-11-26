"""TOTP/HOTP against the published test vectors (RFC 4226 appendix D, RFC 6238 appendix B)."""

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlparse

import pytest

from authkit.security import totp

SHA1_KEY = b"12345678901234567890"
SHA256_KEY = b"12345678901234567890123456789012"
SHA512_KEY = b"1234567890123456789012345678901234567890123456789012345678901234"

HOTP_VECTORS = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
]  # fmt: skip

RFC6238 = [  # (unix time, sha1, sha256, sha512), all 8 digits
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("counter,expected", list(enumerate(HOTP_VECTORS)))
def test_hotp_rfc4226_vectors(counter: int, expected: str) -> None:
    assert totp.hotp(SHA1_KEY, counter) == expected


@pytest.mark.parametrize("t,sha1,_s256,_s512", RFC6238)
def test_totp_rfc6238_sha1(t: int, sha1: str, _s256: str, _s512: str) -> None:
    assert totp.totp_at(SHA1_KEY, t, digits=8, algo="sha1") == sha1


@pytest.mark.parametrize("t,_s1,sha256,_s512", RFC6238)
def test_totp_rfc6238_sha256(t: int, _s1: str, sha256: str, _s512: str) -> None:
    assert totp.totp_at(SHA256_KEY, t, digits=8, algo="sha256") == sha256


@pytest.mark.parametrize("t,_s1,_s256,sha512", RFC6238)
def test_totp_rfc6238_sha512(t: int, _s1: str, _s256: str, sha512: str) -> None:
    assert totp.totp_at(SHA512_KEY, t, digits=8, algo="sha512") == sha512


def test_verify_accepts_current_and_adjacent_steps() -> None:
    now = 1_700_000_000
    for offset in (-1, 0, 1):
        code = totp.totp_at(SHA1_KEY, now + offset * 30)
        assert totp.verify(SHA1_KEY, code, now) == totp.current_step(now) + offset


@pytest.mark.parametrize("offset", [-2, 2, 5])
def test_verify_rejects_outside_window(offset: int) -> None:
    now = 1_700_000_000
    assert totp.verify(SHA1_KEY, totp.totp_at(SHA1_KEY, now + offset * 30), now) is None


def test_verify_replay_protection_rejects_same_and_earlier_step() -> None:
    now = 1_700_000_000
    code = totp.totp_at(SHA1_KEY, now)
    step = totp.verify(SHA1_KEY, code, now)
    assert step is not None
    assert totp.verify(SHA1_KEY, code, now, last_used_step=step) is None
    older = totp.totp_at(SHA1_KEY, now - 30)
    assert totp.verify(SHA1_KEY, older, now, last_used_step=step) is None
    newer = totp.totp_at(SHA1_KEY, now + 30)
    assert totp.verify(SHA1_KEY, newer, now, last_used_step=step) == step + 1


FULLWIDTH = "\uff11\uff12\uff13\uff14\uff15\uff16"  # digits, but not ASCII digits


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 456", FULLWIDTH])
def test_verify_rejects_malformed_codes(bad: str) -> None:
    assert totp.verify(SHA1_KEY, bad, 59) is None


def test_secret_roundtrip_base32() -> None:
    secret = totp.generate_secret()
    assert len(secret) == 20
    assert totp.from_b32(totp.b32(secret)) == secret
    assert "=" not in totp.b32(secret)


def test_provisioning_uri_has_the_fields_authenticator_apps_need() -> None:
    uri = totp.provisioning_uri(SHA1_KEY, "amina@example.com", "Authkit")
    parsed = urlparse(uri)
    assert parsed.scheme == "otpauth" and parsed.netloc == "totp"
    assert unquote(parsed.path) == "/Authkit:amina@example.com"
    q = parse_qs(parsed.query)
    assert q["secret"] == [totp.b32(SHA1_KEY)]
    assert q["issuer"] == ["Authkit"]
    assert q["digits"] == ["6"] and q["period"] == ["30"] and q["algorithm"] == ["SHA1"]
