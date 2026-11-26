"""JWT signing, key rotation by kid, algorithm pinning, expiry on a fake clock."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any

import jwt
import pytest

from authkit.clock import FakeClock
from authkit.config import ConfigError
from authkit.security.keys import (
    Alg,
    KeyRing,
    Secrets,
    TokenError,
    load_secrets,
    new_key_entry,
    prune_jwt_keys,
    rotate_jwt_key,
)
from authkit.security.tokens import JwtIssuer, hash_token, new_opaque_token

ISS, AUD = "authkit", "authkit-api"


def issuer(secrets_: Secrets, clock: FakeClock) -> JwtIssuer:
    return JwtIssuer(secrets_.keyring, clock, ISS, AUD)


@pytest.mark.parametrize("alg", ["EdDSA", "HS256"])
def test_access_token_roundtrip(alg: Alg) -> None:
    clock = FakeClock()
    iss = issuer(Secrets.ephemeral(alg), clock)
    token = iss.access_token("user-1", "sess-1", "user", ["pwd"], 900)
    claims = iss.decode(token, use="access")
    assert claims["sub"] == "user-1" and claims["sid"] == "sess-1" and claims["role"] == "user"
    assert claims["exp"] - claims["iat"] == 900


def test_token_header_carries_the_kid() -> None:
    s = Secrets.ephemeral()
    token = issuer(s, FakeClock()).access_token("u", "s", "user", ["pwd"], 900)
    assert jwt.get_unverified_header(token)["kid"] == s.keyring.active.kid


def test_access_token_expires_after_fifteen_minutes_on_the_fake_clock() -> None:
    clock = FakeClock()
    iss = issuer(Secrets.ephemeral(), clock)
    token = iss.access_token("u", "s", "user", ["pwd"], 900)
    clock.advance(899)
    iss.decode(token, use="access")
    clock.advance(1)
    with pytest.raises(TokenError) as err:
        iss.decode(token, use="access")
    assert err.value.reason == "expired"


def test_token_from_the_future_is_rejected() -> None:
    clock = FakeClock()
    s = Secrets.ephemeral()
    token = issuer(s, clock).access_token("u", "s", "user", ["pwd"], 900)
    earlier = FakeClock(clock.now())
    earlier.advance(-3600)
    with pytest.raises(TokenError, match="issued_in_future"):
        issuer(s, earlier).decode(token, use="access")


def test_tampered_payload_is_rejected() -> None:
    clock = FakeClock()
    iss = issuer(Secrets.ephemeral(), clock)
    head, payload, sig = iss.access_token("u", "s", "user", ["pwd"], 900).split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["role"] = "admin"
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(TokenError):
        iss.decode(f"{head}.{forged}.{sig}", use="access")


def test_wrong_audience_and_issuer_are_rejected() -> None:
    clock = FakeClock()
    s = Secrets.ephemeral()
    token = JwtIssuer(s.keyring, clock, ISS, "someone-else").access_token("u", "s", "user", [], 900)
    with pytest.raises(TokenError):
        issuer(s, clock).decode(token, use="access")
    token = JwtIssuer(s.keyring, clock, "evil", AUD).access_token("u", "s", "user", [], 900)
    with pytest.raises(TokenError):
        issuer(s, clock).decode(token, use="access")


def test_an_mfa_token_cannot_be_used_as_an_access_token_and_vice_versa() -> None:
    clock = FakeClock()
    iss = issuer(Secrets.ephemeral(), clock)
    with pytest.raises(TokenError, match="wrong_use"):
        iss.decode(iss.mfa_token("u", 300), use="access")
    with pytest.raises(TokenError, match="wrong_use"):
        iss.decode(iss.access_token("u", "s", "user", [], 900), use="mfa")


def test_unknown_kid_is_rejected() -> None:
    clock = FakeClock()
    a, b = Secrets.ephemeral(), Secrets.ephemeral()
    token = issuer(a, clock).access_token("u", "s", "user", [], 900)
    with pytest.raises(TokenError, match="unknown_kid"):
        issuer(b, clock).decode(token, use="access")


def test_garbage_is_rejected() -> None:
    iss = issuer(Secrets.ephemeral(), FakeClock())
    for junk in ("", "a.b.c", "not a jwt"):
        with pytest.raises(TokenError):
            iss.decode(junk, use="access")


def test_alg_none_is_rejected() -> None:
    clock = FakeClock()
    s = Secrets.ephemeral()
    iss = issuer(s, clock)
    now = int(clock.now().timestamp())
    claims = {
        "iss": ISS,
        "aud": AUD,
        "sub": "u",
        "jti": "j",
        "iat": now,
        "exp": now + 900,
        "use": "access",
    }
    forged = jwt.encode(claims, key="", algorithm="none", headers={"kid": s.keyring.active.kid})
    with pytest.raises(TokenError):
        iss.decode(forged, use="access")


def test_algorithm_confusion_with_the_public_key_as_hmac_secret_is_rejected() -> None:
    clock = FakeClock()
    s = Secrets.ephemeral("EdDSA")
    iss = issuer(s, clock)
    kid = s.keyring.active.kid
    jwk = s.keyring.jwks()["keys"][0]
    public_raw = base64.urlsafe_b64decode(jwk["x"] + "==")
    now = int(clock.now().timestamp())
    claims = {
        "iss": ISS,
        "aud": AUD,
        "sub": "u",
        "jti": "j",
        "iat": now,
        "exp": now + 900,
        "use": "access",
    }
    forged = jwt.encode(claims, public_raw * 2, algorithm="HS256", headers={"kid": kid})
    with pytest.raises(TokenError, match="alg_mismatch"):
        iss.decode(forged, use="access")


def _write_ring(path: Path) -> Path:
    doc = Secrets.generate_document("EdDSA")
    path.write_text(json.dumps(doc))
    path.chmod(0o600)
    return path


def test_rotation_keeps_old_tokens_valid_until_the_old_key_is_pruned(tmp_path: Path) -> None:
    clock = FakeClock()
    path = _write_ring(tmp_path / "keys.json")
    before = load_secrets(path, create_if_missing=False)
    old_token = issuer(before, clock).access_token("u", "s", "user", [], 900)

    new_kid = rotate_jwt_key(path)
    after = load_secrets(path, create_if_missing=False)
    assert after.keyring.active.kid == new_kid != before.keyring.active.kid
    assert len(after.keyring.kids) == 2
    iss = issuer(after, clock)
    iss.decode(old_token, use="access")  # still verifies
    new_token = iss.access_token("u", "s", "user", [], 900)
    assert jwt.get_unverified_header(new_token)["kid"] == new_kid  # signs with the new key

    removed = prune_jwt_keys(path, keep=1)
    assert removed == [before.keyring.active.kid]
    pruned = load_secrets(path, create_if_missing=False)
    with pytest.raises(TokenError, match="unknown_kid"):
        issuer(pruned, clock).decode(old_token, use="access")


def test_prune_never_removes_the_active_key(tmp_path: Path) -> None:
    path = _write_ring(tmp_path / "keys.json")
    rotate_jwt_key(path)
    doc = json.loads(path.read_text())
    doc["jwt"]["active"] = doc["jwt"]["keys"][0]["kid"]
    path.write_text(json.dumps(doc))
    with pytest.raises(ConfigError):
        prune_jwt_keys(path, keep=1)


def test_mixed_algorithms_can_coexist_in_one_ring() -> None:
    clock = FakeClock()
    hs, ed = new_key_entry("HS256"), new_key_entry("EdDSA")
    doc: dict[str, Any] = {
        "version": 1,
        "jwt": {"active": ed["kid"], "keys": [hs, ed]},
        "data_keys": Secrets.generate_document()["data_keys"],
        "pepper": Secrets.generate_document()["pepper"],
    }
    s = Secrets.from_document(doc)
    hs_only = Secrets.from_document({**doc, "jwt": {"active": hs["kid"], "keys": [hs, ed]}})
    legacy = issuer(hs_only, clock).access_token("u", "s", "user", [], 900)
    issuer(s, clock).decode(legacy, use="access")  # HS256 token verifies in a mixed ring
    assert [k["alg"] for k in s.keyring.jwks()["keys"]] == ["EdDSA"]  # HMAC keys never published


def test_verify_only_key_cannot_be_active() -> None:
    entry = new_key_entry("EdDSA")
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(entry["private_pem"].encode(), None)
    public_pem = (
        priv.public_key()
        .public_bytes(  # type: ignore[union-attr]
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode()
    )
    doc = Secrets.generate_document()
    doc["jwt"] = {
        "active": entry["kid"],
        "keys": [{"kid": entry["kid"], "alg": "EdDSA", "public_pem": public_pem}],
    }
    with pytest.raises(ConfigError):
        Secrets.from_document(doc)


def test_short_hmac_secret_is_refused() -> None:
    doc = Secrets.generate_document("HS256")
    doc["jwt"]["keys"][0]["secret"] = "c2hvcnQ"
    with pytest.raises(ConfigError):
        Secrets.from_document(doc)


def test_key_file_is_created_with_mode_600(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "keys.json"
    load_secrets(path, create_if_missing=True)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_production_requires_an_existing_private_key_file(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    with pytest.raises(ConfigError, match="init-keys"):
        load_secrets(path, create_if_missing=False)
    _write_ring(path)
    path.chmod(0o644)
    if os.name == "posix":
        with pytest.raises(ConfigError, match="chmod 600"):
            load_secrets(path, create_if_missing=False)


def test_jwks_exposes_public_material_only() -> None:
    jwks = Secrets.ephemeral("EdDSA").keyring.jwks()
    assert len(jwks["keys"]) == 1
    assert set(jwks["keys"][0]) == {"kty", "crv", "x", "kid", "alg", "use"}


def test_keyring_requires_the_active_key_to_hold_a_signing_key() -> None:
    with pytest.raises(ConfigError):
        KeyRing("missing", [])


def test_data_encryption_roundtrip_and_ciphertext_hides_plaintext() -> None:
    s = Secrets.ephemeral()
    ct = s.encrypt(b"JBSWY3DPEHPK3PXP")
    assert b"JBSWY3DPEHPK3PXP" not in ct.encode()
    assert s.decrypt(ct) == b"JBSWY3DPEHPK3PXP"
    with pytest.raises(ConfigError):
        Secrets.ephemeral().decrypt(ct)


def test_keyed_hash_depends_on_the_pepper() -> None:
    a, b = Secrets.ephemeral(), Secrets.ephemeral()
    assert a.keyed_hash("ABCD") == a.keyed_hash("ABCD")
    assert a.keyed_hash("ABCD") != b.keyed_hash("ABCD")


def test_opaque_tokens_are_unique_prefixed_and_hash_deterministically() -> None:
    tokens = {new_opaque_token("rt") for _ in range(200)}
    assert len(tokens) == 200
    t = next(iter(tokens))
    assert t.startswith("rt_") and len(t) >= 46
    assert hash_token(t) == hash_token(t) and len(hash_token(t)) == 64 and hash_token(t) != t
