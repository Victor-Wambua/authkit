"""Key material: JWT signing keys (with ``kid`` rotation), the data key and the pepper.

Stored in one JSON file with mode 0600. In production the file must already exist
(``authkit init-keys``); in dev and test it is created on first start.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import jwt
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from authkit.clock import Clock
from authkit.config import ConfigError

Alg = Literal["EdDSA", "HS256"]


class TokenError(Exception):
    """A JWT failed verification. ``reason`` is for logs only, never for responses."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class JwtKey:
    kid: str
    alg: Alg
    verify_key: Any  # Ed25519PublicKey or bytes (HMAC secret)
    sign_key: Any | None  # Ed25519PrivateKey or bytes, None for verify-only retired keys

    def public_jwk(self) -> dict[str, str] | None:
        if self.alg != "EdDSA":
            return None  # HMAC secrets are never published
        raw = self.verify_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": _b64u(raw),
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        }


def _key_from_entry(entry: dict[str, Any]) -> JwtKey:
    kid, alg = entry["kid"], entry["alg"]
    if alg == "HS256":
        secret = _unb64u(entry["secret"])
        if len(secret) < 32:
            raise ConfigError(f"HS256 key {kid} is shorter than 32 bytes")
        return JwtKey(kid, "HS256", secret, secret)
    if alg == "EdDSA":
        if "private_pem" in entry:
            priv = serialization.load_pem_private_key(entry["private_pem"].encode(), None)
            if not isinstance(priv, Ed25519PrivateKey):
                raise ConfigError(f"key {kid} is not an Ed25519 key")
            return JwtKey(kid, "EdDSA", priv.public_key(), priv)
        pub = serialization.load_pem_public_key(entry["public_pem"].encode())
        if not isinstance(pub, Ed25519PublicKey):
            raise ConfigError(f"key {kid} is not an Ed25519 key")
        return JwtKey(kid, "EdDSA", pub, None)
    raise ConfigError(f"unsupported algorithm {alg!r}")


def new_key_entry(alg: Alg = "EdDSA") -> dict[str, Any]:
    kid = f"k-{uuid.uuid4().hex[:8]}"
    if alg == "HS256":
        return {"kid": kid, "alg": alg, "secret": _b64u(secrets.token_bytes(48))}
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return {"kid": kid, "alg": alg, "private_pem": pem}


class KeyRing:
    """Signs with the active key; verifies against any key in the ring by ``kid``."""

    def __init__(self, active_kid: str, keys: list[JwtKey]) -> None:
        self._keys = {k.kid: k for k in keys}
        if active_kid not in self._keys or self._keys[active_kid].sign_key is None:
            raise ConfigError("the active JWT key must exist and hold a signing key")
        self.active = self._keys[active_kid]

    def sign(self, claims: dict[str, Any]) -> str:
        if self.active.sign_key is None:  # also checked in __init__
            raise ConfigError("the active JWT key has no signing key")
        return jwt.encode(
            claims,
            self.active.sign_key,
            algorithm=self.active.alg,
            headers={"kid": self.active.kid},
        )

    def verify(
        self, token: str, *, issuer: str, audience: str, clock: Clock, leeway: int = 30
    ) -> dict[str, Any]:
        """Verify signature, issuer, audience and expiry against the injected clock."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenError("malformed") from exc
        key = self._keys.get(str(header.get("kid")))
        if key is None:
            raise TokenError("unknown_kid")
        if header.get("alg") != key.alg:  # never trust the header to choose the algorithm
            raise TokenError("alg_mismatch")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key.verify_key,
                algorithms=[key.alg],
                issuer=issuer,
                audience=audience,
                # exp/iat are checked below against our Clock, not the wall clock
                options={
                    "require": ["exp", "iat", "sub", "jti"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenError("invalid") from exc
        now = clock.now().timestamp()
        if now >= float(claims["exp"]):
            raise TokenError("expired")
        if float(claims["iat"]) > now + leeway:
            raise TokenError("issued_in_future")
        return claims

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [j for k in self._keys.values() if (j := k.public_jwk()) is not None]}

    @property
    def kids(self) -> list[str]:
        return list(self._keys)


@dataclass
class Secrets:
    keyring: KeyRing
    _fernet: MultiFernet
    _pepper: bytes
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_document(cls, doc: dict[str, Any]) -> Secrets:
        keys = [_key_from_entry(e) for e in doc["jwt"]["keys"]]
        ring = KeyRing(doc["jwt"]["active"], keys)
        fernets = [Fernet(k.encode()) for k in doc["data_keys"]]
        return cls(ring, MultiFernet(fernets), _unb64u(doc["pepper"]), doc)

    @classmethod
    def generate_document(cls, alg: Alg = "EdDSA") -> dict[str, Any]:
        entry = new_key_entry(alg)
        return {
            "version": 1,
            "jwt": {"active": entry["kid"], "keys": [entry]},
            "data_keys": [Fernet.generate_key().decode()],
            "pepper": _b64u(secrets.token_bytes(32)),
        }

    @classmethod
    def ephemeral(cls, alg: Alg = "EdDSA") -> Secrets:
        return cls.from_document(cls.generate_document(alg))

    # --- data at rest -------------------------------------------------
    def encrypt(self, plaintext: bytes) -> str:
        return self._fernet.encrypt(plaintext).decode()

    def decrypt(self, token: str) -> bytes:
        try:
            return self._fernet.decrypt(token.encode())
        except InvalidToken as exc:
            raise ConfigError("cannot decrypt stored secret: wrong data key?") from exc

    def keyed_hash(self, value: str) -> str:
        """HMAC-SHA256 with the pepper. Used for recovery codes, which are low-entropy."""
        return hmac.new(self._pepper, value.encode(), hashlib.sha256).hexdigest()


def load_secrets(path: Path, *, create_if_missing: bool, alg: Alg = "EdDSA") -> Secrets:
    if not path.exists():
        if not create_if_missing:
            raise ConfigError(
                f"key file {path} not found. Run `authkit init-keys` and keep the file secret."
            )
        write_document(path, Secrets.generate_document(alg))
    elif os.name == "posix" and (path.stat().st_mode & 0o077) and not create_if_missing:
        raise ConfigError(f"key file {path} must not be readable by group/others (chmod 600)")
    return Secrets.from_document(json.loads(path.read_text()))


def write_document(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh, indent=2)
    tmp.replace(path)


def rotate_jwt_key(path: Path, alg: Alg = "EdDSA") -> str:
    """Add a new signing key and make it active. Old keys stay (verify-only) until pruned."""
    doc = json.loads(path.read_text())
    entry = new_key_entry(alg)
    doc["jwt"]["keys"].append(entry)
    doc["jwt"]["active"] = entry["kid"]
    write_document(path, doc)
    return str(entry["kid"])


def prune_jwt_keys(path: Path, keep: int = 2) -> list[str]:
    """Drop all but the newest ``keep`` keys (the active one is always kept)."""
    doc = json.loads(path.read_text())
    keys = doc["jwt"]["keys"]
    kept = keys[-keep:]
    if doc["jwt"]["active"] not in {k["kid"] for k in kept}:
        raise ConfigError("active key would be pruned")
    removed = [k["kid"] for k in keys if k not in kept]
    doc["jwt"]["keys"] = kept
    write_document(path, doc)
    return removed


def utc_ts(dt: datetime) -> int:
    return int(dt.timestamp())
