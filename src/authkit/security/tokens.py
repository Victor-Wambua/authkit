"""Opaque token helpers and access/MFA JWT issuing."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import timedelta
from typing import Any

from authkit.clock import Clock
from authkit.security.keys import KeyRing, TokenError

REFRESH_PREFIX = "rt"
EMAIL_PREFIX = "et"


def new_opaque_token(prefix: str) -> str:
    """256 bits from the OS CSPRNG, URL-safe, with a short type prefix for log scanning."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    """SHA-256 hex. Enough for 256-bit random tokens: there is nothing to brute force."""
    return hashlib.sha256(token.encode()).hexdigest()


class JwtIssuer:
    def __init__(self, ring: KeyRing, clock: Clock, issuer: str, audience: str) -> None:
        self.ring = ring
        self.clock = clock
        self.issuer = issuer
        self.audience = audience

    def _claims(self, sub: str, use: str, ttl: int, extra: dict[str, Any]) -> dict[str, Any]:
        now = self.clock.now()
        return {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": sub,
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "use": use,
            **extra,
        }

    def access_token(
        self, user_id: str, session_id: str, role: str, amr: list[str], ttl: int
    ) -> str:
        return self.ring.sign(
            self._claims(user_id, "access", ttl, {"sid": session_id, "role": role, "amr": amr})
        )

    def mfa_token(self, user_id: str, ttl: int) -> str:
        return self.ring.sign(self._claims(user_id, "mfa", ttl, {}))

    def decode(self, token: str, *, use: str) -> dict[str, Any]:
        claims = self.ring.verify(
            token, issuer=self.issuer, audience=self.audience, clock=self.clock
        )
        if claims.get("use") != use:
            raise TokenError("wrong_use")
        return claims
