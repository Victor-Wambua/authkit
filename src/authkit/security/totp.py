"""HOTP (RFC 4226) and TOTP (RFC 6238), implemented from the RFCs."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

_ALGOS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}


def hotp(secret: bytes, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    mac = hmac.new(secret, struct.pack(">Q", counter), _ALGOS[algo]).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def totp_at(
    secret: bytes, unix_time: float, step: int = 30, digits: int = 6, algo: str = "sha1"
) -> str:
    return hotp(secret, int(unix_time // step), digits, algo)


def current_step(unix_time: float, step: int = 30) -> int:
    return int(unix_time // step)


def verify(
    secret: bytes,
    code: str,
    unix_time: float,
    *,
    last_used_step: int = 0,
    window: int = 1,
    step: int = 30,
    digits: int = 6,
    algo: str = "sha1",
) -> int | None:
    """Return the matched time step, or None.

    Accepts steps within +/- ``window`` of now. A step at or before ``last_used_step`` is
    rejected, which is the replay protection: a code works once. Every candidate is
    compared (no early exit) with a constant-time comparison.
    """
    if len(code) != digits or not code.isascii() or not code.isdigit():
        return None
    now_step = current_step(unix_time, step)
    matched: int | None = None
    for s in range(now_step - window, now_step + window + 1):
        expected = hotp(secret, s, digits, algo)
        if hmac.compare_digest(expected.encode(), code.encode()) and s > last_used_step:
            matched = s if matched is None else max(matched, s)
    return matched


def generate_secret(nbytes: int = 20) -> bytes:
    return secrets.token_bytes(nbytes)


def b32(secret: bytes) -> str:
    return base64.b32encode(secret).decode().rstrip("=")


def from_b32(text: str) -> bytes:
    padded = text.upper() + "=" * (-len(text) % 8)
    return base64.b32decode(padded)


def provisioning_uri(secret: bytes, account: str, issuer: str) -> str:
    """The otpauth:// URI that authenticator apps read from a QR code."""
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    query = urlencode(
        {"secret": b32(secret), "issuer": issuer, "algorithm": "SHA1", "digits": 6, "period": 30},
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"
