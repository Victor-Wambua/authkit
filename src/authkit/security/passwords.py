"""Argon2id hashing and a length-first password policy (NIST SP 800-63B)."""

from __future__ import annotations

import itertools
import unicodedata
from dataclasses import dataclass

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


def normalize_password(password: str) -> str:
    """NFKC-normalise so the same visible password always hashes the same way."""
    return unicodedata.normalize("NFKC", password)


class Argon2Hasher:
    """Argon2id with explicit parameters and transparent upgrade of old hashes."""

    def __init__(self, memory_kib: int, time_cost: int, parallelism: int) -> None:
        self.memory_kib = memory_kib
        self.time_cost = time_cost
        self.parallelism = parallelism
        self._ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        # Verified against when the account does not exist, so "unknown user" costs the
        # same CPU time as "wrong password".
        self._dummy = self._ph.hash("authkit-dummy-password-for-constant-work")

    def hash(self, password: str) -> str:
        return self._ph.hash(normalize_password(password))

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            return self._ph.verify(stored_hash, normalize_password(password))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """True if the hash was made with different parameters than the current ones."""
        return self._ph.check_needs_rehash(stored_hash)

    def dummy_verify(self, password: str) -> None:
        self.verify(self._dummy, password)


@dataclass(frozen=True)
class PasswordPolicy:
    """Length first, no composition rules. Blocklist checks happen in the service."""

    min_length: int = 12
    max_length: int = 128

    def problems(self, password: str, email: str | None = None) -> list[str]:
        pw = normalize_password(password)
        found: list[str] = []
        if len(pw) < self.min_length:
            found.append("too_short")
        if len(pw) > self.max_length:
            found.append("too_long")
        if found:
            return found
        low = pw.lower()
        if email:
            local = email.split("@", 1)[0].lower()
            if low == email.lower() or (len(local) >= 4 and local in low):
                found.append("contains_email")
        if _is_repetitive(low):
            found.append("repetitive_or_sequential")
        return found


def _is_repetitive(pw: str) -> bool:
    """Rejects 'aaaaaaaaaaaa', '123456789012', 'abababababab' and similar."""
    if len(set(pw)) == 1:
        return True
    modulus = 10 if pw.isdigit() else 0  # digit runs wrap: 7890123
    steps = {
        (ord(b) - ord(a)) % modulus if modulus else ord(b) - ord(a)
        for a, b in itertools.pairwise(pw)
    }
    if steps in ({1}, {-1}, {9}):
        return True
    return any(len(pw) % unit == 0 and pw == pw[:unit] * (len(pw) // unit) for unit in range(2, 5))
