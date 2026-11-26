"""Breached-password checks using the Have I Been Pwned k-anonymity range model.

Only the first five hex characters of the SHA-1 of the password ever leave the process
(or are looked up in the local file). The service compares the remaining 35 characters
itself. Two sources implement the same interface:

* ``SortedHashFile``: a local file of ``SHA1HEX:COUNT`` lines, sorted. Used in dev and tests.
* ``HibpHttpSource``: the real ``api.pwnedpasswords.com/range`` endpoint. Never called in tests.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO, Protocol

from authkit.security.passwords import normalize_password

log = logging.getLogger("authkit.breach")

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


class BreachCheckUnavailable(RuntimeError):
    """The range source could not be reached or read."""


class RangeSource(Protocol):
    def fetch(self, prefix: str) -> str:
        """Return the API-style body for a 5-char prefix: lines of ``SUFFIX:COUNT``."""
        ...


def sha1_hex(password: str) -> str:
    # SHA-1 is mandated by the HIBP range protocol; it is not used for storage.
    return (
        hashlib.sha1(normalize_password(password).encode(), usedforsecurity=False)
        .hexdigest()
        .upper()
    )


class SortedHashFile:
    """Binary search over a file of ``SHA1HEX:COUNT`` lines sorted by hash."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def fetch(self, prefix: str) -> str:
        want = prefix.upper().encode()
        out: list[str] = []
        try:
            with self.path.open("rb") as f:
                size = f.seek(0, 2)
                lo, hi = 0, size  # lo is always a line start
                while lo < hi:
                    mid = (lo + hi) // 2
                    start = _line_start(f, mid)
                    f.seek(start)
                    line = f.readline()
                    if line[: len(want)] < want:
                        lo = start + len(line)
                    else:
                        hi = start
                f.seek(lo)
                for raw in f:
                    if not raw.startswith(want):
                        break
                    out.append(raw[len(want) :].decode().strip())
        except OSError as exc:
            raise BreachCheckUnavailable(f"cannot read {self.path}") from exc
        return "\n".join(out)


def _line_start(f: BinaryIO, pos: int) -> int:
    """Offset of the start of the line containing byte ``pos``."""
    chunk_start = max(0, pos - 256)
    f.seek(chunk_start)
    buf = f.read(pos - chunk_start)
    idx = buf.rfind(b"\n")
    if idx == -1:
        if chunk_start == 0:
            return 0
        raise BreachCheckUnavailable("line longer than 256 bytes: not a hash file")
    return chunk_start + idx + 1


class HibpHttpSource:
    """The real HIBP range API. Unverified in this repo's tests by design (offline CI)."""

    def __init__(self, timeout: float = 3.0, fetcher: Callable[[str], str] | None = None) -> None:
        self.timeout = timeout
        self._fetcher = fetcher or self._http_get

    def fetch(self, prefix: str) -> str:
        try:
            return self._fetcher(HIBP_RANGE_URL + prefix.upper())
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise BreachCheckUnavailable("HIBP range request failed") from exc

    def _http_get(self, url: str) -> str:
        if not url.startswith("https://"):
            raise BreachCheckUnavailable("refusing non-https URL")
        req = urllib.request.Request(  # noqa: S310
            url, headers={"Add-Padding": "true", "User-Agent": "authkit-breach-check"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310  # nosec B310
            body: bytes = resp.read(2_000_000)
            return body.decode()


class BreachChecker(Protocol):
    def pwned_count(self, password: str) -> int: ...


class NullChecker:
    def pwned_count(self, password: str) -> int:
        return 0


class RangeBreachChecker:
    """Hashes the password, asks the source for the prefix, matches the suffix locally."""

    def __init__(self, source: RangeSource) -> None:
        self.source = source

    def pwned_count(self, password: str) -> int:
        digest = sha1_hex(password)
        prefix, suffix = digest[:5], digest[5:]
        body = self.source.fetch(prefix)
        count = 0
        for line in body.splitlines():
            cand, _, num = line.strip().partition(":")
            if hmac.compare_digest(cand.upper().encode(), suffix.encode()):
                count = max(count, int(num) if num.isdigit() else 1)
        return count


class FailOpenChecker:
    """Wraps a checker so an outage degrades to 'not known breached' (and says so in logs)."""

    def __init__(self, inner: BreachChecker, fail_open: bool) -> None:
        self.inner = inner
        self.fail_open = fail_open

    def pwned_count(self, password: str) -> int:
        try:
            return self.inner.pwned_count(password)
        except BreachCheckUnavailable:
            if not self.fail_open:
                raise
            log.warning("breach check unavailable, allowing password (fail-open)")
            return 0


def build_sorted_hash_file(words: list[str], dest: Path, count: int = 1) -> int:
    """Write a ``SHA1HEX:COUNT`` file, sorted, from a plain word list. Returns line count."""
    hashes = sorted({sha1_hex(w) for w in words if w})
    dest.write_text("".join(f"{h}:{count}\n" for h in hashes), encoding="ascii")
    return len(hashes)
