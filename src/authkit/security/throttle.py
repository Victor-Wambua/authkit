"""Sliding-window login throttling with progressive backoff and temporary lockout."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from authkit.clock import Clock
from authkit.models import ThrottleEvent


@dataclass(frozen=True)
class ThrottlePolicy:
    window_seconds: int
    free_attempts: int  # failures allowed in the window before any delay
    lockout_threshold: int  # failures in the window that trigger a temporary lockout
    backoff_base_seconds: float
    backoff_max_seconds: float
    lockout_seconds: int

    def delay_for(self, failures: int) -> float:
        """Seconds to wait after the latest failure, given failures in the window."""
        if failures < self.free_attempts:
            return 0.0
        if failures >= self.lockout_threshold:
            return float(self.lockout_seconds)
        exponent = failures - self.free_attempts
        return float(min(self.backoff_base_seconds * (2**exponent), self.backoff_max_seconds))


def account_key(email: str) -> str:
    """Hashed so throttle rows never hold the e-mail addresses of non-existent accounts."""
    return hashlib.sha256(email.encode()).hexdigest()[:32]


class Throttle:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock

    def wait_seconds(self, db: Session, scope: str, key: str, policy: ThrottlePolicy) -> int:
        """Whole seconds the caller must still wait (0 = allowed)."""
        now = self.clock.now()
        since = now - timedelta(seconds=policy.window_seconds)
        count, last = db.execute(
            select(func.count(ThrottleEvent.id), func.max(ThrottleEvent.at)).where(
                ThrottleEvent.scope == scope, ThrottleEvent.key == key, ThrottleEvent.at > since
            )
        ).one()
        if not count or last is None:
            return 0
        delay = policy.delay_for(count)
        remaining = (last + timedelta(seconds=delay) - now).total_seconds()
        return max(0, math.ceil(remaining))

    def record_failure(self, db: Session, scope: str, key: str, policy: ThrottlePolicy) -> None:
        now = self.clock.now()
        db.execute(
            delete(ThrottleEvent).where(
                ThrottleEvent.scope == scope,
                ThrottleEvent.key == key,
                ThrottleEvent.at <= now - timedelta(seconds=policy.window_seconds),
            )
        )
        db.add(ThrottleEvent(scope=scope, key=key, at=now))

    def clear(self, db: Session, scope: str, key: str) -> None:
        db.execute(
            delete(ThrottleEvent).where(ThrottleEvent.scope == scope, ThrottleEvent.key == key)
        )

    def allow(self, db: Session, scope: str, key: str, limit: int, window_seconds: int) -> bool:
        """Fixed-quota limiter (n events per window). Records the event when allowed."""
        now = self.clock.now()
        since = now - timedelta(seconds=window_seconds)
        used = db.scalar(
            select(func.count(ThrottleEvent.id)).where(
                ThrottleEvent.scope == scope, ThrottleEvent.key == key, ThrottleEvent.at > since
            )
        )
        if (used or 0) >= limit:
            return False
        db.add(ThrottleEvent(scope=scope, key=key, at=now))
        return True
