"""The application context: every collaborator a request handler needs, built once."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass

from sqlalchemy.orm import Session, sessionmaker

from authkit.clock import Clock
from authkit.config import Settings
from authkit.mailer import Mailer, Message
from authkit.security.breach import BreachChecker
from authkit.security.keys import Secrets
from authkit.security.passwords import Argon2Hasher, PasswordPolicy
from authkit.security.throttle import Throttle, ThrottlePolicy
from authkit.security.tokens import JwtIssuer

log = logging.getLogger("authkit")


@dataclass
class AppContext:
    settings: Settings
    clock: Clock
    secrets: Secrets
    sessions: sessionmaker[Session]
    hasher: Argon2Hasher
    policy: PasswordPolicy
    breach: BreachChecker
    throttle: Throttle
    mailer: Mailer
    jwt: JwtIssuer

    @property
    def account_policy(self) -> ThrottlePolicy:
        s = self.settings
        return ThrottlePolicy(
            s.throttle_window_seconds,
            s.account_free_attempts,
            s.account_lockout_threshold,
            s.throttle_backoff_base_seconds,
            s.throttle_backoff_max_seconds,
            s.throttle_lockout_seconds,
        )

    @property
    def ip_policy(self) -> ThrottlePolicy:
        s = self.settings
        return ThrottlePolicy(
            s.throttle_window_seconds,
            s.ip_free_attempts,
            s.ip_lockout_threshold,
            s.throttle_backoff_base_seconds,
            s.throttle_backoff_max_seconds,
            s.throttle_lockout_seconds,
        )

    def send_mail(self, message: Message) -> None:
        """Deliver in the background. A mail failure must never change an API response."""
        try:
            self.mailer.send(message)
        except Exception:
            log.exception("mail delivery failed", extra={"subject": message.subject})

    def db(self) -> Iterator[Session]:
        with self.sessions() as session:
            yield session
