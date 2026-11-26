"""Compare login response time for a known account vs an unknown one (wrong password both).

    uv run python scripts/timing_probe.py

Uses the production Argon2 defaults and an in-process client, so it measures the service's
own work, not the network. A large gap would mean account existence leaks through timing.
"""

from __future__ import annotations

import statistics
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

from authkit.app import create_app
from authkit.clock import FakeClock
from authkit.config import Settings
from authkit.mailer import MemoryMailer
from authkit.security.keys import Secrets

RUNS = 40


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            _env_file=None,
            env="test",
            database_url=f"sqlite:///{tmp}/probe.db",
            keys_file=Path(tmp) / "keys.json",
            log_level="ERROR",
            # Wide throttle so the probe is never blocked by its own failures.
            account_free_attempts=10_000,
            account_lockout_threshold=20_000,
            ip_free_attempts=10_000,
            ip_lockout_threshold=20_000,
        )
        app = create_app(
            settings, clock=FakeClock(), mailer=MemoryMailer(), secrets=Secrets.ephemeral()
        )
        client = TestClient(app)
        client.post(
            "/api/auth/register",
            json={"email": "known@example.com", "password": "correct horse battery staple"},
        )

        def one(email: str) -> float:
            start = time.perf_counter()
            r = client.post(
                "/api/auth/login", json={"email": email, "password": "wrong passphrase here"}
            )
            elapsed = (time.perf_counter() - start) * 1000
            assert r.status_code == 401
            return elapsed

        one("known@example.com")  # warm-up
        known: list[float] = []
        unknown: list[float] = []
        for _ in range(RUNS):  # interleaved, so drift affects both equally
            known.append(one("known@example.com"))
            unknown.append(one("unknown@example.com"))
        print(f"known account  : median {statistics.median(known):6.1f} ms  (n={RUNS})")
        print(f"unknown account: median {statistics.median(unknown):6.1f} ms  (n={RUNS})")
        app.state.engine.dispose()


if __name__ == "__main__":
    main()
