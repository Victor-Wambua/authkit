"""Time Argon2id parameter sets on this machine.

    uv run python scripts/tune_argon2.py [--runs 15]

Pick the strongest set whose median hash time stays near your latency budget
(here: roughly 50-100 ms on the server that will run it). Run it on the real host.
"""

from __future__ import annotations

import argparse
import platform
import statistics
import time

from argon2 import PasswordHasher, Type

CANDIDATES = [
    # (label, memory KiB, time cost, parallelism)
    ("OWASP minimum  m=19MiB t=2 p=1", 19_456, 2, 1),
    ("OWASP alt      m=46MiB t=1 p=1", 47_104, 1, 1),
    ("m=64MiB t=2 p=1", 65_536, 2, 1),
    ("m=64MiB t=3 p=1 (default)", 65_536, 3, 1),
    ("RFC 9106 low   m=64MiB t=3 p=4", 65_536, 3, 4),
    ("m=128MiB t=3 p=1", 131_072, 3, 1),
    ("RFC 9106 high  m=2GiB t=1 p=4", 2_097_152, 1, 4),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=15)
    args = parser.parse_args()
    print(f"{platform.platform()} / {platform.machine()} / Python {platform.python_version()}")
    print(f"median of {args.runs} hashes (ms)\n")
    for label, mem, t, p in CANDIDATES:
        ph = PasswordHasher(time_cost=t, memory_cost=mem, parallelism=p, type=Type.ID)
        ph.hash("warm-up")
        samples = []
        for _ in range(args.runs):
            start = time.perf_counter()
            ph.hash("correct horse battery staple")
            samples.append((time.perf_counter() - start) * 1000)
        median, lo, hi = statistics.median(samples), min(samples), max(samples)
        print(f"{label:34} {median:8.1f} ms  (min {lo:.1f}, max {hi:.1f})")


if __name__ == "__main__":
    main()
