"""Download the Pyodide runtime and the wheels the demo needs into demo/vendor/pyodide.

Run it only to refresh the vendored files (``python3 demo/tools/fetch_vendor.py``). The build
itself never touches the network: it checks the committed files against vendor/manifest.json.

Pyodide's own packages come from the Pyodide release (their hashes are read from its lock
file and verified). The four pure-Python wheels that Pyodide does not ship are the exact
versions pinned in uv.lock, downloaded from PyPI.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

PYODIDE = "314.0.8"
CDN = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE}/full/"
RUNTIME = ["pyodide.asm.mjs", "pyodide.asm.wasm", "pyodide.mjs", "python_stdlib.zip"]
LOCK = "pyodide-lock.json"
# Top-level packages; their dependencies are resolved from the lock file below.
PYODIDE_PACKAGES = [
    "argon2-cffi",
    "cryptography",
    "sqlalchemy",
    "pydantic",
    "fastapi",
    "starlette",
    "anyio",
]
# (name, version) pinned in uv.lock. Pure Python, so the same wheel runs everywhere.
PYPI_WHEELS = [
    ("pyjwt", "2.15.1"),
    ("segno", "1.6.6"),
    ("pydantic-settings", "2.16.3"),
    ("python-dotenv", "1.2.4"),
]

OUT = Path(__file__).resolve().parent.parent / "vendor"


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (https URLs only)
        return resp.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def closure(packages: dict[str, dict], roots: list[str]) -> list[str]:
    norm = {k.lower().replace("_", "-"): k for k in packages}
    seen: list[str] = []

    def add(name: str) -> None:
        key = norm[name.lower().replace("_", "-")]
        if key not in seen:
            seen.append(key)
            for dep in packages[key]["depends"]:
                add(dep)

    for root in roots:
        add(root)
    return seen


def main() -> int:
    target = OUT / "pyodide"
    target.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict[str, str]] = {}

    lock_bytes = get(CDN + LOCK)
    (target / LOCK).write_bytes(lock_bytes)
    manifest[LOCK] = {"source": CDN + LOCK, "sha256": sha256(lock_bytes)}
    packages = json.loads(lock_bytes)["packages"]

    for name in RUNTIME:
        data = get(CDN + name)
        (target / name).write_bytes(data)
        manifest[name] = {"source": CDN + name, "sha256": sha256(data)}

    for key in closure(packages, PYODIDE_PACKAGES):
        info = packages[key]
        data = get(CDN + info["file_name"])
        if sha256(data) != info["sha256"]:
            print(f"hash mismatch for {info['file_name']}", file=sys.stderr)
            return 1
        (target / info["file_name"]).write_bytes(data)
        manifest[info["file_name"]] = {"source": CDN + info["file_name"], "sha256": info["sha256"]}

    for name, version in PYPI_WHEELS:
        meta = json.loads(get(f"https://pypi.org/pypi/{name}/{version}/json"))
        wheel = next(
            u
            for u in meta["urls"]
            if u["packagetype"] == "bdist_wheel" and u["filename"].endswith("none-any.whl")
        )
        data = get(wheel["url"])
        if sha256(data) != wheel["digests"]["sha256"]:
            print(f"hash mismatch for {wheel['filename']}", file=sys.stderr)
            return 1
        (target / wheel["filename"]).write_bytes(data)
        manifest[wheel["filename"]] = {"source": wheel["url"], "sha256": wheel["digests"]["sha256"]}

    (OUT / "manifest.json").write_text(
        json.dumps({"pyodide": PYODIDE, "files": dict(sorted(manifest.items()))}, indent=2) + "\n"
    )
    total = sum(p.stat().st_size for p in target.iterdir())
    print(f"vendored {len(manifest)} files, {total / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
