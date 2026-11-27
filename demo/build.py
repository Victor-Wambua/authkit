"""Assemble the static demo into demo/dist (standard library only, no network).

    python3 demo/build.py

The output is a plain folder of files that GitHub Pages serves as is. It contains the demo
shell, the repository's own web UI, the Pyodide runtime with its wheels, and a zip of the
unmodified ``authkit`` package.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path

DEMO = Path(__file__).resolve().parent
ROOT = DEMO.parent
DIST = DEMO / "dist"
VENDOR = DEMO / "vendor"

# Packages loaded through Pyodide's own loader (their dependencies come from its lock file).
# Pure wheels Pyodide does not ship are unpacked by the worker; keep this list in step with
# worker.js.
PURE_WHEELS = ["pyjwt-", "segno-", "pydantic_settings-", "python_dotenv-"]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_vendor() -> None:
    manifest = json.loads((VENDOR / "manifest.json").read_text())["files"]
    on_disk = {p.name for p in (VENDOR / "pyodide").iterdir()}
    if on_disk != set(manifest):
        sys.exit(f"vendor/pyodide does not match manifest.json: {sorted(on_disk ^ set(manifest))}")
    for name, info in manifest.items():
        if sha256(VENDOR / "pyodide" / name) != info["sha256"]:
            sys.exit(f"hash mismatch for vendored file {name}")
    for prefix in PURE_WHEELS:
        if not any(n.startswith(prefix) for n in on_disk):
            sys.exit(f"missing vendored wheel {prefix}*")


def copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"))


def zip_package() -> None:
    out = DIST / "py"
    out.mkdir()
    with zipfile.ZipFile(out / "authkit.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted((ROOT / "src" / "authkit").rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                z.write(path, path.relative_to(ROOT / "src"))
        z.write(DEMO / "py" / "demo_host.py", "demo_host.py")


def license_notices() -> str:
    parts = [
        "Third-party software shipped with the Authkit static demo\n"
        "=========================================================\n\n"
        "Pyodide (MPL-2.0) and the CPython runtime it contains (PSF License) are served\n"
        "unmodified from this site. Source: https://github.com/pyodide/pyodide and\n"
        "https://github.com/python/cpython. The wheels below are served unmodified; their\n"
        "licence files are reproduced as found inside each wheel.\n"
    ]
    for wheel in sorted((VENDOR / "pyodide").glob("*.whl")):
        with zipfile.ZipFile(wheel) as z:
            texts = []
            for name in z.namelist():
                low = name.lower()
                is_notice = any(k in low for k in ("licen", "copying", "notice"))
                if ".dist-info/" in low and is_notice and not name.endswith("/"):
                    texts.append((name, z.read(name).decode("utf-8", "replace")))
            parts.append(f"\n\n----- {wheel.name} -----\n")
            if not texts:
                meta = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
                head = z.read(meta).decode("utf-8", "replace").split("\n\n", 1)[0]
                lines = [ln for ln in head.splitlines() if ln.startswith(("License", "Home-page"))]
                parts.append("\n".join(lines) + "\n")
            for name, text in texts:
                parts.append(f"\n[{name.split('.dist-info/', 1)[1]}]\n{text.strip()}\n")
    return "".join(parts)


def write_service_worker(version: str) -> None:
    files = sorted(
        "./" + p.relative_to(DIST).as_posix()
        for p in DIST.rglob("*")
        if p.is_file() and p.name != "sw.js"
    )
    files = ["./", "./app/", *files]  # directory URLs are what a visitor actually requests
    template = (DEMO / "src" / "sw.js").read_text()
    sw = template.replace("__VERSION__", version).replace("__FILES__", json.dumps(files, indent=2))
    (DIST / "sw.js").write_text(sw)


def main() -> None:
    verify_vendor()
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir()

    src = DEMO / "src"
    shutil.copy(src / "index.html", DIST / "index.html")
    shutil.copy(src / "demo.css", DIST / "demo.css")
    shutil.copy(src / "favicon.svg", DIST / "favicon.svg")
    copy_tree(src / "js", DIST / "js")

    # The repository's own web UI, unchanged, framed by a page that points it at the in-page API.
    copy_tree(ROOT / "src" / "authkit" / "web", DIST / "app" / "static")
    shutil.copy(src / "app-frame.html", DIST / "app" / "index.html")
    shutil.copy(src / "frame.js", DIST / "app" / "frame.js")

    copy_tree(VENDOR / "pyodide", DIST / "pyodide")
    zip_package()
    (DIST / "THIRD-PARTY-NOTICES.txt").write_text(license_notices())
    (DIST / ".nojekyll").write_text("")

    digest = hashlib.sha256()
    for p in sorted(DIST.rglob("*")):
        if p.is_file():
            digest.update(p.relative_to(DIST).as_posix().encode())
            digest.update(p.read_bytes())
    write_service_worker(digest.hexdigest()[:12])

    total = sum(p.stat().st_size for p in DIST.rglob("*") if p.is_file())
    print(f"demo built in {DIST} ({total / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
