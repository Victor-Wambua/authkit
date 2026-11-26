"""Write the OpenAPI document to a file: python scripts/export_openapi.py docs/openapi.json"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from authkit.app import create_app
from authkit.config import Settings
from authkit.mailer import MemoryMailer
from authkit.security.keys import Secrets


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "openapi.json")
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(
            _env_file=None,
            env="test",
            database_url=f"sqlite:///{tmp}/openapi.db",
            keys_file=Path(tmp) / "keys.json",
            argon2_memory_kib=64,
            argon2_time_cost=1,
            log_level="ERROR",
        )
        app = create_app(settings, mailer=MemoryMailer(), secrets=Secrets.ephemeral())
        out.write_text(json.dumps(app.openapi(), indent=2) + "\n")
        app.state.engine.dispose()
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
