"""Structured JSON logging with secrets redacted."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

REDACTED = "[REDACTED]"
_EXACT = {"code", "totp", "otp", "authorization", "cookie", "set-cookie", "pwd", "jwt", "pepper"}
_SUFFIXES = ("password", "token", "secret", "key", "recovery_code", "recovery_codes")
_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"\b(?:rt|et)_[A-Za-z0-9_-]{20,}"),  # our opaque tokens
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(password|secret|token)=([^&\s]+)"),
    re.compile(r"\b[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}\b"),  # recovery codes
]
_STD = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


def _sensitive_key(key: str) -> bool:
    k = key.lower().replace("-", "_")
    return k in _EXACT or k.endswith(_SUFFIXES)


def redact(value: Any, key: str | None = None) -> Any:
    """Return a copy of ``value`` with secrets removed, by key name and by shape."""
    if key is not None and _sensitive_key(key) and value not in (None, "", False):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        out = value
        for pat in _PATTERNS:
            out = pat.sub(lambda m: (m.group(1) + "=" + REDACTED) if m.re.groups else REDACTED, out)
        return out
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        for k, v in record.__dict__.items():
            if k not in _STD and not k.startswith("_"):
                doc[k] = redact(v, k)
        if record.exc_info:
            doc["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(doc, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger("authkit")
    root.setLevel(level.upper())
    if not any(getattr(h, "_authkit", False) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler._authkit = True  # type: ignore[attr-defined]
        root.addHandler(handler)
    root.propagate = False
