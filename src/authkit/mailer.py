"""Pluggable mailers. Dev uses the file mailer (one JSON file per message)."""

from __future__ import annotations

import json
import logging
import smtplib
import threading
import uuid
from dataclasses import asdict, dataclass
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from authkit.clock import Clock

log = logging.getLogger("authkit.mail")


@dataclass(frozen=True)
class Message:
    to: str
    subject: str
    text: str


class Mailer(Protocol):
    def send(self, message: Message) -> None: ...


class MemoryMailer:
    """Collects messages in a list. For tests."""

    def __init__(self) -> None:
        self.messages: list[Message] = []
        self._lock = threading.Lock()

    def send(self, message: Message) -> None:
        with self._lock:
            self.messages.append(message)


class FileMailer:
    """Writes each message to ``<dir>/<sequence>-<id>.json``. Dev only: bodies contain tokens."""

    def __init__(self, directory: Path, clock: Clock) -> None:
        self.directory = directory
        self.clock = clock
        directory.mkdir(parents=True, exist_ok=True)

    def send(self, message: Message) -> None:
        now = self.clock.now()
        name = f"{now.strftime('%Y%m%dT%H%M%S%f')}-{uuid.uuid4().hex[:6]}.json"
        doc = {**asdict(message), "sent_at": now.isoformat()}
        (self.directory / name).write_text(json.dumps(doc, indent=2))
        log.info("mail written to outbox", extra={"to": message.to, "subject": message.subject})

    def list_messages(self, limit: int = 30) -> list[dict[str, Any]]:
        files = sorted(self.directory.glob("*.json"), reverse=True)[:limit]
        return [json.loads(p.read_text()) for p in files]


class SmtpMailer:
    """Plain SMTP with optional STARTTLS. Covered by a mocked-SMTP test only; no live server."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        sender: str,
        starttls: bool = True,
    ) -> None:
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.sender, self.starttls = sender, starttls

    def send(self, message: Message) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = message.to
        msg["Subject"] = message.subject
        msg.set_content(message.text)
        with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
            if self.starttls:
                smtp.starttls()
            if self.username and self.password:
                smtp.login(self.username, self.password)
            smtp.send_message(msg)
