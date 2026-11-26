"""Settings, read from AUTHKIT_* environment variables (or a .env file)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(RuntimeError):
    """Raised when the configuration is unsafe or incomplete."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTHKIT_", env_file=".env", extra="ignore", frozen=True
    )

    # Runtime
    env: Literal["dev", "test", "production"] = "production"
    database_url: str = "sqlite:///./data/authkit.db"
    keys_file: Path = Path("./data/keys.json")
    base_url: str = "http://localhost:4120"
    registration_open: bool = True
    require_verified_email: bool = False
    totp_issuer: str = "Authkit"

    # Tokens
    jwt_issuer: str = "authkit"
    jwt_audience: str = "authkit-api"
    access_ttl_seconds: int = Field(900, ge=60, le=3600)
    refresh_ttl_seconds: int = Field(14 * 86400, ge=300)
    session_max_age_seconds: int = Field(30 * 86400, ge=300)
    mfa_token_ttl_seconds: int = Field(300, ge=30, le=900)
    email_verify_ttl_seconds: int = 24 * 3600
    password_reset_ttl_seconds: int = 3600

    # Passwords. The defaults were chosen from a timing run, see docs/CASE-STUDY.md.
    password_min_length: int = Field(12, ge=8)
    password_max_length: int = Field(128, ge=32, le=1024)
    argon2_memory_kib: int = Field(65536, ge=8)
    argon2_time_cost: int = Field(3, ge=1)
    argon2_parallelism: int = Field(1, ge=1)
    breach_mode: Literal["off", "offline", "hibp"] = "offline"
    breach_file: Path | None = None  # None means the small sample list shipped in the package
    hibp_fail_open: bool = True

    # Throttling (per account and per IP)
    throttle_window_seconds: int = Field(900, ge=60)
    throttle_lockout_seconds: int = Field(900, ge=10)
    throttle_backoff_base_seconds: float = Field(1.0, ge=0)
    throttle_backoff_max_seconds: float = Field(60.0, ge=0)
    account_free_attempts: int = Field(5, ge=1)
    account_lockout_threshold: int = Field(10, ge=2)
    ip_free_attempts: int = Field(20, ge=1)
    ip_lockout_threshold: int = Field(50, ge=2)
    register_per_ip_per_hour: int = Field(20, ge=1)
    reset_per_email_per_hour: int = Field(3, ge=1)

    # HTTP
    cors_origins: str = ""  # comma separated; empty means no CORS headers
    max_body_bytes: int = Field(65536, ge=1024)
    trusted_proxy_hops: int = Field(0, ge=0, le=5)
    docs_enabled: bool | None = None  # None: on in dev/test, off in production
    cookie_secure: bool | None = None  # None: secure unless env is dev/test
    log_level: str = "INFO"

    # Mail
    mailer: Literal["file", "smtp"] = "file"
    outbox_dir: Path = Path("./data/outbox")
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "Authkit <no-reply@example.com>"
    smtp_starttls: bool = True

    @model_validator(mode="after")
    def _check(self) -> Settings:
        if self.throttle_lockout_seconds > self.throttle_window_seconds:
            raise ValueError("throttle_lockout_seconds must not exceed throttle_window_seconds")
        if self.account_lockout_threshold <= self.account_free_attempts:
            raise ValueError("account_lockout_threshold must exceed account_free_attempts")
        if self.ip_lockout_threshold <= self.ip_free_attempts:
            raise ValueError("ip_lockout_threshold must exceed ip_free_attempts")
        if "*" in self.cors_origin_list:
            raise ValueError("cors_origins must list explicit origins; '*' is not allowed")
        if self.password_min_length > self.password_max_length:
            raise ValueError("password_min_length must not exceed password_max_length")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_dev(self) -> bool:
        return self.env in ("dev", "test")

    @property
    def docs_on(self) -> bool:
        return self.docs_enabled if self.docs_enabled is not None else self.is_dev

    @property
    def secure_cookies(self) -> bool:
        return self.cookie_secure if self.cookie_secure is not None else not self.is_dev
