"""Domain errors. Each maps to one stable error code in the HTTP API."""

from __future__ import annotations

from typing import Any


class ApiError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}
        self.extra = extra or {}


def invalid_credentials() -> ApiError:
    # One message for unknown user, wrong password, inactive account and bad 2FA input.
    return ApiError(401, "invalid_credentials", "Email or password is incorrect.")


def unauthorized(message: str = "Authentication required.") -> ApiError:
    return ApiError(401, "unauthorized", message, headers={"WWW-Authenticate": "Bearer"})


def invalid_token() -> ApiError:
    return ApiError(401, "invalid_token", "The token is invalid, expired or already used.")


def forbidden(message: str = "You do not have access to this resource.") -> ApiError:
    return ApiError(403, "forbidden", message)


def throttled(wait: int) -> ApiError:
    return ApiError(
        429,
        "too_many_attempts",
        "Too many attempts. Try again later.",
        headers={"Retry-After": str(max(1, wait))},
        extra={"retry_after": max(1, wait)},
    )


def not_found(what: str = "Resource") -> ApiError:
    return ApiError(404, "not_found", f"{what} not found.")


def bad_request(code: str, message: str, **extra: Any) -> ApiError:
    return ApiError(400, code, message, extra=extra)
