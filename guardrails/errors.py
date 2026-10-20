"""Exceptions that are safe to log and safe to show.

Rule: an exception message must never contain request content, credentials or
detector internals. Anything sensitive an operator might need goes in
`internal_detail`, which is NOT part of str() or safe_dict(); the caller decides
whether to log it (and must redact first).
"""
from __future__ import annotations

from guardrails.types import ReasonCode


class GuardrailError(Exception):
    code: ReasonCode = ReasonCode.INTERNAL_ERROR
    default_public_message = "internal error"

    def __init__(self, public_message: str | None = None, *, internal_detail: str | None = None):
        self.public_message = public_message or self.default_public_message
        self.internal_detail = internal_detail
        super().__init__(self.public_message)

    def __str__(self) -> str:
        return f"{self.code.value}: {self.public_message}"

    def safe_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "message": self.public_message}


class ConfigurationError(GuardrailError):
    """Invalid or unsafe settings. Messages name fields, never values."""

    code = ReasonCode.CONFIGURATION_ERROR
    default_public_message = "invalid configuration"


class InputRejected(GuardrailError):
    """The request is malformed or exceeds a limit, so it cannot even be inspected.

    The reason code is chosen per instance (INVALID_INPUT, INPUT_TOO_LONG, ...).
    The public message is a fixed phrase; it never repeats client-supplied text.
    """

    def __init__(self, code: ReasonCode, public_message: str, *, internal_detail: str | None = None):
        super().__init__(public_message, internal_detail=internal_detail)
        self.code = code
