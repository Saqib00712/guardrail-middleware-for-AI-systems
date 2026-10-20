"""Core vocabulary shared by every guardrail component.

Everything here is a plain enum with a *stable string value*: those strings are
what appears in audit records, metrics and API responses, so renaming one is a
breaking change.
"""
from __future__ import annotations

from enum import StrEnum


class Stage(StrEnum):
    """Where in the request lifecycle a check runs."""

    INPUT = "input"
    OUTPUT = "output"
    TOOL = "tool"


class Action(StrEnum):
    """What the middleware tells the caller to do. Ordered by strictness."""

    ALLOW = "allow"
    SANITIZE = "sanitize"
    REQUIRE_REVIEW = "require_review"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _ACTION_RANK[self]

    @property
    def permits_forwarding(self) -> bool:
        """True if the (possibly sanitized) content may continue automatically."""
        return self in (Action.ALLOW, Action.SANITIZE)

    @staticmethod
    def strictest(*actions: "Action") -> "Action":
        if not actions:
            raise ValueError("strictest() needs at least one action")
        return max(actions, key=lambda a: a.rank)


class Severity(StrEnum):
    """How serious a finding is. Ordered low to high."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def at_least(self, other: "Severity") -> bool:
        return self.rank >= other.rank


class Confidence(StrEnum):
    """How sure a detector is that a finding is real (separate from how serious it would be)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class ContentSource(StrEnum):
    """Where a piece of text came from. Decides how suspicious an instruction in it is."""

    USER_MESSAGE = "user_message"
    RETRIEVED_DOCUMENT = "retrieved_document"
    WEB_PAGE = "web_page"
    UPLOADED_FILE = "uploaded_file"
    TOOL_OUTPUT = "tool_output"
    MODEL_OUTPUT = "model_output"


class TrustLevel(StrEnum):
    """USER: a direct instruction from the person using the app (still untrusted data, but
    entitled to give instructions). UNTRUSTED: content that must never give instructions."""

    USER = "user"
    UNTRUSTED = "untrusted"


def trust_of(source: ContentSource) -> TrustLevel:
    return TrustLevel.USER if source is ContentSource.USER_MESSAGE else TrustLevel.UNTRUSTED


class ReasonCode(StrEnum):
    """Machine-readable reason for a decision.

    Codes are defined up front for the whole roadmap so later phases do not
    invent ad-hoc strings. A code existing here does NOT mean the matching
    capability is implemented yet.
    """

    OK = "OK"
    # request validation (phase 2)
    INVALID_INPUT = "INVALID_INPUT"
    INPUT_TOO_LONG = "INPUT_TOO_LONG"
    UNSUPPORTED_CONTENT_TYPE = "UNSUPPORTED_CONTENT_TYPE"
    SUSPICIOUS_ENCODING = "SUSPICIOUS_ENCODING"
    # detectors (phases 3-4)
    PII_DETECTED = "PII_DETECTED"
    SECRET_DETECTED = "SECRET_DETECTED"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    SYSTEM_PROMPT_EXTRACTION = "SYSTEM_PROMPT_EXTRACTION"
    UNSAFE_CONTENT = "UNSAFE_CONTENT"
    # output (phase 7)
    OUTPUT_TOO_LONG = "OUTPUT_TOO_LONG"
    OUTPUT_SCHEMA_INVALID = "OUTPUT_SCHEMA_INVALID"
    # tools (phase 8)
    TOOL_UNKNOWN = "TOOL_UNKNOWN"
    TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"
    TOOL_ARGS_INVALID = "TOOL_ARGS_INVALID"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    # platform (phases 5, 9-11)
    POLICY_DEFAULT = "POLICY_DEFAULT"
    RATE_LIMITED = "RATE_LIMITED"
    DETECTOR_ERROR = "DETECTOR_ERROR"
    DETECTOR_TIMEOUT = "DETECTOR_TIMEOUT"
    AUDIT_UNAVAILABLE = "AUDIT_UNAVAILABLE"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_ACTION_RANK = {
    Action.ALLOW: 0,
    Action.SANITIZE: 1,
    Action.REQUIRE_REVIEW: 2,
    Action.BLOCK: 3,
}
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
