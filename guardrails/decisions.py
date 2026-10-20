"""Typed results of a guardrail check.

Two views of the same outcome:

* `Decision`       internal. Carries findings, policy id/version, severity. For
                   the calling application, audit and metrics.
* `PublicDecision` external. What an untrusted client may see: an action, a
                   coarse code and a fixed message. No detector names, no
                   offsets, no matched text. This is a deliberate boundary:
                   telling an attacker *which* rule fired helps them evade it.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from guardrails.types import Action, Confidence, ReasonCode, Severity, Stage


def new_request_id() -> str:
    return uuid.uuid4().hex


class Finding(BaseModel):
    """One thing a detector noticed. Deliberately has NO field for matched text.

    `extra="forbid"` means nobody can attach the raw value by accident
    (`Finding(matched_text=...)` raises), so findings are safe to log and audit.
    Offsets point into the text that was inspected so a redactor can act on them.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    detector_id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    reason_code: ReasonCode
    severity: Severity
    category: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9_.-]+$")
    confidence: Confidence | None = None
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def _offsets_consistent(self) -> "Finding":
        if (self.start is None) != (self.end is None):
            raise ValueError("start and end must be given together")
        if self.start is not None and self.end < self.start:  # type: ignore[operator]
            raise ValueError("end must be >= start")
        return self


class Decision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Action
    reason_code: ReasonCode
    severity: Severity
    stage: Stage
    policy_id: str = Field(min_length=1, max_length=64)
    policy_version: int = Field(ge=1)
    findings: tuple[Finding, ...] = ()
    request_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _ok_means_allow(self) -> "Decision":
        # OK is reserved for "nothing to report". Any other outcome needs a real reason.
        if self.reason_code is ReasonCode.OK and (self.action is not Action.ALLOW or self.findings):
            raise ValueError("reason_code OK requires action allow and no findings")
        return self

    @property
    def permits_forwarding(self) -> bool:
        return self.action.permits_forwarding

    @classmethod
    def allow(cls, stage: Stage, *, policy_id: str, policy_version: int,
              request_id: str | None = None) -> "Decision":
        return cls(action=Action.ALLOW, reason_code=ReasonCode.OK, severity=Severity.INFO,
                   stage=stage, policy_id=policy_id, policy_version=policy_version,
                   request_id=request_id)

    def to_public(self, *, expose_reason_code: bool = False) -> "PublicDecision":
        return PublicDecision(
            action=self.action,
            code=_PUBLIC_CODE[self.action],
            message=_PUBLIC_MESSAGE[self.action],
            request_id=self.request_id,
            reason_code=self.reason_code if expose_reason_code else None,
        )


class PublicCode(StrEnum):
    OK = "ok"
    SANITIZED = "sanitized"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"


_PUBLIC_CODE = {
    Action.ALLOW: PublicCode.OK,
    Action.SANITIZE: PublicCode.SANITIZED,
    Action.REQUIRE_REVIEW: PublicCode.REVIEW_REQUIRED,
    Action.BLOCK: PublicCode.BLOCKED,
}
_PUBLIC_MESSAGE = {
    Action.ALLOW: "Request allowed.",
    Action.SANITIZE: "Request allowed after some content was removed.",
    Action.REQUIRE_REVIEW: "This request needs human review before it can proceed.",
    Action.BLOCK: "This request was blocked by security policy.",
}


class PublicDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    action: Action
    code: PublicCode
    message: str
    request_id: str | None = None
    reason_code: ReasonCode | None = None  # only when the operator opted in


def most_restrictive(decisions: Iterable[Decision], *, default: Decision | None = None) -> Decision:
    """Pick the decision that must win: strictest action, then highest severity,
    then the earliest one (stable, so results are deterministic).

    An empty input is an error unless a `default` is supplied. We never invent
    an implicit "allow": callers must say what no-decisions means.
    """
    items = list(decisions)
    if not items:
        if default is None:
            raise ValueError("most_restrictive() got no decisions and no default")
        return default
    best = items[0]
    for d in items[1:]:
        if (d.action.rank, d.severity.rank) > (best.action.rank, best.severity.rank):
            best = d
    return best
