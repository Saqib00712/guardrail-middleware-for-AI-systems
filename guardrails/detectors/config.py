"""Validated configuration for the PII and secret detectors."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

PiiCategory = Literal["email", "phone", "credit_card", "national_id", "ip_address"]
MAX_PATTERN_CHARS = 300


def _check_regex(p: str) -> str:
    if not p or len(p) > MAX_PATTERN_CHARS:
        raise ValueError(f"pattern must be 1..{MAX_PATTERN_CHARS} characters")
    try:
        re.compile(p)
    except re.error:
        raise ValueError("pattern is not a valid regular expression") from None
    return p


class AllowSpec(BaseModel):
    """Values that must NOT be reported. `exact` is case-insensitive; `regex` must
    match the whole value. Both are checked against the short matched value only
    (never the whole text), which also bounds their cost."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    exact: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()

    @field_validator("exact")
    @classmethod
    def _exact_ok(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not x.strip() for x in v):
            raise ValueError("allowlist entries must not be blank")
        return v

    @field_validator("regex")
    @classmethod
    def _regex_ok(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for p in v:
            _check_regex(p)
        return v


class NationalIdPattern(BaseModel):
    """An extra, operator-defined identifier pattern (reported as category national_id).
    Patterns are admin-trusted: keep them simple, avoid nested quantifiers."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9_]{1,32}$")
    regex: str

    @field_validator("regex")
    @classmethod
    def _regex_ok(cls, v: str) -> str:
        return _check_regex(v)


class InjectionConfig(BaseModel):
    """Settings for the deterministic prompt-injection detector."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = True
    # Decode-and-rescan work limits (the detector reads hostile input).
    max_decode_candidates: int = Field(default=20, ge=0, le=200)
    max_decode_depth: int = Field(default=2, ge=0, le=4)
    max_derived_texts: int = Field(default=40, ge=0, le=400)
    max_derived_chars: int = Field(default=60_000, ge=0, le=2_000_000)
    # This many distinct injection signals in one text raises an extra "multiple_signals" finding.
    escalation_threshold: int = Field(default=3, ge=2, le=50)
    # Phrases that must NOT be reported (e.g. a security-training product that quotes attacks).
    allow: AllowSpec = AllowSpec()


class DetectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    pii_categories: frozenset[PiiCategory] = frozenset({"email", "phone", "credit_card", "national_id"})
    builtin_national_ids: frozenset[Literal["us_ssn", "pk_cnic"]] = frozenset({"us_ssn", "pk_cnic"})
    national_ids: tuple[NationalIdPattern, ...] = ()
    secrets_enabled: bool = True
    pii_allow: AllowSpec = AllowSpec()
    secret_allow: AllowSpec = AllowSpec()
    injection: InjectionConfig = InjectionConfig()
