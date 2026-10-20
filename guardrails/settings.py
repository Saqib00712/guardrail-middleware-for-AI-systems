"""Validated, centralized configuration.

Design rules:
* Safe defaults. The default environment is **production**, so a forgotten
  setting fails strict rather than loose. Local work sets
  GUARDRAILS_ENVIRONMENT=development.
* Pure pydantic (no pydantic-settings), so the core package keeps one dependency.
* Unknown GUARDRAILS_* variables are an ERROR. A typo like
  GUARDRAILS_MAX_INPUT_CHAR would otherwise silently leave the default in place
  while the operator believes a limit is set.
* Error messages name fields and error types, never the supplied values.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from guardrails.errors import ConfigurationError

FailMode = Literal["closed", "open"]
ENV_PREFIX = "GUARDRAILS_"


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    environment: Literal["development", "production"] = "production"

    # Size limits (enforced in phase 2 / API in phase 10)
    max_request_body_bytes: int = Field(default=1_000_000, ge=1, le=50_000_000)
    max_input_chars: int = Field(default=20_000, ge=1, le=1_000_000)
    max_output_chars: int = Field(default=50_000, ge=1, le=2_000_000)
    max_nesting_depth: int = Field(default=8, ge=1, le=64)

    # What to do when a control's own dependency fails. "closed" = deny/stop.
    detector_failure_mode: FailMode = "closed"
    audit_failure_mode: FailMode = "closed"
    rate_limit_failure_mode: FailMode = "closed"

    # Limits (phase 11). In-memory, per process: see guardrails/limits.py for what that means.
    rate_limit_per_minute: float = Field(default=120, gt=0, le=1_000_000)         # per API key
    rate_limit_burst: int = Field(default=30, ge=1, le=1_000_000)                 # per API key
    tenant_rate_limit_per_minute: float = Field(default=600, gt=0, le=10_000_000)  # all keys of one tenant together
    auth_failures_per_minute: float = Field(default=10, gt=0, le=100_000)         # per client address
    tenant_budget_chars_per_hour: int = Field(default=5_000_000, ge=1)
    request_deadline_seconds: float = Field(default=5.0, gt=0, le=120)

    # Whether untrusted clients may see the internal reason code.
    expose_reason_codes: bool = False

    # Explicit opt-in before ANY text may leave this process to an external detector.
    allow_external_detectors: bool = False

    @model_validator(mode="after")
    def _production_rules(self) -> "Settings":
        if self.environment == "production":
            # Security-critical controls must not silently turn themselves off.
            # (Rate-limit fail-open stays a documented operator choice.)
            bad = [n for n in ("detector_failure_mode", "audit_failure_mode")
                   if getattr(self, n) == "open"]
            if bad:
                raise ValueError("fail-open is not allowed in production for: " + ", ".join(bad))
        return self

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        raw: dict[str, str] = {}
        unknown: list[str] = []
        known = set(cls.model_fields)
        for key, value in env.items():
            if not key.startswith(ENV_PREFIX):
                continue
            name = key[len(ENV_PREFIX):].lower()
            if name in known:
                raw[name] = value
            else:
                unknown.append(key)
        if unknown:
            raise ConfigurationError("unknown settings: " + ", ".join(sorted(unknown)))
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            problems = []
            for err in exc.errors(include_input=False, include_url=False, include_context=False):
                where = ".".join(str(p) for p in err["loc"]) or "settings"
                problems.append(f"{where} ({err['type']})")
            raise ConfigurationError("invalid settings: " + ", ".join(problems)) from None
