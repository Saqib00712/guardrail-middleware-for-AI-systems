"""Policy engine: turns findings into ONE decision.

Detectors say what they saw. The policy says what to do about it.

Rules of the engine (each is tested):
* **Order never matters.** Every rule that matches a finding applies, and the
  strictest action wins (block > require_review > sanitize > allow). So a waiver
  ("allow") can never override a block, however the rules are ordered.
* **Fail closed.** A finding that no rule covers gets `unmatched_action`
  (default block). No findings at all means allow.
* **Some things cannot be waived.** At load time a policy is rejected if an
  "allow" rule could cover a secret, or any finding of HIGH/CRITICAL severity.
* **Missing confidence counts as HIGH**, so a detector that forgets to set it
  is treated strictly, not leniently.
* **Monitor mode** (log what WOULD happen, enforce nothing) exists for rollout
  and is refused in production.
* Decisions carry rule ids and findings, never matched text.

JSON is the file format (no extra dependency). Errors name fields, not values.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from guardrails.decisions import Decision, Finding
from guardrails.errors import ConfigurationError
from guardrails.settings import Settings
from guardrails.types import Action, Confidence, ReasonCode, Severity, Stage

MAX_POLICY_FILE_BYTES = 256_000
NON_WAIVABLE_CODES = frozenset({ReasonCode.SECRET_DETECTED})
_ID = r"^[a-z0-9_.-]+$"


class PolicyRule(BaseModel):
    """Matches a finding when ALL given selectors match (empty selector = any)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=64, pattern=_ID)
    action: Action
    reason_codes: tuple[ReasonCode, ...] = ()
    categories: tuple[str, ...] = ()
    stages: tuple[Stage, ...] = ()
    min_severity: Severity = Severity.INFO
    max_severity: Severity = Severity.CRITICAL
    min_confidence: Confidence | None = None  # None = any confidence

    @model_validator(mode="after")
    def _checks(self) -> "PolicyRule":
        if self.min_severity.rank > self.max_severity.rank:
            raise ValueError("min_severity is above max_severity")
        if self.action is Action.ALLOW:
            if self.max_severity.at_least(Severity.HIGH):
                raise ValueError("an allow rule must set max_severity below high")
            if not self.reason_codes:
                raise ValueError("an allow rule must name reason_codes")
            if NON_WAIVABLE_CODES & set(self.reason_codes):
                raise ValueError("secrets cannot be waived")
        return self

    def matches(self, f: Finding, stage: Stage) -> bool:
        if self.reason_codes and f.reason_code not in self.reason_codes:
            return False
        if self.categories and f.category not in self.categories:
            return False
        if self.stages and stage not in self.stages:
            return False
        if not (self.min_severity.rank <= f.severity.rank <= self.max_severity.rank):
            return False
        if self.min_confidence is not None:
            conf = f.confidence or Confidence.HIGH
            if conf.rank < self.min_confidence.rank:
                return False
        return True


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=64, pattern=_ID)
    version: int = Field(ge=1)
    mode: Literal["enforce", "monitor"] = "enforce"
    unmatched_action: Action = Action.BLOCK
    rules: tuple[PolicyRule, ...] = Field(default=(), max_length=200)

    @model_validator(mode="after")
    def _unique_ids(self) -> "Policy":
        ids = [r.id for r in self.rules]
        if len(set(ids)) != len(ids):
            raise ValueError("rule ids must be unique")
        if self.unmatched_action is Action.ALLOW:
            raise ValueError("unmatched_action cannot be allow (policies fail closed)")
        return self


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    would_have: Action              # what enforce mode would have done
    matched_rules: tuple[str, ...]  # sorted rule ids that fired (safe to audit)
    unmatched_findings: int         # findings that fell through to unmatched_action

    @property
    def shadow(self) -> bool:
        return self.decision.action is not self.would_have


class PolicyEngine:
    def __init__(self, policy: Policy, settings: Settings | None = None) -> None:
        s = settings or Settings()
        if policy.mode == "monitor" and s.environment == "production":
            raise ConfigurationError("monitor mode is not allowed in production")
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, findings: Iterable[Finding], stage: Stage, *,
                 request_id: str | None = None) -> Evaluation:
        p = self._policy
        fs = tuple(findings)
        if not fs:
            d = Decision.allow(stage, policy_id=p.id, policy_version=p.version, request_id=request_id)
            return Evaluation(d, Action.ALLOW, (), 0)

        fired: set[str] = set()
        unmatched = 0
        best: tuple[int, int, int] | None = None  # (action rank, severity rank, -index)
        best_f: Finding | None = None
        total = Action.ALLOW
        for i, f in enumerate(fs):
            hit = [r for r in p.rules if r.matches(f, stage)]
            if hit:
                act = Action.strictest(*(r.action for r in hit))
                fired.update(r.id for r in hit)
            else:
                act = p.unmatched_action
                unmatched += 1
            total = Action.strictest(total, act)
            key = (act.rank, f.severity.rank, -i)
            if best is None or key > best:
                best, best_f = key, f
        assert best_f is not None
        enforced = total if p.mode == "enforce" else Action.ALLOW
        d = Decision(action=enforced, reason_code=best_f.reason_code, severity=best_f.severity,
                     stage=stage, policy_id=p.id, policy_version=p.version,
                     findings=fs, request_id=request_id)
        return Evaluation(d, total, tuple(sorted(fired)), unmatched)


# --------------------------------------------------------------------------- built-in policy
def default_policy() -> Policy:
    return Policy(id="default", version=1, unmatched_action=Action.BLOCK, rules=(
        PolicyRule(id="secrets-block", action=Action.BLOCK, reason_codes=(ReasonCode.SECRET_DETECTED,)),
        PolicyRule(id="pii-sanitize", action=Action.SANITIZE, reason_codes=(ReasonCode.PII_DETECTED,)),
        PolicyRule(id="injection-low", action=Action.SANITIZE,
                   reason_codes=(ReasonCode.PROMPT_INJECTION, ReasonCode.SYSTEM_PROMPT_EXTRACTION)),
        PolicyRule(id="injection-medium", action=Action.REQUIRE_REVIEW,
                   reason_codes=(ReasonCode.PROMPT_INJECTION, ReasonCode.SYSTEM_PROMPT_EXTRACTION),
                   min_confidence=Confidence.MEDIUM),
        PolicyRule(id="injection-high", action=Action.BLOCK,
                   reason_codes=(ReasonCode.PROMPT_INJECTION, ReasonCode.SYSTEM_PROMPT_EXTRACTION),
                   min_confidence=Confidence.HIGH),
        PolicyRule(id="unsafe-content-sanitize", action=Action.SANITIZE, reason_codes=(ReasonCode.UNSAFE_CONTENT,)),
        PolicyRule(id="unsafe-content-high", action=Action.BLOCK, reason_codes=(ReasonCode.UNSAFE_CONTENT,),
                   min_severity=Severity.HIGH),
        PolicyRule(id="encoding-review", action=Action.REQUIRE_REVIEW,
                   reason_codes=(ReasonCode.SUSPICIOUS_ENCODING,)),
    ))


# --------------------------------------------------------------------------- loading + tenants
_TENANT = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


def _load(data: object, what: str) -> Policy:
    try:
        return Policy.model_validate(data)
    except ValidationError as e:  # never echo input values
        def where(err: dict) -> str:  # an unknown key is input, not a field name: do not echo it
            return "<unknown field>" if err["type"] == "extra_forbidden" else ".".join(str(x) for x in err["loc"])
        problems = "; ".join(f"{where(err)}: {err['type']}" for err in e.errors())
        raise ConfigurationError(f"invalid {what}: {problems}") from None


def policy_from_dict(data: object) -> Policy:
    return _load(data, "policy")


def policy_from_json_file(path: str | Path) -> Policy:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_POLICY_FILE_BYTES:
            raise ConfigurationError("policy file is too large")
        data = json.loads(p.read_text(encoding="utf-8"))
    except ConfigurationError:
        raise
    except (OSError, ValueError):
        raise ConfigurationError("policy file could not be read as JSON") from None
    return _load(data, "policy")


class PolicyRegistry:
    """A baseline policy plus optional per-tenant policies.

    A tenant policy replaces the baseline for that tenant but passes the same
    load-time rules (it cannot waive secrets or high-severity findings). An
    unknown or missing tenant gets the baseline, never a looser policy.
    """

    def __init__(self, baseline: Policy, tenants: dict[str, Policy] | None = None,
                 settings: Settings | None = None) -> None:
        self._settings = settings or Settings()
        tenants = tenants or {}
        for t in tenants:
            if not _TENANT.match(t):
                raise ConfigurationError("invalid tenant id in policy registry")
        self._engines = {t: PolicyEngine(p, self._settings) for t, p in tenants.items()}
        self._baseline = PolicyEngine(baseline, self._settings)

    def engine_for(self, tenant_id: str | None) -> PolicyEngine:
        if tenant_id is not None and tenant_id in self._engines:
            return self._engines[tenant_id]
        return self._baseline
