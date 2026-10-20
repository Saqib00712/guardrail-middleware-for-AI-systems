"""The input pipeline: one call from raw request to a safe decision.

    validate -> normalize -> detect (rules [+ model]) -> policy -> sanitize -> verify

Guarantees (each is tested):
* Never raises an "allow" by accident. Malformed input, detector failures and
  unexpected internal errors all become BLOCK decisions (when failure mode is
  "closed", the production default). Error text never contains request content.
* `GuardResult.text` is set ONLY when the decision permits forwarding. For
  BLOCK / REQUIRE_REVIEW it is None, so a caller cannot forward by mistake.
* "Sanitize" is verified: the cleaned text is scanned again, and if anything
  is still found the request is blocked instead of released.
* "Sanitize" cannot remove what has no span (e.g. hidden characters found by
  the normalizer). If the policy says sanitize but such a finding is present,
  the result is upgraded to REQUIRE_REVIEW rather than pretending it was cleaned.
* Monitor-mode policies (non-production) forward the original text unchanged.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from guardrails.decisions import Decision, Finding, PublicDecision
from guardrails.detectors.base import Match
from guardrails.detectors.model_assisted import ModelAssistedDetector, ModelStatus
from guardrails.detectors.scanner import Scanner, build_default_scanner
from guardrails.errors import ConfigurationError, InputRejected
from guardrails.normalization import normalize_text
from guardrails.policy import Evaluation, PolicyRegistry
from guardrails.redaction import Style, redact
from guardrails.settings import Settings
from guardrails.types import Action, ReasonCode, Severity, Stage
from guardrails.validation import InspectRequest, ValidatedInput, reject_decision, validate_input

log = logging.getLogger("guardrails.pipeline")
PIPELINE_POLICY_ID = "builtin.pipeline"


@dataclass(frozen=True)
class GuardResult:
    decision: Decision
    text: str | None                 # safe to forward; None unless decision permits forwarding
    redactions: int = 0
    by_category: Mapping[str, int] | None = None
    degraded: bool = False           # a non-critical layer failed and failure mode was "open"
    elapsed_ms: float = 0.0
    evaluation: Evaluation | None = None
    parsed: Any = None               # validated object when a schema was given (output stage)

    @property
    def allowed(self) -> bool:
        return self.decision.permits_forwarding and self.text is not None

    def public(self, *, expose_reason_code: bool = False) -> PublicDecision:
        return self.decision.to_public(expose_reason_code=expose_reason_code)

    def require_text(self) -> str:
        """The text to forward, or raise GuardrailBlocked (public decision only)."""
        if not self.allowed or self.text is None:
            from guardrails.sdk import GuardrailBlocked
            raise GuardrailBlocked(self.public())
        return self.text


def _fail(code: ReasonCode, request_id: str | None, started: float, action: Action = Action.BLOCK,
          stage: Stage = Stage.INPUT) -> GuardResult:
    d = Decision(action=action, reason_code=code, severity=Severity.HIGH, stage=stage,
                 policy_id=PIPELINE_POLICY_ID, policy_version=1, request_id=request_id)
    return GuardResult(d, None, elapsed_ms=_ms(started))


def _ms(started: float, now: float | None = None) -> float:
    return max(0.0, round(((time.perf_counter() if now is None else now) - started) * 1000, 3))


class InputPipeline:
    def __init__(self, settings: Settings, registry: PolicyRegistry, *, scanner: Scanner | None = None,
                 model_detector: ModelAssistedDetector | None = None, style: Style = "label",
                 stage: Stage = Stage.INPUT, clock: Callable[[], float] = time.perf_counter) -> None:
        self._clock = clock
        self._stage = stage
        self._s = settings
        self._registry = registry
        self._scanner = scanner or build_default_scanner()
        self._model = model_detector
        self._style: Style = style

    # ------------------------------------------------------------------ public API
    def check(self, raw: Mapping[str, Any] | InspectRequest, *, tenant_id: str | None = None) -> GuardResult:
        if self._model is not None:
            raise ConfigurationError("a model detector is configured: use the async check")
        started = self._clock()
        try:
            v = validate_input(raw, self._s)
        except InputRejected as exc:
            return GuardResult(reject_decision(exc), None, elapsed_ms=_ms(started))
        except Exception as exc:  # noqa: BLE001
            return self._internal(exc, None, started)
        return self._run(v, tenant_id, started, model_matches=(), degraded=False)

    async def acheck(self, raw: Mapping[str, Any] | InspectRequest, *, tenant_id: str | None = None) -> GuardResult:
        started = self._clock()
        try:
            v = validate_input(raw, self._s)
        except InputRejected as exc:
            return GuardResult(reject_decision(exc), None, elapsed_ms=_ms(started))
        except Exception as exc:  # noqa: BLE001
            return self._internal(exc, None, started)
        model_matches: tuple[Match, ...] = ()
        degraded = False
        if self._model is not None:
            try:
                res = await self._model.detect(v.normalized, v.source)
            except Exception as exc:  # noqa: BLE001
                return self._internal(exc, v.request_id, started)
            if res.failed:
                if self._s.detector_failure_mode == "closed":
                    code = ReasonCode.DETECTOR_TIMEOUT if res.status is ModelStatus.TIMEOUT else ReasonCode.DETECTOR_ERROR
                    return _fail(code, v.request_id, started, stage=self._stage)
                degraded = True
            model_matches = res.matches
        return self._run(v, tenant_id, started, model_matches=model_matches, degraded=degraded)

    # ------------------------------------------------------------------ internals
    def _late(self, started: float) -> bool:
        """True when this request has used up its time. Checked between stages, never inside one."""
        return self._clock() - started >= self._s.request_deadline_seconds

    def _internal(self, exc: Exception, request_id: str | None, started: float) -> GuardResult:
        log.error("guardrail internal error: %s", type(exc).__name__)  # type only: messages may hold content
        return _fail(ReasonCode.INTERNAL_ERROR, request_id, started, stage=self._stage)

    def _run(self, v: ValidatedInput, tenant_id: str | None, started: float, *,
             model_matches: tuple[Match, ...], degraded: bool) -> GuardResult:
        try:
            try:
                matches = list(self._scanner.scan(v.normalized, v.source).matches)
            except Exception as exc:  # noqa: BLE001
                log.error("detector failure: %s", type(exc).__name__)
                if self._s.detector_failure_mode == "closed":
                    return _fail(ReasonCode.DETECTOR_ERROR, v.request_id, started, stage=self._stage)
                matches, degraded = [], True
            if self._late(started):
                return _fail(ReasonCode.DEADLINE_EXCEEDED, v.request_id, started, stage=self._stage)
            matches += list(model_matches)
            unremovable = v.findings()  # normalizer flags: have a span but nothing to cut out
            findings: tuple[Finding, ...] = tuple(m.to_finding() for m in matches) + unremovable

            engine = self._registry.engine_for(tenant_id)
            ev = engine.evaluate(findings, self._stage, request_id=v.request_id)
            d = ev.decision

            if d.action is Action.SANITIZE:
                return self._sanitize(v, matches, bool(unremovable), ev, started, degraded)
            text = v.original if d.permits_forwarding else None
            return GuardResult(d, text, degraded=degraded, elapsed_ms=_ms(started), evaluation=ev)
        except Exception as exc:  # noqa: BLE001
            return self._internal(exc, v.request_id, started)

    def _sanitize(self, v: ValidatedInput, matches: list[Match], has_unremovable: bool, ev: Evaluation,
                  started: float, degraded: bool) -> GuardResult:
        d = ev.decision
        if has_unremovable:
            # Cannot honestly claim to have cleaned hidden characters: ask a human instead.
            d2 = d.model_copy(update={"action": Action.REQUIRE_REVIEW})
            return GuardResult(d2, None, degraded=degraded, elapsed_ms=_ms(started), evaluation=ev)
        if self._late(started):
            return _fail(ReasonCode.DEADLINE_EXCEEDED, v.request_id, started, stage=self._stage)
        r = redact(v.original, matches, style=self._style)
        # Verify what we are about to release.
        left = self._scanner.scan(normalize_text(r.text), v.source).matches
        if left:
            f = left[0]
            d2 = d.model_copy(update={"action": Action.BLOCK, "reason_code": f.reason_code, "severity": f.severity})
            return GuardResult(d2, None, degraded=degraded, elapsed_ms=_ms(started), evaluation=ev)
        return GuardResult(d, r.text, r.redacted_count, dict(r.by_category), degraded, _ms(started), ev)
