"""Optional model-assisted injection detection, behind a provider interface.

Rules for this layer:
* It is OPTIONAL and never the only boundary. If the provider is down, slow or over
  budget, the deterministic layer (injection.py) still runs; this class only reports a
  status so the pipeline can apply the configured fail-open / fail-closed behavior.
* Nothing leaves the process unless the operator opted in (`allow_external_detectors`).
  A provider that sends data out is refused at construction otherwise.
* Even when allowed, text sent to an external provider is first scanned and redacted
  for PII and secrets, then re-normalized, so credentials are not shipped off.
* Hard limits: per-call timeout, max characters sent, concurrent calls, and a call
  budget per time window.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from guardrails.detectors.base import Match
from guardrails.detectors.config import DetectorConfig, InjectionConfig
from guardrails.detectors.scanner import build_default_scanner
from guardrails.errors import ConfigurationError
from guardrails.normalization import NormalizedText, normalize_text
from guardrails.redaction import redact
from guardrails.settings import Settings
from guardrails.types import Confidence, ContentSource, ReasonCode, Severity


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    INJECTION = "injection"


@dataclass(frozen=True)
class ClassifierResult:
    verdict: Verdict
    score: float  # 0.0 .. 1.0, higher = more likely an injection


class InjectionClassifier(Protocol):
    name: str                    # stable id, [a-z0-9_.-]+, used in finding ids
    sends_data_externally: bool  # True if text leaves this process

    async def classify(self, text: str, source: ContentSource) -> ClassifierResult: ...


class ModelStatus(StrEnum):
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True)
class ModelDetectionResult:
    status: ModelStatus
    matches: tuple[Match, ...] = ()

    @property
    def failed(self) -> bool:
        return self.status is not ModelStatus.OK


class CallBudget:
    """At most `max_calls` provider calls per sliding `window_seconds` (clock is injectable)."""

    def __init__(self, max_calls: int, window_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        if max_calls < 1 or window_seconds <= 0:
            raise ValueError("max_calls must be >= 1 and window_seconds > 0")
        self._max, self._window, self._clock = max_calls, window_seconds, clock
        self._stamps: deque[float] = deque()

    def try_acquire(self) -> bool:
        now = self._clock()
        while self._stamps and self._stamps[0] <= now - self._window:
            self._stamps.popleft()
        if len(self._stamps) >= self._max:
            return False
        self._stamps.append(now)
        return True


_NAME = re.compile(r"^[a-z0-9_.-]{1,32}$")


class ModelAssistedDetector:
    def __init__(self, provider: InjectionClassifier, *, settings: Settings, timeout_seconds: float = 2.0,
                 max_chars: int = 4000, max_concurrent: int = 4, budget: CallBudget | None = None) -> None:
        if not _NAME.match(provider.name):
            raise ConfigurationError("classifier name must match [a-z0-9_.-]{1,32}")
        if provider.sends_data_externally and not settings.allow_external_detectors:
            raise ConfigurationError("an external detector is configured but allow_external_detectors is false")
        if timeout_seconds <= 0 or max_chars < 1 or max_concurrent < 1:
            raise ConfigurationError("invalid model detector limits")
        self._provider = provider
        self._timeout = timeout_seconds
        self._max_chars = max_chars
        self._budget = budget
        self._sem = asyncio.Semaphore(max_concurrent)
        # PII + secrets only: used to scrub text before it goes to an external provider.
        self._scrubber = build_default_scanner(DetectorConfig(injection=InjectionConfig(enabled=False)))

    def _prepare(self, text: NormalizedText) -> str:
        if self._provider.sends_data_externally:
            scrubbed = redact(text.original, self._scrubber.scan(text).matches).text
            return normalize_text(scrubbed).text[: self._max_chars]
        return text.text[: self._max_chars]

    async def detect(self, text: NormalizedText, source: ContentSource) -> ModelDetectionResult:
        if self._budget is not None and not self._budget.try_acquire():
            return ModelDetectionResult(ModelStatus.BUDGET_EXHAUSTED)
        payload = self._prepare(text)
        try:
            async with self._sem:
                res = await asyncio.wait_for(self._provider.classify(payload, source), timeout=self._timeout)
        except asyncio.TimeoutError:
            return ModelDetectionResult(ModelStatus.TIMEOUT)
        except Exception:  # noqa: BLE001 - provider bugs/outages must not escape; the message may hold content
            return ModelDetectionResult(ModelStatus.ERROR)
        if not isinstance(res, ClassifierResult) or not isinstance(res.verdict, Verdict) \
                or not isinstance(res.score, (int, float)) or not 0.0 <= res.score <= 1.0:
            return ModelDetectionResult(ModelStatus.ERROR)
        if res.verdict is Verdict.BENIGN:
            return ModelDetectionResult(ModelStatus.OK)
        severity = Severity.HIGH if res.verdict is Verdict.INJECTION else Severity.MEDIUM
        conf = Confidence.HIGH if res.score >= 0.8 else Confidence.MEDIUM if res.score >= 0.5 else Confidence.LOW
        end = max(len(text.original), 1)
        m = Match(f"injection.model.{self._provider.name}", "model_classifier", "injection",
                  ReasonCode.PROMPT_INJECTION, severity, 55, 0, end, conf)
        return ModelDetectionResult(ModelStatus.OK, (m,))
