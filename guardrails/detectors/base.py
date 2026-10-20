"""Detector building blocks.

A detector reads a `NormalizedText` and returns `Match`es. A Match records WHAT
and WHERE (offsets into the ORIGINAL text) but never the matched value, so
matches, findings and audit records cannot leak what they found.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from guardrails.decisions import Finding
from guardrails.detectors.config import AllowSpec
from guardrails.normalization import NormalizedText
from guardrails.types import Confidence, ReasonCode, Severity

Kind = Literal["pii", "secret", "injection", "unsafe", "leak"]
MAX_ALLOW_VALUE_CHARS = 256


@dataclass(frozen=True)
class Match:
    detector_id: str   # e.g. "pii.email"
    category: str      # e.g. "email"   (becomes the redaction label)
    kind: Kind
    reason_code: ReasonCode
    severity: Severity
    priority: int      # higher wins when spans overlap
    start: int         # ORIGINAL text offsets
    end: int
    confidence: Confidence = Confidence.HIGH

    def to_finding(self) -> Finding:
        return Finding(detector_id=self.detector_id, reason_code=self.reason_code, severity=self.severity,
                       category=self.category, confidence=self.confidence, start=self.start, end=self.end)


class Detector(Protocol):
    def detect(self, text: NormalizedText) -> list[Match]: ...


class Allowlist:
    def __init__(self, spec: AllowSpec) -> None:
        self._exact = frozenset(x.strip().lower() for x in spec.exact)
        self._regexes = tuple(re.compile(r) for r in spec.regex)

    def allows(self, value: str) -> bool:
        if len(value) > MAX_ALLOW_VALUE_CHARS:
            return False
        if value.strip().lower() in self._exact:
            return True
        return any(r.fullmatch(value) for r in self._regexes)


@dataclass(frozen=True)
class Rule:
    detector_id: str
    category: str
    kind: Kind
    severity: Severity
    priority: int
    pattern: re.Pattern[str]
    group: int = 0
    validator: Callable[[str], bool] | None = None
    confidence: Confidence = Confidence.HIGH
    reason: ReasonCode | None = None

    @property
    def reason_code(self) -> ReasonCode:
        if self.reason is not None:
            return self.reason
        return ReasonCode.PII_DETECTED if self.kind == "pii" else ReasonCode.SECRET_DETECTED


class RegexDetector:
    def __init__(self, rules: Sequence[Rule], allow: Allowlist) -> None:
        self.rules = tuple(rules)
        self._allow = allow

    def detect(self, text: NormalizedText) -> list[Match]:
        t = text.text
        out: list[Match] = []
        for rule in self.rules:
            for m in rule.pattern.finditer(t):
                s, e = m.span(rule.group)
                if s < 0 or e <= s:
                    continue
                value = t[s:e]
                if rule.validator is not None and not rule.validator(value):
                    continue
                if self._allow.allows(value):
                    continue
                os_, oe = text.original_span(s, e)
                out.append(Match(rule.detector_id, rule.category, rule.kind, rule.reason_code,
                                 rule.severity, rule.priority, os_, oe, rule.confidence))
        return out
