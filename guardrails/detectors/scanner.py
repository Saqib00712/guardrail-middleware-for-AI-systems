"""Run all configured detectors over one NormalizedText."""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from guardrails.decisions import Finding
from guardrails.detectors.base import Detector, Match
from guardrails.detectors.config import DetectorConfig
from guardrails.detectors.injection import InjectionDetector
from guardrails.detectors.pii import build_pii_detector
from guardrails.detectors.secrets import build_secret_detector
from guardrails.normalization import NormalizedText
from guardrails.types import ContentSource


@dataclass(frozen=True)
class ScanResult:
    matches: tuple[Match, ...]

    def findings(self) -> tuple[Finding, ...]:
        return tuple(m.to_finding() for m in self.matches)

    def counts_by_category(self) -> dict[str, int]:
        return dict(sorted(Counter(m.category for m in self.matches).items()))

    @property
    def has_secrets(self) -> bool:
        return any(m.kind == "secret" for m in self.matches)


class Scanner:
    def __init__(self, detectors: Sequence[Detector]) -> None:
        self._detectors = tuple(detectors)

    def scan(self, text: NormalizedText, source: ContentSource = ContentSource.USER_MESSAGE) -> ScanResult:
        found: list[Match] = []
        for d in self._detectors:
            if getattr(d, "contextual", False):
                found.extend(d.detect_with_source(text, source))  # type: ignore[attr-defined]
            else:
                found.extend(d.detect(text))
        # Stable, deterministic order regardless of detector registration order.
        found.sort(key=lambda m: (m.start, m.end, m.detector_id))
        return ScanResult(tuple(found))


def build_default_scanner(config: DetectorConfig | None = None) -> Scanner:
    cfg = config or DetectorConfig()
    detectors: list[Detector] = [build_pii_detector(cfg)]
    if cfg.secrets_enabled:
        detectors.append(build_secret_detector(cfg))
    if cfg.injection.enabled:
        detectors.append(InjectionDetector(cfg.injection))
    return Scanner(detectors)


def build_output_scanner(config: DetectorConfig | None = None, *, system_prompt: str | None = None,
                         canaries: Sequence[str] = (), allowed_hosts: Sequence[str] = (),
                         ngram: int = 8) -> Scanner:
    """Scanner for MODEL OUTPUT: everything the input scanner has, plus unsafe-content and prompt-leak checks."""
    from guardrails.detectors.output import PromptLeakDetector, UnsafeContentDetector

    base = build_default_scanner(config)
    detectors: list[Detector] = list(base._detectors) + [UnsafeContentDetector(allowed_hosts)]
    leak = PromptLeakDetector(system_prompt, canaries, ngram=ngram)
    if leak.active:
        detectors.append(leak)
    return Scanner(detectors)
