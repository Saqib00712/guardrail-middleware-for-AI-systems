"""Layered prompt-injection detector (deterministic layer).

Layers, all offline and deterministic:
 1. source-aware rules on the normalized text            (injection_rules.py)
 2. decode-and-rescan: base64, hex, URL, \\uXXXX, HTML entities, ROT13, leetspeak
    (decoding.py); a hit inside an encoded payload is a strong signal on its own
 3. escalation: several distinct signals in one text add a "multiple_signals" finding
    (repetition / piling-on is itself evidence)

The optional model-assisted layer lives in model_assisted.py and is never required.
"""
from __future__ import annotations

from guardrails.detectors.base import Allowlist, Match
from guardrails.detectors.config import InjectionConfig
from guardrails.detectors.decoding import derive
from guardrails.detectors.injection_rules import RULES
from guardrails.normalization import NormalizedText
from guardrails.types import Confidence, ContentSource, ReasonCode, Severity


class InjectionDetector:
    contextual = True  # the Scanner passes the content source to detect_with_source()

    def __init__(self, config: InjectionConfig | None = None) -> None:
        self._cfg = config or InjectionConfig()
        self._allow = Allowlist(self._cfg.allow)

    # Detector protocol: treat plain detect() as a direct user message.
    def detect(self, text: NormalizedText) -> list[Match]:
        return self.detect_with_source(text, ContentSource.USER_MESSAGE)

    def _apply_rules(self, t: str, source: ContentSource) -> list[tuple[object, int, int]]:
        hits = []
        for ir in RULES:
            if not ir.applies_to(source):
                continue
            for m in ir.rule.pattern.finditer(t):
                if m.end() > m.start():
                    hits.append((ir.rule, m.start(), m.end()))
        return hits

    def detect_with_source(self, text: NormalizedText, source: ContentSource) -> list[Match]:
        if not self._cfg.enabled:
            return []
        t = text.text
        out: list[Match] = []

        # Layer 1: plain text
        for rule, s, e in self._apply_rules(t, source):
            if self._allow.allows(t[s:e]):
                continue
            os_, oe = text.original_span(s, e)
            out.append(Match(rule.detector_id, rule.category, "injection", rule.reason_code, rule.severity,
                             rule.priority, os_, oe, rule.confidence))

        # Layer 2: decode-and-rescan (bounded)
        cfg = self._cfg
        budget_hit = False
        scanned_chars = 0
        derived_count = 0
        seen_regions: set[tuple[str, int, int]] = set()
        # queue items: (text, depth, top_region) ; top_region None => same-length transform of the full text
        queue: list[tuple[str, int, tuple[int, int] | None]] = [(t, 0, None)]
        while queue:
            current, depth, top = queue.pop(0)
            if depth >= cfg.max_decode_depth:
                continue
            derived, cut = derive(current, max_candidates=cfg.max_decode_candidates)
            budget_hit = budget_hit or cut
            for d in derived:
                derived_count += 1
                scanned_chars += len(d.text)
                if derived_count > cfg.max_derived_texts or scanned_chars > cfg.max_derived_chars:
                    budget_hit = True
                    queue.clear()
                    break
                # where this derived text sits in the level-0 (normalized) text
                if depth == 0:
                    region = d.region          # None for whole-text transforms
                else:
                    region = top               # nested: report the outermost payload
                    if region is None:
                        continue               # whole-text transforms are not decoded further
                hit_rules = self._apply_rules(d.text, source)
                for rule, s, e in hit_rules:
                    if self._allow.allows(d.text[s:e]):
                        continue
                    if region is None:        # rot13 / leetspeak: same length, positions line up
                        a, b = s, e
                    else:
                        a, b = region
                    key = (d.kind, a, b)
                    if key in seen_regions:
                        continue
                    seen_regions.add(key)
                    os_, oe = text.original_span(a, b)
                    kind_slug = d.kind.replace("_", "-")
                    category = "obfuscated_text" if d.kind in ("rot13", "leetspeak") else "encoded_payload"
                    out.append(Match(f"injection.{category.replace('_', '-')}.{kind_slug}", category, "injection",
                                     ReasonCode.PROMPT_INJECTION, Severity.HIGH, 60, os_, oe, Confidence.HIGH))
                if d.kind not in ("rot13", "leetspeak"):
                    queue.append((d.text, depth + 1, region))
        if budget_hit and t:
            os_, oe = text.original_span(0, len(t))
            out.append(Match("injection.decode-budget", "decode_budget_exhausted", "injection",
                             ReasonCode.SUSPICIOUS_ENCODING, Severity.MEDIUM, 40, os_, oe, Confidence.HIGH))

        # Layer 3: escalation on accumulated evidence
        distinct = {(m.start, m.end) for m in out if m.category not in ("decode_budget_exhausted",)}
        if len(distinct) >= cfg.escalation_threshold:
            lo = min(m.start for m in out)
            hi = max(m.end for m in out)
            out.append(Match("injection.multiple-signals", "multiple_signals", "injection",
                             ReasonCode.PROMPT_INJECTION, Severity.HIGH, 70, lo, hi, Confidence.HIGH))
        return out
