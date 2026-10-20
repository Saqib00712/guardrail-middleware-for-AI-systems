"""Deterministic redaction.

Redaction edits the ORIGINAL text using the spans in `Match`es.

Overlaps: matches whose spans overlap are merged into ONE span covering their union
(so no part of any of them is left exposed), labeled by the highest-priority match
(ties: longer span, then earlier start, then category name). Touching-but-not-
overlapping spans stay separate.

Styles:
* "label"   -> [REDACTED_EMAIL]. Simplest; all values of a category look the same.
* "indexed" -> [EMAIL_1], [EMAIL_2]. The same value gets the same number within one
               text, so a model can still tell "same person" from "different people".
               Still irreversible: no mapping is kept anywhere.

Downstream quality: redaction is lossy by design. A model asked "what is this
candidate's email?" cannot answer once the email is removed; "indexed" keeps
coreference ("the first email") but not content. Redact only what a boundary
must not carry, and prefer allow/block decisions when content IS the point.
"""
from __future__ import annotations

import re
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from typing import Literal

from guardrails.detectors.base import Match

Style = Literal["label", "indexed"]


@dataclass(frozen=True)
class RedactionResult:
    text: str
    redacted_count: int
    by_category: dict[str, int]


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    category: str


def _label_key(m: Match) -> tuple[int, int, int, str]:
    return (m.priority, m.end - m.start, -m.start, m.category)


def merge_spans(matches: Sequence[Match]) -> list[_Span]:
    ordered = sorted(matches, key=lambda m: (m.start, m.end))
    spans: list[_Span] = []
    group: list[Match] = []
    group_end = -1

    def flush() -> None:
        if group:
            winner = max(group, key=_label_key)
            spans.append(_Span(min(m.start for m in group), max(m.end for m in group), winner.category))

    for m in ordered:
        if group and m.start < group_end:
            group.append(m)
            group_end = max(group_end, m.end)
        else:
            flush()
            group = [m]
            group_end = m.end
    flush()
    return spans


def redact(original: str, matches: Sequence[Match], *, style: Style = "label",
           categories: Collection[str] | None = None) -> RedactionResult:
    """Replace matched spans in `original`. `categories=None` redacts everything given."""
    chosen = [m for m in matches if categories is None or m.category in categories]
    for m in chosen:
        if not (0 <= m.start < m.end <= len(original)):
            raise ValueError("match span is outside the text")
    if not chosen:
        return RedactionResult(original, 0, {})

    pieces: list[str] = []
    cursor = 0
    counts: dict[str, int] = {}
    seen: dict[str, dict[str, int]] = {}
    for span in merge_spans(chosen):
        pieces.append(original[cursor:span.start])
        if style == "indexed":
            key = re.sub(r"[\s\-().]", "", original[span.start:span.end]).lower()
            table = seen.setdefault(span.category, {})
            idx = table.setdefault(key, len(table) + 1)
            pieces.append(f"[{span.category.upper()}_{idx}]")
        else:
            pieces.append(f"[REDACTED_{span.category.upper()}]")
        counts[span.category] = counts.get(span.category, 0) + 1
        cursor = span.end
    pieces.append(original[cursor:])
    return RedactionResult("".join(pieces), sum(counts.values()), dict(sorted(counts.items())))
