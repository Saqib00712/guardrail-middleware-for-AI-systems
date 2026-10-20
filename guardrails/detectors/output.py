"""Detectors that only make sense on MODEL OUTPUT.

* UnsafeContentDetector  - things that become dangerous when a UI renders the
  output: images/links that can smuggle data out, active HTML, script URLs.
* PromptLeakDetector     - the model repeating the operator's system prompt:
  canary tokens (exact) and long word-for-word overlap (shingles).

Both return Matches with offsets into the ORIGINAL text and never store matched text.
Known limits: a paraphrased prompt is not detected; a prompt shorter than the shingle
size can only be protected by canaries; URL checks look at markdown and basic HTML only.
"""
from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from guardrails.detectors.base import Match
from guardrails.errors import ConfigurationError
from guardrails.normalization import NormalizedText
from guardrails.types import Confidence, ReasonCode, Severity

_MD_IMAGE = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*<?(https?://[^)\s>]{1,2000})[^)\n]{0,200}\)", re.I)
_HTML_IMG = re.compile(r"<\s*img\b[^>]{0,500}?\bsrc\s*=\s*[\"']?(https?://[^\"'\s>]{1,2000})[^>]{0,500}>", re.I)
_ACTIVE_TAG = re.compile(r"<\s*/?\s*(script|iframe|object|embed|form|meta|base|link|style)\b[^>]{0,500}>?", re.I)
_EVENT_ATTR = re.compile(r"<[a-z][^>]{0,300}?\son[a-z]{3,20}\s*=", re.I)
_SCRIPT_URL = re.compile(r"(?:javascript|vbscript)\s*:|data\s*:\s*text/html", re.I)
EXFIL_URL_CHARS = 48  # query/fragment/path data longer than this looks like a data channel


def _host_allowed(host: str, allowed: frozenset[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowed)


class UnsafeContentDetector:
    def __init__(self, allowed_hosts: Sequence[str] = ()) -> None:
        self._allowed = frozenset(h.strip().lower().rstrip(".") for h in allowed_hosts if h.strip())

    def detect(self, text: NormalizedText) -> list[Match]:
        t, out = text.text, []

        def add(s: int, e: int, det: str, cat: str, sev: Severity) -> None:
            os_, oe = text.original_span(s, e)
            out.append(Match(det, cat, "unsafe", ReasonCode.UNSAFE_CONTENT, sev, 60, os_, oe, Confidence.HIGH))

        for pat in (_MD_IMAGE, _HTML_IMG):
            for m in pat.finditer(t):
                try:
                    u = urlsplit(m.group(1))
                    host = u.hostname or ""
                except ValueError:
                    host, u = "", None
                if host and _host_allowed(host, self._allowed):
                    continue
                data = (len(u.query) + len(u.fragment) + len(u.path)) if u else 999
                if data > EXFIL_URL_CHARS or (u and (u.query or u.fragment)):
                    add(m.start(), m.end(), "output.image-exfiltration", "image_exfiltration", Severity.HIGH)
                else:
                    add(m.start(), m.end(), "output.external-image", "external_image", Severity.MEDIUM)
        for m in _ACTIVE_TAG.finditer(t):
            add(m.start(), m.end(), "output.active-html", "active_html", Severity.HIGH)
        for m in _EVENT_ATTR.finditer(t):
            add(m.start(), m.end(), "output.event-handler", "active_html", Severity.HIGH)
        for m in _SCRIPT_URL.finditer(t):
            add(m.start(), m.end(), "output.script-url", "script_url", Severity.HIGH)
        return out


_WORD = re.compile(r"\w+", re.UNICODE)


class PromptLeakDetector:
    def __init__(self, system_prompt: str | None = None, canaries: Sequence[str] = (), *, ngram: int = 8) -> None:
        if ngram < 5 or ngram > 40:
            raise ConfigurationError("ngram must be between 5 and 40")
        for c in canaries:
            if not (8 <= len(c) <= 128) or not c.isprintable():
                raise ConfigurationError("each canary must be 8..128 printable characters")
        self._canaries = tuple(c.lower() for c in canaries)
        self._n = ngram
        self._shingles: frozenset[tuple[str, ...]] = frozenset()
        if system_prompt:
            words = [w.lower() for w in _WORD.findall(system_prompt)]
            self._shingles = frozenset(tuple(words[i:i + ngram]) for i in range(len(words) - ngram + 1))

    @property
    def active(self) -> bool:
        return bool(self._canaries or self._shingles)

    def detect(self, text: NormalizedText) -> list[Match]:
        t, out = text.text, []
        low = t.lower()
        for c in self._canaries:
            start = 0
            while (i := low.find(c, start)) != -1:
                os_, oe = text.original_span(i, i + len(c))
                out.append(Match("output.prompt-canary", "prompt_canary", "leak", ReasonCode.SYSTEM_PROMPT_EXTRACTION,
                                 Severity.CRITICAL, 90, os_, oe, Confidence.HIGH))
                start = i + len(c)
        if self._shingles:
            ws = [(m.group().lower(), m.start(), m.end()) for m in _WORD.finditer(t)]
            n, i = self._n, 0
            hit_runs: list[tuple[int, int]] = []
            while i + n <= len(ws):
                if tuple(w for w, _, _ in ws[i:i + n]) in self._shingles:
                    s_idx, j = i, i + n
                    while j < len(ws) and tuple(w for w, _, _ in ws[j - n + 1:j + 1]) in self._shingles:
                        j += 1
                    hit_runs.append((ws[s_idx][1], ws[j - 1][2]))
                    i = j
                else:
                    i += 1
            for s, e in hit_runs:
                os_, oe = text.original_span(s, e)
                out.append(Match("output.prompt-overlap", "system_prompt_leak", "leak",
                                 ReasonCode.SYSTEM_PROMPT_EXTRACTION, Severity.HIGH, 80, os_, oe, Confidence.HIGH))
        return out
