"""Request validation: the first gate, before any detector runs.

Order of checks is chosen so the cheap ones run first and nothing expensive
(normalization, regexes) ever touches oversized or malformed input:

  body bytes -> size -> UTF-8 -> JSON depth pre-scan -> JSON parse -> schema ->
  content type -> character limit -> blank -> encodable -> (JSON payload checks) -> normalize

Failures raise `InputRejected` with a fixed public message that never echoes
client-supplied text. `reject_decision()` turns one into a typed block Decision.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardrails.decisions import Decision, Finding, new_request_id
from guardrails.errors import InputRejected
from guardrails.normalization import FlagKind, NormalizedText, normalize_text
from guardrails.settings import Settings
from guardrails.types import Action, ContentSource, ReasonCode, Severity, Stage

ALLOWED_CONTENT_TYPES = frozenset({"text/plain", "text/markdown", "application/json"})
HARD_MAX_TEXT_CHARS = 1_000_000   # schema ceiling; the configurable limit is Settings.max_input_chars
MAX_JSON_NODES = 100_000
VALIDATION_POLICY_ID = "builtin.input-validation"

_KNOWN_FIELDS = {"text", "content_type", "request_id", "source"}


class InspectRequest(BaseModel):
    """Wire schema for an input-inspection request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(strict=True, max_length=HARD_MAX_TEXT_CHARS)
    content_type: str = Field(default="text/plain", strict=True, max_length=100)
    request_id: str | None = Field(default=None, strict=True, pattern=r"^[A-Za-z0-9._-]{1,64}$")
    # Where the text came from. Untrusted sources (documents, web pages, tool output) are
    # held to a stricter standard than a direct user message.
    source: ContentSource = ContentSource.USER_MESSAGE


@dataclass(frozen=True)
class ValidatedInput:
    request_id: str
    content_type: str
    normalized: NormalizedText
    source: ContentSource = ContentSource.USER_MESSAGE

    @property
    def original(self) -> str:
        return self.normalized.original

    @property
    def text(self) -> str:
        """The normalized copy detectors should read."""
        return self.normalized.text

    def findings(self) -> tuple[Finding, ...]:
        """Normalization flags as Findings (offsets into the ORIGINAL text)."""
        return tuple(
            Finding(detector_id="normalizer", reason_code=ReasonCode.SUSPICIOUS_ENCODING,
                    severity=_FLAG_SEVERITY[f.kind], category=f.kind.value,
                    start=f.first_start, end=f.first_end)
            for f in self.normalized.flags
        )


_FLAG_SEVERITY = {
    FlagKind.TAG_CHARACTERS: Severity.HIGH,
    FlagKind.BIDI_OVERRIDE: Severity.MEDIUM,
    FlagKind.INVISIBLE_IN_WORD: Severity.MEDIUM,
    FlagKind.MIXED_SCRIPT_WORD: Severity.MEDIUM,
    FlagKind.COMPAT_LATIN: Severity.LOW,
    FlagKind.CONTROL_CHARACTERS: Severity.LOW,
    FlagKind.EXCESSIVE_REPETITION: Severity.LOW,
}


# ---------------------------------------------------------------------------- JSON helpers
def json_depth_exceeds(text: str, max_depth: int) -> bool:
    """Linear scan, no recursion: True if brackets nest deeper than max_depth.
    Runs BEFORE json.loads so a hostile "[[[[..." can never reach the parser."""
    depth = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                return True
        elif ch in "]}" and depth > 0:
            depth -= 1
    return False


def _count_nodes_exceeds(value: Any, limit: int) -> bool:
    stack = [value]
    seen = 0
    while stack:
        v = stack.pop()
        seen += 1
        if seen > limit:
            return True
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return False


def _parse_json(text: str, settings: Settings, *, what: str) -> Any:
    if json_depth_exceeds(text, settings.max_nesting_depth):
        raise InputRejected(ReasonCode.INVALID_INPUT, f"{what} is nested too deeply")
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        raise InputRejected(ReasonCode.INVALID_INPUT, f"{what} is not valid JSON") from None
    if _count_nodes_exceeds(value, MAX_JSON_NODES):
        raise InputRejected(ReasonCode.INVALID_INPUT, f"{what} has too many elements")
    return value


# ---------------------------------------------------------------------------- entry points
def parse_json_body(body: bytes, settings: Settings) -> dict[str, Any]:
    """Turn raw request bytes into a dict, or raise InputRejected."""
    if not isinstance(body, (bytes, bytearray)):
        raise InputRejected(ReasonCode.INVALID_INPUT, "request body must be bytes")
    if len(body) > settings.max_request_body_bytes:
        raise InputRejected(ReasonCode.INPUT_TOO_LONG, "request body is too large")
    try:
        text = bytes(body).decode("utf-8")
    except UnicodeDecodeError:
        raise InputRejected(ReasonCode.INVALID_INPUT, "request body is not valid UTF-8") from None
    value = _parse_json(text, settings, what="request body")
    if not isinstance(value, dict):
        raise InputRejected(ReasonCode.INVALID_INPUT, "request body must be a JSON object")
    return value


def _safe_field(loc: tuple[Any, ...]) -> str:
    # Field names in errors may be attacker-chosen (extra keys): echo only known ones.
    name = str(loc[0]) if loc else "request"
    return name if name in _KNOWN_FIELDS else "<unknown field>"


def _schema_check(raw: Mapping[str, Any] | InspectRequest) -> InspectRequest:
    if isinstance(raw, InspectRequest):
        return raw
    if not isinstance(raw, Mapping):
        raise InputRejected(ReasonCode.INVALID_INPUT, "request must be an object")
    try:
        return InspectRequest.model_validate(dict(raw))
    except ValidationError as exc:
        parts = sorted({f"{_safe_field(e['loc'])} ({e['type']})"
                        for e in exc.errors(include_input=False, include_url=False, include_context=False)})
        raise InputRejected(ReasonCode.INVALID_INPUT, "invalid request: " + ", ".join(parts)) from None


def validate_input(raw: Mapping[str, Any] | InspectRequest, settings: Settings) -> ValidatedInput:
    """Validate, then normalize. Raises InputRejected; never returns partial results."""
    req = _schema_check(raw)

    content_type = req.content_type.split(";", 1)[0].strip().lower()
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise InputRejected(ReasonCode.UNSUPPORTED_CONTENT_TYPE, "unsupported content type")

    if len(req.text) > settings.max_input_chars:
        raise InputRejected(ReasonCode.INPUT_TOO_LONG, "input is too long")
    if not req.text.strip():
        raise InputRejected(ReasonCode.INVALID_INPUT, "input is empty")
    try:
        req.text.encode("utf-8")  # lone surrogates cannot be stored or logged safely
    except UnicodeEncodeError:
        raise InputRejected(ReasonCode.INVALID_INPUT, "input contains invalid characters") from None

    if content_type == "application/json":
        _parse_json(req.text, settings, what="JSON content")

    normalized = normalize_text(req.text)
    if not normalized.text.strip():
        # Only invisible/control characters: nothing real to inspect (and a classic padding trick).
        raise InputRejected(ReasonCode.INVALID_INPUT, "input is empty")
    return ValidatedInput(request_id=req.request_id or new_request_id(), content_type=content_type,
                          normalized=normalized, source=req.source)


def reject_decision(exc: InputRejected, *, request_id: str | None = None) -> Decision:
    """A rejected request as a typed, blocking Decision (for audit and the pipeline)."""
    return Decision(action=Action.BLOCK, reason_code=exc.code, severity=Severity.MEDIUM,
                    stage=Stage.INPUT, policy_id=VALIDATION_POLICY_ID, policy_version=1,
                    request_id=request_id)
