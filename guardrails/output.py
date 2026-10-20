"""Output guardrails: check what the model said BEFORE the user or a tool sees it.

`OutputPipeline.check(text)`  whole response (optionally validated against a schema).
`StreamGuard`                 incremental checking of a streamed response.

Same guarantees as the input pipeline (fail closed, text only when allowed, verified
sanitizing). Extra for output: system-prompt leakage, unsafe markup/URLs, strict
structured output.

STREAMING, honestly: a streamed response is released in pieces. The guard holds back
the last `holdback` characters so a finding that straddles two chunks is still seen,
but text ALREADY released can never be taken back. If a block happens mid-stream, the
earlier safe-looking part was already delivered; the stream is cut and the caller must
discard or mark the partial answer. A single finding longer than `holdback` characters
can slip across the window (the private-key rule is safe: it fires on the header alone),
and multi-signal escalation only counts signals inside one window.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel

from guardrails.decisions import Decision, most_restrictive
from guardrails.detectors.scanner import Scanner
from guardrails.errors import ConfigurationError
from guardrails.normalization import normalize_text
from guardrails.pipeline import GuardResult, InputPipeline, _fail, _ms, log
from guardrails.policy import PolicyRegistry
from guardrails.redaction import Style, redact
from guardrails.settings import Settings
from guardrails.structured import OutputInvalid, parse_structured, require_strict_schema
from guardrails.types import Action, ContentSource, ReasonCode, Stage
from guardrails.validation import ValidatedInput
from guardrails.decisions import new_request_id


class OutputPipeline:
    def __init__(self, settings: Settings, registry: PolicyRegistry, scanner: Scanner, *,
                 style: Style = "label", clock: Callable[[], float] = time.perf_counter) -> None:
        self._s, self._registry, self._scanner, self._style = settings, registry, scanner, style
        self._core = InputPipeline(settings, registry, scanner=scanner, style=style, stage=Stage.OUTPUT, clock=clock)

    def check(self, text: str, *, tenant_id: str | None = None, schema: type[BaseModel] | None = None,
              request_id: str | None = None) -> GuardResult:
        started = self._core._clock()
        if schema is not None:
            require_strict_schema(schema)  # programmer error: raise, do not turn into a decision
        rid = request_id or new_request_id()
        try:
            if not isinstance(text, str):
                return _fail(ReasonCode.INVALID_INPUT, rid, started, stage=Stage.OUTPUT)
            if len(text) > self._s.max_output_chars:
                return _fail(ReasonCode.OUTPUT_TOO_LONG, rid, started, stage=Stage.OUTPUT)
            try:
                text.encode("utf-8")
            except UnicodeEncodeError:
                return _fail(ReasonCode.INVALID_INPUT, rid, started, stage=Stage.OUTPUT)
            v = ValidatedInput(request_id=rid, content_type="text/plain", normalized=normalize_text(text),
                               source=ContentSource.MODEL_OUTPUT)
            res = self._core._run(v, tenant_id, started, model_matches=(), degraded=False)
            if schema is None or not res.allowed or res.text is None:
                return res
            try:
                parsed = parse_structured(res.text, schema, self._s)
            except OutputInvalid:
                return _fail(ReasonCode.OUTPUT_SCHEMA_INVALID, rid, started, stage=Stage.OUTPUT)
            return GuardResult(res.decision, res.text, res.redactions, res.by_category, res.degraded,
                               _ms(started), res.evaluation, parsed)
        except ConfigurationError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("output guardrail internal error: %s", type(exc).__name__)
            return _fail(ReasonCode.INTERNAL_ERROR, rid, started, stage=Stage.OUTPUT)

    def stream(self, *, tenant_id: str | None = None, holdback: int = 256, request_id: str | None = None) -> "StreamGuard":
        return StreamGuard(self, tenant_id=tenant_id, holdback=holdback, request_id=request_id)


@dataclass(frozen=True)
class StreamUpdate:
    text: str                       # safe text to send now (may be empty)
    terminated: bool = False        # the stream was cut; send nothing more
    decision: Decision | None = None  # set when terminated, and on finish()


class StreamGuard:
    def __init__(self, pipeline: OutputPipeline, *, tenant_id: str | None, holdback: int, request_id: str | None) -> None:
        if not 32 <= holdback <= 8192:
            raise ConfigurationError("holdback must be between 32 and 8192 characters")
        self._p, self._tenant, self._hold = pipeline, tenant_id, holdback
        self._rid = request_id or new_request_id()
        self._buf = ""
        self._total = 0
        self._worst: Decision | None = None
        self.terminated = False
        self.released_chars = 0

    # ------------------------------------------------------------------ public
    def feed(self, chunk: str) -> StreamUpdate:
        if self.terminated:
            return StreamUpdate("", True, self._worst)
        try:
            if not isinstance(chunk, str):
                return self._stop(ReasonCode.INVALID_INPUT)
            self._total += len(chunk)
            if self._total > self._p._s.max_output_chars:
                return self._stop(ReasonCode.OUTPUT_TOO_LONG)
            self._buf += chunk
            return self._step(final=False)
        except Exception as exc:  # noqa: BLE001
            log.error("stream guard internal error: %s", type(exc).__name__)
            return self._stop(ReasonCode.INTERNAL_ERROR)

    def finish(self) -> StreamUpdate:
        if self.terminated:
            return StreamUpdate("", True, self._worst)
        try:
            u = self._step(final=True)
            if u.terminated:
                return u
            d = self._worst or Decision.allow(Stage.OUTPUT, policy_id="builtin.stream", policy_version=1,
                                              request_id=self._rid)
            return StreamUpdate(u.text, False, d)
        except Exception as exc:  # noqa: BLE001
            log.error("stream guard internal error: %s", type(exc).__name__)
            return self._stop(ReasonCode.INTERNAL_ERROR)

    # ------------------------------------------------------------------ internals
    def _stop(self, code: ReasonCode) -> StreamUpdate:
        self.terminated, self._buf = True, ""
        self._worst = _fail(code, self._rid, time.perf_counter(), stage=Stage.OUTPUT).decision
        return StreamUpdate("", True, self._worst)

    def _step(self, *, final: bool) -> StreamUpdate:
        p = self._p
        buf = self._buf
        if not buf:
            return StreamUpdate("")
        nt = normalize_text(buf)
        v = ValidatedInput(self._rid, "text/plain", nt, ContentSource.MODEL_OUTPUT)
        matches = list(p._scanner.scan(nt, ContentSource.MODEL_OUTPUT).matches)
        unremovable = v.findings()
        findings = tuple(m.to_finding() for m in matches) + unremovable
        ev = p._registry.engine_for(self._tenant).evaluate(findings, Stage.OUTPUT, request_id=self._rid)
        d = ev.decision
        if d.action is Action.SANITIZE and unremovable:
            d = d.model_copy(update={"action": Action.REQUIRE_REVIEW})
        if not d.permits_forwarding:  # block or review: a stream has no human in the loop, so cut it
            self.terminated, self._buf, self._worst = True, "", d
            return StreamUpdate("", True, d)
        self._worst = most_restrictive([x for x in (self._worst, d) if x is not None])

        if final:
            boundary = len(buf)
        else:
            boundary = max(0, len(buf) - self._hold)
            changed = True
            while changed:  # never cut a finding in half: wait for more text
                changed = False
                for m in matches:
                    if m.start < boundary < m.end:
                        boundary, changed = m.start, True
        out = buf[:boundary]
        if d.action is Action.SANITIZE:
            out = redact(out, [m for m in matches if m.end <= boundary], style=p._style).text
            left = p._scanner.scan(normalize_text(out), ContentSource.MODEL_OUTPUT).matches
            if left:  # verify what we release
                self.terminated, self._buf = True, ""
                self._worst = d.model_copy(update={"action": Action.BLOCK, "reason_code": left[0].reason_code})
                return StreamUpdate("", True, self._worst)
        self._buf = buf[boundary:]
        self.released_chars += len(out)
        return StreamUpdate(out)
