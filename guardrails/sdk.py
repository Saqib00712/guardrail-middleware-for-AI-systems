"""Developer-facing SDK: the small surface an application actually uses.

    from guardrails.sdk import Guardrails
    g = Guardrails.from_env()                 # strict production defaults
    result = g.check_input(user_text)
    prompt = result.require_text()            # raises GuardrailBlocked unless forwarding is allowed
"""
from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from dataclasses import replace

from guardrails.audit import AuditLogger, AuditUnavailable
from guardrails.decisions import Decision, PublicDecision
from guardrails.detectors.config import DetectorConfig
from guardrails.detectors.model_assisted import ModelAssistedDetector
from collections.abc import Sequence

from pydantic import BaseModel

from guardrails.detectors.scanner import build_default_scanner, build_output_scanner
from guardrails.output import OutputPipeline, StreamGuard
from guardrails.errors import GuardrailError
from guardrails.pipeline import GuardResult, InputPipeline, _fail
from guardrails.policy import Policy, PolicyRegistry, default_policy, policy_from_json_file
from guardrails.redaction import Style
from guardrails.metrics import Metrics
from guardrails.settings import Settings
from guardrails.tracing import Tracer, safe_span
from guardrails.tools import AgentContext, ApprovalManager, ToolGuard, ToolRegistry
from guardrails.types import ContentSource, ReasonCode


class GuardrailBlocked(GuardrailError):
    """Raised by `require_text()`. Carries only the safe, public decision."""

    code = ReasonCode.POLICY_DEFAULT
    default_public_message = "This request was blocked or needs review."

    def __init__(self, public: PublicDecision) -> None:
        super().__init__(public.message)
        self.public = public


class Guardrails:
    def __init__(self, settings: Settings | None = None, *, policy: Policy | None = None,
                 tenant_policies: dict[str, Policy] | None = None, detector_config: DetectorConfig | None = None,
                 model_detector: ModelAssistedDetector | None = None, redaction_style: Style = "label",
                 system_prompt: str | None = None, canaries: Sequence[str] = (),
                 allowed_url_hosts: Sequence[str] = (), audit: AuditLogger | None = None,
                 clock: Callable[[], float] = time.perf_counter, metrics: Metrics | None = None,
                 tracer: Tracer | None = None) -> None:
        self.settings = settings or Settings()
        self._audit = audit
        self.metrics = metrics
        self._tracer = tracer
        registry = self._registry = PolicyRegistry(policy or default_policy(), tenant_policies, self.settings)
        scanner = build_default_scanner(detector_config)
        self._pipeline = InputPipeline(self.settings, registry, scanner=scanner,
                                       model_detector=model_detector, style=redaction_style, clock=clock)
        self._output = OutputPipeline(
            self.settings, registry,
            build_output_scanner(detector_config, system_prompt=system_prompt, canaries=canaries,
                                 allowed_hosts=allowed_url_hosts),
            style=redaction_style, clock=clock)

    @classmethod
    def from_env(cls, **kw: Any) -> "Guardrails":
        return cls(Settings.from_env(), **kw)

    @classmethod
    def from_policy_file(cls, path: str | Path, settings: Settings | None = None, **kw: Any) -> "Guardrails":
        return cls(settings, policy=policy_from_json_file(path), **kw)

    def _audited(self, r: GuardResult, event_type: str, text: object, tenant_id: str | None,
                 user_id: str | None) -> GuardResult:
        """Audit the result, then count it. Every check passes through here exactly once."""
        final = self._write_audit(r, event_type, text, tenant_id, user_id)
        m = self.metrics
        if m is not None:
            d = final.decision
            secs = None if event_type == "output_stream" else final.elapsed_ms / 1000.0
            m.safe(m.record_decision, d.stage, d.action, d.reason_code, secs, final.degraded)
        return final

    def _write_audit(self, r: GuardResult, event_type: str, text: object, tenant_id: str | None,
                     user_id: str | None) -> GuardResult:
        """Write the audit record. If it cannot be written (and we fail closed), nothing is released."""
        if self._audit is None:
            return r
        try:
            self._audit.record_decision(event_type, r.decision, tenant_id=tenant_id, user_id=user_id,
                                        content_chars=len(text) if isinstance(text, str) else None,
                                        redactions=r.redactions, degraded=r.degraded)
        except AuditUnavailable:
            if self.metrics is not None:
                self.metrics.safe(self.metrics.inc, "guardrails_audit_failures_total", event_type)
            if self.settings.audit_failure_mode == "closed":
                if r.allowed:
                    stage = r.decision.stage
                    return _fail(ReasonCode.AUDIT_UNAVAILABLE, r.decision.request_id, time.perf_counter(), stage=stage)
                return r
            return replace(r, degraded=True)
        return r

    def check_input(self, text: str, *, source: ContentSource = ContentSource.USER_MESSAGE,
                    tenant_id: str | None = None, request_id: str | None = None,
                    content_type: str = "text/plain", context: AgentContext | None = None,
                    user_id: str | None = None) -> GuardResult:
        with safe_span(self._tracer, "guardrails.check_input") as sp:
            r = self._pipeline.check(self._request(text, source, request_id, content_type), tenant_id=tenant_id)
            if context is not None:
                context.observe(r, source)
            r = self._audited(r, "input_check", text, tenant_id, user_id)
            self._span_result(sp, r)
            return r

    async def acheck_input(self, text: str, *, source: ContentSource = ContentSource.USER_MESSAGE,
                           tenant_id: str | None = None, request_id: str | None = None,
                           content_type: str = "text/plain", context: AgentContext | None = None,
                           user_id: str | None = None) -> GuardResult:
        with safe_span(self._tracer, "guardrails.check_input") as sp:
            r = await self._pipeline.acheck(self._request(text, source, request_id, content_type), tenant_id=tenant_id)
            if context is not None:
                context.observe(r, source)
            r = self._audited(r, "input_check", text, tenant_id, user_id)
            self._span_result(sp, r)
            return r

    def check_output(self, text: str, *, tenant_id: str | None = None, schema: type[BaseModel] | None = None,
                     request_id: str | None = None, user_id: str | None = None) -> GuardResult:
        with safe_span(self._tracer, "guardrails.check_output") as sp:
            r = self._output.check(text, tenant_id=tenant_id, schema=schema, request_id=request_id)
            r = self._audited(r, "output_check", text, tenant_id, user_id)
            self._span_result(sp, r)
            return r

    @staticmethod
    def _span_result(sp: Any, r: GuardResult) -> None:
        d = r.decision
        sp.set_attribute("stage", d.stage)
        sp.set_attribute("action", d.action)
        sp.set_attribute("reason_code", d.reason_code)
        sp.set_attribute("degraded", r.degraded)
        sp.set_attribute("redactions", r.redactions)
        if d.request_id:
            sp.set_attribute("request_id", d.request_id)

    def stream_output(self, *, tenant_id: str | None = None, holdback: int = 256, request_id: str | None = None,
                      user_id: str | None = None) -> "StreamGuard | AuditedStream":
        sg = self._output.stream(tenant_id=tenant_id, holdback=holdback, request_id=request_id)
        return AuditedStream(sg, self, tenant_id, user_id) if (self._audit is not None or self.metrics is not None) else sg

    def tool_guard(self, registry: ToolRegistry, approvals: ApprovalManager | None = None) -> ToolGuard:
        """A ToolGuard that shares this instance's settings and policies. Freeze `registry` first."""
        return ToolGuard(registry, self.settings, self._registry, approvals=approvals, audit=self._audit)

    def public(self, result: GuardResult) -> PublicDecision:
        return result.decision.to_public(expose_reason_code=self.settings.expose_reason_codes)

    @staticmethod
    def _request(text: object, source: ContentSource, request_id: str | None, content_type: str) -> Mapping[str, Any]:
        # Passed as a plain mapping so that wrong types are rejected by the schema, not by us.
        d: dict[str, Any] = {"text": text, "source": source, "content_type": content_type}
        if request_id is not None:
            d["request_id"] = request_id
        return d


class AuditedStream:
    """A StreamGuard that writes ONE audit record when the stream ends or is cut.

    If that record cannot be written (closed mode) the stream is reported as cut. Text
    already sent cannot be recalled (see StreamGuard): audit failure at the very end can
    only stop what has not been released yet.
    """

    def __init__(self, inner: StreamGuard, g: "Guardrails", tenant_id: str | None, user_id: str | None) -> None:
        self._in, self._g, self._tenant, self._user = inner, g, tenant_id, user_id
        self._logged = False
        self._chars = 0

    @property
    def terminated(self) -> bool:
        return self._in.terminated

    @property
    def released_chars(self) -> int:
        return self._in.released_chars

    def _log(self, u: Any) -> Any:
        if self._logged or u.decision is None:
            return u
        self._logged = True
        d: Decision = u.decision
        r = self._g._audited(GuardResult(d, "" if d.permits_forwarding else None), "output_stream", None,
                             self._tenant, self._user)
        if r.decision is not d:  # audit failure turned an allow into a block
            self._in.terminated = True
            return type(u)("", True, r.decision)
        return u

    def feed(self, chunk: str) -> Any:
        return self._log(self._in.feed(chunk))

    def finish(self) -> Any:
        return self._log(self._in.finish())
