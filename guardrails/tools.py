"""Tool authorization and agent protection.

An agent that can call tools is the most dangerous place for a prompt injection to land,
because the injected text can make the MODEL act. This module decides, for every tool
call the model wants to make, whether it may proceed. Nothing here trusts the model.

Rules (each is tested):
* **Allowlist only.** A tool must be registered by the operator; the registry is frozen
  after setup so a running agent cannot add tools. Names are matched exactly (no case
  folding, no Unicode tricks); anything else is "unknown".
* **Roles and tenants are checked per call**, from the caller's Principal, never from
  anything the model wrote.
* **Arguments are validated strictly** against the tool's pydantic model (extra fields
  forbidden). The caller must run the tool with the returned, validated arguments.
* **Arguments are scanned** for secrets, card/ID numbers, injection text and hidden
  characters. Arguments are never silently rewritten: "sanitize" becomes "needs review".
* **Taint tracking.** Once untrusted content (web page, document, tool output) has been
  seen, external/destructive tools need human approval; once it looked like an injection,
  external/destructive tools are blocked and write tools need approval.
* **Approvals** are signed, short-lived, single-use, and bound to the exact tool, exact
  arguments, user and tenant. The approver must hold the approver role and (by default)
  must not be the requester.
* **Loop and volume limits** per agent run.

Limits: used-approval records are in memory (one process; share a store for several).
Taint is only as good as the injection detector. Tool OUTPUT must be passed through
`Guardrails.check_input(..., source=TOOL_OUTPUT, context=ctx)` so taint is recorded.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardrails.audit import AuditLogger, AuditUnavailable
from guardrails.decisions import Decision, Finding, new_request_id
from guardrails.detectors.config import DetectorConfig
from guardrails.detectors.scanner import Scanner, build_default_scanner
from guardrails.errors import ConfigurationError
from guardrails.normalization import normalize_text
from guardrails.pipeline import GuardResult
from guardrails.policy import PolicyRegistry
from guardrails.settings import Settings
from guardrails.types import Action, Confidence, ContentSource, ReasonCode, Severity, Stage
from guardrails.validation import ValidatedInput, json_depth_exceeds

TOOL_POLICY_ID = "builtin.tools"
_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_IDENT = r"^[A-Za-z0-9_.@:-]{1,128}$"
_ROLE = r"^[a-z][a-z0-9_-]{0,31}$"
MAX_LEAVES = 500


class Risk(StrEnum):
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"        # can send data out of the system (email, HTTP, chat)
    DESTRUCTIVE = "destructive"  # deletes or irreversibly changes things


class Principal(BaseModel):
    """Who is acting. Comes from authentication, never from model output."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    user_id: str = Field(pattern=_IDENT)
    tenant_id: str = Field(pattern=_IDENT)
    roles: frozenset[str] = frozenset()


class ToolSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    name: str = Field(pattern=_NAME.pattern)
    description: str = Field(max_length=300)
    args_model: type[BaseModel]
    risk: Risk
    allowed_roles: frozenset[str] = Field(min_length=1)
    allowed_tenants: frozenset[str] | None = None   # None = any tenant
    requires_approval: bool | None = None            # None = default by risk
    max_arg_chars: int = Field(default=10_000, ge=2, le=100_000)

    def model_post_init(self, _ctx: Any) -> None:
        if self.args_model.model_config.get("extra") != "forbid":
            raise ValueError("args_model must set extra='forbid'")
        for r in self.allowed_roles:
            if not re.match(_ROLE, r):
                raise ValueError("invalid role name")

    @property
    def approval_by_default(self) -> bool:
        if self.requires_approval is not None:
            return self.requires_approval
        return self.risk in (Risk.EXTERNAL, Risk.DESTRUCTIVE)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._frozen = False

    def register(self, spec: ToolSpec) -> None:
        if self._frozen:
            raise ConfigurationError("tool registry is frozen")
        if spec.name in self._tools:
            raise ConfigurationError("tool is already registered")
        self._tools[spec.name] = spec

    def freeze(self) -> "ToolRegistry":
        self._frozen = True
        return self

    @property
    def frozen(self) -> bool:
        return self._frozen

    def get(self, name: object) -> ToolSpec | None:
        return self._tools.get(name) if isinstance(name, str) and _NAME.match(name) else None


# ------------------------------------------------------------------------------ agent context
_INJECTION_CODES = {ReasonCode.PROMPT_INJECTION, ReasonCode.SYSTEM_PROMPT_EXTRACTION}


@dataclass
class AgentContext:
    """State of ONE agent run. Create a fresh one per run; do not share between users."""

    max_calls: int = 20
    max_identical_calls: int = 3
    untrusted_seen: bool = False
    injection_suspected: bool = False
    calls: int = 0
    _seen: Counter = field(default_factory=Counter, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def observe(self, result: GuardResult, source: ContentSource) -> None:
        """Record content that entered the run (call after checking it)."""
        with self._lock:
            if source is not ContentSource.USER_MESSAGE:
                self.untrusted_seen = True
            for f in result.decision.findings:
                conf = f.confidence or Confidence.HIGH
                if f.reason_code in _INJECTION_CODES and conf.rank >= Confidence.MEDIUM.rank:
                    self.injection_suspected = True

    def _count(self) -> int:
        with self._lock:
            self.calls += 1
            return self.calls

    def _count_identical(self, fingerprint: str) -> int:
        with self._lock:
            self._seen[fingerprint] += 1
            return self._seen[fingerprint]


# ------------------------------------------------------------------------------ approvals
class NonceStore(Protocol):
    def use(self, nonce: str, expires_at: float) -> bool: ...   # True if newly used, False if replay/full


class InMemoryNonceStore:
    def __init__(self, max_entries: int = 10_000, clock: Callable[[], float] = time.time) -> None:
        self._d: dict[str, float] = {}
        self._max, self._clock, self._lock = max_entries, clock, threading.Lock()

    def use(self, nonce: str, expires_at: float) -> bool:
        with self._lock:
            now = self._clock()
            if len(self._d) >= self._max:
                self._d = {k: v for k, v in self._d.items() if v > now}
                if len(self._d) >= self._max:
                    return False  # fail closed when full
            if nonce in self._d:
                return False
            self._d[nonce] = expires_at
            return True


def canonical_args(args: Mapping[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def args_fingerprint(args: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_args(args).encode("utf-8")).hexdigest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class ApprovalManager:
    MAX_TOKEN_CHARS = 1024

    def __init__(self, secret: bytes, *, ttl_seconds: int = 300, approver_role: str = "approver",
                 allow_self_approval: bool = False, clock: Callable[[], float] = time.time,
                 nonce_store: NonceStore | None = None, audit: AuditLogger | None = None) -> None:
        self._audit = audit
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ConfigurationError("approval secret must be at least 32 bytes")
        if not 1 <= ttl_seconds <= 3600:
            raise ConfigurationError("approval ttl must be 1..3600 seconds")
        self._secret, self._ttl, self._role = bytes(secret), ttl_seconds, approver_role
        self._self_ok, self._clock = allow_self_approval, clock
        self._nonces = nonce_store or InMemoryNonceStore(clock=clock)

    def _sign(self, payload: bytes) -> bytes:
        return hmac.new(self._secret, payload, hashlib.sha256).digest()

    def issue(self, tool: str, validated_args: Mapping[str, Any], requester: Principal, approver: Principal) -> str:
        if self._role not in approver.roles:
            raise PermissionError("approver lacks the approver role")
        if approver.tenant_id != requester.tenant_id:
            raise PermissionError("approver is in a different tenant")
        if approver.user_id == requester.user_id and not self._self_ok:
            raise PermissionError("self-approval is not allowed")
        body = {"v": 1, "tool": tool, "args": args_fingerprint(validated_args), "tenant": requester.tenant_id,
                "user": requester.user_id, "approver": approver.user_id, "exp": self._clock() + self._ttl,
                "nonce": hashlib.sha256(new_request_id().encode() + str(time.time_ns()).encode()).hexdigest()[:32]}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if self._audit is not None:
            try:
                self._audit.record_approval(tool, args_fingerprint(validated_args), requester.tenant_id,
                                            requester.user_id, approver.user_id)
            except AuditUnavailable:
                if self._audit.settings.audit_failure_mode == "closed":
                    raise  # no audit trail, no approval
        return f"{_b64(payload)}.{_b64(self._sign(payload))}"

    def verify(self, token: object, tool: str, validated_args: Mapping[str, Any], requester: Principal,
               *, consume: bool = True) -> bool:
        """True only for a valid, unexpired, unused token bound to exactly this call."""
        try:
            if not isinstance(token, str) or len(token) > self.MAX_TOKEN_CHARS or token.count(".") != 1:
                return False
            p64, s64 = token.split(".")
            payload, sig = _unb64(p64), _unb64(s64)
            if not hmac.compare_digest(sig, self._sign(payload)):
                return False
            b = json.loads(payload)
            if (b.get("v") != 1 or b.get("tool") != tool or b.get("tenant") != requester.tenant_id
                    or b.get("user") != requester.user_id or b.get("args") != args_fingerprint(validated_args)
                    or not isinstance(b.get("exp"), (int, float)) or b["exp"] <= self._clock()
                    or not isinstance(b.get("nonce"), str)):
                return False
            return self._nonces.use(b["nonce"], float(b["exp"])) if consume else True
        except Exception:  # noqa: BLE001 - any malformed token is simply invalid
            return False


# ------------------------------------------------------------------------------ the guard
@dataclass(frozen=True)
class ToolDecision:
    decision: Decision
    tool: str | None = None
    arguments: dict[str, Any] | None = None   # validated; present only when the call may run
    fingerprint: str | None = None            # hash of validated args, for an approval UI
    approval_required: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision.action is Action.ALLOW and self.arguments is not None


def build_tool_scanner() -> Scanner:
    """Arguments legitimately contain emails and phone numbers, so only high-sensitivity PII is scanned."""
    return build_default_scanner(DetectorConfig(pii_categories=frozenset({"credit_card", "national_id"})))


def _leaves(value: Any, out: list[str]) -> None:
    stack = [value]
    while stack and len(out) < MAX_LEAVES:
        v = stack.pop()
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, Mapping):
            for k, x in v.items():
                out.append(str(k))
                stack.append(x)
        elif isinstance(v, (list, tuple)):
            stack.extend(v)


class ToolGuard:
    def __init__(self, registry: ToolRegistry, settings: Settings, policies: PolicyRegistry, *,
                 approvals: ApprovalManager | None = None, scanner: Scanner | None = None,
                 audit: AuditLogger | None = None) -> None:
        self._audit = audit
        if not registry.frozen:
            raise ConfigurationError("freeze the tool registry before use")
        self._reg, self._s, self._pol = registry, settings, policies
        self._approvals = approvals
        self._scanner = scanner or build_tool_scanner()

    # ---- helpers
    def _stop(self, code: ReasonCode, rid: str, tool: str | None = None, action: Action = Action.BLOCK,
              sev: Severity = Severity.HIGH, findings: tuple[Finding, ...] = (), **kw: Any) -> ToolDecision:
        d = Decision(action=action, reason_code=code, severity=sev, stage=Stage.TOOL, policy_id=TOOL_POLICY_ID,
                     policy_version=1, findings=findings, request_id=rid)
        return ToolDecision(d, tool, approval_required=action is Action.REQUIRE_REVIEW, **kw)

    def _validated(self, spec: ToolSpec, arguments: object) -> dict[str, Any] | None:
        if not isinstance(arguments, Mapping):
            return None
        try:
            raw = json.dumps(arguments, ensure_ascii=False, allow_nan=False)
            if len(raw) > spec.max_arg_chars or json_depth_exceeds(raw, self._s.max_nesting_depth):
                return None
            return spec.args_model.model_validate_json(raw, strict=True).model_dump(mode="json")
        except (TypeError, ValueError, ValidationError, RecursionError):
            return None

    def validate_arguments(self, tool_name: object, arguments: object) -> dict[str, Any] | None:
        """The validated arguments for a known tool, else None. (Used to bind approvals to exact arguments.)"""
        spec = self._reg.get(tool_name)
        return None if spec is None else self._validated(spec, arguments)

    def check(self, tool_name: object, arguments: object, principal: Principal, context: AgentContext, *,
              approval_token: str | None = None, request_id: str | None = None) -> ToolDecision:
        rid = request_id or new_request_id()
        try:
            td = self._check(tool_name, arguments, principal, context, approval_token, rid)
        except Exception:  # noqa: BLE001
            td = self._stop(ReasonCode.INTERNAL_ERROR, rid)
        return self._audited(td, principal)

    def _audited(self, td: ToolDecision, principal: object) -> ToolDecision:
        if self._audit is None:
            return td
        p = principal if isinstance(principal, Principal) else None
        try:
            self._audit.record_decision("tool_check", td.decision, tenant_id=p.tenant_id if p else None,
                                        user_id=p.user_id if p else None, tool=td.tool, fingerprint=td.fingerprint)
        except AuditUnavailable:
            if self._audit.settings.audit_failure_mode == "closed" and td.allowed:
                return self._stop(ReasonCode.AUDIT_UNAVAILABLE, td.decision.request_id or new_request_id(), td.tool)
        return td

    def _check(self, name: object, arguments: object, principal: Principal, ctx: AgentContext,
               token: str | None, rid: str) -> ToolDecision:
        if not isinstance(principal, Principal) or not isinstance(ctx, AgentContext):
            return self._stop(ReasonCode.TOOL_NOT_PERMITTED, rid)
        if ctx._count() > ctx.max_calls:
            return self._stop(ReasonCode.RATE_LIMITED, rid)

        spec = self._reg.get(name)
        if spec is None:
            return self._stop(ReasonCode.TOOL_UNKNOWN, rid)
        if (principal.roles.isdisjoint(spec.allowed_roles)
                or (spec.allowed_tenants is not None and principal.tenant_id not in spec.allowed_tenants)):
            return self._stop(ReasonCode.TOOL_NOT_PERMITTED, rid, spec.name)

        # ---- strict arguments
        args = self._validated(spec, arguments)
        if args is None:
            return self._stop(ReasonCode.TOOL_ARGS_INVALID, rid, spec.name)
        fp = args_fingerprint(args)
        if ctx._count_identical(spec.name + ":" + fp) > ctx.max_identical_calls:
            return self._stop(ReasonCode.RATE_LIMITED, rid, spec.name)

        # ---- scan what the model put in the arguments
        leaves: list[str] = []
        _leaves(args, leaves)
        text = "\n".join(leaves)
        findings: tuple[Finding, ...] = ()
        policy_action = Action.ALLOW
        ev_decision: Decision | None = None
        if text.strip():
            nt = normalize_text(text)
            v = ValidatedInput(rid, "text/plain", nt, ContentSource.MODEL_OUTPUT)
            ms = self._scanner.scan(nt, ContentSource.MODEL_OUTPUT).matches
            # offsets would point into our joined text, not anything the caller has: drop them
            fs = tuple(f.model_copy(update={"start": None, "end": None})
                       for f in (tuple(m.to_finding() for m in ms) + v.findings()))
            if fs:
                ev_decision = self._pol.engine_for(principal.tenant_id).evaluate(fs, Stage.TOOL, request_id=rid).decision
                findings, policy_action = fs, ev_decision.action
        if policy_action is Action.BLOCK:
            return ToolDecision(ev_decision, spec.name, fingerprint=fp)  # type: ignore[arg-type]
        needs_review = policy_action in (Action.SANITIZE, Action.REQUIRE_REVIEW)  # never rewrite arguments

        # ---- agent protection (taint)
        risky = spec.risk in (Risk.EXTERNAL, Risk.DESTRUCTIVE)
        if ctx.injection_suspected and risky:
            return self._stop(ReasonCode.PROMPT_INJECTION, rid, spec.name, findings=findings, fingerprint=fp)
        needs_approval = (needs_review or spec.approval_by_default or (ctx.untrusted_seen and risky)
                          or (ctx.injection_suspected and spec.risk is Risk.WRITE))

        if needs_approval:
            ok = self._approvals is not None and self._approvals.verify(token, spec.name, args, principal)
            if not ok:
                return self._stop(ReasonCode.APPROVAL_REQUIRED, rid, spec.name, Action.REQUIRE_REVIEW,
                                  Severity.MEDIUM, findings, fingerprint=fp)

        d = ev_decision.model_copy(update={"action": Action.ALLOW}) if ev_decision else \
            Decision.allow(Stage.TOOL, policy_id=TOOL_POLICY_ID, policy_version=1, request_id=rid)
        return ToolDecision(d, spec.name, arguments=args, fingerprint=fp)
