"""The HTTP service.

Security properties (each tested):
* Every /v1 route needs `Authorization: Bearer <key>`; all auth failures look identical (401).
* Tenant and user come ONLY from the key. Request bodies cannot name a tenant (unknown fields -> 422).
* Scopes per route (inspect / tools / approve); a key without the scope gets 403.
* Request bodies are size-limited before parsing (413) and must be application/json (415).
* Responses show only the PUBLIC decision (action, coarse code, fixed message); detector names,
  offsets and policy internals never leave. Reason codes only if the operator opted in.
* Error bodies are fixed text. Validation errors never echo what the client sent.
* No-store caching, nosniff, no CORS, and API docs only in development.
* Agent runs (taint state) are server-side, per tenant+user; a lost run is an error, never a fresh start.

Not here yet: rate limits and per-tenant budgets (Phase 11), metrics and readiness (Phase 12),
HTTP streaming (use the SDK's StreamGuard).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from guardrails.audit import AuditUnavailable
from guardrails.decisions import new_request_id
from guardrails.limits import ApiLimits, RateDecision
from guardrails.metrics import Metrics
from guardrails.api.auth import ApiKeyRecord, ApiKeyStore
from guardrails.api.runs import RunStore, RunStoreFull
from guardrails.sdk import Guardrails
from guardrails.tools import ApprovalManager, Principal, ToolGuard
from guardrails.types import Action, ContentSource, ReasonCode


log = logging.getLogger("guardrails.api")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, retry_after: str | None = None) -> None:
        self.status, self.code, self.message, self.retry_after = status, code, message, retry_after


def _err(status: int, code: str, message: str, request_id: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if request_id:
        body["request_id"] = request_id
    return JSONResponse(body, status_code=status)


# ------------------------------------------------------------------ request/response models
class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InputRequest(_Req):
    text: str
    source: ContentSource = ContentSource.USER_MESSAGE
    content_type: str = Field(default="text/plain", max_length=100)
    request_id: str | None = Field(default=None, max_length=64)
    run_id: str | None = Field(default=None, max_length=64)


class OutputRequest(_Req):
    text: str
    schema_name: str | None = Field(default=None, max_length=64)
    request_id: str | None = Field(default=None, max_length=64)


class ToolCheckRequest(_Req):
    run_id: str = Field(max_length=64)
    tool: str = Field(max_length=100)
    arguments: dict[str, Any]
    approval_token: str | None = Field(default=None, max_length=1024)
    request_id: str | None = Field(default=None, max_length=64)


class ApprovalRequest(_Req):
    tool: str = Field(max_length=100)
    arguments: dict[str, Any]
    requester_user_id: str = Field(max_length=128)


# ------------------------------------------------------------------ body limit middleware
class BodyLimitMiddleware:
    """Reads at most `max_bytes`, then replays the body to the app. Over the limit -> 413 before any parsing."""

    def __init__(self, app: Any, max_bytes: int, metrics: Metrics | None = None) -> None:
        self.app, self.max, self.metrics = app, max_bytes, metrics

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope["headers"]}
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                n = int(cl)
            except ValueError:
                return await self._reject(scope, receive, send, 400, "INVALID_REQUEST", "malformed request")
            if n < 0 or n > self.max:
                return await self._reject(scope, receive, send, 413, "BODY_TOO_LARGE", "request body is too large")
        body, more = b"", True
        while more:
            msg = await receive()
            if msg["type"] != "http.request":
                return
            body += msg.get("body", b"")
            more = msg.get("more_body", False)
            if len(body) > self.max:
                return await self._reject(scope, receive, send, 413, "BODY_TOO_LARGE", "request body is too large")
        sent = False

        async def replay() -> dict:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, scope: dict, receive: Any, send: Any, status: int, code: str, msg: str) -> None:
        if self.metrics is not None:
            self.metrics.safe(self.metrics.inc, "guardrails_http_requests_total", "rejected_early", status)
        await _err(status, code, msg)(scope, receive, send)


# ------------------------------------------------------------------ app factory
@dataclass(frozen=True)
class Auth:
    principal: Principal
    record: ApiKeyRecord


def create_app(g: Guardrails, keys: ApiKeyStore, *, tool_guard: ToolGuard | None = None,
               approvals: ApprovalManager | None = None, schemas: Mapping[str, type[BaseModel]] | None = None,
               runs: RunStore | None = None, limits: ApiLimits | None = None) -> FastAPI:
    settings = g.settings
    lim = limits or ApiLimits.from_settings(settings)
    dev = settings.environment == "development"
    app = FastAPI(title="Guardrail middleware", version="0.1.0",
                  docs_url="/docs" if dev else None, redoc_url=None, openapi_url="/openapi.json" if dev else None)
    run_store = runs or RunStore()
    schema_map = dict(schemas or {})

    # ---- middleware (last added runs first): body limit outermost
    metrics = g.metrics

    @app.middleware("http")
    async def observability(request: Request, call_next: Any) -> Any:
        """Request id (validated or fresh), security headers, and HTTP metrics by route TEMPLATE."""
        supplied = request.headers.get("x-request-id", "")
        rid = supplied if _REQUEST_ID.match(supplied) else new_request_id()
        request.state.request_id = rid
        t0 = time.perf_counter()
        try:
            resp = await call_next(request)
        except Exception:
            _count_http(request, 500, t0)
            raise
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Request-ID"] = rid
        _count_http(request, resp.status_code, t0)
        return resp

    def _count_http(request: Request, status: int, t0: float) -> None:
        if metrics is None:
            return
        route = request.scope.get("route")
        endpoint = getattr(route, "path", None) or "unmatched"     # the template, never the raw path
        metrics.safe(metrics.inc, "guardrails_http_requests_total", endpoint, status)
        metrics.safe(metrics.observe, "guardrails_http_request_seconds", time.perf_counter() - t0, endpoint)

    def _rid(request: Request, supplied: str | None) -> str | None:
        return supplied or getattr(request.state, "request_id", None)

    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_request_body_bytes, metrics=metrics)

    # ---- errors: fixed text, never client content
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, e: ApiError) -> JSONResponse:
        r = _err(e.status, e.code, e.message)
        if e.status == 401:
            r.headers["WWW-Authenticate"] = "Bearer"
        if e.retry_after is not None:
            r.headers["Retry-After"] = e.retry_after
        return r

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, e: RequestValidationError) -> JSONResponse:
        types = sorted({str(x["type"]) for x in e.errors()})
        body = {"error": {"code": "INVALID_REQUEST", "message": "request did not match the expected format"},
                "error_types": types}
        return JSONResponse(body, status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, e: StarletteHTTPException) -> JSONResponse:
        return _err(e.status_code, "HTTP_ERROR", "request could not be served")

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, e: Exception) -> JSONResponse:
        r = _err(500, "INTERNAL_ERROR", "internal error")
        rid = getattr(request.state, "request_id", None)
        if rid:
            r.headers["X-Request-ID"] = rid
        return r

    # ---- auth dependencies
    def _limited(call: Any, *args: Any) -> RateDecision:
        """Run a limiter. If the limiter itself breaks, follow rate_limit_failure_mode (default: closed)."""
        try:
            return call(*args)
        except Exception as exc:  # noqa: BLE001
            log.error("rate limiter failure: %s", type(exc).__name__)
            _count_denial("limiter_error")
            if settings.rate_limit_failure_mode == "closed":
                return RateDecision(False, 1.0)
            return RateDecision(True)

    def _audit_limit(event: str, who: Principal | None, key: str) -> None:
        """At most about one audit record per key per minute, so a flood cannot fill the audit log."""
        if g._audit is None or not _limited(lim.log_gate.check, f"{event}:{key}").allowed:
            return
        try:
            g._audit.record(event, action=Action.BLOCK, reason_code=ReasonCode.RATE_LIMITED,
                            tenant_id=who.tenant_id if who else None,
                            actor=g._audit.pseudonym(who.user_id) if who else None)
        except AuditUnavailable:
            pass

    def _count_denial(kind: str) -> None:
        if metrics is not None:
            metrics.safe(metrics.inc, "guardrails_limit_denials_total", kind)

    def _too_many(d: RateDecision, code: str = "RATE_LIMITED", message: str = "too many requests; slow down") -> ApiError:
        return ApiError(429, code, message, d.retry_after_header if math.isfinite(d.retry_after) else "3600")

    def authenticate(request: Request) -> Auth:
        client = request.client.host if request.client else "unknown"
        # Already failing too often from this address? Refuse before looking at the key at all.
        d = _limited(lim.auth_failures.peek, client)
        if not d.allowed:
            _count_denial("auth_lockout")
            _audit_limit("rate_limited", None, "auth:" + client)
            raise _too_many(d)
        res = keys.authenticate(request.headers.get("authorization"))
        if res is None:
            _limited(lim.auth_failures.check, client)       # a failure spends one token
            _audit_auth_failure()
            raise ApiError(401, "UNAUTHORIZED", "authentication required")
        a = Auth(*res)
        for limiter, bucket in ((lim.per_key, a.record.key_id), (lim.per_tenant, a.principal.tenant_id)):
            d = _limited(limiter.check, bucket)
            if not d.allowed:
                _count_denial("rate_limit_key" if limiter is lim.per_key else "rate_limit_tenant")
                _audit_limit("rate_limited", a.principal, bucket)
                raise _too_many(d)
        return a

    def charge_budget(a: Auth, chars: int) -> None:
        d = _limited(lim.budget.charge, a.principal.tenant_id, chars)
        if not d.allowed:
            _count_denial("budget")
            _audit_limit("budget_exceeded", a.principal, "budget:" + a.principal.tenant_id)
            raise _too_many(d, "BUDGET_EXCEEDED", "usage budget for this period is used up")

    def _audit_auth_failure() -> None:
        if g._audit is not None:
            try:
                g._audit.record("auth_failure", action=Action.BLOCK, reason_code=ReasonCode.POLICY_DEFAULT)
            except AuditUnavailable:
                if metrics is not None:
                    metrics.safe(metrics.inc, "guardrails_audit_failures_total", "auth_failure")  # still a 401

    def require(scope: str, *, json_body: bool = False) -> Any:
        """Authenticate first, then check scope, then content type (so strangers learn nothing)."""
        def dep(request: Request) -> Auth:
            a = authenticate(request)
            if scope not in a.record.scopes:
                raise ApiError(403, "FORBIDDEN", "this key may not use this endpoint")
            if json_body:
                ct = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if ct != "application/json":
                    raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "send application/json")
            return a
        return dep

    def public(result: Any) -> dict[str, Any]:
        return json.loads(result.decision.to_public(expose_reason_code=settings.expose_reason_codes).model_dump_json())

    # ---- routes
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    if dev:
        ui_html = (Path(__file__).with_name("ui.html")).read_bytes()
        ui_text = ui_html.decode("utf-8")
        hashes = [base64.b64encode(hashlib.sha256(m.encode("utf-8")).digest()).decode()
                  for m in re.findall(r"<(?:script|style)>(.*?)</(?:script|style)>", ui_text, re.S)]
        scripts, styles = hashes[-1], hashes[0]
        ui_csp = ("default-src 'none'; script-src 'sha256-%s'; style-src 'sha256-%s'; connect-src 'self'; "
                  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % (scripts, styles))

        @app.get("/ui", include_in_schema=False)
        def ui_page() -> Response:
            """A small test console. Development only (404 in production, like /docs)."""
            return Response(ui_html, media_type="text/html; charset=utf-8",
                            headers={"Content-Security-Policy": ui_csp, "Referrer-Policy": "no-referrer"})

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        """Readiness: can this instance do its job right now? Fixed words only; no paths, errors or counts."""
        checks = {"keys": "ok" if len(keys) > 0 else "fail"}
        if g._audit is not None:
            checks["audit"] = "ok" if g._audit.healthy() else "fail"
        elif not dev:
            checks["audit"] = "fail"             # production without an audit log must not receive traffic
        ready = all(v == "ok" for v in checks.values())
        return JSONResponse({"status": "ready" if ready else "not_ready", "checks": checks},
                            status_code=200 if ready else 503)

    @app.get("/metrics")
    def metrics_page(_: Auth = Depends(require("admin"))) -> Response:
        if metrics is None:
            raise ApiError(404, "METRICS_DISABLED", "metrics are not configured")
        return Response(metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/v1/whoami")
    def whoami(a: Auth = Depends(authenticate)) -> dict[str, Any]:
        return {"tenant_id": a.principal.tenant_id, "user_id": a.principal.user_id,
                "roles": sorted(a.principal.roles), "scopes": sorted(a.record.scopes)}

    @app.post("/v1/runs", status_code=201)
    def create_run(a: Auth = Depends(require("tools"))) -> dict[str, Any]:
        try:
            return {"run_id": run_store.create(a.principal), "expires_in": run_store.ttl_seconds}
        except RunStoreFull:
            raise ApiError(503, "CAPACITY", "service is at capacity") from None

    @app.post("/v1/inspect/input")
    def inspect_input(request: Request, body: InputRequest, a: Auth = Depends(require("inspect", json_body=True))) -> dict[str, Any]:
        ctx = None
        if body.run_id is not None:
            ctx = run_store.get(a.principal, body.run_id)
            if ctx is None:
                raise ApiError(404, "RUN_NOT_FOUND", "run not found or expired; start a new run")
        charge_budget(a, len(body.text))
        r = g.check_input(body.text, source=body.source, tenant_id=a.principal.tenant_id, user_id=a.principal.user_id,
                          request_id=_rid(request, body.request_id), content_type=body.content_type, context=ctx)
        return {**public(r), "text": r.text if r.allowed else None, "redactions": r.redactions, "degraded": r.degraded}

    @app.post("/v1/inspect/output")
    def inspect_output(request: Request, body: OutputRequest, a: Auth = Depends(require("inspect", json_body=True))) -> dict[str, Any]:
        schema = None
        if body.schema_name is not None:
            schema = schema_map.get(body.schema_name)
            if schema is None:
                raise ApiError(422, "UNKNOWN_SCHEMA", "unknown schema_name")
        charge_budget(a, len(body.text))
        r = g.check_output(body.text, tenant_id=a.principal.tenant_id, user_id=a.principal.user_id,
                           schema=schema, request_id=_rid(request, body.request_id))
        out = {**public(r), "text": r.text if r.allowed else None, "redactions": r.redactions, "degraded": r.degraded}
        if schema is not None:
            out["parsed"] = r.parsed.model_dump(mode="json") if r.parsed is not None else None
        return out

    @app.post("/v1/tools/check")
    def tools_check(request: Request, body: ToolCheckRequest, a: Auth = Depends(require("tools", json_body=True))) -> dict[str, Any]:
        if tool_guard is None:
            raise ApiError(404, "TOOLS_DISABLED", "tool checking is not configured")
        ctx = run_store.get(a.principal, body.run_id)
        if ctx is None:
            raise ApiError(404, "RUN_NOT_FOUND", "run not found or expired; start a new run")
        td = tool_guard.check(body.tool, body.arguments, a.principal, ctx, approval_token=body.approval_token,
                              request_id=_rid(request, body.request_id))
        if metrics is not None:
            metrics.safe(metrics.inc, "guardrails_tool_decisions_total", td.decision.action, td.decision.reason_code)
        d = td.decision.to_public(expose_reason_code=settings.expose_reason_codes)
        return {**json.loads(d.model_dump_json()), "allowed": td.allowed,
                "arguments": td.arguments if td.allowed else None,
                "approval_required": td.approval_required, "fingerprint": td.fingerprint if td.approval_required else None}

    @app.post("/v1/approvals", status_code=201)
    def issue_approval(body: ApprovalRequest, a: Auth = Depends(require("approve", json_body=True))) -> dict[str, Any]:
        if tool_guard is None or approvals is None:
            raise ApiError(404, "APPROVALS_DISABLED", "approvals are not configured")
        args = tool_guard.validate_arguments(body.tool, body.arguments)
        if args is None:
            raise ApiError(422, "INVALID_REQUEST", "unknown tool or invalid arguments")
        requester = Principal(user_id=body.requester_user_id, tenant_id=a.principal.tenant_id)  # same tenant only
        try:
            token = approvals.issue(body.tool, args, requester, a.principal)
        except PermissionError:
            raise ApiError(403, "FORBIDDEN", "this key may not approve this request") from None
        except AuditUnavailable:
            raise ApiError(503, "AUDIT_UNAVAILABLE", "service unavailable") from None
        return {"approval_token": token}

    return app
