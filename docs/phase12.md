# Phase 12 — Metrics, tracing, health checks, Docker, CI

## What was added
| Item | Files |
|---|---|
| Metrics in Prometheus text format (no new dependency) | `guardrails/metrics.py`, `GET /metrics` |
| Tracing hook (no OpenTelemetry dependency) | `guardrails/tracing.py` |
| Request ids (`X-Request-ID`) | `guardrails/api/app.py` |
| Liveness and readiness | `GET /healthz`, `GET /readyz`, `AuditLogger.healthy()` |
| Container image and example compose file | `Dockerfile`, `.dockerignore`, `docker-compose.yml` |
| CI (tests on Linux and Windows, lint, secrets check, Docker checks) | `.github/workflows/ci.yml` |
| Lint config (real mistakes only) | `pyproject.toml` `[tool.ruff.lint]` |
Tests: `tests/unit/test_ops.py`.

## Metrics
`GET /metrics` needs a key with the **admin** scope (create one with `--scope admin`). Series:
`guardrails_decisions_total{stage,action,reason_code}`, `guardrails_decision_seconds` (histogram), `guardrails_degraded_total`, `guardrails_http_requests_total{endpoint,status}`, `guardrails_http_request_seconds`, `guardrails_limit_denials_total{kind}`, `guardrails_audit_failures_total`, `guardrails_tool_decisions_total`.
* Labels are fixed and low-cardinality. **No tenant, user, key or request id is ever a label**, and endpoint is the route template (`/v1/inspect/input`), never the raw path.
* Odd label values become `other`; each metric is capped at 500 series (extra ones count under `overflow`).
* A metrics bug is logged and ignored; it never changes a decision.
* Values live in one process. With several workers each has its own `/metrics`.

## Request ids
Send `X-Request-ID` (8 to 64 characters: letters, digits, `.`, `_`, `-`) and it is used in the decision, the audit record and the response header. Anything else is replaced by a fresh id. A `request_id` in the body wins over the header. Every response, including errors, carries `X-Request-ID`.

## Tracing
`Guardrails(..., tracer=my_tracer)`. `my_tracer.span(name)` must return a context manager that gives back an object with `set_attribute(key, value)`. Spans: `guardrails.check_input`, `guardrails.check_output`. Only these attributes are ever set: `stage, action, reason_code, degraded, redactions, request_id`. Anything else is dropped, and text is never sent. A tracer that raises is ignored. Streams are not traced yet.
An OpenTelemetry adapter is a few lines, but it is **not included or tested here**.

## Health
* `/healthz`: the process is alive. Always 200.
* `/readyz`: 200 when keys are loaded and the audit log can be opened for appending; 503 otherwise. In production, no audit log means not ready. The answer uses fixed words only. The probe writes nothing, so readiness recovers by itself.
* A **full disk** is not detected by the probe. It shows up as `guardrails_audit_failures_total` going up and requests being blocked (fail closed).

## Docker
```
docker build -t guardrails .
```
* Runs as user 10001, production mode by default, so it refuses to start without keys and an audit log.
* No key, audit key or log is baked into the image. `.dockerignore` keeps `.env`, `keys*.json`, `*.jsonl`, `*.db`, tests and docs out.
* `docker-compose.yml` needs `GR_AUDIT_KEY` (32+ characters) set in your shell or an untracked `.env`, binds to `127.0.0.1` only, mounts keys read-only, and drops all capabilities.
* The Docker health check calls `/readyz`.
**Not built or run here:** the Docker daemon is not available in my workspace, so the Dockerfile and compose file are only checked by static tests and the YAML parser. The first `docker build` is yours; the CI `docker` job builds it too. The same service was started for real with `python -m guardrails.api` (see the smoke test in the phase notes).

## CI
`.github/workflows/ci.yml`: tests on Ubuntu and Windows with Python 3.11, 3.12 and 3.13; ruff for real mistakes; a check that no `.env`, `keys*.json`, `*.db` or `*.jsonl` is tracked; a Docker job (build, non-root check, refuses to start without configuration).
**Not run here:** GitHub Actions cannot run in my workspace. The file parses as YAML and the same commands were run locally. Actions are pinned by major version (`@v4`, `@v5`); pinning by commit hash is stronger and is left for you to do when you set the repository up.

## Honest limits
1. Metrics, rate limits and run state are per process.
2. `/readyz` is unauthenticated and tells a stranger whether audit or keys are down (fixed words, no details). Restrict it at the proxy if that matters.
3. HTTP metrics count requests that reach the app, plus oversize bodies rejected early (`endpoint="rejected_early"`). Requests dropped by a proxy are not seen.
4. No log shipping or alert rules are included. Suggested alerts: `guardrails_audit_failures_total` increasing; `guardrails_degraded_total` increasing; `guardrails_limit_denials_total{kind="limiter_error"}` increasing; `/readyz` failing.

## Understanding check
The audit disk fills up. Which signal fires first, and what does a user's request get? (Answer: `guardrails_audit_failures_total` rises; in the default closed mode the request is blocked with `AUDIT_UNAVAILABLE`; `/readyz` still says ready because the probe cannot see a full disk.)
