# Phase 0 — Repository inspection, baseline, gap analysis, threat model, plan

## 1. Repository situation

Project 5 has **no existing repository**, so there is nothing to refactor. It is a new, separate repo
(`guardrail-middleware`), as Project 4 was. The three earlier projects were inspected read-only and are **not modified**.
The guardrail package must not import them. It integrates through documented interfaces only.

| Repo | What it is | Used here for |
|---|---|---|
| `production-rag` (Project 1) | FastAPI RAG service | Conventions + security patterns to copy (not import) |
| `eval-harness` (Project 2) | Evaluation platform | Convention: provider interfaces, injectable clocks, mock providers |
| `observability-dashboard` (Project 4) | FastAPI + OTel + Prometheus | Conventions: config, metrics label bounding, redaction, Docker hardening |

## 2. Baseline test results (run in this sandbox, `python -m pytest -q`)

| Repo | Result |
|---|---|
| production-rag | 363 passed, 1 warning |
| eval-harness | 348 passed, 4 skipped (the 4 need the optional `openai` package, which is not installed here) |
| observability-dashboard | 240 passed, 3 warnings |
| guardrail-middleware (this repo, Phase 0) | 2 passed |

Note: running the bare `pytest` command in eval-harness (instead of `python -m pytest`) gave 31 collection errors in this
sandbox. I did not investigate; the `python -m pytest` form is the one that passes, and it is the form used throughout.

## 3. Existing security-relevant code (what is already there)

| Area | Where | What it does | Reuse decision |
|---|---|---|---|
| API key auth | production-rag `app/auth.py` | Bearer / `X-API-Key`; keys stored as SHA-256 hashes; same 401 for wrong vs revoked | **Reuse the pattern** (hashed keys, no wrong/revoked distinction). Add scopes/roles |
| Shared-token auth | obsdash `auth.py` | One shared token, `hmac.compare_digest`, header only | Reuse the constant-time compare; one shared token is not enough for tenants/roles |
| Tenant limits | production-rag `enforce_tenant_limits` | Rate limit by tenant after auth (dependency, not middleware) | **Reuse the idea**: limit by principal after auth, plus a cheap pre-auth limit |
| Rate limiter | production-rag `middleware/rate_limit.py` | Sliding window, in-memory, injectable clock | **Reuse the design**; add a backend interface and explicit fail-open/closed |
| PII | production-rag `services/pii.py` | Regex + Luhn, counts only, `[REDACTED_X]` markers | **Reuse** category list and Luhn idea; known weakness: its phone regex is broad |
| Secret/PII redaction | obsdash `redaction.py`, `span_redaction.py` | Key=value, bearer, provider keys, JWT, email, Luhn cards; bounded scan length | **Reuse the pattern list**; scan-length bound is a good ReDoS/cost defence |
| Label bounding | obsdash `LabelLimiter` | Caps metric label cardinality | Reuse the idea for metrics (Phase 12) |
| Docker hardening | obsdash `Dockerfile`/compose | Non-root, read-only FS, cap_drop, loopback publish | Reuse for Phase 12 |
| Observability | obsdash OTLP receiver + dashboard | Accepts OTel spans | Optional integration target only |

Reuse means "copy the idea and write it fresh, with tests" — the new package stays standalone.

## 4. Gap analysis

| Required capability | Exists today? | Plan |
|---|---|---|
| Typed allow/sanitize/block/require_review decisions with reason code, severity, policy id | No | Phase 1 |
| Input validation + Unicode normalization | Partial (Pydantic models only) | Phase 2 |
| PII + secret detection with configurable policy and allowlists | Partial (count-only PII; secret redaction for logs) | Phase 3 |
| Prompt-injection detection (trusted vs untrusted context, encoded text) | No | Phase 4 |
| Policy engine with precedence and validation | No | Phase 5 |
| End-to-end pipeline + Python SDK | No | Phase 6 |
| Output guardrails, structured-output validation, streaming rules | No | Phase 7 |
| Tool registry + authorization + human approval | No | Phase 8 |
| Audit events without raw sensitive content | No (logging exists in obsdash only) | Phase 9 |
| Roles, tenants, hashed key storage, admin vs normal API | Partial (hashed keys in P1) | Phase 10 |
| Rate limits, budgets, deadlines, backend-failure behavior | Partial (in-memory limiter in P1) | Phase 11 |
| Metrics, tracing, health/readiness, Docker, CI | Patterns in P4 | Phase 12 |
| Labeled adversarial dataset + precision/recall | No | Phase 13 |
| Docs, final report, Definition-of-Done evidence | No | Phase 14 |

## 5. Threat model (draft; refined as phases land)

**Assets:** credentials and secrets, personal data, system prompts / hidden instructions, tool-execution power
(delete, send, pay), tenant data, the availability of the guardrail service itself.

**Actors:** an anonymous caller; an authenticated user of one tenant (may be malicious); *content authors* whose text
reaches the model indirectly (web pages, uploaded files, retrieved documents, tool outputs); a compromised or
manipulated LLM; a curious tenant trying to read another tenant's data; an operator making configuration mistakes.

**Trust boundaries**
1. Client → guardrail API: **untrusted**. Everything in the request body is data, never instructions.
2. Guardrail → model provider: only content that passed the input policy crosses it.
3. Model → user: model output is **untrusted** until the output policy has run.
4. Model → tools: an LLM asking for a tool is **not** authorization. Trusted application code decides.
5. Guardrail → audit store / metrics / traces: only redacted, low-cardinality data.
6. Guardrail → optional model-based detector: off by default; sending text out is an explicit opt-in.

| # | Threat | Main control | Phase |
|---|---|---|---|
| T1 | Direct prompt injection ("ignore previous instructions") | Rules + policy action | 4 |
| T2 | Indirect injection in retrieved docs / tool output | Trust labels on content; stricter policy for untrusted sources | 4 |
| T3 | Secret / PII exfiltration in input or output | Detectors + redaction before each boundary | 3, 7 |
| T4 | Unauthorized or unregistered tool call | Registry, per-tool permissions, schema validation, approvals | 8 |
| T5 | Cross-tenant access to policies or audit data | Tenant-scoped queries, tests that try to cross | 10 |
| T6 | Resource exhaustion (huge input, regex cost, detector flood) | Size limits, bounded scans, rate limits, deadlines | 2, 11 |
| T7 | Guardrail bypass via encoding / Unicode tricks | Normalization + decode-and-rescan, limits documented | 2, 4 |
| T8 | Sensitive data leaking through logs, errors, metrics | Redacted audit, safe errors, bounded labels | 9, 12 |
| T9 | Backend failure silently disabling a control | Explicit fail-open/fail-closed per control, tested | 9, 11 |
| T10 | Weak admin access / policy tampering | Roles, admin-only policy writes, validated policies | 5, 10 |

**Out of scope (stated up front):** a guarantee that every prompt injection is caught (it is not achievable with rules);
factual correctness of model answers; protection if the host application is itself compromised; tamper-proof audit
logs (only an optional extension is designed, in Phase 9).

## 6. Design decisions made in Phase 0

1. **Separate repo**, package name `guardrails`.
2. **Core depends only on Pydantic.** FastAPI is an optional extra (`pip install .[api]`). A test enforces that importing `guardrails` does not load FastAPI.
3. **Deterministic first.** Every protection works with no network and no model. Model-assisted detection is an optional provider behind an interface, never the only boundary.
4. **No new heavy libraries.** Pydantic, FastAPI, pytest, httpx are already installed here. Redis is *not* added unless Phase 11 proves it is needed.
5. **Safe defaults:** unknown tool → block; detector failure on a security-critical stage → fail closed (refined per control in Phases 9 and 11).
6. **Tests need no paid calls and no network.** Live-provider tests (if any) are opt-in and reported as skipped with a reason.

## 7. Phase roadmap

| Phase | Scope |
|---|---|
| 0 | Inspection, baseline, gap analysis, threat model, skeleton (this phase) |
| 1 | Core types: decisions, reason codes, severities, settings, safe errors |
| 2 | Input validation and Unicode normalization |
| 3 | PII and secret detectors, deterministic redaction |
| 4 | Prompt-injection detection, trust labels, provider interface |
| 5 | Policy engine: precedence, validation, versions |
| 6 | Input pipeline + Python SDK |
| 7 | Output guardrails, structured output, streaming |
| 8 | Tool registry and authorization, approvals |
| 9 | Audit events, failure behavior |
| 10 | FastAPI service: auth, roles, tenants |
| 11 | Rate limiting, budgets, deadlines |
| 12 | Metrics, tracing, health, Docker, CI |
| 13 | Adversarial dataset and measured detection metrics |
| 14 | Documentation, final report, Definition-of-Done matrix |

## 8. Phase 0 status

Done: inspection, baselines, gap analysis, threat model draft, roadmap, skeleton, 2 passing tests.
Not done (by design): no guardrail logic yet. Nothing in this phase is claimed to detect or block anything.
