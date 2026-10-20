# Architecture

A **standalone** guardrail layer for LLM apps. It is a Python package (`guardrails`) plus an optional FastAPI service. It
does not call a model itself and does not import any other project. The core depends only on `pydantic`.

## Where it sits

```
 user / client ──► your app ──► [ input guard ] ──► LLM ──► [ output guard ] ──► user
                      │                                        │
   retrieved docs ────┤ (each checked as UNTRUSTED content)    │
   web pages, files ──┘                                        ▼
                                                        model asks for a tool
                                                               │
                                                        [ tool guard ] ──► your tool code
                      every check ──► decision ──► audit log (no content) + metrics
```

Your application owns the model call and the tools. The guardrails answer one question each time: **allow, sanitize,
require review, or block?** The answer is a typed decision. Text is returned only when the decision permits forwarding.

## Modules

| Area | Files | Job |
|---|---|---|
| Decisions and types | `guardrails/types.py`, `decisions.py`, `errors.py`, `settings.py` | The vocabulary: actions, severities, reason codes, findings (never matched text), public view, strict settings |
| Input hygiene | `validation.py`, `normalization.py` | Strict request schema, size and depth limits, Unicode clean-up that keeps a map back to the original text |
| Detectors | `detectors/pii.py`, `secrets.py`, `injection*.py`, `decoding.py`, `output.py`, `model_assisted.py`, `scanner.py` | Say what was seen. Do not decide what to do |
| Redaction | `redaction.py` | Deterministic cleaning, verified by re-scanning |
| Policy | `policy.py` | Turns findings into ONE decision. Strictest rule wins; unknown means block |
| Pipelines | `pipeline.py`, `output.py`, `structured.py` | validate, normalize, detect, decide, sanitize, verify. Output also does leaks, unsafe markup, strict JSON, streaming |
| Tools | `tools.py` | Registry, roles, tenants, strict arguments, approvals, loop limits, "taint" from untrusted content |
| Audit | `audit.py`, `audit_cli.py` | HMAC-chained JSONL with no content fields |
| Limits | `limits.py` | Rate limits, budgets, deadlines |
| Observability | `metrics.py`, `tracing.py` | Prometheus text, tracing hook |
| SDK | `sdk.py` | `Guardrails`: the one object an app uses |
| Service | `api/` | FastAPI app, API keys, runs, config from environment |
| Measurement | `evaluation/` (repo root, not installed) | Labeled cases, metrics, baseline |

## One input check, step by step

1. **Validate**: must be an object with known fields; text within size limits; content type allowed. Failure is a BLOCK decision, not an exception.
2. **Normalize**: a copy of the text with hidden characters removed, look-alike letters mapped, and a map back to the original.
3. **Detect**: PII, secrets, prompt-injection rules (strictness depends on the **source**), decoded payloads (base64, hex, URL, unicode escapes, HTML entities, rot13, leetspeak; bounded depth and count), optional model-based detector.
4. **Decide**: the policy engine applies every matching rule; the strictest action wins. Findings no rule covers use `unmatched_action` (block).
5. **Sanitize and verify**: redact, then scan the result again. If anything is still found, block instead. Findings with no span (hidden characters) cannot be cleaned, so they become "require review".
6. **Audit and count**: one record with codes and counts, never content. If the audit write fails and the mode is closed, an allowed result becomes a block.

## Trust rules the design depends on

* Everything from a client is **data, never instructions**. The same sentence is a request from the user but an attack inside a retrieved document.
* A model asking for a tool is **not** authorization. Trusted code (roles, tenants, approvals) decides.
* Model output is **untrusted** until the output guard has run.
* Tenant and user identity come only from the API key, never from the request body.
* Public responses carry a fixed code and message. The internal reason code is shown only if the operator opts in.
* Controls fail **closed** by default. Fail-open for detectors and audit is refused in production. Rate-limit fail-open is an explicit operator choice.

## Deployment shapes

* **Library**: `from guardrails import Guardrails` inside your app. No network, no service.
* **Sidecar / service**: `python -m guardrails.api` (or the Docker image), called over HTTP with API keys.
Both use the same code and the same tests.
