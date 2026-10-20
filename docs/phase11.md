# Phase 11 — Rate limits, budgets and deadlines

Goal: one caller, one tenant or one slow input must not be able to use up the service.

## What was added
| Control | Where | Default | Setting (`GUARDRAILS_...`) |
|---|---|---|---|
| Requests per minute, per API key | every authenticated endpoint | 120/min, burst 30 | `RATE_LIMIT_PER_MINUTE`, `RATE_LIMIT_BURST` |
| Requests per minute, per tenant (all its keys) | same | 600/min | `TENANT_RATE_LIMIT_PER_MINUTE` |
| Failed logins per client address | before the key is checked | 10/min | `AUTH_FAILURES_PER_MINUTE` |
| Text budget per tenant | `/v1/inspect/input`, `/v1/inspect/output` | 5,000,000 characters/hour | `TENANT_BUDGET_CHARS_PER_HOUR` |
| Time limit per request | input and output pipelines | 5 seconds | `REQUEST_DEADLINE_SECONDS` |
| What happens if the limiter itself breaks | API | `closed` (refuse) | `RATE_LIMIT_FAILURE_MODE` |

Files: `guardrails/limits.py` (`TokenBucketLimiter`, `BudgetTracker`, `Deadline`, `ApiLimits`), `guardrails/pipeline.py` and `guardrails/output.py` (deadline checks), `guardrails/api/app.py` (limits on every request). Tests: `tests/unit/test_limits.py` and the "phase 11" section of `tests/unit/test_api.py`.

## How it behaves
* **Too many requests** → HTTP 429, `{"error":{"code":"RATE_LIMITED",...}}`, header `Retry-After` (seconds). Fixed text; nothing from the request is echoed.
* **Budget used up** → 429 with code `BUDGET_EXCEEDED`. A refused request is not inspected at all, and is not counted against the budget.
* **Repeated wrong keys** from one address → that address gets 429 (even with a correct key) until its allowance refills. Correct requests never use this allowance.
* **Deadline** → the result is a BLOCK with reason `DEADLINE_EXCEEDED` and no text. It is checked after detection and before cleaning. A slow request is never released "unchecked".
* **Audit**: denials are recorded as `rate_limited` / `budget_exceeded`, but at most about one record per key per minute, so a flood cannot fill the audit log.
* The tables are bounded. When full of *active* keys, **new** keys are refused; old keys are never evicted (eviction would let a flood reset someone's counter).

## Using it from Python
```python
from guardrails import Guardrails, Settings
g = Guardrails(Settings(request_deadline_seconds=2))     # deadline applies to check_input / check_output
```
Rate limits and budgets belong to the API layer. To change them, set the settings above, or pass your own `ApiLimits(...)` to `create_app(..., limits=...)`.

## Honest limits (please read)
1. **Counts live in memory, in one process.** With 4 workers or 2 servers each keeps its own counts, so the real limit is 4x or 2x what you set. A shared store (for example Redis) is needed for exact limits; `RateLimiter` is a Protocol so one can be plugged in, but none is included.
2. **A restart resets all counts.**
3. **The deadline is checked between stages.** It cannot interrupt one long step. The input size limits are the first defense; the deadline is the second.
4. **Behind a reverse proxy every client may look like one address** (`X-Forwarded-For` is deliberately not trusted, because clients can fake it). Then the failed-login lockout applies to everyone behind that proxy together. Put an address-aware limit at the proxy.
5. **Budgets use a fixed window**, so up to twice the quota can pass across a window boundary.
6. **Malformed JSON is rejected before authentication** (FastAPI reads the JSON first). The cost is capped by the body size limit; throttle raw traffic at the proxy. Pinned by a test.
7. Tool checks (`/v1/tools/check`) count toward the request limits but not the character budget.
8. The model-assisted detector keeps its own timeout; the request deadline does not cut it short.

## Understanding check
A bucket allows 3 requests per minute with burst 3. A client sends 3 requests at once, waits 20 seconds and sends 1 more. Is it allowed? (Answer: yes — 20 seconds earns back 1 token.)
