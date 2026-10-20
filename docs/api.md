# HTTP API

Start it: `python -m guardrails.api` (see `docs/configuration.md` and `docs/operations.md`). Every `/v1/...` route needs
`Authorization: Bearer <key>`. Request bodies must be `application/json`, at most `max_request_body_bytes` (default 1,000,000).
Unknown JSON fields are rejected. In development only, interactive docs are at `/docs`; in production they are off.

## Keys, scopes, roles
A key looks like `gr_<id>.<secret>`. Only a hash is stored. Each key has one **tenant**, one **user**, optional domain **roles**
(used by tool rules) and **scopes** (what the key may call). **Tenant and user always come from the key, never the body.**

| Scope | Allows |
|---|---|
| `inspect` | `/v1/inspect/input`, `/v1/inspect/output` |
| `tools` | `/v1/runs`, `/v1/tools/check` |
| `approve` | `/v1/approvals` (and the key's user must hold the approver role) |
| `admin` | `/metrics` |

Create one: `python -m guardrails.api.auth create --tenant acme --user alice --role user --scope inspect --scope tools --keys-file keys.json`
(the key is printed once; the file gets the hashed record).

## Endpoints

| Method and path | Scope | Purpose |
|---|---|---|
| `GET /ui` | none | Test console in the browser. **Development only** (404 in production). The key is typed into the page, never stored |
| `GET /healthz` | none | Alive |
| `GET /readyz` | none | Ready: keys loaded and audit log writable. 200 or 503, fixed words only |
| `GET /metrics` | admin | Prometheus text |
| `GET /v1/whoami` | any valid key | Shows tenant, user, roles, scopes |
| `POST /v1/inspect/input` | inspect | Check text going toward a model |
| `POST /v1/inspect/output` | inspect | Check text the model produced |
| `POST /v1/runs` | tools | Start an agent run (tracks loop limits and taint). Returns `run_id`, `expires_in` |
| `POST /v1/tools/check` | tools | Ask whether a tool call may run |
| `POST /v1/approvals` | approve | A human approver issues a single-use token for one exact call |

### `POST /v1/inspect/input`
Body: `text` (required), `source` (`user_message` default, `retrieved_document`, `web_page`, `uploaded_file`, `tool_output`,
`model_output`), `content_type` (`text/plain` default, `text/markdown`, `application/json`), `request_id` (optional),
`run_id` (optional: links the check to a run so untrusted content is remembered).
Reply: `action`, `code`, `message`, `request_id`, `reason_code` (only if the operator opted in), `text` (null unless allowed or sanitized), `redactions`, `degraded`.
```
curl -s -X POST http://127.0.0.1:8000/v1/inspect/input -H "Authorization: Bearer KEY" -H "Content-Type: application/json" -d "{\"text\":\"mail bob@example.com\"}"
{"action":"sanitize","code":"sanitized","message":"Request allowed after some content was removed.","request_id":"...","reason_code":null,"text":"mail [REDACTED_EMAIL]","redactions":1,"degraded":false}
```
`action` is one of `allow`, `sanitize`, `require_review`, `block`. **Only forward `text` when it is not null.**

### `POST /v1/inspect/output`
Body: `text`, optional `request_id`, optional `schema_name`. `schema_name` selects a Pydantic model registered by the host
application through `create_app(..., schemas={...})`. The standalone service has no schemas, so any `schema_name` there returns `UNKNOWN_SCHEMA`.
The reply has the same shape as input checks, plus `parsed` when a schema was used.

### `POST /v1/tools/check`
Body: `run_id`, `tool`, `arguments` (object), optional `approval_token`, optional `request_id`. Tools come from the JSON file named by `GR_TOOLS_FILE` (`examples/tools.example.json`).
Reply: the decision fields plus `allowed`, `arguments` (validated; only when allowed), `approval_required`, `fingerprint` (when approval is needed).
Unknown tool, wrong role or tenant, invalid arguments, a secret in the arguments, or injection-tainted context all block.

### `POST /v1/approvals`
Body: `tool`, `arguments`, `requester_user_id`. The approver must be in the requester's tenant, hold the `approver` role, and (by default) not be the requester.
Reply `201`: `{"approval_token": "..."}`. The token is bound to the tool, the exact arguments, the requester and the tenant; it expires (default 300 s) and works once.

## Errors
Every error is `{"error": {"code": "...", "message": "..."}}` with fixed text. Nothing the client sent is ever echoed.

| Status | Code | Meaning |
|---|---|---|
| 401 | `UNAUTHORIZED` | Missing, malformed, wrong, disabled or expired key (all look identical). Header `WWW-Authenticate: Bearer` |
| 403 | `FORBIDDEN` | Valid key, wrong scope or not allowed to approve |
| 404 | `RUN_NOT_FOUND`, `TOOLS_DISABLED`, `APPROVALS_DISABLED`, `METRICS_DISABLED` | Not found or not configured |
| 413 | `BODY_TOO_LARGE` | Over the body limit (checked before parsing) |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Send `application/json` |
| 422 | `INVALID_REQUEST` (plus `error_types`), `UNKNOWN_SCHEMA` | Request did not match the format |
| 429 | `RATE_LIMITED`, `BUDGET_EXCEEDED` | Header `Retry-After` in seconds |
| 503 | `CAPACITY`, `AUDIT_UNAVAILABLE` | Run store full; audit could not be written (fail closed) |
| 404, 405 and other framework errors | `HTTP_ERROR` | Unknown path or method; fixed text |
| 500 | `INTERNAL_ERROR` | Unexpected error; fixed text |

A **blocked or sanitized input is not an HTTP error**: it is a normal `200` with `action` set. Check `action`, not the status code.
Every response carries `X-Request-ID` (yours if it is 8 to 64 safe characters, otherwise generated), `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

## Limits that apply (defaults)
120 requests/minute per key (burst 30), 600/minute per tenant, 10 failed logins/minute per client address, 5,000,000 characters/hour per tenant, 5 s per request. See `docs/phase11.md` for what these cannot do.
