# Phase 10 — HTTP service (FastAPI): auth, roles, tenants

Install: `pip install -e ".[api]"`   Run: `python -m guardrails.api`   (reads `GR_*` and `GUARDRAILS_*` env vars)

## Make an API key (shown once; only a hash is stored)
    python -m guardrails.api.auth create --tenant acme --user alice --role user --scope inspect --scope tools --days 90
Put the printed record into the keys file `{"keys": [ ... ]}`; hand the key to the app that will call the service.

## Configuration (environment)
| Variable | Meaning |
|---|---|
| GR_API_KEYS_FILE | keys JSON (required) |
| GR_AUDIT_FILE + GR_AUDIT_KEY | audit log + 32+ char key (required in production) |
| GR_POLICY_FILE | policy JSON (default: built-in policy) |
| GR_TOOLS_FILE | tool definitions JSON (see `guardrails/api/toolsconfig.py`) |
| GR_APPROVAL_SECRET | 32+ chars, enables approvals |
| GR_HOST / GR_PORT | default 127.0.0.1:8000 |
| GUARDRAILS_ENVIRONMENT | `development` to allow no audit file and enable /docs |
Production refuses to start with no keys, no audit log, a short audit key, or any unknown `GR_*` / `GUARDRAILS_*` variable.

## Endpoints (all `/v1/*` need `Authorization: Bearer <key>`)
| Route | Scope | Purpose |
|---|---|---|
| GET /healthz | none | liveness |
| GET /v1/whoami | any | who the key says you are |
| POST /v1/runs | tools | start an agent run (holds taint state) |
| POST /v1/inspect/input | inspect | check text going to the model; optional `run_id` records taint |
| POST /v1/inspect/output | inspect | check model output; optional server-side `schema_name` |
| POST /v1/tools/check | tools | authorize one tool call in a run |
| POST /v1/approvals | approve | issue a signed single-use approval for exact arguments |

## Security properties (all tested, including mutation checks)
- Tenant and user come ONLY from the key; bodies cannot name them (unknown field -> 422).
- Identical 401 for every authentication failure; 401 comes before 415/422; keys in URLs are ignored.
- Scopes per route; the approver must also hold the domain role `approver`; approvals are minted only for users in the approver's own tenant, never for yourself.
- Runs are private to tenant+user; a missing/expired run is a 404 (never silently recreated, since that would drop taint); a full store refuses new runs instead of evicting.
- 413 before parsing (Content-Length and chunked), 415 for non-JSON, fixed-text errors that never echo client data, `Cache-Control: no-store`, nosniff, no CORS, docs only in development.
- Responses carry only the public decision (action, coarse code, fixed message, optional reason code if the operator opted in) plus the sanitized text when allowed.
- Audit uses the key's tenant/user. Audit down => allowed requests become blocks; approvals are not issued (503).
- Checked on a real server over HTTP: sanitize, 401, docs hidden, audit chain verifies, no email in the audit file.

## Limits (honest)
- No rate limiting or budgets yet, so key guessing and auth-failure logging are not throttled (Phase 11).
- Malformed JSON from an unauthenticated caller gets a generic 422 (the framework parses before auth); it reveals nothing about keys.
- API keys are bearer secrets: use TLS in front of the service (not included) and rotate keys.
- The calling app states the content `source`; the service trusts it (it is your server, not the end user).
- One process: runs and used approvals live in memory. Several replicas need shared stores.
- `GR_APPROVAL_SECRET` is read from the environment: use a secrets manager in real deployments.
- Sync endpoints only (threadpool); the optional model detector needs the async SDK path, not this service yet. No HTTP streaming; use the SDK's StreamGuard.

## Changed in earlier phases
The audit verify command is now `python -m guardrails.audit_cli verify FILE` (the old module path printed a Python warning).

## Windows quick start (cmd)

Type each command as ONE line (a wrapped line is run as separate commands).

```
python -m guardrails.api.auth create --tenant acme --user alice --role user --scope inspect --scope tools --keys-file keys.json
set GUARDRAILS_ENVIRONMENT=development
set GR_API_KEYS_FILE=keys.json
python -m guardrails.api
```

The first command prints the key once and writes the (hashed) record into `keys.json`. Copy the key now; it cannot be shown again.
Development mode runs without an audit log. For production-style runs also set `GR_AUDIT_FILE` and `GR_AUDIT_KEY` (32+ characters).
`GR_API_KEYS_FILE is required` means the variable is not set in that cmd window. `set` only lasts for that window.

Test from a second window (replace KEY):

```
curl -s -X POST http://127.0.0.1:8000/v1/inspect/input -H "Authorization: Bearer KEY" -H "Content-Type: application/json" -d "{\"text\":\"my email is bob@example.com\",\"source\":\"user_message\"}"
```
