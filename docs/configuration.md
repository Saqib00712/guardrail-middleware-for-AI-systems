# Configuration

Two groups of environment variables. **Unknown names are an error** (a typo must not silently keep a default).

## Guardrail settings (`GUARDRAILS_<NAME>`, upper case)
Production is the default. Production refuses `detector_failure_mode=open` and `audit_failure_mode=open`.

| Setting | Default | Meaning |
|---|---|---|
| `environment` | `production` | `production` or `development` (development allows monitor mode, fail-open, `/docs`) |
| `max_request_body_bytes` | 1000000 | Largest HTTP body, checked before parsing |
| `max_input_chars` | 20000 | Longest text for input checks |
| `max_output_chars` | 50000 | Longest text for output checks |
| `max_nesting_depth` | 8 | Deepest JSON nesting accepted |
| `detector_failure_mode` | `closed` | A broken detector blocks (`closed`) or is marked degraded (`open`, development only) |
| `audit_failure_mode` | `closed` | A failed audit write blocks the request (`closed`) |
| `rate_limit_failure_mode` | `closed` | A broken limiter refuses requests (`closed`) |
| `rate_limit_per_minute` | 120 | Per API key |
| `rate_limit_burst` | 30 | Per API key burst size |
| `tenant_rate_limit_per_minute` | 600 | All keys of one tenant together |
| `auth_failures_per_minute` | 10 | Failed logins per client address |
| `tenant_budget_chars_per_hour` | 5000000 | Characters inspected per tenant per hour |
| `request_deadline_seconds` | 5.0 | Time limit per check |
| `expose_reason_codes` | false | Return the reason code to callers (off by default) |
| `allow_external_detectors` | false | Allow a model-based detector that sends (redacted) text out |

Example: `GUARDRAILS_ENVIRONMENT=development` (Windows cmd: `set GUARDRAILS_ENVIRONMENT=development`).

## Service variables (`GR_...`)
| Variable | Needed | Meaning |
|---|---|---|
| `GR_API_KEYS_FILE` | always | Keys JSON, made by `python -m guardrails.api.auth create ... --keys-file` |
| `GR_POLICY_FILE` | no | Policy JSON (see `docs/policy.md`); built-in default otherwise |
| `GR_AUDIT_FILE` | production | Audit log path (JSON lines, created with owner-only permissions where the system allows) |
| `GR_AUDIT_KEY` | with the audit file | 32 or more random characters; signs the audit chain |
| `GR_TOOLS_FILE` | no | Tool definitions JSON (`examples/tools.example.json`); no tools otherwise |
| `GR_APPROVAL_SECRET` | no | 32 or more characters; turns on `/v1/approvals` (needs `GR_TOOLS_FILE`) |
| `GR_HOST`, `GR_PORT` | no | Bind address, default `127.0.0.1:8000` |

Never commit keys, `.env`, audit logs or `*.db` files (`.gitignore` covers them). Generate secrets with
`python -c "import secrets; print(secrets.token_urlsafe(48))"`.
