# Operations

## Run locally
```
pip install -e ".[api]"
python -m guardrails.api.auth create --tenant acme --user alice --role user --scope inspect --scope tools --keys-file keys.json
set GUARDRAILS_ENVIRONMENT=development
set GR_API_KEYS_FILE=keys.json
python -m guardrails.api
```
(Linux/macOS: `export` instead of `set`. One command per line.) Then call `/v1/inspect/input` as shown in `docs/api.md`.

## Production checklist
1. Keep `GUARDRAILS_ENVIRONMENT` unset (production). It will not start without keys, an audit log and an audit key.
2. Put a TLS-terminating proxy in front. The service itself speaks plain HTTP and binds to loopback by default.
3. Create one key per client application, with only the scopes it needs. Give `admin` only to the metrics scraper.
4. Keep the audit key and approval secret in a secret store, not in the image or the repo.
5. Store the audit log on persistent storage; verify it regularly: `python -m guardrails.audit_cli verify audit.jsonl` (the key is read from `GR_AUDIT_KEY`).
   Save the latest head (sequence number and hash) elsewhere, otherwise cutting off the end of the log is not detectable.
6. Scrape `/metrics` (admin key) and alert on `guardrails_audit_failures_total`, `guardrails_limit_denials_total` and rising `block` rates.
7. Use `/healthz` for liveness and `/readyz` for readiness.

## Docker
`docker build -t guardrails .` and `docker-compose.yml` (read-only filesystem, non-root user 10001, all capabilities dropped,
published on loopback only). **The image and the CI workflow were written but never built or run in the environment where this project was developed.** Build and test them yourself before relying on them.

## Known operating limits
* Rate limits, budgets, lockouts, runs and approvals' used-token list live in one process's memory. With several workers or instances each has its own state, and a restart clears it. Use one instance, or put shared limits in front.
* The audit log is hash-chained and keyed. It detects edits to the middle of the log. It is not tamper-proof against someone who holds the key or the host.
* A full disk shows up as blocked requests and a rising audit-failure counter, not as a failed readiness probe.
* Metrics and tracing are per process.
* See `docs/phase11.md` and `docs/phase12.md` for details.
