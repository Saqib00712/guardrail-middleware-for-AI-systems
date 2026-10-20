# guardrail-middleware (Project 5)

Security guardrails for LLM apps, RAG pipelines and agents: input inspection, output inspection (including streaming),
tool authorization with human approval, per-tenant policies, a tamper-evident audit log, rate limits, and an optional HTTP service.
It reduces some risks. It does **not** make an application secure, and it misses many prompt injections
(measured: `docs/final_report.md`).

Status: Phase 14 done (documentation, final report, Definition-of-Done matrix). The 16-item matrix is in `docs/definition_of_done.md`.

## Install
```
pip install -e ".[api]"        # core only: pip install -e .   (needs just Pydantic)
pip install -e ".[api,dev]"    # plus test tools
```

## Try it (no server, no network)
```
python examples/quickstart.py
```
It checks an email (sanitized), a fake key (blocked), an injected document (blocked), a prompt leak in the output (blocked),
a tool call that needs approval, the approval, and the audit chain.

## Use it in Python
```python
from guardrails import Guardrails, Settings
g = Guardrails(Settings())
r = g.check_input("my email is bob@example.com", source="user_message")
print(r.decision.action, r.text)   # forward r.text only when it is not None
```

## Run the service
Step by step, with a browser test console: `docs/run_guide.md`. See `docs/operations.md`. Short version: create a key with `python -m guardrails.api.auth create ... --keys-file keys.json`, set `GR_API_KEYS_FILE`
(and `GUARDRAILS_ENVIRONMENT=development` for a local try), then `python -m guardrails.api`.

## Test and measure
```
python -m pytest -q
python -m evaluation check      # regression gate against evaluation/baseline.json
python -m evaluation run        # regenerate docs/evaluation_results.md
```

## Documentation
| Read | For |
|---|---|
| `docs/architecture.md` | How the pieces fit |
| `docs/run_guide.md` | Run it step by step, including the browser console at `/ui` |
| `docs/api.md` | Endpoints, scopes, errors |
| `docs/configuration.md` | Every setting and environment variable |
| `docs/policy.md` | Writing policies |
| `docs/operations.md` | Running, Docker, production checklist, operating limits |
| `docs/security.md` | Threats, controls, evidence, what remains |
| `docs/final_report.md` | Results and limitations |
| `docs/definition_of_done.md` | The 16-item matrix |
| `docs/phase0.md` to `docs/phase13.md` | Build history and decisions |
| `SECURITY.md` | Reporting and handling secrets |

Never commit `.env`, keys files, audit logs or `*.db`.
