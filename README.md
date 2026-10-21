# guardrail-middleware

Security guardrail layer for LLM applications, RAG pipelines, and AI agents — input inspection, output inspection (including streaming), tool authorization with human approval, per-tenant policies, tamper-evident audit logging, rate limiting, and an optional HTTP service. Built as Project 5 of a 43-project AI Engineering curriculum.

> **Honest scope:** This middleware reduces some risks. It does not make an application secure, and it misses many prompt injections — measured results are in `docs/final_report.md`.

---

## What This Project Does

Most LLM apps ship with no systematic security layer between user input and the model. This middleware sits in that gap — inspecting every input before it reaches the LLM, every output before it reaches the user, and every tool call before it executes.

```
User Input
    ↓
Input Inspection — PII detection/sanitization, prompt injection detection,
                   blocklist matching, per-tenant policy enforcement
    ↓
LLM / RAG Pipeline / Agent
    ↓
Output Inspection — PII/secret leak detection, policy violation check,
                    streaming output inspection
    ↓
Tool Call? → Tool Authorization → Human Approval (if required)
    ↓
Tamper-evident Audit Log — every decision recorded and chained
    ↓
Response to User
```

---

## Built Phase by Phase — 14 Phases

| Phase | What Was Built |
|-------|---------------|
| 0 | Project scaffold, threat model, architecture decisions |
| 1 | Core `Guardrails` class, `Settings`, `Decision` model, input pipeline skeleton |
| 2 | PII detection — email, phone, credit card, SSN patterns; sanitization (redact/replace) |
| 3 | Prompt injection detection — heuristic + pattern-based; injection scoring |
| 4 | Secret/key detection in inputs — API keys, tokens, bearer credentials |
| 5 | Output inspection — PII and secret leak detection in LLM responses |
| 6 | Streaming output inspection — inspect token chunks, buffer partial patterns |
| 7 | Tool authorization — per-tool policies, `require_approval` flag, approval flow |
| 8 | Human-in-the-loop approval — approval request queue, approve/deny/timeout |
| 9 | Per-tenant policies — tenant-scoped rules, blocklists, PII handling config |
| 10 | Rate limiting — per-tenant request and token rate limits |
| 11 | Tamper-evident audit log — hash-chained entries, chain verification |
| 12 | HTTP service (`guardrails.api`) — REST endpoints, API key auth, scopes, browser console at `/ui` |
| 13 | Evaluation framework — detection rate measurement, regression gate, baseline comparison |
| 14 | Documentation, final report, 16-item Definition-of-Done matrix |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   GUARDRAIL MIDDLEWARE                       │
├──────────────────────────────────────────────────────────────┤
│  Input Pipeline                                              │
│  ├── PII Inspector — detect + sanitize (redact/replace)      │
│  ├── Injection Detector — heuristic + pattern scoring        │
│  ├── Secret Detector — API keys, tokens, credentials         │
│  ├── Blocklist Matcher — per-tenant custom blocklists        │
│  └── Policy Engine — per-tenant rule evaluation              │
│                                                              │
│  Output Pipeline                                             │
│  ├── PII Leak Detector — catches PII in LLM responses        │
│  ├── Secret Leak Detector — catches keys/tokens in output    │
│  ├── Streaming Inspector — buffers + inspects token chunks   │
│  └── Policy Violation Check                                  │
│                                                              │
│  Tool Authorization                                          │
│  ├── Per-tool policy (allow / deny / require_approval)       │
│  └── Human Approval Queue — approve / deny / timeout         │
│                                                              │
│  Per-tenant Policies                                         │
│  ├── Tenant-scoped PII handling config                       │
│  ├── Custom blocklists per tenant                            │
│  └── Per-tenant rate limits (requests + tokens)             │
│                                                              │
│  Audit Log                                                   │
│  └── Tamper-evident hash-chained entries + chain verifier   │
│                                                              │
│  HTTP Service (optional)                                     │
│  ├── REST API — check_input, check_output, tool_auth         │
│  ├── API key auth with scopes                                │
│  ├── Browser test console at /ui                             │
│  └── Docker deployment                                       │
└──────────────────────────────────────────────────────────────┘
```

---

## What It Catches

| Threat | How |
|--------|-----|
| PII in input (email, phone, card, SSN) | Pattern detection + sanitization before forwarding |
| Prompt injection in user messages | Heuristic scoring + injection pattern library |
| API keys / secrets in input | Credential pattern matching |
| PII leaked in LLM output | Output inspector before response reaches user |
| Secrets leaked in LLM output | Output credential scanner |
| Unauthorized tool calls | Per-tool policy + optional human approval gate |
| Tenant policy violations | Per-tenant rule engine on every request |
| Rate abuse | Per-tenant request + token rate limits |

**What it misses:** Many prompt injections — especially novel, context-dependent, or multi-turn attacks. Measured false-negative rate is documented in `docs/final_report.md`.

---

## Tech Stack

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Pydantic](https://img.shields.io/badge/Pydantic-Settings%20%2B%20Models-red?style=flat-square)
![FastAPI](https://img.shields.io/badge/FastAPI-HTTP%20Service-green?style=flat-square)
![pytest](https://img.shields.io/badge/pytest-Test%20Suite-yellow?style=flat-square)

- **Core** — pure Python + Pydantic (zero heavy dependencies for the guardrail layer itself)
- **HTTP service** — FastAPI (`pip install -e ".[api]"`)
- **Pydantic** — settings, decision models, policy schemas
- **pytest** — test suite
- **Evaluation framework** — detection rate measurement, regression gate, baseline comparison

---

## Project Structure

```
guardrail-middleware/
│
├── guardrails/
│   ├── __init__.py                  # Guardrails, Settings — public API
│   ├── core.py                      # Main Guardrails class, check_input / check_output
│   ├── decision.py                  # Decision model (action, reason, modified text)
│   ├── settings.py                  # Settings (Pydantic BaseSettings)
│   │
│   ├── inspectors/
│   │   ├── pii.py                   # PII detection + sanitization
│   │   ├── injection.py             # Prompt injection detection
│   │   ├── secrets.py               # API key / credential detection
│   │   └── output.py                # Output inspection (PII + secrets)
│   │
│   ├── streaming.py                 # Streaming output inspector (buffered chunks)
│   ├── tools.py                     # Tool authorization + approval queue
│   ├── policy.py                    # Per-tenant policy engine
│   ├── ratelimit.py                 # Per-tenant rate limiting
│   ├── audit.py                     # Tamper-evident hash-chained audit log
│   │
│   └── api/
│       ├── __init__.py              # Entry point: python -m guardrails.api
│       ├── auth.py                  # API key management + scopes
│       ├── routes.py                # REST endpoints
│       └── ui/                      # Browser test console at /ui
│
├── evaluation/
│   ├── __init__.py                  # python -m evaluation check / run
│   ├── runner.py                    # Detection rate measurement
│   ├── baseline.json                # Regression baseline
│   └── datasets/                   # Labeled test cases per threat category
│
├── examples/
│   └── quickstart.py               # End-to-end demo (no server, no network)
│
├── tests/                          # Full test suite
├── docs/
│   ├── architecture.md             # How the pieces fit
│   ├── run_guide.md                # Step-by-step run guide + browser console
│   ├── api.md                      # Endpoints, scopes, errors
│   ├── configuration.md            # Every setting and env var
│   ├── policy.md                   # Writing per-tenant policies
│   ├── operations.md               # Docker, production checklist, limits
│   ├── security.md                 # Threats, controls, evidence, what remains
│   ├── final_report.md             # Results and honest limitations
│   ├── definition_of_done.md       # 16-item DoD matrix
│   └── phase0.md … phase13.md      # Build history and decisions
│
├── SECURITY.md                     # Reporting vulnerabilities, handling secrets
├── pyproject.toml
└── README.md
```

---

## Getting Started

### Install

```bash
git clone https://github.com/Saqib00712/guardrail-middleware.git
cd guardrail-middleware

# Core only (just Pydantic)
pip install -e .

# With HTTP service
pip install -e ".[api]"

# With test tools
pip install -e ".[api,dev]"
```

### Try it (no server, no network)

```bash
python examples/quickstart.py
```

Runs through: email sanitization, fake API key blocking, injected document blocking, prompt leak in output blocking, tool call requiring approval, the approval flow, and audit chain verification.

### Use it in Python

```python
from guardrails import Guardrails, Settings

g = Guardrails(Settings())

# Check input before sending to LLM
result = g.check_input("my email is bob@example.com", source="user_message")
print(result.decision.action)   # sanitize / block / forward
print(result.text)              # forward result.text (not the original) when not None

# Check output before returning to user
out = g.check_output(llm_response, context=context)
print(out.decision.action)      # forward / block
```

### Run the HTTP service

```bash
# Create an API key
python -m guardrails.api.auth create --name myapp --scopes read,write --keys-file keys.json

# Set env vars
export GR_API_KEYS_FILE=keys.json
export GUARDRAILS_ENVIRONMENT=development

# Start the service
python -m guardrails.api
# Browser console at http://localhost:8000/ui
```

Full step-by-step: `docs/run_guide.md`

### Run tests and evaluation

```bash
# Full test suite
python -m pytest -q

# Regression gate (fails if detection drops below baseline)
python -m evaluation check

# Re-run full evaluation and update docs/evaluation_results.md
python -m evaluation run
```

---

## Per-tenant Policy Example

```python
from guardrails import Guardrails, Settings
from guardrails.policy import TenantPolicy

policy = TenantPolicy(
    tenant_id="acme",
    pii_action="redact",           # redact / block / forward
    blocklist=["competitor", "confidential"],
    require_approval_tools=["send_email", "delete_record"],
    rate_limit_rpm=100,
)

g = Guardrails(Settings(), policies={"acme": policy})
result = g.check_input(user_input, source="user_message", tenant_id="acme")
```

---

## Audit Log

Every guardrail decision is appended to a tamper-evident hash-chained log. Each entry contains:
- timestamp, tenant, source, action, reason
- hash of the entry content
- `prev_hash` — the hash of the previous entry

```python
from guardrails.audit import AuditLog

log = AuditLog("audit.db")
log.verify_chain()   # raises if any entry has been tampered with
```

---

## Key Concepts Covered

- **Defence in depth** — multiple independent detection layers; failing one does not bypass all
- **Sanitize vs. block** — PII is sanitized (text forwarded with PII replaced) rather than always blocked, to preserve utility
- **Streaming inspection** — buffering partial token chunks to catch patterns that span chunk boundaries
- **Human-in-the-loop tool authorization** — high-risk tool calls pause for explicit human approval before executing
- **Per-tenant isolation** — complete policy, blocklist, and rate-limit separation per tenant
- **Tamper-evident audit** — hash-chained log means any post-hoc deletion or modification is detectable
- **Regression gate** — CI enforces that detection rates never silently drop below measured baseline
- **Honest limitations** — documented false-negative rate on prompt injections; no security theatre

---

## Related Certifications

Built applying skills from the IBM **RAG for Generative AI Applications Specialization**, **Building AI Agents and Agentic Workflows Specialization**, and **Generative AI Engineering with Transformers & LLMs** on Coursera.

[![IBM Badge](https://img.shields.io/badge/IBM-RAG%20Specialization-blue?style=flat-square)](https://www.credly.com/users/muhammad-saqib.361f9b8c)
[![IBM Badge](https://img.shields.io/badge/IBM-AI%20Agents%20Specialization-blue?style=flat-square)](https://www.credly.com/users/muhammad-saqib.361f9b8c)
[![IBM Badge](https://img.shields.io/badge/IBM-GenAI%20Engineering-blue?style=flat-square)](https://www.credly.com/users/muhammad-saqib.361f9b8c)

---

## Author

**Muhammad Saqib**
- GitHub: [@Saqib00712](https://github.com/Saqib00712)
- LinkedIn: [muhammad-saqib](https://www.linkedin.com/in/muhammad-saqib-68b9b3374/)
- Email: saqibkhosa649@gmail.com
- Credly: [15x IBM Certified](https://www.credly.com/users/muhammad-saqib.361f9b8c)

