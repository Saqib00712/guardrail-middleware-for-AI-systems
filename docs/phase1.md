# Phase 1 — Core types, decisions, settings, safe errors

## What was built
The shared vocabulary every later phase uses. No detection logic yet.

| Piece | File | Purpose |
|---|---|---|
| `Stage`, `Action`, `Severity`, `ReasonCode` | `guardrails/types.py` | Stable string enums. `Action` and `Severity` have a strictness order |
| `Finding` | `guardrails/decisions.py` | One thing a detector noticed. **Has no field for matched text** |
| `Decision` | same | Internal result: action, reason code, severity, stage, policy id + version, findings |
| `PublicDecision` | same | What an untrusted client may see: action, coarse code, fixed message |
| `most_restrictive()` | same | Picks the winning decision: strictest action, then highest severity, then first |
| `Settings` | `guardrails/settings.py` | Validated config, loaded from `GUARDRAILS_*` env vars |
| `GuardrailError`, `ConfigurationError` | `guardrails/errors.py` | Exceptions that never put content or secrets in their message |

## Decisions and why
1. **Findings cannot hold raw text.** `extra="forbid"` makes `Finding(matched_text=...)` an error, so findings are safe to audit and log by construction.
2. **Two views of a decision.** The public view hides detector names, policy ids and offsets. Telling an attacker which rule fired helps them evade it. Operators may opt in to show the reason code (`expose_reason_codes`).
3. **No implicit allow.** `most_restrictive([])` raises unless the caller passes a default. `Action.strictest()` with nothing also raises.
4. **`OK` is reserved.** A decision with reason `OK` must be `allow` with no findings.
5. **Default environment is `production`.** A forgotten setting fails strict. Set `GUARDRAILS_ENVIRONMENT=development` for local work.
6. **Production forbids fail-open** for detector and audit failures. Rate-limit fail-open stays an allowed, documented operator choice.
7. **Unknown `GUARDRAILS_*` variables are an error**, so a typo cannot silently leave a limit at its default.
8. **Config errors name fields, never values.**
9. **Core depends only on Pydantic** (no `pydantic-settings`). A test still enforces that importing `guardrails` does not load FastAPI.

## Honest notes
- Many `ReasonCode` values exist for later phases. A code existing does not mean the capability exists.
- Limits in `Settings` (`max_input_chars`, etc.) are validated but **not enforced yet**; enforcement arrives in Phase 2 and Phase 10.
- Tests need no network and no paid calls.

## Test it
    python -m pytest -q

## Results (build sandbox)
44 passed (Phase 0's 2 + 42 new).
A mutation check was done on the "public view hides internals" test: after making the public message leak the policy id, the first version of the test still passed (it did not look for that value). The test was strengthened, then failed on the mutation as it should, and the mutation was reverted.
