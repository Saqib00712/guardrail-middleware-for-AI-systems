# Phase 6 — Input pipeline and SDK

    validate -> normalize -> detect (rules [+ optional model]) -> policy -> sanitize -> verify

## Guarantees (all tested)
- Bad input, detector failures and unexpected errors become **BLOCK** decisions (production default), never exceptions that could be caught-and-ignored into an allow. Logs hold the error type only, never content.
- `GuardResult.text` exists **only** when forwarding is permitted; it is None for block / require_review.
- **Sanitize is verified:** cleaned text is scanned again; anything left means block.
- **Unremovable findings** (hidden characters found by the normalizer) cannot be "sanitized": result is upgraded to require_review.
- Model layer: failure/timeout blocks in closed mode; in development open mode the result is flagged `degraded`. The sync call refuses to run if a model layer is configured (use `acheck_input`), so it can't be skipped silently.
- Monitor-mode policies (non-production) forward the original text and report `would_have`.
- Decisions never contain the input text.

## SDK
    from guardrails import Guardrails
    g = Guardrails.from_env()                       # production defaults
    r = g.check_input(user_text, source=ContentSource.USER_MESSAGE, tenant_id="acme")
    prompt = r.require_text()                       # raises GuardrailBlocked (public info only)
    await g.acheck_input(...)                       # when a model detector is configured

## Measured on the Phase 4 dataset through the whole pipeline
- Malicious (58): 39 block, 16 require_review, 3 sanitize, **0 passed unchanged**.
- Benign (60): 55 allowed unchanged; 5 sanitized, all because they contain an email/phone (correct).
- Same caveat: the dataset was written with the rules, so this is a regression check, not real-world accuracy. Known misses (Phase 4) still pass.

## Limits
- Input stage only. Output guardrails come in Phase 7, tools in Phase 8.
- Redaction removes matched spans; a model-detector match spans the whole text, so sanitizing it removes everything.
- No audit log yet (Phase 9) and no HTTP service yet (Phase 10).

## Commands
    python -m pytest -q tests/unit/test_pipeline.py
    python -m pytest -q
