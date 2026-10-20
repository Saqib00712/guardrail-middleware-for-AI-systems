# Phase 7 — Output guardrails, structured output, streaming

    g = Guardrails(system_prompt=..., canaries=[...], allowed_url_hosts=["cdn.example.com"])
    r = g.check_output(model_text)                       # whole response
    r = g.check_output(model_text, schema=MyModel)       # + strict JSON validation (r.parsed)
    s = g.stream_output(); u = s.feed(chunk); ...; s.finish()   # streaming

## What is checked on model output
- Everything input has (PII -> sanitize, secrets -> block, injection) with the source set to `model_output`.
- **System-prompt leakage:** canary tokens (exact, case-insensitive, hidden-character-proof) and long word-for-word overlap (default 8 words) with your system prompt. Paraphrases are NOT detected; short prompts are protected by canaries only.
- **Unsafe content:** images that can smuggle data out (URL with query/long path) -> block; plain external images -> removed; allowed hosts are exact or true subdomains (`cdn.acme.com.evil.example` is not allowed); `<script>`, `<iframe>`, event handlers, `javascript:` URLs -> block.
- Hidden characters in output (e.g. invisible tag characters) -> review.
- Size limit; wrong types become blocks.

## Structured output (`guardrails/structured.py`)
Size, depth and node limits before parsing; duplicate keys, NaN/Infinity rejected; one surrounding ``` fence tolerated; schema must set `extra="forbid"` (otherwise a ConfigurationError, because that is a programmer mistake, not bad data). Sanitized JSON is re-validated; errors never echo the model's text.

## Streaming (read this)
The last `holdback` characters (default 256) are held back so a finding split across chunks is still seen. Findings are never cut in half. BUT text already released cannot be recalled: a mid-stream block cuts the stream and the caller must discard or mark the partial answer. A finding longer than the holdback can slip across; multi-signal escalation counts only inside one window. A stream cannot sanitize hidden characters, so it cuts. Released text is rescanned before sending.

## Windows fix (found by you)
25 errors on Windows were not logic bugs: pytest stores each test id in an environment variable, Windows limits those to 32,767 characters, and some hostile-input tests used 100,000-character strings as their ids. `tests/conftest.py` now gives long string parameters a short id and fails collection if any id exceeds 400 characters. Longest id now: 285. Not yet re-run on Windows by me (no Windows here).

## Commands
    python -m pytest -q tests/unit/test_output.py
    python -m pytest -q
