# Phase 2 — Input validation and Unicode normalization

## What was built
| Piece | File | Purpose |
|---|---|---|
| `InspectRequest` | `guardrails/validation.py` | Strict wire schema: `text`, `content_type`, `request_id`. Unknown fields rejected, no type coercion |
| `parse_json_body()` | same | Raw bytes -> dict: size cap, strict UTF-8, JSON depth pre-scan, parse, must be an object |
| `validate_input()` | same | Schema, content type, length, blank, encodable, JSON payload checks, then normalization |
| `InputRejected` | `guardrails/errors.py` | Rejection with a reason code and a fixed public message |
| `reject_decision()` | `validation.py` | A rejection as a typed `block` Decision (policy `builtin.input-validation`) |
| `normalize_text()` | `guardrails/normalization.py` | Builds the inspection copy + offset map + flags |
| `ValidatedInput.findings()` | `validation.py` | Normalization flags as `Finding`s |

Phase 1 settings are now enforced for input: `max_request_body_bytes`, `max_input_chars`, `max_nesting_depth`.

## Check order (cheap first, nothing expensive touches bad input)
body size -> UTF-8 -> JSON depth scan -> JSON parse -> schema -> content type -> char limit -> blank -> encodable -> JSON payload -> normalize -> blank-after-normalize

## Key decisions
1. **The original text is never changed.** Detectors read `ValidatedInput.text` (normalized copy). Anything forwarded downstream is the original unless a later phase sanitizes it.
2. **Offsets rule for the whole project:** a `Finding`'s `start`/`end` always point into the ORIGINAL text. Detectors work on the normalized copy and convert with `NormalizedText.original_span()`.
3. **Normalization is not detection.** It undoes tricks and reports them as flags (findings). The policy engine (Phase 5) decides what to do with them.
4. **Multilingual text is protected.** Russian, Arabic, Urdu, Chinese, Hindi, Greek and emoji sequences pass through with no flags. Zero-width (non-)joiners are dropped from the inspection copy but flagged only when they sit between ASCII letters. Look-alike mapping happens only inside a word that also contains Latin letters.
5. **Tag characters are decoded.** U+E0020..E007E encode hidden ASCII; the inspection copy shows the hidden text and flags it HIGH.
6. **Everything is linear time and non-recursive.** JSON depth is pre-scanned with a state machine before `json.loads`, so `[[[[...` never reaches the parser.
7. **Errors never echo client text.** Unknown field names are shown as `<unknown field>`.

## Flags
`invisible_in_word` (medium), `bidi_override` (medium), `tag_characters` (high), `mixed_script_word` (medium), `compat_latin` (low), `control_characters` (low), `excessive_repetition` (low; runs longer than 64 are collapsed in the inspection copy).

## Bug found by the tests
Text made only of invisible characters (e.g. zero-width space + ideographic space) passed the blank check, because Python does not treat U+200B as whitespace. Fixed by re-checking for blank text after normalization. Four test cases fail without the fix.

## Known limits (stated honestly)
- A word written entirely in look-alike Cyrillic/Greek letters is not mapped; the look-alike table is small.
- For `application/json`, the raw JSON text is inspected. Escapes like `ignore` are not decoded here; decode-and-rescan is planned for Phase 4.
- NFKC folding is done per character, so it does not compose combining sequences. It is for inspection only.
- JSON nesting limit is `max_nesting_depth` (default 8); deeper tool arguments need that setting raised.
- Limits and flags are not a security decision by themselves; no policy engine exists yet.

## Test it
    python -m pytest -q

## Results (build sandbox)
144 passed (Phases 0-1: 44, Phase 2: 100 new). Includes hostile-input timing tests (100k-char inputs, 500k-deep JSON) with a 3 s budget each; they finished well inside it, but timings depend on the machine.
