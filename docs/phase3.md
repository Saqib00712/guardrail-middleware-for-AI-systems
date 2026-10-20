# Phase 3 — PII and secret detection, deterministic redaction

## What was built
| Piece | File | Purpose |
|---|---|---|
| `Match` | `guardrails/detectors/base.py` | What + where (ORIGINAL offsets) + severity + priority. **No matched value is stored** |
| `RegexDetector`, `Rule`, `Allowlist` | same | Pattern + validator rules; allowlists applied to the short matched value only |
| `DetectorConfig`, `AllowSpec`, `NationalIdPattern` | `detectors/config.py` | Validated config: categories, custom ID patterns, PII and secret allowlists |
| PII detectors | `detectors/pii.py` | email, phone, credit card, national id (US SSN, Pakistan CNIC, custom), IPv4 (off by default) |
| Secret detectors | `detectors/secrets.py` | provider keys, JWT, bearer/basic, `password=` pairs, "my password is", DB URIs with credentials, PEM private keys |
| `Scanner`, `ScanResult` | `detectors/scanner.py` | Runs detectors over a `NormalizedText`; stable ordering; findings and counts |
| `redact()`, `merge_spans()` | `guardrails/redaction.py` | Deterministic redaction of the original text |

## How false positives are limited (not every number is PII)
* **Phone:** needs `+` or visible separators; 10-15 digits; a digit group of 3+; not a date, IPv4, repeated digit, card or national ID. A **bare run of digits is never a phone** (including `03001234567`). Space-only numbers need a leading 0, `+`, or 3+ groups.
* **Card:** 13-19 digits, plausible grouping, a real network prefix AND Luhn. Luhn alone would flag ~1 in 10 random 16-digit numbers.
* **SSN:** hyphenated only; 000/666/9xx and zero groups excluded. **CNIC:** `[1-7]####-#######-#`.
* **Secrets:** placeholders (`<your-password>`, `${X}`, `xxxx`, `changeme`, `None`, ...) and ordinary prose ("password policy requires...") are ignored.
* **Allowlists:** exact (case-insensitive) or full-match regex, per PII and per secrets.

## Redaction rules
* Edits the ORIGINAL text; the untouched parts are preserved exactly (spacing, Urdu, emoji).
* **Overlaps merge to the union** so no part of any overlapping detection is left exposed; the label comes from the highest priority (ties: longer, earlier, then category name).
* Styles: `label` -> `[REDACTED_EMAIL]`; `indexed` -> `[EMAIL_1]` (same value = same number in one text; still irreversible, no mapping stored).
* `categories=` lets a caller redact only some categories (the policy engine will choose per stage in Phase 5).
* Deterministic, and redacted output rescans clean (idempotent).

## Downstream model quality (the cost of irreversible redaction)
Redaction removes information. A model asked "what is this candidate's email?" cannot answer after the email is gone, and a redacted card number makes "is this number valid?" unanswerable. `indexed` keeps "same vs different" but not content. Use redaction where a boundary must not carry the value (to a third-party model, into logs), and prefer allow/block when the content is the point of the request. Production-rag's `PII_MODE=redact` has the same trade-off.

## Bugs found by the tests and fixed
1. `order 12345 67890` flagged as a phone number.
2. A card (Amex) and a CNIC were each reported twice, as the specific type and as a phone.
3. **A database URI with an email as the username was only partly redacted**: the password was read as an email and left exposed. The URI rule now allows an `@` in the username.
4. `password = 'x'` was reported twice by two rules.
A mutation check also showed one safeguard (bare digits are not phones) had no direct test; cases were added and the mutant is now caught.

## Known limits
* Not detected: names, street addresses, dates of birth, IPv6, unlabeled high-entropy strings, "pw=..." style key names not in the list.
* Phone and card rules are heuristics: some real numbers will be missed (bare digits) and some IDs may still look like phones (e.g. `12 345 678 90`).
* Custom `NationalIdPattern` regexes are admin-trusted; Python's `re` has no timeout, so keep them simple.
* Detectors read the normalized copy; text split across separate requests or fields is not joined.
* Secret detection is prefix/shape based. New provider key formats need new rules.
* No policy decides allow/redact/block yet; that is Phase 5.

## Safe test data
`tests/unit/fakes.py` builds fake credentials from pieces at runtime so no real-looking secret is committed (AWS's documented example key, test card numbers, invented tokens).

## Test it
    python -m pytest -q

## Results (build sandbox)
313 passed (Phases 0-2: 144, Phase 3: 169 new).
Mutation checks: removing Luhn, the card-issuer check, overlap merging, or the bare-digit phone rule each makes tests fail.
Timing on hostile inputs (single run, this sandbox, normalize + scan): 100,000 digits 53 ms; 100,000 chars after `sk-` 47 ms; 27,000 chars of repeated BEGIN-key markers 25 ms; 19,600 chars of realistic prose with 800 matches 25 ms. Machine-dependent.
