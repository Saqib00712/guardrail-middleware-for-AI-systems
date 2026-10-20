# Phase 13 — An evaluation set and measured results

Goal: replace "it seems to work" with numbers, and say plainly where it does not.
Full tables (generated, never typed by hand): `docs/evaluation_results.md`. Raw results: `evaluation/results.json`.

<!-- numbers: all_bad=172/309; benign_fp=10/128; first_all_bad=168/309; first_benign_fp=12/128 -->

## What was added
| File | What it is |
|---|---|
| `evaluation/build_dataset.py` | Writes the case file. Deterministic. Holds the notes on how the set was made. |
| `evaluation/data/cases.ndjson` | 437 cases (309 bad, 128 normal). Fake credentials are placeholders like `{{AWS_KEY}}`; nothing credential-shaped is stored. |
| `evaluation/runner.py` | Runs every case through the real `Guardrails`, computes results, times the service. |
| `evaluation/metrics.py` | Confidence intervals, precision/recall, percentiles. Tested against hand-computed values. |
| `evaluation/baseline.json` | The accepted results. A test fails when behavior changes, so a change is always a decision. |
| `evaluation/first_measurement.json` | The numbers before any rule change in this phase. |
| `tests/unit/test_evaluation.py` | Tests for: the math, the scoring rules, the dataset, determinism, the baseline, slow inputs, the report. |

Run from the repo root: `python -m evaluation run` (measure and write the report), `python -m evaluation check`, `python -m evaluation run --show-misses dev`.

## How to read the numbers (please read this part)
1. **The set is not independent.** I wrote the rules and I wrote this set, in a separate pass, trying to think like an attacker. My blind spots are in both. Real-world results are probably **worse** than these.
2. **It is small.** Every rate has a 95% confidence interval in the report. With 9 cases the interval is huge; do not compare two close numbers.
3. **Precision depends on the mix.** The set has about 1 normal text per 2.4 bad ones. Real traffic is mostly normal, so real precision would be lower. That is why the report leads with recall and the false-alarm rate on normal texts.
4. **Hand-written vs generated.** "Generated" cases are the same few payloads under encodings. They are easier for decoding rules and make the totals look better. The report splits them.
5. **Dev and held-out.** Cases are split in two halves by a hash of the text. I looked at the **dev** half's misses and fixed gaps from them. I only looked at the held-out half's totals. Because both halves contain the same kinds of cases, held-out is still **not** a clean test of the fixes. It is a check, not a proof.

### Definitions
* **Intervened** = the decision was anything but ALLOW (block, require review, or sanitize).
* Bad text is **handled** when the system intervened. Personal data and secrets are handled only if the system intervened **and** the planted value is gone from the released text. (For the obfuscated secret cases the literal value never appears in the text, so "handled" means "intervened".)
* A normal text is a **false alarm** if the system changed or blocked it in any way.

## Results (numbers come from `docs/evaluation_results.md`)
| | Before the fixes | After the fixes |
|---|---|---|
| Bad cases handled (all) | 168 of 309 | 172 of 309 |
| Normal texts wrongly changed (all) | 12 of 128 | 10 of 128 |

By area, after the fixes (all cases): prompt injection 81 of 196, secrets 39 of 46, personal data 31 of 41, unsafe output markup 14 of 17, prompt leaks 7 of 9.

**Prompt injection is the weak spot.** Hand-written injection attempts: 31 of 126 handled (24.6%). The same payloads under encodings: 50 of 70 (71.4%). The rules catch the well-known direct phrasings and many encodings. They miss almost everything that is paraphrased, role-play, social engineering, or written in many other languages. This is expected from pattern rules and is exactly why the optional model-assisted detector and the "untrusted content cannot trigger tools" controls exist. **Do not rely on the injection rules alone.**

Techniques with **zero** cases handled (see the generated report for counts): exfiltration instructions, indirect instructions inside uploaded files and tool output, social engineering, base32, reversed text and letter-spaced text, paraphrased or translated system-prompt leaks, IP addresses (off by default), obfuscated emails, base64 / spaced / URL-encoded secrets, and links (not images) to untrusted hosts. Links are not flagged by design: they need a click.

Fully handled: credit cards, phone numbers, national ids, plain emails, output PII, rot13, html-comment and JSON wrapping, alternating case, zero-width characters, markdown quoting.

**False alarms on normal text** (10 of 128): 3 look-alike numbers (order, ISBN and invoice numbers read as phone numbers), 2 security-discussion texts that quote an attack phrase, 2 code answers containing HTML, 1 role address (`support@...`), 1 near-miss answer, 1 document. Five were blocks and five were sanitizes. These are known limits of pattern matching: a regex cannot know that an address belongs to a company, or that a number is an order id.

### Gaps found and fixed (from DEV cases only)
* `DB_PASSWORD=...` and similar prefixed names were not detected (the underscore hid the word `password`).
* "The admin password is: ..." (with a colon) was not detected.
* `aws_secret_access_key = ...` was not detected.
* npm tokens (`npm_` + 36 characters) were not detected. (My fake token was 35 characters, so I also corrected the fake.)
* `password = os.environ["X"]` and `process.env.KEY` were reported as secrets. Code that reads a secret is not a secret.
Each has tests, and each test fails if the fix is removed (checked by breaking the code on purpose).

### Process log (so you can judge how clean the held-out half is)
1. Wrote the set. First run: totals only, plus dev misses. Held-out misses were not looked at.
2. Found 5 gaps on dev (above), fixed them, re-ran.
3. Two generated cases turned out to be identical to Phase 4 regression cases, so they were removed from the set (ids not renumbered). The first measurement was then re-recorded on the final 437 cases with the old rules put back temporarily. For the record, the very first run on 439 cases read: all 170 of 311 handled, 12 of 128 false alarms.
4. Not fixed on purpose: injection paraphrases and other languages (more patterns would only memorize my own examples), look-alike numbers and role addresses (a real precision/recall trade-off that needs context), quoted attacks.

## Speed (this machine only; see the report for the table)
One thread, one process, Python 3.13 on Linux x86-64. Checking a 100-character input: median 0.29 ms. 1,000 characters: median 2.4 ms. 5,000: 11.3 ms. 20,000 (the default maximum): median 42 ms, 99th percentile 63 ms. Your machine will differ: run `python -m evaluation run`.
Twenty inputs built to be slow (20,000 characters of repeated attack phrases, digits, brackets, entities, zero-width runs and so on) all finished in under 0.1 s on this machine. A test fails if any takes over 3 s. This is evidence that the patterns have no obvious runaway case, not a proof.

## What I would do next (not done)
* Add semantic detection (the model-assisted detector, run in a controlled way) and re-measure on a set written by someone else.
* Collect real, labeled examples from your own traffic. That is the only number that matters.
* Base32, reversed and letter-spaced decoding; multi-language injection phrases (cheap, but measure first).
* Context for look-alike numbers (the word "order" or "invoice" before it) to cut false alarms.

## Understanding check
The report says 9 of 9 cases were handled. Can you say the system "catches 100%" of that kind of attack? (Answer: no. With 9 cases the 95% interval runs from about 70% to 100%, and the cases were written by the person who wrote the rules.)
