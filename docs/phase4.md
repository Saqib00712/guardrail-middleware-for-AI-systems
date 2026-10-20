# Phase 4 — Prompt-injection detection

## What it does
- **Source-aware rules** (21): the same sentence is a normal request from a user but an attack inside a retrieved document, web page, upload, tool output or model output. `ContentSource` / `TrustLevel` carry this.
- **Decode-and-rescan**: base64, hex, URL, unicode escapes, HTML entities, ROT13, leetspeak are decoded and rescanned. Bounded by candidates, depth, count and characters; hitting the budget is itself a finding (`decode_budget_exhausted`).
- **Escalation**: several distinct weak signals together become one HIGH-confidence finding.
- **Model-assisted detector** (optional, interface only; no real provider shipped): timeout, concurrency limit, call budget; external providers refused unless `allow_external_detectors=true`; text sent out is PII/secret-redacted first. Never the only boundary.

## Measured (regression metrics only)
The dataset (58 malicious, 60 benign) was written together with the rules, so these are NOT real-world accuracy.
| Operating point | TP | FN | FP | TN | Precision | Recall | FPR |
|---|---|---|---|---|---|---|---|
| any finding | 58 | 0 | 0 | 60 | 1.00 | 1.00 | 0.00 |
| actionable | 55 | 3 | 0 | 60 | 1.00 | 0.948 | 0.00 |

## Known limits (strict xfail, so a silent fix is noticed)
Misses: paraphrase, unsupported language, reversed text, spaced letters, uncovered phrasing, indirect injection with no override words.
False positives: quoted attack text, documentation about attacks.
Multilingual rules (es/fr/de/pt/it/ru/ar/ur) need native-speaker review.

## Mutation checks (each made tests fail, then reverted)
source gate off (3 fail); decode rescan off (13); decode depth limit off (1); escalation off (2); external-provider gate off (1).

## Commands
    python -m pytest -q tests/unit/test_injection.py -s
    python -m pytest -q
