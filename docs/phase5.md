# Phase 5 — Policy engine

Detectors report findings. The policy decides: allow, sanitize, require_review or block.

## Rules of the engine
- **Order never matters.** Every rule that matches a finding applies; the strictest action wins. A waiver can never override a block. (Tested with 120 rule orderings and all finding orderings.)
- **Fail closed.** A finding no rule covers gets `unmatched_action` (default block, and it cannot be "allow"). No findings = allow.
- **Non-waivable.** At load time a policy is rejected if an "allow" rule could cover secrets, any finding of HIGH/CRITICAL severity, or "any code".
- **Missing confidence counts as HIGH.**
- **Monitor mode** reports what would have happened but allows; refused in production.
- **No matched text** in decisions; only rule ids and findings. The public view hides policy and rule ids.
- **Files:** JSON only (no extra dependency), size-limited, errors name fields but never echo unknown keys or values.
- **Tenants:** `PolicyRegistry` gives a tenant its own policy (same load-time rules). Unknown tenant = baseline, never a looser policy. Authenticating tenants is Phase 10.

## Default policy
secrets → block · PII → sanitize · injection high confidence → block, medium → require_review, low → sanitize · suspicious encoding → require_review · anything else → block.

## Limits
- Policy sees findings only. It does not know the content source (the detectors already use it).
- A tenant policy may be stricter or looser than baseline within the load-time rules; there is no "never looser than baseline" comparison yet.

## Commands
    python -m pytest -q tests/unit/test_policy.py
    python -m pytest -q
