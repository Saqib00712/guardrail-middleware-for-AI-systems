# Writing a policy

A policy turns **findings** (what the detectors saw) into one **action**. A full example is `examples/policy.example.json`.
Load it with `GR_POLICY_FILE=path` or `Guardrails(settings, policy=policy_from_json_file(path))`.

## Actions
`allow` < `sanitize` < `require_review` < `block`. With several findings the **strictest wins**; rule order never changes the result.

## File format
Top level: `id`, `version` (positive integer), `mode` (`enforce`, or `monitor` in development only), `unmatched_action`
(what to do with a finding no rule covers; cannot be `allow`; default `block`), `rules`.
Each rule: `id`, `action`, plus optional selectors that must **all** match:
`reason_codes`, `stages` (`input`, `output`, `tool`), `min_severity`, `max_severity`, `min_confidence`, `max_confidence`.

## Safety rules the loader enforces
* An `allow` rule may only waive low-severity findings. It can never waive secrets or high severity.
* A finding with no confidence is treated as high confidence.
* Bad files are rejected with a message that does not repeat the file's values. Files over the size limit are rejected.
* `monitor` mode forwards the original text and reports what would have happened. It is refused in production.

## Per tenant
`PolicyRegistry` maps tenant ids to policies with a fallback. The tenant always comes from the API key, never the request body.

## Reason codes
`PII_DETECTED`, `SECRET_DETECTED`, `PROMPT_INJECTION`, `SYSTEM_PROMPT_EXTRACTION`, `SUSPICIOUS_ENCODING`, `UNSAFE_CONTENT`, and others in `guardrails/decisions.py`.

Rule of thumb: start strict (default), look at `monitor` results in development, then loosen a specific rule only with evidence.
