# Phase 9 — Audit logging

    sink = JsonlFileSink("audit.jsonl")                      # 0600 on Linux/macOS, fsync on every write
    audit = AuditLogger(sink, key_32_bytes_or_more)
    g = Guardrails(audit=audit)                              # input, output, stream, tool checks and approvals are logged
    g.check_input(text, tenant_id="acme", user_id="alice")   # user_id is stored only as a keyed pseudonym
    python -m guardrails.audit_cli verify audit.jsonl            # key from env GR_AUDIT_KEY

## What a record holds
Ids, time (UTC), event type, stage, action, reason code, severity, policy id/version, finding SUMMARIES (detector, reason, severity, category, confidence), tool name, lengths and counts. **No text field exists** (`extra="forbid"`): prompts, matched values, tool arguments and model output cannot be logged by mistake. Tested by sending secrets, emails, card numbers, attack text and tool arguments through every path and searching the log.
- User ids -> keyed pseudonyms (HMAC). Tool-argument fingerprints -> keyed hashes (guessable arguments cannot be brute-forced without the key). Client-supplied ids that are malformed become `invalid-id` (no log injection).

## Tamper evidence
Each record has `seq`, the previous record's hash, and its own HMAC-SHA256 over the whole record. Edit, delete, reorder, duplicate or drop the head and verification names the first bad line and the reason; without the key a valid record cannot be forged (tested).
- **Limit:** removing the END of the file looks valid. Save `audit.head()` (seq + hash) in a different system to detect that.
- A write that fails after the line really reached disk causes a repeated sequence number at the next record: noisy but safe.
- On restart the logger checks the last record against the key and refuses to continue from a wrong key or corrupt tail.

## Failure behaviour
Audit down + closed mode (production default): an allowed input/output/tool result becomes BLOCK `AUDIT_UNAVAILABLE`, approvals are not issued, and a stream is cut. Already-blocked results stay as they were. Open mode exists only outside production and marks results `degraded`. A stream's single record is written at its end, so a failure there cannot recall text already sent.

## Platform note (found on your Windows run)
The 0600 file mode applies on Linux/macOS only. Windows ignores it (always shows 0o666), so on Windows protect the log with the folder's permissions. The one test that checks the mode is skipped on Windows; every other audit test, including tamper detection, passed there.

## Windows note (found by you)
The permission test failed on Windows (`0o666` instead of `0o600`): Windows ignores Unix permission bits. On Linux/macOS the log file is created owner-only (0600). On Windows it inherits the folder's access rules, so keep the log in a folder only the service account can read. `JsonlFileSink.permissions_enforced` is False there. The test now checks 0600 only where it can exist. Mutation check (0o644) still fails on Linux.

## Not done here
Rotation, retention and shipping to a log system (use an external collector); a shared sink for multiple processes (one writer per file; chains are per file).
