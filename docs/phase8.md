# Phase 8 — Tool authorization and agent protection

    reg = ToolRegistry(); reg.register(ToolSpec(name="send_email", args_model=Mail, risk=Risk.EXTERNAL,
                                                allowed_roles=frozenset({"user"}), description="...")); reg.freeze()
    tg  = g.tool_guard(reg, ApprovalManager(secret_32_bytes_or_more))
    ctx = AgentContext()                                   # one per agent run, per user
    g.check_input(doc_text, source=ContentSource.RETRIEVED_DOCUMENT, context=ctx)   # records taint
    r = tg.check("send_email", model_args, principal, ctx, approval_token=tok)
    if r.allowed: run_tool(r.arguments)                    # run the VALIDATED arguments, not the raw ones

## What it enforces
1. **Allowlist.** Only registered tools; registry frozen before use (a running agent cannot add tools). Exact name match only: no case folding, spaces, hidden characters or look-alike letters.
2. **Roles and tenants** from the authenticated `Principal`, checked every call.
3. **Strict arguments:** pydantic model with `extra="forbid"`, strict types (no "7" -> 7), size and depth limits, NaN rejected. The caller runs the returned validated arguments.
4. **Argument scanning:** secrets and injection text block; card/ID numbers and hidden characters need review. Arguments are NEVER silently rewritten ("sanitize" becomes "needs review"). Emails/phones are not scanned (normal tool inputs).
5. **Taint:** untrusted content seen -> external/destructive tools need approval even if the tool says otherwise; injection suspected -> external/destructive tools BLOCKED (approval cannot override), write tools need approval.
6. **Approvals:** signed (HMAC-SHA256), 5-minute default life (max 1 hour), single-use, bound to tool + exact arguments + user + tenant. Approver needs the approver role, same tenant, and is not the requester unless you allow it. Full replay store fails closed.
7. **Volume/loop limits** per agent run (20 calls, 3 identical calls by default); blocked attempts count.

## Limits (honest)
- Used-approval records are in memory: with several server processes, plug a shared `NonceStore`.
- Taint depends on the injection detector (Phase 4 limits apply) and on you passing every untrusted input through `check_input(..., context=ctx)`. A missed injection means no taint.
- Taint cannot be cleared inside a run; start a new run after a human reviews.
- Argument scanning treats model text as non-user text, so a legitimate argument containing an attack-like phrase can be blocked. Tune with per-tenant policy.
- Tools run in YOUR code: this module decides, it does not sandbox. Run tools with least privilege.
- Real rate limits and budgets arrive in Phase 11; this is only a per-run safety net.

## Commands
    python -m pytest -q tests/unit/test_tools.py
    python -m pytest -q
