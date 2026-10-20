"""Server-side agent runs: the taint state for tool authorization lives here.

A run belongs to ONE (tenant, user). Unknown, expired or someone else's run id looks the
same (not found). A run is NEVER silently re-created: losing taint state would quietly
re-allow dangerous tools, so a missing run is an error the client must handle by starting
a new run. When the store is full it refuses new runs (fail closed) rather than evicting.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable

from guardrails.tools import AgentContext, Principal


class RunStoreFull(Exception):
    pass


class RunStore:
    def __init__(self, *, max_runs: int = 10_000, ttl_seconds: int = 3600,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._d: dict[tuple[str, str, str], tuple[float, AgentContext]] = {}
        self._max, self._ttl, self._clock, self._lock = max_runs, ttl_seconds, clock, threading.Lock()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def _purge(self, now: float) -> None:
        for k in [k for k, (exp, _) in self._d.items() if exp <= now]:
            del self._d[k]

    def create(self, p: Principal) -> str:
        with self._lock:
            now = self._clock()
            if len(self._d) >= self._max:
                self._purge(now)
                if len(self._d) >= self._max:
                    raise RunStoreFull
            run_id = secrets.token_urlsafe(16)
            self._d[(p.tenant_id, p.user_id, run_id)] = (now + self._ttl, AgentContext())
            return run_id

    def get(self, p: Principal, run_id: str) -> AgentContext | None:
        with self._lock:
            item = self._d.get((p.tenant_id, p.user_id, run_id))
            if item is None:
                return None
            if item[0] <= self._clock():
                del self._d[(p.tenant_id, p.user_id, run_id)]
                return None
            return item[1]
