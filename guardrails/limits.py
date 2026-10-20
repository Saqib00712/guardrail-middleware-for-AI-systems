"""Rate limits, usage budgets and deadlines: keep one caller (or one slow input) from using everything.

* TokenBucketLimiter  requests per minute with a burst allowance, per key.
* BudgetTracker       a fixed-window quota (for example characters per hour), per key.
* Deadline            a time limit for one request, checked between pipeline stages.

HONEST LIMITS (also in docs/phase11.md):
* State is in memory, per process. Two workers or two servers each keep their own
  counts, so the real limit is multiplied by the number of processes. Sharing counts needs
  a shared store (for example Redis). `RateLimiter` is a Protocol so one can be plugged in; none is provided.
* A deadline is checked BETWEEN stages. It cannot interrupt one long-running step.
  The input length caps are the first defense; the deadline is the second.
* A fixed-window budget allows up to twice the quota across a window boundary.
* The tables are bounded. When full of active keys, NEW keys are refused (fail closed),
  never old keys evicted (that would let a flood reset someone's counter).
"""
from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

Clock = Callable[[], float]


class DeadlineExceeded(Exception):
    """Raised by Deadline.check(). Carries no request content."""


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after: float = 0.0          # seconds until a retry could succeed

    @property
    def retry_after_header(self) -> str:
        return str(max(1, math.ceil(self.retry_after)))


class RateLimiter(Protocol):
    def check(self, key: str, cost: float = 1.0) -> RateDecision: ...
    def peek(self, key: str) -> RateDecision: ...


class TokenBucketLimiter:
    """`per_minute` tokens added each minute, at most `burst` stored. Thread-safe, bounded."""

    def __init__(self, per_minute: float, burst: float, *, clock: Clock = time.monotonic, max_keys: int = 10_000) -> None:
        if per_minute <= 0 or burst < 1 or max_keys < 1:
            raise ValueError("per_minute must be > 0, burst >= 1, max_keys >= 1")
        self._rate = per_minute / 60.0
        self._burst = float(burst)
        self._clock = clock
        self._max = max_keys
        self._b: dict[str, tuple[float, float]] = {}      # key -> (tokens, last_seen)
        self._lock = threading.Lock()
        self.denied_total = 0

    def _refilled(self, key: str, now: float) -> float | None:
        st = self._b.get(key)
        if st is None:
            return None
        tokens, last = st
        return min(self._burst, tokens + max(0.0, now - last) * self._rate)

    def _purge_full(self, now: float) -> None:
        # A bucket that has refilled completely is the same as a new one, so dropping it is harmless.
        for k in [k for k in self._b if (self._refilled(k, now) or 0) >= self._burst]:
            del self._b[k]

    def peek(self, key: str) -> RateDecision:
        """Would a request be allowed right now? Does not spend a token."""
        with self._lock:
            now = self._clock()
            t = self._refilled(key, now)
            if t is None or t >= 1.0:
                return RateDecision(True)
            return RateDecision(False, (1.0 - t) / self._rate)

    def check(self, key: str, cost: float = 1.0) -> RateDecision:
        with self._lock:
            now = self._clock()
            t = self._refilled(key, now)
            if t is None:
                if len(self._b) >= self._max:
                    self._purge_full(now)
                if len(self._b) >= self._max:
                    self.denied_total += 1
                    return RateDecision(False, 1.0 / self._rate)       # table full of active keys: refuse new ones
                t = self._burst
            if cost > self._burst:
                self.denied_total += 1
                return RateDecision(False, math.inf)
            if t >= cost:
                self._b[key] = (t - cost, now)
                return RateDecision(True)
            self._b[key] = (t, now)
            self.denied_total += 1
            return RateDecision(False, (cost - t) / self._rate)


class BudgetTracker:
    """At most `limit` units per `window_seconds` per key (fixed window). A charge that does not fit is refused whole."""

    def __init__(self, limit: int, window_seconds: float, *, clock: Clock = time.monotonic, max_keys: int = 10_000) -> None:
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("limit >= 1, window_seconds > 0, max_keys >= 1")
        self._limit, self._win, self._clock, self._max = limit, float(window_seconds), clock, max_keys
        self._u: dict[str, tuple[float, int]] = {}         # key -> (window_start, used)
        self._lock = threading.Lock()
        self.denied_total = 0

    def charge(self, key: str, amount: int) -> RateDecision:
        if amount < 0:
            raise ValueError("amount must be >= 0")
        with self._lock:
            now = self._clock()
            st = self._u.get(key)
            if st is not None and now - st[0] >= self._win:
                st = None
                del self._u[key]
            if st is None:
                if len(self._u) >= self._max:
                    for k in [k for k, (s, _) in self._u.items() if now - s >= self._win]:
                        del self._u[k]
                    if len(self._u) >= self._max:
                        self.denied_total += 1
                        return RateDecision(False, self._win)
                st = (now, 0)
            start, used = st
            if used + amount > self._limit:
                self._u[key] = st
                self.denied_total += 1
                return RateDecision(False, max(0.0, start + self._win - now))
            self._u[key] = (start, used + amount)
            return RateDecision(True)

    def used(self, key: str) -> int:
        with self._lock:
            st = self._u.get(key)
            return 0 if st is None or self._clock() - st[0] >= self._win else st[1]


class Deadline:
    def __init__(self, seconds: float, *, clock: Clock = time.perf_counter) -> None:
        if seconds <= 0:
            raise ValueError("seconds must be > 0")
        self._clock = clock
        self._end = clock() + seconds

    def remaining(self) -> float:
        return self._end - self._clock()

    @property
    def expired(self) -> bool:
        return self.remaining() <= 0

    def check(self) -> None:
        if self.expired:
            raise DeadlineExceeded


@dataclass(frozen=True)
class ApiLimits:
    """The limiters the API uses, built from Settings. Replace members in tests or with a shared-store version."""
    per_key: RateLimiter
    per_tenant: RateLimiter
    auth_failures: RateLimiter
    budget: BudgetTracker
    log_gate: RateLimiter            # keeps denial AUDIT records to ~1 per key per minute, so a flood cannot fill the audit log

    @classmethod
    def from_settings(cls, s: "object", clock: Clock = time.monotonic) -> "ApiLimits":
        return cls(
            per_key=TokenBucketLimiter(s.rate_limit_per_minute, s.rate_limit_burst, clock=clock),            # type: ignore[attr-defined]
            per_tenant=TokenBucketLimiter(s.tenant_rate_limit_per_minute, max(1.0, s.tenant_rate_limit_per_minute), clock=clock),  # type: ignore[attr-defined]
            auth_failures=TokenBucketLimiter(s.auth_failures_per_minute, max(1.0, s.auth_failures_per_minute), clock=clock),  # type: ignore[attr-defined]
            budget=BudgetTracker(s.tenant_budget_chars_per_hour, 3600, clock=clock),                         # type: ignore[attr-defined]
            log_gate=TokenBucketLimiter(1, 1, clock=clock),
        )
