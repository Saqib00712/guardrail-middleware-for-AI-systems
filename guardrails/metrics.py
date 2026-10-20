"""Counters and timings in Prometheus text format, with no extra dependency.

Privacy and safety rules (tested):
* Labels are fixed per metric and low-cardinality: stage, action, reason code, endpoint TEMPLATE, status.
  There is NO tenant, user, key or request id label: those would leak who is calling and blow up memory.
* Every label value is checked against a safe pattern; anything else becomes "other".
* Each metric has a cap on distinct series. Beyond it, new label combinations are counted under "overflow".
* Metrics never raise into a request: callers use `safe()` and a failure is only logged.
HONEST LIMIT: values live in this process only (like the limiter state). Several workers = several /metrics pages.
"""
from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any

log = logging.getLogger("guardrails.metrics")
_VALUE = re.compile(r"^[A-Za-z0-9_:./{}-]{1,60}$")      # '{' '}' allow route templates like /v1/runs/{id}
DEFAULT_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

COUNTERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "guardrails_decisions_total": ("Decisions made, by stage, action and reason code", ("stage", "action", "reason_code")),
    "guardrails_degraded_total": ("Decisions made while a non-critical layer was down (fail-open)", ("stage",)),
    "guardrails_http_requests_total": ("HTTP requests by route template and status", ("endpoint", "status")),
    "guardrails_limit_denials_total": ("Requests refused by a limit", ("kind",)),
    "guardrails_audit_failures_total": ("Audit records that could not be written", ("event",)),
    "guardrails_tool_decisions_total": ("Tool-call decisions", ("action", "reason_code")),
}
HISTOGRAMS: dict[str, tuple[str, tuple[str, ...]]] = {
    "guardrails_decision_seconds": ("Time to make a decision", ("stage",)),
    "guardrails_http_request_seconds": ("HTTP request time", ("endpoint",)),
}


def _clean(v: object) -> str:
    s = str(getattr(v, "value", v))
    return s if _VALUE.match(s) else "other"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    def __init__(self, *, max_series_per_metric: int = 500, buckets: Sequence[float] = DEFAULT_BUCKETS) -> None:
        if max_series_per_metric < 1 or list(buckets) != sorted(set(buckets)) or not buckets:
            raise ValueError("max_series_per_metric >= 1 and buckets must be sorted and unique")
        self._max, self._buckets = max_series_per_metric, tuple(buckets)
        self._lock = threading.Lock()
        self._c: dict[str, dict[tuple[str, ...], float]] = {n: {} for n in COUNTERS}
        self._h: dict[str, dict[tuple[str, ...], list[float]]] = {n: {} for n in HISTOGRAMS}   # counts per bucket, +Inf, sum

    # ---- recording
    def _key(self, table: Mapping[tuple[str, ...], Any], labels: tuple[str, ...], names: tuple[str, ...]) -> tuple[str, ...]:
        if len(labels) != len(names):
            raise ValueError("wrong number of labels")
        k = tuple(_clean(x) for x in labels)
        if k not in table and len(table) >= self._max:
            return ("overflow",) * len(names)
        return k

    def inc(self, name: str, *labels: object, by: float = 1.0) -> None:
        if name not in COUNTERS or by < 0:
            raise ValueError("unknown counter or negative increment")
        with self._lock:
            t = self._c[name]
            k = self._key(t, labels, COUNTERS[name][1])  # type: ignore[arg-type]
            t[k] = t.get(k, 0.0) + by

    def observe(self, name: str, seconds: float, *labels: object) -> None:
        if name not in HISTOGRAMS:
            raise ValueError("unknown histogram")
        if seconds != seconds or seconds < 0:       # NaN or negative: ignore rather than poison the sum
            return
        with self._lock:
            t = self._h[name]
            k = self._key(t, labels, HISTOGRAMS[name][1])  # type: ignore[arg-type]
            row = t.setdefault(k, [0.0] * (len(self._buckets) + 2))
            for i, ub in enumerate(self._buckets):
                if seconds <= ub:
                    row[i] += 1
            row[len(self._buckets)] += 1             # +Inf (= count)
            row[len(self._buckets) + 1] += seconds   # sum

    def safe(self, fn: Callable[..., None], *a: Any, **kw: Any) -> None:
        """Call a recording method; a metrics bug must never break or block a request."""
        try:
            fn(*a, **kw)
        except Exception as exc:  # noqa: BLE001
            log.error("metrics failure: %s", type(exc).__name__)

    # ---- convenience for the pipeline
    def record_decision(self, stage: object, action: object, reason_code: object, seconds: float | None, degraded: bool) -> None:
        self.inc("guardrails_decisions_total", stage, action, reason_code)
        if degraded:
            self.inc("guardrails_degraded_total", stage)
        if seconds is not None:
            self.observe("guardrails_decision_seconds", seconds, stage)

    # ---- reading
    def value(self, name: str, *labels: object) -> float:
        with self._lock:
            return self._c[name].get(tuple(_clean(x) for x in labels), 0.0)

    def render(self) -> str:
        out: list[str] = []
        with self._lock:
            for name, (help_, names) in COUNTERS.items():
                out += [f"# HELP {name} {help_}", f"# TYPE {name} counter"]
                for k, v in sorted(self._c[name].items()):
                    out.append(f"{name}{self._labels(names, k)} {v:g}")
            for name, (help_, names) in HISTOGRAMS.items():
                out += [f"# HELP {name} {help_}", f"# TYPE {name} histogram"]
                for k, row in sorted(self._h[name].items()):
                    for i, ub in enumerate(self._buckets):
                        out.append(f"{name}_bucket{self._labels(names + ('le',), k + (f'{ub:g}',))} {row[i]:g}")
                    out.append(f"{name}_bucket{self._labels(names + ('le',), k + ('+Inf',))} {row[len(self._buckets)]:g}")
                    out.append(f"{name}_sum{self._labels(names, k)} {row[len(self._buckets) + 1]:.6f}")
                    out.append(f"{name}_count{self._labels(names, k)} {row[len(self._buckets)]:g}")
        return "\n".join(out) + "\n"

    @staticmethod
    def _labels(names: tuple[str, ...], values: tuple[str, ...]) -> str:
        return "{" + ",".join(f'{n}="{_esc(v)}"' for n, v in zip(names, values)) + "}" if names else ""
