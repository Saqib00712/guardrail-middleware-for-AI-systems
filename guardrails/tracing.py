"""A tiny tracing hook. The core package does not depend on OpenTelemetry.

`Tracer.span(name)` returns a context manager whose object has `set_attribute(key, value)`.
Guardrails only ever sets the attributes in ALLOWED_ATTRIBUTES: decisions and counts, never text,
tenant ids, user ids or keys (tested). A tracer that fails is ignored: tracing must never
change a security decision, and an error raised by the guarded code itself is never hidden.
"""
from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator
from typing import Any, Protocol

log = logging.getLogger("guardrails.tracing")
ALLOWED_ATTRIBUTES = frozenset({"stage", "action", "reason_code", "degraded", "redactions", "request_id"})


class Span(Protocol):
    def set_attribute(self, key: str, value: Any) -> None: ...


class Tracer(Protocol):
    def span(self, name: str) -> Any: ...      # a context manager yielding a Span


class _SafeSpan:
    def __init__(self, inner: Span | None) -> None:
        self._inner = inner

    def set_attribute(self, key: str, value: Any) -> None:
        if self._inner is None or key not in ALLOWED_ATTRIBUTES:
            return
        try:
            self._inner.set_attribute(key, value if isinstance(value, (bool, int, float)) else str(getattr(value, "value", value)))
        except Exception as exc:  # noqa: BLE001
            log.error("tracer failure: %s", type(exc).__name__)


@contextlib.contextmanager
def safe_span(tracer: Tracer | None, name: str) -> Iterator[_SafeSpan]:
    cm: Any = None
    inner: Span | None = None
    if tracer is not None:
        try:
            cm = tracer.span(name)
            inner = cm.__enter__()
        except Exception as exc:  # noqa: BLE001
            log.error("tracer failure: %s", type(exc).__name__)
            cm = inner = None
    try:
        yield _SafeSpan(inner)
    except BaseException as exc:
        if cm is not None:
            try:
                cm.__exit__(type(exc), exc, exc.__traceback__)
            except Exception:  # noqa: BLE001
                log.error("tracer failure on exit")
        raise
    else:
        if cm is not None:
            try:
                cm.__exit__(None, None, None)
            except Exception as exc:  # noqa: BLE001
                log.error("tracer failure: %s", type(exc).__name__)
