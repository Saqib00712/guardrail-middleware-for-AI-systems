"""Small, dependency-free statistics. Each function is unit-tested against hand-computed values."""
from __future__ import annotations

import math
from collections.abc import Sequence


def ratio(num: int, den: int) -> float | None:
    return None if den == 0 else num / den


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    """95% Wilson score interval for a proportion. With few cases it is WIDE: that is the honest message."""
    if n == 0:
        return None
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, centre - half), min(1.0, centre + half)


def prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    p, r = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)
    return {"precision": p, "recall": r, "f1": f1}


def percentile(values: Sequence[float], q: float) -> float:
    """Nearest-rank percentile (q in 0..100)."""
    if not values:
        raise ValueError("no values")
    if not 0 <= q <= 100:
        raise ValueError("q must be between 0 and 100")
    s = sorted(values)
    k = max(1, math.ceil(q / 100 * len(s)))
    return s[k - 1]
