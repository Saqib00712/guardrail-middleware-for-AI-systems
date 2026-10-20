"""Phase 11: rate limits, budgets, deadlines. No network, no real waiting: every clock is fake."""
import math
import threading

import pytest

from guardrails import Guardrails, Settings
from guardrails.errors import ConfigurationError
from guardrails.limits import BudgetTracker, Deadline, DeadlineExceeded, TokenBucketLimiter
from guardrails.pipeline import InputPipeline
from guardrails.policy import PolicyRegistry, default_policy
from guardrails.types import Action, ReasonCode


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


# ------------------------------------------------------------------ token bucket
def test_burst_then_refusal_then_refill():
    c = Clock()
    lim = TokenBucketLimiter(60, 3, clock=c)                 # 1 token per second, burst 3
    assert [lim.check("k").allowed for _ in range(3)] == [True, True, True]
    d = lim.check("k")
    assert not d.allowed and d.retry_after == pytest.approx(1.0) and d.retry_after_header == "1"
    c.t += 0.5
    assert not lim.check("k").allowed                         # half a token is not enough
    c.t += 0.5
    assert lim.check("k").allowed and not lim.check("k").allowed
    c.t += 1000
    assert [lim.check("k").allowed for _ in range(4)] == [True, True, True, False]   # refill never exceeds the burst


def test_keys_are_independent_and_cost_works():
    c = Clock()
    lim = TokenBucketLimiter(60, 5, clock=c)
    assert lim.check("a", cost=5).allowed and not lim.check("a").allowed
    assert lim.check("b").allowed                              # another key is untouched
    d = lim.check("c", cost=6)                                 # can never fit in the burst
    assert not d.allowed and math.isinf(d.retry_after)


def test_peek_does_not_spend_tokens():
    lim = TokenBucketLimiter(60, 1, clock=Clock())
    for _ in range(5):
        assert lim.peek("k").allowed
    assert lim.check("k").allowed
    assert not lim.peek("k").allowed and lim.peek("k").retry_after > 0


def test_a_denied_request_does_not_reset_the_refill_timer():
    c = Clock()
    lim = TokenBucketLimiter(60, 1, clock=c)
    assert lim.check("k").allowed
    for _ in range(10):                                        # hammering while empty
        c.t += 0.1
        lim.check("k")
    c.t += 0.01                                                # about 1s in total: the token is back
    assert lim.check("k").allowed


@pytest.mark.parametrize("args", [(0, 1), (-1, 1), (60, 0), (60, 0.5)])
def test_bucket_rejects_bad_parameters(args):
    with pytest.raises(ValueError):
        TokenBucketLimiter(*args)
    with pytest.raises(ValueError):
        TokenBucketLimiter(60, 1, max_keys=0)


def test_table_is_bounded_and_refuses_new_keys_instead_of_evicting_old_ones():
    c = Clock()
    lim = TokenBucketLimiter(60, 2, clock=c, max_keys=2)
    assert lim.check("a", 2).allowed and lim.check("b", 2).allowed       # both now empty (active)
    assert not lim.check("flood-1").allowed                              # full of active keys: new key refused
    assert not lim.check("flood-2").allowed
    assert not lim.check("a").allowed                                    # a's counter was NOT reset by the flood
    c.t += 5
    assert lim.check("flood-1").allowed                                  # refilled buckets are purged, room again


def test_concurrent_callers_cannot_exceed_the_burst():
    lim = TokenBucketLimiter(60, 50, clock=Clock())                      # frozen clock: no refill
    allowed, lock = [], threading.Lock()

    def worker():
        for _ in range(20):
            r = lim.check("k").allowed
            with lock:
                allowed.append(r)

    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(allowed) == 50 and len(allowed) == 160 and lim.denied_total == 110


# ------------------------------------------------------------------ budget
def test_budget_refuses_whole_charges_and_resets_each_window():
    c = Clock()
    b = BudgetTracker(100, 3600, clock=c)
    assert b.charge("t", 60).allowed
    d = b.charge("t", 60)
    assert not d.allowed and d.retry_after == pytest.approx(3600)
    assert b.used("t") == 60                                   # the refused charge was not partly counted
    assert b.charge("t", 40).allowed and not b.charge("t", 1).allowed
    assert b.charge("other", 100).allowed                      # tenants are separate
    c.t += 1800
    assert b.charge("t", 1).retry_after == pytest.approx(1800)
    c.t += 1800
    assert b.charge("t", 100).allowed and b.used("t") == 100   # new window


def test_budget_zero_charge_and_bad_inputs():
    b = BudgetTracker(10, 60, clock=Clock())
    assert b.charge("t", 0).allowed
    with pytest.raises(ValueError):
        b.charge("t", -5)                                      # a negative charge must not mint credit
    for args in ((0, 60), (10, 0)):
        with pytest.raises(ValueError):
            BudgetTracker(*args)


def test_budget_table_is_bounded():
    c = Clock()
    b = BudgetTracker(10, 60, clock=c, max_keys=2)
    assert b.charge("a", 1).allowed and b.charge("b", 1).allowed
    assert not b.charge("c", 1).allowed and b.used("a") == 1
    c.t += 61
    assert b.charge("c", 1).allowed


# ------------------------------------------------------------------ deadline
def test_deadline_object():
    c = Clock()
    d = Deadline(5, clock=c)
    d.check()
    assert d.remaining() == 5 and not d.expired
    c.t = 5
    assert d.expired
    with pytest.raises(DeadlineExceeded):
        d.check()
    with pytest.raises(ValueError):
        Deadline(0)


class Tick:
    """Every reading of the clock moves time forward, so a request always looks slow."""
    def __init__(self, step):
        self.t, self.step = 0.0, step

    def __call__(self):
        self.t += self.step
        return self.t


def test_slow_input_is_blocked_with_deadline_exceeded_and_no_text():
    g = Guardrails(Settings(request_deadline_seconds=1), clock=Tick(10))
    r = g.check_input("hello there")
    assert r.decision.action is Action.BLOCK and r.decision.reason_code is ReasonCode.DEADLINE_EXCEEDED
    assert r.text is None and not r.allowed


def test_slow_output_is_blocked_too():
    g = Guardrails(Settings(request_deadline_seconds=1), clock=Tick(10))
    r = g.check_output("a perfectly fine answer")
    assert r.decision.action is Action.BLOCK and r.decision.reason_code is ReasonCode.DEADLINE_EXCEEDED and r.text is None


def test_fast_requests_are_unaffected():
    g = Guardrails(Settings(request_deadline_seconds=1), clock=Tick(0.0001))
    assert g.check_input("hello there").allowed and g.check_output("fine").allowed


def test_deadline_is_also_checked_before_sanitizing():
    """Time lost AFTER detection (policy stage) still stops the request before it is cleaned and released."""
    c = Clock()
    s = Settings(request_deadline_seconds=5)

    class SlowEngineRegistry(PolicyRegistry):
        def engine_for(self, tenant):
            eng = super().engine_for(tenant)

            class Slow:
                def evaluate(self, *a, **k):
                    c.t += 10
                    return eng.evaluate(*a, **k)
            return Slow()

    p = InputPipeline(s, SlowEngineRegistry(default_policy(), None, s), clock=c)
    r = p.check({"text": "mail bob@example.com please"})
    assert r.decision.reason_code is ReasonCode.DEADLINE_EXCEEDED and r.text is None
    c.t = 0
    p2 = InputPipeline(s, PolicyRegistry(default_policy(), None, s), clock=c)
    assert p2.check({"text": "mail bob@example.com please"}).text == "mail [REDACTED_EMAIL] please"


# ------------------------------------------------------------------ settings
def test_limit_settings_defaults_and_env():
    s = Settings()
    assert (s.rate_limit_per_minute, s.rate_limit_burst, s.request_deadline_seconds) == (120, 30, 5.0)
    s2 = Settings.from_env({"GUARDRAILS_RATE_LIMIT_BURST": "7", "GUARDRAILS_REQUEST_DEADLINE_SECONDS": "2.5",
                            "GUARDRAILS_TENANT_BUDGET_CHARS_PER_HOUR": "1000"})
    assert (s2.rate_limit_burst, s2.request_deadline_seconds, s2.tenant_budget_chars_per_hour) == (7, 2.5, 1000)


@pytest.mark.parametrize("name,value", [("REQUEST_DEADLINE_SECONDS", "0"), ("RATE_LIMIT_BURST", "0"),
                                       ("RATE_LIMIT_PER_MINUTE", "-1"), ("TENANT_BUDGET_CHARS_PER_HOUR", "0"),
                                       ("AUTH_FAILURES_PER_MINUTE", "0"), ("REQUEST_DEADLINE_SECONDS", "9999")])
def test_limit_settings_reject_nonsense(name, value):
    with pytest.raises(ConfigurationError):
        Settings.from_env({"GUARDRAILS_" + name: value})
