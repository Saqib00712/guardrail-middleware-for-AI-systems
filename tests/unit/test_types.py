import pytest

from guardrails import Action, ReasonCode, Severity, Stage


def test_action_strictness_order():
    order = [Action.ALLOW, Action.SANITIZE, Action.REQUIRE_REVIEW, Action.BLOCK]
    assert [a.rank for a in order] == sorted(a.rank for a in order)
    assert len({a.rank for a in order}) == 4


def test_strictest_picks_block_over_everything():
    assert Action.strictest(Action.ALLOW, Action.BLOCK, Action.SANITIZE) is Action.BLOCK
    assert Action.strictest(Action.SANITIZE, Action.REQUIRE_REVIEW) is Action.REQUIRE_REVIEW
    assert Action.strictest(Action.ALLOW) is Action.ALLOW


def test_strictest_empty_is_an_error_not_an_implicit_allow():
    with pytest.raises(ValueError):
        Action.strictest()


def test_only_allow_and_sanitize_permit_forwarding():
    assert {a for a in Action if a.permits_forwarding} == {Action.ALLOW, Action.SANITIZE}


def test_severity_order_and_at_least():
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert Severity.HIGH.at_least(Severity.HIGH)
    assert not Severity.LOW.at_least(Severity.MEDIUM)
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]


def test_stable_string_values():
    # These strings appear in audit logs/APIs: changing them is a breaking change.
    assert [a.value for a in Action] == ["allow", "sanitize", "require_review", "block"]
    assert [s.value for s in Stage] == ["input", "output", "tool"]


def test_reason_codes_are_unique_upper_snake_and_match_names():
    values = [r.value for r in ReasonCode]
    assert len(values) == len(set(values))
    for r in ReasonCode:
        assert r.value == r.name
        assert r.value.isupper() or "_" in r.value
        assert r.value.replace("_", "").isalpha()
