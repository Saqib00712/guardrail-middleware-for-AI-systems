import pytest
from pydantic import ValidationError

from guardrails import (Action, Decision, Finding, PublicCode, ReasonCode, Severity, Stage,
                        most_restrictive, new_request_id)


def mk(action, severity=Severity.LOW, reason=ReasonCode.PII_DETECTED, **kw):
    return Decision(action=action, reason_code=reason, severity=severity, stage=Stage.INPUT,
                    policy_id="default", policy_version=1, **kw)


def test_allow_factory():
    d = Decision.allow(Stage.INPUT, policy_id="default", policy_version=3, request_id="r1")
    assert d.action is Action.ALLOW and d.reason_code is ReasonCode.OK
    assert d.permits_forwarding and d.policy_version == 3


def test_ok_reason_cannot_accompany_a_block():
    with pytest.raises(ValidationError):
        mk(Action.BLOCK, reason=ReasonCode.OK)


def test_ok_reason_cannot_accompany_findings():
    f = Finding(detector_id="email", reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW)
    with pytest.raises(ValidationError):
        Decision(action=Action.ALLOW, reason_code=ReasonCode.OK, severity=Severity.INFO,
                 stage=Stage.INPUT, policy_id="p", policy_version=1, findings=(f,))


def test_decision_is_immutable():
    d = mk(Action.BLOCK)
    with pytest.raises(ValidationError):
        d.action = Action.ALLOW


def test_policy_version_must_be_positive():
    with pytest.raises(ValidationError):
        Decision(action=Action.BLOCK, reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW,
                 stage=Stage.INPUT, policy_id="p", policy_version=0)


def test_finding_cannot_carry_matched_text():
    with pytest.raises(ValidationError):
        Finding(detector_id="email", reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW,
                matched_text="person@example.com")


def test_finding_offsets_validated():
    with pytest.raises(ValidationError):
        Finding(detector_id="e", reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW, start=5)
    with pytest.raises(ValidationError):
        Finding(detector_id="e", reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW, start=5, end=2)
    with pytest.raises(ValidationError):
        Finding(detector_id="e", reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW, start=-1, end=2)
    ok = Finding(detector_id="e", reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW, start=2, end=2)
    assert (ok.start, ok.end) == (2, 2)


def test_finding_ids_reject_odd_characters():
    for bad in ("", "Has Space", "a" * 65, "x;drop"):
        with pytest.raises(ValidationError):
            Finding(detector_id=bad, reason_code=ReasonCode.PII_DETECTED, severity=Severity.LOW)


def test_most_restrictive_prefers_action_then_severity_then_first():
    a = mk(Action.SANITIZE, Severity.CRITICAL)
    b = mk(Action.BLOCK, Severity.LOW)
    c = mk(Action.BLOCK, Severity.HIGH)
    d = mk(Action.BLOCK, Severity.HIGH, reason=ReasonCode.SECRET_DETECTED)
    assert most_restrictive([a, b]) is b          # action beats severity
    assert most_restrictive([a, b, c]) is c       # then severity
    assert most_restrictive([c, d]) is c          # tie: first one wins (deterministic)


def test_most_restrictive_empty_needs_explicit_default():
    with pytest.raises(ValueError):
        most_restrictive([])
    dflt = Decision.allow(Stage.INPUT, policy_id="p", policy_version=1)
    assert most_restrictive([], default=dflt) is dflt


def test_public_view_hides_internals():
    f = Finding(detector_id="secret.openai", reason_code=ReasonCode.SECRET_DETECTED,
                severity=Severity.HIGH, start=3, end=40)
    d = Decision(action=Action.BLOCK, reason_code=ReasonCode.SECRET_DETECTED, severity=Severity.HIGH,
                 stage=Stage.INPUT, policy_id="pol-internal-42", policy_version=7, findings=(f,),
                 request_id="r1")
    pub = d.to_public()
    dumped = pub.model_dump_json()
    assert pub.code is PublicCode.BLOCKED and pub.request_id == "r1"
    for leak in ("secret.openai", "SECRET_DETECTED", "pol-internal-42", "policy_id", "policy_version", "start", "findings", "severity", "detector"):
        assert leak not in dumped
    assert pub.reason_code is None


def test_public_view_can_expose_reason_code_only_by_opt_in():
    d = mk(Action.BLOCK, reason=ReasonCode.PROMPT_INJECTION)
    assert d.to_public(expose_reason_code=True).reason_code is ReasonCode.PROMPT_INJECTION
    assert d.to_public().reason_code is None


@pytest.mark.parametrize("action,code", [
    (Action.SANITIZE, PublicCode.SANITIZED), (Action.REQUIRE_REVIEW, PublicCode.REVIEW_REQUIRED),
    (Action.BLOCK, PublicCode.BLOCKED)])
def test_public_codes_map_one_to_one(action, code):
    assert mk(action).to_public().code is code


def test_request_ids_are_unique_and_short():
    ids = {new_request_id() for _ in range(1000)}
    assert len(ids) == 1000 and all(len(i) == 32 for i in ids)
