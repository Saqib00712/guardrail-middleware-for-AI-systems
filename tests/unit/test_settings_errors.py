import pytest
from pydantic import ValidationError

from guardrails import ConfigurationError, GuardrailError, ReasonCode, Settings


def test_defaults_are_strict():
    s = Settings()
    assert s.environment == "production"
    assert s.detector_failure_mode == s.audit_failure_mode == s.rate_limit_failure_mode == "closed"
    assert s.expose_reason_codes is False and s.allow_external_detectors is False


def test_settings_are_immutable():
    with pytest.raises(ValidationError):
        Settings().max_input_chars = 1


@pytest.mark.parametrize("field,bad", [
    ("max_input_chars", 0), ("max_input_chars", 10**9), ("max_request_body_bytes", -1),
    ("max_output_chars", 0), ("max_nesting_depth", 0), ("max_nesting_depth", 1000)])
def test_numeric_bounds(field, bad):
    with pytest.raises(ValidationError):
        Settings(**{field: bad})


def test_production_rejects_fail_open_for_detector_and_audit():
    with pytest.raises(ValidationError):
        Settings(environment="production", detector_failure_mode="open")
    with pytest.raises(ValidationError):
        Settings(environment="production", audit_failure_mode="open")


def test_production_allows_documented_rate_limit_fail_open():
    assert Settings(environment="production", rate_limit_failure_mode="open").rate_limit_failure_mode == "open"


def test_development_may_fail_open():
    s = Settings(environment="development", detector_failure_mode="open", audit_failure_mode="open")
    assert s.detector_failure_mode == "open"


def test_from_env_reads_prefixed_vars_only():
    s = Settings.from_env({"GUARDRAILS_ENVIRONMENT": "development", "GUARDRAILS_MAX_INPUT_CHARS": "500",
                           "GUARDRAILS_EXPOSE_REASON_CODES": "true", "PATH": "/bin", "OTHER_MAX": "1"})
    assert (s.environment, s.max_input_chars, s.expose_reason_codes) == ("development", 500, True)


def test_from_env_empty_gives_defaults():
    assert Settings.from_env({}) == Settings()


def test_from_env_unknown_variable_is_an_error_naming_only_the_variable():
    with pytest.raises(ConfigurationError) as e:
        Settings.from_env({"GUARDRAILS_MAX_INPUT_CHAR": "500"})  # typo: missing S
    assert "GUARDRAILS_MAX_INPUT_CHAR" in str(e.value)


def test_from_env_invalid_value_error_does_not_echo_the_value():
    secret_looking = "sk-THIS-MUST-NOT-APPEAR-123456"
    with pytest.raises(ConfigurationError) as e:
        Settings.from_env({"GUARDRAILS_MAX_INPUT_CHARS": secret_looking})
    assert secret_looking not in str(e.value) and secret_looking not in repr(e.value)
    assert "max_input_chars" in str(e.value)


def test_from_env_production_rule_surfaces_as_configuration_error():
    with pytest.raises(ConfigurationError):
        Settings.from_env({"GUARDRAILS_DETECTOR_FAILURE_MODE": "open"})


def test_from_env_bad_bool_and_bad_enum():
    for env in ({"GUARDRAILS_EXPOSE_REASON_CODES": "maybe"}, {"GUARDRAILS_ENVIRONMENT": "staging"}):
        with pytest.raises(ConfigurationError):
            Settings.from_env(env)


def test_error_str_and_safe_dict_exclude_internal_detail():
    err = GuardrailError("something failed", internal_detail="token=abc123")
    assert "abc123" not in str(err) and "abc123" not in repr(err.safe_dict())
    assert err.internal_detail == "token=abc123"
    assert err.safe_dict() == {"code": "INTERNAL_ERROR", "message": "something failed"}


def test_configuration_error_code():
    assert ConfigurationError().code is ReasonCode.CONFIGURATION_ERROR
