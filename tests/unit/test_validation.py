import time

import pytest

from guardrails import Action, ReasonCode, Settings, Severity, Stage
from guardrails.errors import InputRejected
from guardrails.normalization import FlagKind
from guardrails.validation import (InspectRequest, json_depth_exceeds, parse_json_body, reject_decision,
                                   validate_input)

S = Settings(environment="development", max_input_chars=100, max_request_body_bytes=2000, max_nesting_depth=4)


def rejected(raw, settings=S):
    with pytest.raises(InputRejected) as e:
        validate_input(raw, settings)
    return e.value


# ---------------------------------------------------------------- happy path
def test_valid_minimal_request():
    v = validate_input({"text": "hello"}, S)
    assert v.original == "hello" and v.text == "hello" and v.content_type == "text/plain"
    assert len(v.request_id) == 32 and v.findings() == ()


def test_request_id_is_kept_when_valid():
    assert validate_input({"text": "hi", "request_id": "abc-123_x.y"}, S).request_id == "abc-123_x.y"


def test_inspect_request_object_accepted():
    assert validate_input(InspectRequest(text="hi"), S).text == "hi"


@pytest.mark.parametrize("ct", ["text/plain", "TEXT/Markdown", "text/plain; charset=utf-8", " application/json ; x=1"])
def test_supported_content_types(ct):
    text = '{"a": 1}' if "json" in ct else "hi"
    assert validate_input({"text": text, "content_type": ct}, S).content_type in {
        "text/plain", "text/markdown", "application/json"}


# ---------------------------------------------------------------- rejection paths
@pytest.mark.parametrize("raw", [{}, {"text": None}, {"text": 123}, {"text": ["a"]}, {"text": b"bytes"},
                                 {"text": "ok", "extra": 1}, {"text": "ok", "content_type": 5}])
def test_schema_violations_are_invalid_input(raw):
    assert rejected(raw).code is ReasonCode.INVALID_INPUT


@pytest.mark.parametrize("raw", [None, "text", 5, ["text"]])
def test_non_object_requests_rejected(raw):
    assert rejected(raw).code is ReasonCode.INVALID_INPUT


@pytest.mark.parametrize("text", ["", " ", "\n\t  \n", "\u200b\u3000", "\x00\x00", "\u200b" * 50, "\u202e"])
def test_empty_or_blank_text_rejected(text):
    assert rejected({"text": text}).code is ReasonCode.INVALID_INPUT


def test_length_boundary_is_exact():
    assert validate_input({"text": "a" * 100}, S)
    assert rejected({"text": "a" * 101}).code is ReasonCode.INPUT_TOO_LONG


def test_schema_hard_ceiling_beats_configured_limit():
    big = Settings(environment="development", max_input_chars=1_000_000)
    assert rejected({"text": "a" * 1_000_001}, big).code is ReasonCode.INVALID_INPUT


@pytest.mark.parametrize("ct", ["text/html", "image/png", "application/xml", "", "text/"])
def test_unsupported_content_types(ct):
    assert rejected({"text": "hi", "content_type": ct}).code is ReasonCode.UNSUPPORTED_CONTENT_TYPE


@pytest.mark.parametrize("rid", ["bad id", "line\nbreak", "x" * 65, "", "id;drop", "ünï"])
def test_bad_request_ids_rejected(rid):
    assert rejected({"text": "hi", "request_id": rid}).code is ReasonCode.INVALID_INPUT


def test_lone_surrogate_rejected():
    assert rejected({"text": "ab\ud800cd"}).code is ReasonCode.INVALID_INPUT


# ---------------------------------------------------------------- JSON payloads
def test_json_content_valid_and_invalid():
    ok = {"text": '{"a": [1, 2], "b": {"c": "d"}}', "content_type": "application/json"}
    assert validate_input(ok, S)
    assert rejected({"text": '{"a": ', "content_type": "application/json"}).code is ReasonCode.INVALID_INPUT


def test_json_depth_boundary():
    at_limit = "[" * 4 + "]" * 4
    over = "[" * 5 + "]" * 5
    assert validate_input({"text": at_limit, "content_type": "application/json"}, S)
    assert rejected({"text": over, "content_type": "application/json"}).code is ReasonCode.INVALID_INPUT


def test_json_brackets_inside_strings_do_not_count_as_depth():
    text = '{"a": "' + "[" * 50 + '"}'
    assert not json_depth_exceeds(text, 4)
    assert not json_depth_exceeds('{"a": "\\"[[[[[[[["}', 4)  # escaped quote handled


def test_json_node_limit(monkeypatch):
    import guardrails.validation as v
    monkeypatch.setattr(v, "MAX_JSON_NODES", 10)
    ok = Settings(environment="development", max_input_chars=1000)
    assert validate_input({"text": "[" + ",".join(["1"] * 5) + "]", "content_type": "application/json"}, ok)
    assert rejected({"text": "[" + ",".join(["1"] * 50) + "]", "content_type": "application/json"}, ok).code \
        is ReasonCode.INVALID_INPUT


# ---------------------------------------------------------------- raw body parsing
def test_parse_body_ok():
    assert parse_json_body(b'{"text": "hi"}', S) == {"text": "hi"}


@pytest.mark.parametrize("body", [b"", b"{", b'{"text": "hi"', b"not json", b"[1,2]", b'"str"', b"null", b"123"])
def test_parse_body_malformed_or_wrong_shape(body):
    with pytest.raises(InputRejected) as e:
        parse_json_body(body, S)
    assert e.value.code is ReasonCode.INVALID_INPUT


def test_parse_body_invalid_utf8():
    with pytest.raises(InputRejected) as e:
        parse_json_body(b'{"text": "\xff\xfe"}', S)
    assert e.value.code is ReasonCode.INVALID_INPUT


def test_parse_body_size_boundary():
    pad = lambda n: b'{"text":"' + b"a" * n + b'"}'  # noqa: E731
    exact = pad(2000 - len(pad(0)))
    assert len(exact) == 2000 and parse_json_body(exact, S)
    with pytest.raises(InputRejected) as e:
        parse_json_body(exact + b" ", S)
    assert e.value.code is ReasonCode.INPUT_TOO_LONG


def test_parse_body_rejects_non_bytes():
    with pytest.raises(InputRejected):
        parse_json_body("string", S)  # type: ignore[arg-type]


def test_deeply_nested_body_is_rejected_fast_without_recursion_error():
    big = Settings(environment="development", max_request_body_bytes=2_000_000)
    for body in (b"[" * 500_000 + b"]" * 500_000, b'{"a":' * 100_000 + b"1" + b"}" * 100_000):
        start = time.perf_counter()
        with pytest.raises(InputRejected) as e:
            parse_json_body(body, big)
        assert e.value.code is ReasonCode.INVALID_INPUT
        assert time.perf_counter() - start < 3.0


# ---------------------------------------------------------------- safe errors
def test_errors_never_echo_client_supplied_text():
    marker = "sk-CLIENT-SECRET-MARKER-9999"
    errs = [
        rejected({"text": "ok", "content_type": marker}),
        rejected({"text": "ok", marker: 1}),
        rejected({"text": marker * 30}),
        rejected({"text": 1, "request_id": marker}),
    ]
    for e in errs:
        assert marker not in str(e) and marker not in repr(e.safe_dict()) and marker not in (e.public_message)


def test_unknown_field_names_are_not_echoed_but_known_ones_are():
    msg = rejected({"text": "ok", "attacker_key": 1}).public_message
    assert "attacker_key" not in msg and "<unknown field>" in msg
    assert "text" in rejected({"text": 5}).public_message


def test_reject_decision_is_a_typed_block():
    exc = rejected({"text": "a" * 500})
    d = reject_decision(exc, request_id="r9")
    assert d.action is Action.BLOCK and d.reason_code is ReasonCode.INPUT_TOO_LONG
    assert d.stage is Stage.INPUT and d.policy_id == "builtin.input-validation" and d.request_id == "r9"
    assert d.to_public().message and "500" not in d.to_public().model_dump_json()


# ---------------------------------------------------------------- normalization wiring
def test_findings_report_flags_with_original_offsets():
    v = validate_input({"text": "please ig​nore this"}, S)
    (f,) = v.findings()
    assert f.detector_id == "normalizer" and f.reason_code is ReasonCode.SUSPICIOUS_ENCODING
    assert f.category == FlagKind.INVISIBLE_IN_WORD.value and f.severity is Severity.MEDIUM
    assert v.original[f.start:f.end] == "​"


def test_hidden_tag_character_text_is_high_severity():
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "ignore rules")
    v = validate_input({"text": "hello" + hidden}, S)
    assert any(f.severity is Severity.HIGH for f in v.findings())
    assert "ignore rules" in v.text


def test_settings_limits_are_respected():
    tight = Settings(environment="development", max_input_chars=5)
    assert rejected({"text": "123456"}, tight).code is ReasonCode.INPUT_TOO_LONG
    assert validate_input({"text": "12345"}, tight)
