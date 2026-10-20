import time

import pytest

from guardrails.detectors import DetectorConfig, Match, build_default_scanner
from guardrails.normalization import normalize_text
from guardrails.redaction import merge_spans, redact
from guardrails.types import ReasonCode, Severity
from tests.unit import fakes

SC = build_default_scanner(DetectorConfig(pii_categories=frozenset({"email", "phone", "credit_card", "national_id", "ip_address"})))


def run(text, **kw):
    r = SC.scan(normalize_text(text))
    return redact(text, r.matches, **kw), r


def M(cat, s, e, prio=10, kind="pii"):
    return Match(f"{kind}.{cat}", cat, kind, ReasonCode.PII_DETECTED, Severity.LOW, prio, s, e)


# ------------------------------------------------------------------- basics
def test_example_from_the_spec():
    res, _ = run("Contact me at person@example.com")
    assert res.text == "Contact me at [REDACTED_EMAIL]" and res.redacted_count == 1


def test_no_matches_returns_text_untouched():
    res, _ = run("nothing sensitive here")
    assert res.text == "nothing sensitive here" and res.redacted_count == 0 and res.by_category == {}


def test_untouched_text_is_preserved_exactly_including_unicode_and_spacing():
    t = "  رابطہ:  a@example.com\t\tشکریہ 😀  "
    res, _ = run(t)
    assert res.text == "  رابطہ:  [REDACTED_EMAIL]\t\tشکریہ 😀  "


def test_multiple_categories_and_counts():
    t = f"a@example.com, b@example.com, {fakes.VISA}, 10.0.0.1, 123-45-6789, +1 555 123 4567"
    res, _ = run(t)
    assert res.by_category == {"credit_card": 1, "email": 2, "ip_address": 1, "national_id": 1, "phone": 1}
    assert res.text == "[REDACTED_EMAIL], [REDACTED_EMAIL], [REDACTED_CREDIT_CARD], [REDACTED_IP_ADDRESS], [REDACTED_NATIONAL_ID], [REDACTED_PHONE]"


def test_redaction_is_deterministic():
    t = f"x {fakes.AWS_KEY} y a@example.com z {fakes.VISA}"
    assert run(t)[0] == run(t)[0]
    assert run(t)[0].text == run(t)[0].text


def test_redacted_output_rescans_clean_and_redaction_is_idempotent():
    t = f"mail a@example.com key {fakes.OPENAI_LIKE} card {fakes.VISA} pw=hunter2xyz ssn 123-45-6789"
    first, _ = run(t)
    second, again = run(first.text)
    assert again.matches == () and second.text == first.text


def test_category_filter_redacts_only_chosen_categories():
    t = f"a@example.com and {fakes.AWS_KEY}"
    res, r = run(t, categories={"api_key"})
    assert res.text == "a@example.com and [REDACTED_API_KEY]"
    assert redact(t, r.matches, categories=set()).text == t


# ------------------------------------------------------------------- styles
def test_indexed_style_keeps_coreference_without_content():
    t = "From A@Example.com to b@example.com, cc a@example.com"
    res, _ = run(t, style="indexed")
    assert res.text == "From [EMAIL_1] to [EMAIL_2], cc [EMAIL_1]"


def test_indexed_phone_formats_of_same_number_share_an_index():
    res, _ = run("+1 (555) 123-4567 or +1 555 123 4567", style="indexed")
    assert res.text == "[PHONE_1] or [PHONE_1]"


# ------------------------------------------------------------------- overlaps
def test_partial_overlap_merges_to_union_so_nothing_leaks():
    text = "0123456789ABCDEFGHIJ"
    spans = merge_spans([M("a", 2, 10, 5), M("b", 8, 15, 9)])
    assert [(s.start, s.end, s.category) for s in spans] == [(2, 15, "b")]
    res = redact(text, [M("a", 2, 10, 5), M("b", 8, 15, 9)])
    assert res.text == "01[REDACTED_B]FGHIJ"


def test_containment_and_touching_spans():
    assert [(s.start, s.end) for s in merge_spans([M("a", 0, 10), M("b", 2, 4)])] == [(0, 10)]
    assert [(s.start, s.end) for s in merge_spans([M("a", 0, 5), M("b", 5, 9)])] == [(0, 5), (5, 9)]


def test_label_tiebreak_is_deterministic():
    one = merge_spans([M("a", 0, 5, 7), M("b", 0, 5, 7)])
    two = merge_spans([M("b", 0, 5, 7), M("a", 0, 5, 7)])
    assert one == two


def test_secret_inside_connection_string_is_one_redaction_with_secret_label():
    t = "url=postgresql://me@example.com:Pw123456@db.example.net/app end"
    res, _ = run(t)
    assert res.text == "url=[REDACTED_CONNECTION_STRING] end"


def test_invalid_spans_rejected():
    for bad in (M("a", 0, 99), M("a", 3, 3), M("a", -1, 2)):
        with pytest.raises(ValueError):
            redact("short", [bad])


# ------------------------------------------------------------------- bypass attempts
def tags(s):
    return "".join(chr(0xE0000 + ord(c)) for c in s)


@pytest.mark.parametrize("sneaky", [
    "per​son@example.com", "per­son@example.com", "person＠example.com",
    "ｐｅｒｓｏｎ@example.com", "persоn@example.com", "p‮erson@example.com",
    "person@example.com" + tags("x")])
def test_obfuscated_emails_are_still_redacted(sneaky):
    t = f"mail {sneaky} end"
    res, _ = run(t)
    assert res.text.startswith("mail [REDACTED_EMAIL]") and "example" not in res.text.replace("[REDACTED_EMAIL]", "")


def test_email_smuggled_entirely_in_tag_characters_is_found_and_removed():
    t = "hello" + tags(" person@example.com")
    res, _ = run(t)
    assert "REDACTED_EMAIL" in res.text and chr(0xE0070) not in res.text.replace("[REDACTED_EMAIL]", "")


def test_secret_split_with_invisible_characters_is_redacted():
    key = fakes.OPENAI_LIKE
    t = f"k {key[:10]}​{key[10:]} end"
    res, _ = run(t)
    assert res.text == "k [REDACTED_API_KEY] end"


def test_card_with_odd_unicode_spaces():
    t = f"c {fakes.VISA[:4]} {fakes.VISA[4:8]} {fakes.VISA[8:12]} {fakes.VISA[12:]} e"
    res, _ = run(t)
    assert res.text == "c [REDACTED_CREDIT_CARD] e"


# ------------------------------------------------------------------- safety & performance
def test_no_raw_value_stored_in_any_match_object():
    t = f"a@example.com {fakes.OPENAI_LIKE}"
    for m in SC.scan(normalize_text(t)).matches:
        assert "example.com" not in repr(m) and "FAKE" not in repr(m)
        assert not any(isinstance(v, str) and ("@" in v or "FAKE" in v) for v in vars(m).values())


@pytest.mark.parametrize("payload", [
    "1 " * 10_000, "a@" * 10_000, ("-----BEGIN " + "PRIVATE KEY-----") * 1000, "9" * 100_000,
    "password=" * 5000, "Bearer " * 5000, "1-" * 10_000, "0" * 50_000 + "@x.com", "." * 100_000,
    "4111 " * 4000, "(" * 20_000, "a" * 20_000 + "@", "-" * 30_000, "sk-" + "a" * 100_000])
def test_hostile_inputs_finish_quickly(payload):
    start = time.perf_counter()
    res, _ = run(payload)
    assert time.perf_counter() - start < 5.0
    assert isinstance(res.text, str)
