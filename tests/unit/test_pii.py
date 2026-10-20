import pytest

from guardrails.detectors import AllowSpec, DetectorConfig, NationalIdPattern, build_default_scanner
from guardrails.normalization import normalize_text
from tests.unit.fakes import AMEX, DISCOVER, MASTERCARD, VISA, luhn_number


def scan(text, **cfg):
    return build_default_scanner(DetectorConfig(**cfg)).scan(normalize_text(text))


def cats(text, **cfg):
    return [m.category for m in scan(text, **cfg).matches]


def spans(text, **cfg):
    return [text[m.start:m.end] for m in scan(text, **cfg).matches]


# ------------------------------------------------------------------------ email
@pytest.mark.parametrize("email", [
    "person@example.com", "first.last+tag@sub.example.co.uk", "A_B-C@Example.ORG", "x@y-z.io", "user123@mail.example.com"])
def test_emails_detected(email):
    assert spans(f"Contact me at {email} please") == [email]


def test_email_before_sentence_punctuation():
    assert spans("Write to person@example.com.") == ["person@example.com"]
    assert spans("(person@example.com)") == ["person@example.com"]


@pytest.mark.parametrize("text", ["user@localhost", "@handle", "a@b.c", "not an email @ all", "name@", "foo@bar",
                                  "see git@github", "price is 5@10"])
def test_non_emails_ignored(text):
    assert "email" not in cats(text)


def test_email_hidden_with_zero_width_and_fullwidth_at_is_still_found():
    text = "per​son＠example.com"
    (m,) = scan(text).matches
    assert m.category == "email" and text[m.start:m.end] == text  # span covers the obfuscated original


# ------------------------------------------------------------------------ phone
@pytest.mark.parametrize("phone", [
    "+1 (555) 123-4567", "555-123-4567", "(555) 123-4567", "+92 300 1234567", "0300-1234567",
    "+923001234567", "+44 20 7946 0958", "555.123.4567"])
def test_phones_detected(phone):
    assert spans(f"call {phone} now") == [phone]


@pytest.mark.parametrize("text", [
    "1234567890", "order 12345 67890", "2024-01-15", "2024-01-15 10:30:45", "10 20 30 40 50", "192.168.100.200",
    "1234567890123456", "123-45-6789", "version 1.2.3", "$1,234,567.89", "0000000000", "000-000-0000", "12345",
    "ID: 20240115103045", "03001234567", "0123456789", "00923001234567"])
def test_numbers_that_are_not_phones_ignored(text):
    assert "phone" not in cats(text), text


# ------------------------------------------------------------------------ cards
@pytest.mark.parametrize("card", [VISA, MASTERCARD, AMEX, DISCOVER, "4111 1111 1111 1111", "4111-1111-1111-1111",
                                  "3782 822463 10005", "5555 5555 5555 4444"])
def test_valid_cards_detected(card):
    assert spans(f"pay with {card} today") == [card]


@pytest.mark.parametrize("text", [
    "4111111111111112",                       # fails Luhn
    luhn_number("1", 16),                     # passes Luhn, but no card network uses prefix 1
    luhn_number("9", 16),
    "4111 1111 11111111",                     # odd grouping
    "4111-1111 1111-1111",                    # mixed separators
    "12345678901234567890123",                # too long
    "order 1234567812345678",                 # not Luhn
])
def test_numbers_that_are_not_cards_ignored(text):
    assert "credit_card" not in cats(text), text


def test_card_vs_phone_overlap_prefers_card_after_redaction():
    from guardrails.redaction import redact
    t = f"card {VISA[:4]} {VISA[4:8]} {VISA[8:12]} {VISA[12:]} ok"
    r = scan(t)
    assert "credit_card" in {m.category for m in r.matches}
    assert redact(t, r.matches).text == "card [REDACTED_CREDIT_CARD] ok"


# ------------------------------------------------------------------------ national ids
def test_us_ssn_and_pk_cnic_detected():
    assert spans("SSN 123-45-6789 ok") == ["123-45-6789"]
    assert spans("CNIC 35202-1234567-1 ok") == ["35202-1234567-1"]


@pytest.mark.parametrize("text", ["000-12-3456", "666-12-3456", "912-12-3456", "123-00-4567", "123-45-0000",
                                  "123456789", "81234-1234567-1", "35202-1234567", "1123-45-67890"])
def test_invalid_national_ids_ignored(text):
    assert "national_id" not in cats(text), text


def test_custom_national_id_pattern_and_disabling_builtins():
    cfg = dict(national_ids=(NationalIdPattern(name="xx_id", regex=r"\bXX\d{6}\b"),),
               builtin_national_ids=frozenset())
    assert spans("id XX123456 and 123-45-6789", **cfg) == ["XX123456"]


def test_bad_custom_pattern_rejected_at_config_time():
    with pytest.raises(ValueError):
        NationalIdPattern(name="bad", regex="(unclosed")
    with pytest.raises(ValueError):
        NationalIdPattern(name="Bad Name", regex="x")
    with pytest.raises(ValueError):
        NationalIdPattern(name="long", regex="a" * 301)


# ------------------------------------------------------------------------ ip
def test_ip_off_by_default_and_on_when_enabled():
    assert cats("server 10.0.0.12 here") == []
    on = dict(pii_categories=frozenset({"ip_address"}))
    assert spans("server 10.0.0.12 here", **on) == ["10.0.0.12"]
    assert spans("host 192.168.1.1.", **on) == ["192.168.1.1"]


@pytest.mark.parametrize("text", ["256.1.1.1", "1.2.3", "1.2.3.4.5", "01.02.03.04", "999.999.999.999"])
def test_invalid_ips_ignored(text):
    assert cats(text, pii_categories=frozenset({"ip_address"})) == []


def test_categories_can_be_switched_off():
    t = "a@example.com 555-123-4567"
    assert cats(t, pii_categories=frozenset({"email"})) == ["email"]
    assert cats(t, pii_categories=frozenset()) == []


# ------------------------------------------------------------------------ allowlists
def test_allowlist_exact_is_case_insensitive_and_regex_is_full_match():
    allow = AllowSpec(exact=("Support@Example.com",), regex=(r".*@docs\.example\.org",))
    t = "support@example.com, anyone@docs.example.org, real@example.net"
    assert spans(t, pii_allow=allow) == ["real@example.net"]


def test_allowlist_regex_must_cover_the_whole_value():
    allow = AllowSpec(regex=(r"x@",))
    assert spans("a@example.com", pii_allow=allow) == ["a@example.com"]


def test_bad_allowlist_entries_rejected():
    with pytest.raises(ValueError):
        AllowSpec(regex=("(",))
    with pytest.raises(ValueError):
        AllowSpec(exact=("  ",))


# ------------------------------------------------------------------------ prose
def test_ordinary_prose_has_no_findings():
    text = ("The meeting is at 10:30 on 2024-01-15. We shipped version 3.12.1 with 4096 tokens, "
            "an invoice total of $12,345.67 and ticket #20240115. Contact the help desk for details.")
    assert scan(text).matches == ()


def test_urdu_text_with_email_only_flags_the_email():
    t = "رابطہ کریں person@example.com شکریہ"
    assert spans(t) == ["person@example.com"]
