import pytest

from guardrails.detectors import AllowSpec, DetectorConfig, build_default_scanner
from guardrails.normalization import normalize_text
from tests.unit import fakes


def scan(text, **cfg):
    return build_default_scanner(DetectorConfig(**cfg)).scan(normalize_text(text))


def found(text, **cfg):
    return [(m.category, text[m.start:m.end]) for m in scan(text, **cfg).matches if m.kind == "secret"]


@pytest.mark.parametrize("key", [fakes.OPENAI_LIKE, fakes.ANTHROPIC_LIKE, fakes.GITHUB_PAT, fakes.AWS_KEY,
                                 fakes.SLACK, fakes.STRIPE, fakes.GOOGLE])
def test_provider_keys_detected(key):
    assert found(f"use {key} for auth") == [("api_key", key)]


def test_jwt_detected():
    assert found(f"token {fakes.JWT} end") == [("jwt", fakes.JWT)]


def test_bearer_token_reports_only_the_token():
    tok = "abcDEF123456789xyz_-.~+/="
    assert found(f"Authorization: Bearer {tok}") == [("bearer_token", tok)]
    assert found(f"authorization: BEARER {tok}") == [("bearer_token", tok)]


def test_basic_auth_value():
    assert found("Authorization: Basic dXNlcjpzZWNyZXRwYXNzd29yZA==") == [("basic_auth", "dXNlcjpzZWNyZXRwYXNzd29yZA==")]


@pytest.mark.parametrize("text,value", [
    ("password=hunter2xyz", "hunter2xyz"), ("PASSWORD: S3cretValue", "S3cretValue"),
    ('{"api_key": "abc12345xyz"}', "abc12345xyz"), ("db_password = 'pa55w0rd!'".replace("db_", ""), "pa55w0rd!"),
    ("client_secret=Zm9vYmFy1234", "Zm9vYmFy1234"), ("access-token: tok_12345678", "tok_12345678"),
    ("my password is correcthorse9", "correcthorse9")])
def test_password_style_pairs_report_only_the_value(text, value):
    assert found(text) == [("password", value)]


@pytest.mark.parametrize("text", [
    "password=<your-password>", "password=${DB_PASSWORD}", "api_key: xxxxxxxx", "password: ********",
    "secret=changeme", "password=None", "api_key={{ api_key }}", "password: required",
    "the password policy requires 12 characters", "Enter your password", "password=%(pw)s",
    "token=[REDACTED_API_KEY]"])
def test_placeholders_and_prose_about_passwords_ignored(text):
    assert found(text) == [], text


def test_db_uris_with_credentials_are_one_whole_secret():
    uri = "postgresql://admin:S3cr3tPw@db.internal.example:5432/app"
    assert found(f"DATABASE_URL={uri} ok") == [("connection_string", uri)]
    assert found("mongodb+srv://u:p4ss@cluster0.example.net/db") != []


@pytest.mark.parametrize("text", ["postgresql://db.internal.example:5432/app", "redis://localhost:6379",
                                  "https://user:pw@example.com/x", "mysql://localhost/db"])
def test_uris_without_embedded_db_credentials_ignored(text):
    assert [c for c, _ in found(text) if c == "connection_string"] == []


def test_private_key_block_whole_and_truncated():
    assert found(f"here:\n{fakes.PEM}\nthanks") == [("private_key", fakes.PEM)]
    truncated = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nAAAAFAKEFAKEFAKEFAKE\nAAAAFAKE"
    (cat, val), = found("oops " + truncated)
    assert cat == "private_key" and val == truncated  # runs to the end, nothing left exposed


def test_two_private_keys():
    assert len(found(fakes.PEM + "\nmiddle\n" + fakes.PEM)) == 2


@pytest.mark.parametrize("text", [
    "sk-learn is a Python library", "git commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
    "sha256: " + "a" * 64, "uuid 123e4567-e89b-12d3-a456-426614174000", "ask-me-anything-about-it",
    "the key idea is simple", "api_key parameter is optional", "AKIA is a prefix", "Basic usage: run it",
    "bearer of bad news", "eyJ is how base64 JSON starts"])
def test_lookalikes_and_prose_are_not_secrets(text):
    assert found(text) == [], text


def test_secret_allowlist():
    allow = AllowSpec(exact=(fakes.AWS_KEY,))
    assert found(f"key {fakes.AWS_KEY}", secret_allow=allow) == []
    assert found(f"key {fakes.OPENAI_LIKE}", secret_allow=allow) != []


def test_secrets_can_be_disabled():
    assert found(f"key {fakes.AWS_KEY}", secrets_enabled=False) == []


def test_findings_never_contain_the_secret():
    r = scan(f"key {fakes.OPENAI_LIKE} and {fakes.PEM}")
    dumped = repr(r) + repr(r.findings()) + "".join(f.model_dump_json() for f in r.findings())
    assert fakes.OPENAI_LIKE not in dumped and "FAKEFAKE" not in dumped
    assert r.has_secrets and r.counts_by_category() == {"api_key": 1, "private_key": 1}


# ---- Phase 13: gaps found by the evaluation set (dev half)
@pytest.mark.parametrize("text,value", [
    ("DB_PASSWORD=Vq7Lm2Rt9Zw4Kb", "Vq7Lm2Rt9Zw4Kb"),
    ("MY_API_KEY: abcd1234efgh", "abcd1234efgh"),
    ("export APP_SECRET_KEY=Zm9vYmFyMTIz", "Zm9vYmFyMTIz"),
    ("aws_secret_access_key = " + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"),
    ("The admin password is: Vq7Lm2Rt9Zw4Kb", "Vq7Lm2Rt9Zw4Kb"),
    ("the passphrase was:  Tr0ub4dor&3x", "Tr0ub4dor&3x"),
])
def test_prefixed_names_and_colon_phrases_are_found(text, value):
    assert [v for _, v in found(text)] == [value]


def test_npm_token_detected_only_at_the_real_length():
    tok = "npm_" + "Fq3Lm8Rt2Vw6Zb9Nc4Hd7Jf1Ps5Ae0Gu2IkW"
    assert len(tok) == 40 and found(f"publish with {tok} now") == [("api_key", tok)]      # bare token, no name in front
    assert found("npm_install is a command") == [] and found("npm_" + "A" * 20) == []


@pytest.mark.parametrize("text", [
    'password = os.environ["DB_PASSWORD"]', "const apiKey = process.env.API_KEY;", "secret = os.getenv('X')",
    "password: config.db.password", "api_key = settings.OPENAI_KEY", "password = System.getenv(\"P\")",
])
def test_code_that_reads_a_secret_is_not_a_secret(text):
    assert found(text) == []


@pytest.mark.parametrize("text", ["the password issue was fixed", "password is", "Her passphrase is: ", "subpassword=abcd1234"])
def test_new_patterns_do_not_overreach(text):
    assert found(text) == []
