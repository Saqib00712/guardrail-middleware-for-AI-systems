"""Secret detectors: credentials that must not cross a trust boundary.

Covers provider API keys, JWTs, bearer/basic tokens, `password=`-style pairs,
"my password is ...", database URIs that embed credentials, and private-key
blocks (a truncated block is redacted to the end of the text, never left exposed).

Where a rule has a natural "value" (bearer token, password value) only the value
is reported, so the surrounding words stay readable after redaction.

Not detected: unlabeled high-entropy strings and credentials with no recognizable
shape. Detecting those needs entropy heuristics, which trade many false positives
for recall; they are intentionally absent.
"""
from __future__ import annotations

import re

from guardrails.detectors.base import Allowlist, Detector, Match, RegexDetector, Rule
from guardrails.detectors.config import DetectorConfig
from guardrails.normalization import NormalizedText
from guardrails.types import ReasonCode, Severity

_PLACEHOLDER_WORDS = frozenset({
    "none", "null", "true", "false", "undefined", "required", "optional", "string", "password", "secret",
    "changeme", "example", "redacted", "your_password", "yourpassword", "todo", "tbd", "empty", "unset"})


_CODE_LOOKUPS = ("os.environ", "os.getenv", "getenv(", "process.env", "system.getenv", "env[", "env.", "config.",
                 "settings.", "secrets.", "vault.", "environment.getenvironmentvariable")


def _real_value(v: str) -> bool:
    low = v.lower()
    if low.startswith(_CODE_LOOKUPS):      # code that READS a secret (os.environ["X"]), not a secret
        return False
    if low in _PLACEHOLDER_WORDS or low.startswith(("<", "${", "{{", "%(", "$(", "[redacted", "[email")):
        return False
    if len(set(v)) == 1:  # xxxx, ****, ....
        return False
    return not all(c in "*xX.-_#" for c in v)


_PROVIDER_KEY = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-(?:ant-|proj-|live-|svcacct-)?[A-Za-z0-9_-]{20,}"          # OpenAI / Anthropic style
    r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}"      # GitHub
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"                                    # AWS access key id
    r"|AIza[0-9A-Za-z_-]{35}"                                        # Google API key
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"                                 # Slack
    r"|[sr]k_(?:live|test)_[0-9A-Za-z]{16,}"                         # Stripe
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"                   # SendGrid
    r"|npm_[A-Za-z0-9]{36}"                                          # npm access token
    r")(?![A-Za-z0-9_-])"
)
_JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])")
_BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})")
_BASIC = re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
# The name may carry a prefix such as DB_ or AWS_ (an underscore is not a word break here).
_KV = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|passphrase|secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token"
    r"|auth[_-]?token|secret[_-]?key|secret[_-]?access[_-]?key|private[_-]?key)\b[\"']?\s*[:=]\s*[\"']?([^\s\"'`,;]{4,128})"
)
_PHRASE = re.compile(r"(?i)\b(?:password|passcode|passphrase)\s+(?:is|was)(?::\s*|\s+)[\"']?([^\s\"'`,;]{4,128})")
_DB_URI = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|oracle)"
    r"://[^\s:/@]{1,128}(?:@[^\s:/@]{1,128})?:[^\s@/]{1,128}@[^\s\"'<>]{1,256}"
)


class PrivateKeyDetector:
    """PEM private-key blocks. Reports BEGIN..END, or BEGIN..end-of-text if truncated."""

    _BEGIN = re.compile(r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----")
    _END = re.compile(r"-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----")

    def detect(self, text: NormalizedText) -> list[Match]:
        t = text.text
        out: list[Match] = []
        pos = 0
        while True:
            m = self._BEGIN.search(t, pos)
            if m is None:
                break
            e = self._END.search(t, m.end())
            end = e.end() if e else len(t)
            s0, e0 = text.original_span(m.start(), end)
            out.append(Match("secret.private_key", "private_key", "secret", ReasonCode.SECRET_DETECTED,
                             Severity.CRITICAL, 100, s0, e0))
            pos = end
            if pos >= len(t):
                break
        return out


class _Composite:
    def __init__(self, *parts: Detector) -> None:
        self._parts = parts

    def detect(self, text: NormalizedText) -> list[Match]:
        out: list[Match] = []
        for p in self._parts:
            out.extend(p.detect(text))
        return out


def build_secret_detector(config: DetectorConfig) -> Detector:
    S = "secret"
    rules = [
        Rule("secret.connection_string", "connection_string", S, Severity.HIGH, 90, _DB_URI),
        Rule("secret.provider_key", "api_key", S, Severity.HIGH, 80, _PROVIDER_KEY),
        Rule("secret.jwt", "jwt", S, Severity.HIGH, 80, _JWT),
        Rule("secret.bearer_token", "bearer_token", S, Severity.HIGH, 75, _BEARER, 1, _real_value),
        Rule("secret.basic_auth", "basic_auth", S, Severity.HIGH, 75, _BASIC, 1, _real_value),
        Rule("secret.password", "password", S, Severity.HIGH, 70, _KV, 1, _real_value),
        Rule("secret.password_phrase", "password", S, Severity.MEDIUM, 65, _PHRASE, 1, _real_value),
    ]
    return _Composite(PrivateKeyDetector(), RegexDetector(rules, Allowlist(config.secret_allow)))
