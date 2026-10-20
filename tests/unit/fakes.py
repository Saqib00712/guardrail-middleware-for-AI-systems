"""FAKE credentials and synthetic PII for tests.

Secrets are assembled from pieces at runtime so no real-looking credential is ever
written literally into the repository (which would trip secret scanners and
could be mistaken for a leak). All values here are invented or documented examples.
"""
import random

AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"                      # AWS's documented example key id
OPENAI_LIKE = "sk-" + "FAKE" * 8
ANTHROPIC_LIKE = "sk-ant-" + "FAKE" * 6
GITHUB_PAT = "ghp_" + "F4KE" * 9
SLACK = "xoxb-" + "123456789012-" + "FAKEFAKEFAKE"
STRIPE = "sk_test_" + "FAKEFAKEFAKEFAKE"
GOOGLE = "AIza" + "F" * 35
JWT = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "zdWIiOiJmYWtlIn0", "FAKESIGNATURE12345"])
PEM_BODY = "\n".join(["FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE" * 2] * 3)
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + PEM_BODY + "\n-----END " + "RSA PRIVATE KEY-----"
VISA = "4111111111111111"
MASTERCARD = "5555555555554444"
AMEX = "378282246310005"
DISCOVER = "6011111111111117"


def luhn_number(prefix: str, length: int) -> str:
    """A Luhn-valid number with the given prefix (for false-positive tests)."""
    rnd = random.Random(7)
    body = prefix + "".join(str(rnd.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return body + str((10 - total % 10) % 10)
