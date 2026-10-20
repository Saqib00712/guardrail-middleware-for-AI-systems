"""PII detectors.

Goal: report real personal identifiers while NOT treating every number as one.
Each rule pairs a candidate regex with a validator:

* email         needs a dotted domain with an alphabetic TLD of 2+ letters
* phone         needs a leading "+" or visible separators, 10-15 digits, at least one
                digit group of 3+, and must not look like a date, IPv4 or repeated digit.
                A bare run of digits is NOT a phone (invoice and order numbers).
* credit_card   13-19 digits, sane grouping, a real card-network prefix AND a valid Luhn
                checksum. A random Luhn-valid number with no issuer prefix is ignored.
* national_id   US SSN (hyphenated, invalid ranges excluded), Pakistan CNIC
                (#####-#######-#), plus operator-defined patterns
* ip_address    IPv4 only, off by default (classified sensitive by policy)

Not detected: names, street addresses, dates of birth, IPv6, free-text identifiers.
"""
from __future__ import annotations

import re

from guardrails.detectors.base import Allowlist, Detector, RegexDetector, Rule
from guardrails.detectors.config import DetectorConfig
from guardrails.types import Severity


def luhn_valid(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ----------------------------------------------------------------------------- phone
_PHONE_CAND = re.compile(r"(?<![\w.+-])\+?\(?\d[\d\s().-]{7,18}\d(?![\w-])")


def _phone_ok(v: str) -> bool:
    digits = re.sub(r"\D", "", v)
    if not 10 <= len(digits) <= 15:
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", v):  # IPv4
        return False
    if re.search(r"\d{4}-\d{2}-\d{2}", v):  # ISO date
        return False
    if not (v.startswith("+") or re.search(r"[\s().-]", v)):
        return False
    if re.search(r"[\s().-]{3,}", v):
        return False
    groups = re.findall(r"\d+", v)
    if max(len(g) for g in groups) < 3:
        return False
    # Spaces only (no "+", dash, dot or parentheses): "12345 67890" is as likely an order id
    # as a phone. Accept it only with a national trunk prefix 0 or three or more groups.
    if not v.startswith("+") and not re.search(r"[().-]", v) and len(groups) < 3 and not v.startswith("0"):
        return False
    if len(set(digits)) == 1:
        return False
    if _card_ok(v) or any(p.fullmatch(v) for p in BUILTIN_NATIONAL_IDS.values()):
        return False  # reported by the more specific detector instead of twice
    return True


# ----------------------------------------------------------------------------- card
_CARD_CAND = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_CARD_LAYOUTS = {(4, 4, 5), (4, 6, 4), (4, 6, 5), (4, 4, 4, 4), (4, 4, 4, 4, 3)}


def _issuer_ok(d: str) -> bool:
    n = len(d)
    if d[0] == "4":
        return n in (13, 16, 19)
    if n == 16 and (51 <= int(d[:2]) <= 55 or 2221 <= int(d[:4]) <= 2720):
        return True
    if n == 15 and d[:2] in ("34", "37"):
        return True
    if 16 <= n <= 19 and (d[:4] == "6011" or d[:2] == "65" or 644 <= int(d[:3]) <= 649 or d[:2] == "62"
                          or 3528 <= int(d[:4]) <= 3589):
        return True
    return 14 <= n <= 19 and (d[:2] in ("36", "38", "39") or 300 <= int(d[:3]) <= 305)


def _card_ok(v: str) -> bool:
    digits = re.sub(r"[ -]", "", v)
    if not 13 <= len(digits) <= 19:
        return False
    if re.search(r"[ -]", v):
        if " " in v and "-" in v:
            return False
        if tuple(len(g) for g in re.split(r"[ -]", v)) not in _CARD_LAYOUTS:
            return False
    return _issuer_ok(digits) and luhn_valid(digits)


# ----------------------------------------------------------------------------- others
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}(?![\w-])")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d)(?!\.\d)")


def _ipv4_ok(v: str) -> bool:
    parts = v.split(".")
    return all(int(p) <= 255 and (len(p) == 1 or not p.startswith("0")) for p in parts)


BUILTIN_NATIONAL_IDS: dict[str, re.Pattern[str]] = {
    "us_ssn": re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"),
    "pk_cnic": re.compile(r"(?<![\d-])[1-7]\d{4}-\d{7}-\d(?![\d-])"),
}


def build_pii_detector(config: DetectorConfig) -> Detector:
    cats = config.pii_categories
    rules: list[Rule] = []
    if "credit_card" in cats:
        rules.append(Rule("pii.credit_card", "credit_card", "pii", Severity.HIGH, 60, _CARD_CAND, 0, _card_ok))
    if "national_id" in cats:
        for name in sorted(config.builtin_national_ids):
            rules.append(Rule(f"pii.national_id.{name}", "national_id", "pii", Severity.HIGH, 55,
                              BUILTIN_NATIONAL_IDS[name]))
        for custom in config.national_ids:
            rules.append(Rule(f"pii.national_id.{custom.name}", "national_id", "pii", Severity.HIGH, 55,
                              re.compile(custom.regex)))
    if "email" in cats:
        rules.append(Rule("pii.email", "email", "pii", Severity.LOW, 40, _EMAIL))
    if "phone" in cats:
        rules.append(Rule("pii.phone", "phone", "pii", Severity.LOW, 30, _PHONE_CAND, 0, _phone_ok))
    if "ip_address" in cats:
        rules.append(Rule("pii.ip_address", "ip_address", "pii", Severity.LOW, 20, _IPV4, 0, _ipv4_ok))
    return RegexDetector(rules, Allowlist(config.pii_allow))
