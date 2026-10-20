"""Decode-and-rescan helpers.

Attackers hide instructions in base64, hex, URL-encoding, escapes, ROT13 or leetspeak.
These helpers produce DERIVED texts that the injection rules are run over again.

Work is bounded (candidate count, size of each, total characters, recursion depth)
because this code reads hostile input. If a limit is hit, the caller reports it as a
finding: a request engineered to exhaust the decoder must not become a silent bypass.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import urllib.parse
from dataclasses import dataclass

MAX_CANDIDATE_CHARS = 16_384
MAX_DECODED_CHARS = 8_192

_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_UESC = re.compile(r"\\u([0-9a-fA-F]{4})")
_HENT = re.compile(r"&#(?:x[0-9a-fA-F]+|\d+);")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


@dataclass(frozen=True)
class Derived:
    kind: str                          # base64 | hex | url | unicode_escape | html_entity | rot13 | leetspeak
    text: str
    region: tuple[int, int] | None     # where in the SOURCE text it came from; None = whole text, same length


def _as_text(raw: bytes) -> str | None:
    if len(raw) < 12:
        return None
    try:
        t = raw[: MAX_DECODED_CHARS * 4].decode("utf-8")
    except UnicodeDecodeError:
        return None
    t = t[:MAX_DECODED_CHARS]
    if sum(ch.isprintable() or ch in "\n\t\r" for ch in t) / len(t) < 0.95:
        return None
    if sum(ch.isalpha() or ch.isspace() for ch in t) / len(t) < 0.6:
        return None
    return t


def _b64_text(candidate: str) -> str | None:
    s = candidate.rstrip("=").replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return _as_text(base64.b64decode(s, validate=True))
    except (binascii.Error, ValueError):
        return None


def derive(text: str, *, max_candidates: int) -> tuple[list[Derived], bool]:
    """Derived texts of `text`, and whether the candidate limit cut the search short."""
    out: list[Derived] = []
    exhausted = False
    candidates = 0

    for kind, pattern in (("base64", _B64), ("hex", _HEX)):
        for m in pattern.finditer(text):
            candidates += 1
            if candidates > max_candidates:
                exhausted = True
                break
            cand = m.group()
            if len(cand) > MAX_CANDIDATE_CHARS:
                cand = cand[: MAX_CANDIDATE_CHARS - MAX_CANDIDATE_CHARS % 4]
            if kind == "base64":
                decoded = _b64_text(cand)
            else:
                try:
                    decoded = _as_text(bytes.fromhex(cand))
                except ValueError:
                    decoded = None
            if decoded:
                out.append(Derived(kind, decoded, (m.start(), m.end())))

    # URL / \\uXXXX / HTML-entity encodings: decode the WHOLE text so surrounding words stay in
    # context; the finding's span is then the whole text (coarse but honest).
    whole = (0, len(text))
    if len(_PCT.findall(text)) >= 2:
        dec = urllib.parse.unquote(text, errors="replace")
        if dec != text:
            out.append(Derived("url", dec, whole))
    if len(_UESC.findall(text)) >= 2:
        dec = _UESC.sub(lambda m: "" if 0xD800 <= int(m.group(1), 16) <= 0xDFFF else chr(int(m.group(1), 16)), text)
        out.append(Derived("unicode_escape", dec, whole))
    if len(_HENT.findall(text)) >= 2:
        out.append(Derived("html_entity", html.unescape(text), whole))

    if sum(c.isalpha() for c in text[:2000]) >= 20:
        out.append(Derived("rot13", codecs.encode(text, "rot13"), None))
    leet = text.translate(_LEET)
    if leet != text:
        out.append(Derived("leetspeak", leet, None))
    return out, exhausted
