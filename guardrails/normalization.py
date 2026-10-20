"""Text normalization for INSPECTION only.

The original text is never modified. Detectors receive `NormalizedText.text`,
a cleaned copy in which common evasion tricks are undone, plus a map from every
character of that copy back to the original. Findings always carry offsets into
the ORIGINAL text (that is what a redactor acts on), converted with
`NormalizedText.original_span()`.

What it undoes (and flags, because the trick itself is a signal):
* invisible format characters (zero-width space, soft hyphen, ...) hiding inside
  a Latin word:                    "ig​nore"  -> "ignore"
* "tag" characters U+E0020..E007E, which encode hidden ASCII text, are DECODED
  so a detector can see the smuggled instruction
* full-width / mathematical Latin letters: "ｉｇｎｏｒｅ" -> "ignore"
* Cyrillic/Greek look-alikes, but ONLY inside a word that also contains Latin
  letters: "ignоre" (Cyrillic о) -> "ignore"
* control characters, odd whitespace, bidi override characters
* very long runs of one repeated character (bounds later regex work)

What it deliberately does NOT do:
* It does not change meaning for ordinary multilingual text. A purely Russian,
  Arabic, Urdu or Chinese string passes through unchanged. Zero-width non-joiner
  and joiner (needed by Persian/Urdu/Indic scripts and emoji) are dropped from
  the inspection copy but are only FLAGGED when they sit between ASCII letters.
* It is not detection. Flags are findings for the policy engine to weigh.

Known limits: a word written entirely in look-alike Cyrillic/Greek letters is
not mapped; only a small table of common look-alikes is covered.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

MAX_RUN = 64  # longer runs of one repeated character are collapsed to this


class FlagKind(StrEnum):
    INVISIBLE_IN_WORD = "invisible_in_word"
    BIDI_OVERRIDE = "bidi_override"
    TAG_CHARACTERS = "tag_characters"
    CONTROL_CHARACTERS = "control_characters"
    COMPAT_LATIN = "compat_latin"
    MIXED_SCRIPT_WORD = "mixed_script_word"
    EXCESSIVE_REPETITION = "excessive_repetition"


@dataclass(frozen=True)
class NormalizationFlag:
    kind: FlagKind
    count: int
    first_start: int  # offsets into the ORIGINAL text
    first_end: int


@dataclass(frozen=True)
class NormalizedText:
    original: str
    text: str
    offset_map: tuple[int, ...]  # offset_map[i] = original index that produced text[i]
    flags: tuple[NormalizationFlag, ...]

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Convert [start, end) in `text` to [start, end) in `original`."""
        n = len(self.text)
        if not (0 <= start <= end <= n):
            raise ValueError("span outside normalized text")
        if start == end:
            pos = self.offset_map[start] if start < n else len(self.original)
            return pos, pos
        return self.offset_map[start], self.offset_map[end - 1] + 1


_NEWLINES = {"\n", " ", " ", "\x85", "\x0b", "\x0c"}
_BIDI_OVERRIDES = {chr(c) for c in range(0x202A, 0x202F)}  # LRE RLE PDF LRO RLO
_WORD = re.compile(r"[^\W\d_]+")

# Small table of the most common look-alikes. Applied only in mixed-script words.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "ο": "o", "ν": "v", "ρ": "p", "α": "a", "ι": "i", "κ": "k", "υ": "u", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}


def _script(ch: str) -> str:
    if ch.isascii():
        return "latin"
    cp = ord(ch)
    if 0x0400 <= cp <= 0x052F:
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF or 0x1F00 <= cp <= 0x1FFF:
        return "greek"
    return "other"


class _Flags:
    def __init__(self) -> None:
        self._d: dict[FlagKind, list[int]] = {}

    def add(self, kind: FlagKind, start: int, end: int) -> None:
        e = self._d.get(kind)
        if e is None:
            self._d[kind] = [1, start, end]
        else:
            e[0] += 1

    def result(self) -> tuple[NormalizationFlag, ...]:
        return tuple(NormalizationFlag(k, v[0], v[1], v[2]) for k, v in self._d.items())


def normalize_text(original: str) -> NormalizedText:
    if not isinstance(original, str):
        raise TypeError("normalize_text expects str")
    flags = _Flags()
    out: list[str] = []
    omap: list[int] = []

    last_visible_ascii_letter = False
    pending_invisible: int | None = None  # original index of first invisible char in the current gap
    n = len(original)

    for i, ch in enumerate(original):
        cp = ord(ch)
        cat = unicodedata.category(ch)

        # --- tag characters: decode hidden ASCII -------------------------------------
        if 0xE0000 <= cp <= 0xE007F:
            flags.add(FlagKind.TAG_CHARACTERS, i, i + 1)
            if 0xE0020 <= cp <= 0xE007E:
                out.append(chr(cp - 0xE0000))
                omap.append(i)
            continue

        # --- control characters -------------------------------------------------------
        if cat == "Cc" and ch not in "\t\n\r" and ch not in _NEWLINES:
            flags.add(FlagKind.CONTROL_CHARACTERS, i, i + 1)
            continue

        # --- invisible format characters ----------------------------------------------
        if cat == "Cf":
            if ch in _BIDI_OVERRIDES:
                flags.add(FlagKind.BIDI_OVERRIDE, i, i + 1)
            elif pending_invisible is None:
                pending_invisible = i
            continue

        # --- newlines and other whitespace --------------------------------------------
        if ch == "\r":
            if i + 1 < n and original[i + 1] == "\n":
                continue  # the \n that follows produces the newline
            ch_out = "\n"
        elif ch in _NEWLINES or ch == "\n":
            ch_out = "\n"
        elif ch.isspace():
            ch_out = " "
        else:
            ch_out = None

        if ch_out is not None:
            if ch_out == " " and out and out[-1] == " ":
                pass  # collapse runs of spaces
            else:
                out.append(ch_out)
                omap.append(i)
            last_visible_ascii_letter = False
            pending_invisible = None
            continue

        # --- ordinary character: resolve a pending invisible gap, then fold -----------
        is_ascii_letter = ch.isascii() and ch.isalpha()
        if pending_invisible is not None:
            if last_visible_ascii_letter and is_ascii_letter:
                flags.add(FlagKind.INVISIBLE_IN_WORD, pending_invisible, pending_invisible + 1)
            pending_invisible = None

        if ch.isascii():
            folded = ch
        else:
            folded = unicodedata.normalize("NFKC", ch)
            if folded != ch and folded.isascii() and any(c.isalpha() for c in folded):
                flags.add(FlagKind.COMPAT_LATIN, i, i + 1)
        for f in folded:
            out.append(f)
            omap.append(i)
        last_visible_ascii_letter = is_ascii_letter or (folded.isascii() and folded[-1:].isalpha())

    text = "".join(out)

    # --- mixed-script words: undo look-alikes (only when Latin is also present) -------
    if not text.isascii():
        chars = list(text)
        for m in _WORD.finditer(text):
            word = m.group()
            if word.isascii():
                continue
            scripts = {_script(c) for c in word}
            if "latin" in scripts and scripts & {"cyrillic", "greek"}:
                changed = False
                for k in range(m.start(), m.end()):
                    repl = _CONFUSABLES.get(chars[k])
                    if repl is not None:
                        chars[k] = repl
                        changed = True
                if changed:
                    flags.add(FlagKind.MIXED_SCRIPT_WORD, omap[m.start()], omap[m.end() - 1] + 1)
        text = "".join(chars)

    # --- collapse very long runs of one character ------------------------------------
    if len(text) > MAX_RUN:
        text, omap = _collapse_runs(text, omap, flags)

    return NormalizedText(original=original, text=text, offset_map=tuple(omap), flags=flags.result())


def _collapse_runs(text: str, omap: list[int], flags: _Flags) -> tuple[str, list[int]]:
    out: list[str] = []
    new_map: list[int] = []
    i, n = 0, len(text)
    while i < n:
        j = i
        while j < n and text[j] == text[i]:
            j += 1
        run = j - i
        keep = min(run, MAX_RUN)
        out.append(text[i] * keep)
        new_map.extend(omap[i:i + keep])
        if run > MAX_RUN:
            flags.add(FlagKind.EXCESSIVE_REPETITION, omap[i], omap[j - 1] + 1)
        i = j
    return "".join(out), new_map
