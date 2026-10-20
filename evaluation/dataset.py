"""Load and validate evaluation/data/cases.ndjson (placeholders expanded)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from evaluation.fakevalues import expand

DATA = Path(__file__).parent / "data" / "cases.ndjson"
LABELS = {"malicious", "sensitive", "benign"}
CATEGORIES = {"injection", "pii", "secret", "leak", "unsafe", "benign"}
STAGES = {"input", "output"}
SPLITS = {"dev", "heldout"}
ORIGINS = {"hand", "generated"}
SOURCES = {"user_message", "retrieved_document", "web_page", "tool_output", "uploaded_file", "model_output"}


@dataclass(frozen=True)
class Case:
    id: str
    stage: str
    source: str
    label: str
    category: str
    technique: str
    text: str
    sensitive: tuple[str, ...]
    split: str
    origin: str


def load(path: Path = DATA) -> list[Case]:
    out: list[Case] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        r = json.loads(line)
        if (r["label"] not in LABELS or r["category"] not in CATEGORIES or r["stage"] not in STAGES
                or r["split"] not in SPLITS or r["origin"] not in ORIGINS or r["source"] not in SOURCES):
            raise ValueError(f"bad case on line {n}")
        out.append(Case(r["id"], r["stage"], r["source"], r["label"], r["category"], r["technique"], expand(r["text"]),
                        tuple(expand(v) for v in r["sensitive"]), r["split"], r["origin"]))
    ids = [c.id for c in out]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case ids")
    return out
