"""Documentation must stay true: files exist, links resolve, every setting/route/error is documented, examples run,
and the evidence named in the Definition-of-Done matrix and security notes really exists."""
import contextlib
import io
import json
import re
import runpy
from pathlib import Path

import pytest

from guardrails.api.config import KNOWN
from guardrails.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
REQUIRED = ["run_guide", "architecture", "api", "configuration", "policy", "operations", "security", "final_report", "definition_of_done"]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_required_documents_exist_and_are_not_empty():
    for name in REQUIRED:
        assert len(read(DOCS / f"{name}.md")) > 500, name
    assert len(read(ROOT / "README.md")) > 500
    assert len(read(ROOT / "SECURITY.md")) > 100


def test_readme_indexes_every_required_document():
    readme = read(ROOT / "README.md")
    for name in REQUIRED:
        assert f"docs/{name}.md" in readme, name


def _repo_paths(text: str):
    for m in re.finditer(r"`((?:docs|examples|guardrails|tests|evaluation)/[A-Za-z0-9_./-]+)(?:::[A-Za-z0-9_]+)?`", text):
        yield m.group(1)


@pytest.mark.parametrize("doc", ["README.md"] + [f"docs/{n}.md" for n in REQUIRED])
def test_paths_mentioned_in_the_docs_exist(doc):
    for p in _repo_paths(read(ROOT / doc)):
        if "*" in p or p.endswith("/"):
            continue
        assert (ROOT / p).exists(), f"{doc} mentions missing path {p}"


def test_every_setting_is_documented():
    doc = read(DOCS / "configuration.md")
    for name in Settings.model_fields:
        assert f"`{name}`" in doc or f"`{name.upper()}`" in doc, name


def test_every_service_variable_is_documented():
    doc = read(DOCS / "configuration.md")
    for name in KNOWN:
        assert f"`{name}`" in doc, name


def test_every_route_and_error_code_is_documented():
    from fastapi.routing import APIRoute

    from guardrails.api.app import create_app
    from guardrails.api.auth import ApiKeyStore
    from guardrails.sdk import Guardrails

    app = create_app(Guardrails(Settings(environment="development")), ApiKeyStore([]))
    doc = read(DOCS / "api.md")
    paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
    assert "/v1/inspect/input" in paths
    for p in paths:
        assert p in doc, p
    source = read(ROOT / "guardrails" / "api" / "app.py")
    codes = set(re.findall(r'"([A-Z][A-Z_]{4,})"', source)) & {
        "APPROVALS_DISABLED", "AUDIT_UNAVAILABLE", "BODY_TOO_LARGE", "BUDGET_EXCEEDED", "CAPACITY", "FORBIDDEN",
        "INTERNAL_ERROR", "INVALID_REQUEST", "METRICS_DISABLED", "RATE_LIMITED", "RUN_NOT_FOUND", "TOOLS_DISABLED",
        "UNAUTHORIZED", "UNKNOWN_SCHEMA", "UNSUPPORTED_MEDIA_TYPE"}
    assert len(codes) == 15
    for c in codes:
        assert c in doc, c


def test_every_error_code_in_the_app_source_is_in_the_known_list():
    """If a new error code appears in app.py it must be added to api.md and to the list above."""
    source = read(ROOT / "guardrails" / "api" / "app.py")
    used = set(re.findall(r'_err\([^,]+,\s*"([A-Z_]+)"', source)) | set(re.findall(r'ApiError\([^,]+,\s*"([A-Z_]+)"', source))
    doc = read(DOCS / "api.md")
    assert "HTTP_ERROR" in doc
    for c in used:
        assert c in doc, c


def test_example_json_files_load():
    from guardrails.api.toolsconfig import registry_from_json_file
    from guardrails.policy import policy_from_json_file

    assert policy_from_json_file(str(ROOT / "examples" / "policy.example.json")).id == "acme-strict"
    assert registry_from_json_file(str(ROOT / "examples" / "tools.example.json")) is not None
    json.loads(read(ROOT / "examples" / "tools.example.json"))


def test_quickstart_runs_and_prints_the_documented_outcomes():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        runpy.run_path(str(ROOT / "examples" / "quickstart.py"), run_name="__main__")
    text = out.getvalue()
    for want in ("1a sanitize -> Please email [REDACTED_EMAIL] the invoice", "1b block", "2  block", "3  block",
                 "4a require_review approval_required = True", "4b allow allowed = True", "4c require_review",
                 "5  audit chain ok = True records = 7"):
        assert want in text, want
    assert "AKIA" not in text


def _evidence(text: str):
    return re.findall(r"`(tests/unit/test_[a-z_0-9]+\.py)::(test_[a-z_0-9]+)`", text)


@pytest.mark.parametrize("doc", ["definition_of_done", "security"])
def test_evidence_named_in_the_docs_exists(doc):
    found = _evidence(read(DOCS / f"{doc}.md"))
    assert len(found) >= 10
    for file, name in found:
        src = read(ROOT / file)
        assert re.search(rf"^def {name}\(", src, re.M), f"{doc}: {file}::{name}"


ITEMS = [
    "Input and output guardrail interfaces work.",
    "Prompt-injection checks have deterministic regression tests.",
    "PII and secret detection and redaction work as configured.",
    "Policies have validated actions and documented precedence.",
    "Tool authorization blocks unauthorized operations.",
    "Authentication and authorization protect privileged endpoints.",
    "Resource limits and timeout behavior are tested.",
    "Audit records avoid storing sensitive raw content.",
    "API and Python integration examples work.",
    "Security failures have explicit, tested handling behavior.",
    "Adversarial tests cover malicious and benign cases.",
    "Monitoring integrates with the existing observability architecture.",
    "CI executes the required automated checks.",
    "Documentation describes actual functionality and limitations.",
    "Existing functionality has not regressed.",
    "All test results are reported truthfully.",
]


def test_definition_of_done_has_the_sixteen_original_items_in_order():
    doc = read(DOCS / "definition_of_done.md")
    for i, item in enumerate(ITEMS, 1):
        assert re.search(rf"^\| {i} \| {re.escape(item)} \|", doc, re.M), item
    rows = re.findall(r"^\| (\d+) \|", doc, re.M)
    assert rows == [str(i) for i in range(1, 17)]
    for line in doc.splitlines():
        if re.match(r"^\| \d+ \|", line):
            assert re.search(r"\| (Met|Partly) \|", line), line
            assert "tests/unit/" in line or "evaluation" in line or "final_report" in line, line


def test_the_final_report_quotes_the_real_evaluation_numbers():
    result = json.loads((ROOT / "evaluation" / "results.json").read_text(encoding="utf-8"))
    a = result["summaries"]["all"]
    doc = read(DOCS / "final_report.md")
    m = re.search(r"<!-- numbers: all_bad=(\d+)/(\d+); benign_fp=(\d+)/(\d+) -->", doc)
    assert m
    assert tuple(map(int, m.groups())) == (a["recall_all_bad"]["ok"], a["recall_all_bad"]["n"],
                                           a["benign"]["false_positives"], a["benign"]["n"])
    cats = a["recall_by_category"]
    for name, label in (("injection", "prompt injection"), ("secret", "secrets"), ("pii", "personal data"),
                        ("unsafe", "unsafe content"), ("leak", "system prompt leak")):
        assert f"| {label} | {cats[name]['ok']} of {cats[name]['n']} " in doc, name


def test_the_docs_do_not_claim_complete_security():
    for name in REQUIRED + ["../README", "../SECURITY"]:
        text = read(DOCS / f"{name}.md").lower()
        for bad in ("completely secure", "fully secure", "unbreakable", "100% secure", "guarantees security"):
            for line in text.splitlines():
                if bad in line:
                    assert any(n in line for n in ("not ", "no ", "never", "nothing", "do not", "without")), (name, line)
