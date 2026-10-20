"""The development test console (/ui): served only in development, locked down by a content-security policy."""
import base64
import hashlib
import re
from pathlib import Path

from guardrails.settings import Settings
from tests.unit.test_api import build

HTML = Path(__file__).resolve().parents[2] / "guardrails" / "api" / "ui.html"


def _hash(s: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(s.encode("utf-8")).digest()).decode()


def test_ui_is_not_served_in_production():
    c, *_ = build()
    assert c.get("/ui").status_code == 404


def test_ui_is_served_in_development_with_a_policy_that_matches_the_page():
    c, *_ = build(Settings(environment="development"))
    r = c.get("/ui")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    html = r.text
    script = re.search(r"<script>(.*?)</script>", html, re.S).group(1)
    style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    assert f"script-src '{_hash(script)}'" in csp and f"style-src '{_hash(style)}'" in csp
    for must in ("default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'", "form-action 'none'"):
        assert must in csp
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in r.headers


def test_ui_page_makes_no_outside_requests_and_never_writes_html_from_responses():
    text = HTML.read_text(encoding="utf-8")
    assert not re.search(r"https?://", text)
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "localStorage", "sessionStorage"):
        assert bad not in text, bad


def test_hidden_parts_really_hide():
    assert "[hidden]{display:none!important}" in HTML.read_text(encoding="utf-8")


def test_ui_samples_contain_no_complete_credential_literal():
    text = HTML.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in text


def test_ui_talks_only_to_documented_endpoints():
    text = HTML.read_text(encoding="utf-8")
    assert set(re.findall(r'"(/v1/[a-z/]+)"', text)) == {"/v1/whoami", "/v1/inspect/input", "/v1/inspect/output"}
