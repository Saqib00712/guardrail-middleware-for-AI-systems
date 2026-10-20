"""Phase 12: metrics, tracing, request ids, health checks, and the deployment files. No network, no Docker needed."""
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardrails import AuditLogger, Guardrails, MemorySink, Settings
from guardrails.api.app import create_app
from guardrails.api.auth import ApiKeyStore, generate_api_key
from guardrails.api.config import build_app
from guardrails.errors import ConfigurationError
from guardrails.metrics import Metrics
from guardrails.tracing import ALLOWED_ATTRIBUTES, safe_span
from guardrails.types import Action
from tests.unit import fakes

ROOT = Path(__file__).resolve().parents[2]
AUDIT_KEY = b"a" * 40


def mk(tenant, user, scopes):
    return generate_api_key(tenant_id=tenant, user_id=user, roles=frozenset(), scopes=frozenset(scopes))


KEYS = {"user": mk("acme-secret-tenant", "alice-private", {"inspect", "tools"}), "admin": mk("acme-secret-tenant", "ops", {"admin"})}


def H(name):
    return {"Authorization": "Bearer " + KEYS[name][0]}


def build(settings=None, sink=None, metrics=True, audit=True, tracer=None):
    settings = settings or Settings()
    sink = sink or MemorySink()
    lg = AuditLogger(sink, AUDIT_KEY, settings) if audit else None
    m = Metrics() if metrics else None
    g = Guardrails(settings, audit=lg, metrics=m, tracer=tracer)
    app = create_app(g, ApiKeyStore([r for _, r in KEYS.values()]))
    return TestClient(app, raise_server_exceptions=False), g, m, sink


# ------------------------------------------------------------------ metrics unit
def test_counter_and_histogram_render_in_prometheus_format():
    m = Metrics()
    m.record_decision("input", "block", "SECRET_DETECTED", 0.02, False)
    m.record_decision("input", "block", "SECRET_DETECTED", 0.2, True)
    text = m.render()
    assert '# TYPE guardrails_decisions_total counter' in text
    assert 'guardrails_decisions_total{stage="input",action="block",reason_code="SECRET_DETECTED"} 2' in text
    assert 'guardrails_degraded_total{stage="input"} 1' in text
    assert 'guardrails_decision_seconds_bucket{stage="input",le="0.025"} 1' in text      # 0.02 fits, 0.2 does not
    assert 'guardrails_decision_seconds_bucket{stage="input",le="0.25"} 2' in text
    assert 'guardrails_decision_seconds_bucket{stage="input",le="+Inf"} 2' in text
    assert 'guardrails_decision_seconds_count{stage="input"} 2' in text
    assert 'guardrails_decision_seconds_sum{stage="input"} 0.220000' in text
    assert text.endswith("\n")


def test_label_values_are_checked_and_cannot_inject_lines():
    m = Metrics()
    m.inc("guardrails_limit_denials_total", 'x"} 999\nfake_metric 1')
    m.inc("guardrails_limit_denials_total", "a" * 200)
    text = m.render()
    assert "fake_metric" not in text and "999" not in text
    assert text.count('guardrails_limit_denials_total{kind="other"} 2') == 1


def test_series_are_capped_so_labels_cannot_exhaust_memory():
    m = Metrics(max_series_per_metric=3)
    for i in range(50):
        m.inc("guardrails_limit_denials_total", f"kind{i}")
    lines = [l for l in m.render().splitlines() if l.startswith("guardrails_limit_denials_total{")]
    assert len(lines) == 4 and 'guardrails_limit_denials_total{kind="overflow"} 47' in lines
    m.inc("guardrails_limit_denials_total", "kind0")                       # existing series still counts
    assert m.value("guardrails_limit_denials_total", "kind0") == 2


def test_bad_metric_calls_are_rejected_and_safe_swallows_them():
    m = Metrics()
    for bad in (lambda: m.inc("nope"), lambda: m.inc("guardrails_limit_denials_total", "a", "b"),
                lambda: m.inc("guardrails_limit_denials_total", "a", by=-1), lambda: m.observe("nope", 1.0)):
        with pytest.raises(ValueError):
            bad()
    m.safe(m.inc, "nope")                                                    # does not raise
    m.observe("guardrails_decision_seconds", float("nan"), "input")           # ignored, does not poison the sum
    m.observe("guardrails_decision_seconds", -1.0, "input")
    assert "guardrails_decision_seconds_count" not in m.render().replace('# TYPE', '')
    with pytest.raises(ValueError):
        Metrics(buckets=[1, 0.5])


# ------------------------------------------------------------------ sdk metrics
def test_every_decision_is_counted_by_stage_action_and_reason():
    m = Metrics()
    g = Guardrails(Settings(), metrics=m)
    g.check_input("hello there")
    g.check_input("my key is " + fakes.AWS_KEY)
    g.check_output("fine answer")
    text = m.render()
    assert 'stage="input",action="block",reason_code="SECRET_DETECTED"' in text
    assert 'stage="input",action="allow"' in text and 'stage="output",action="allow"' in text
    assert 'guardrails_decision_seconds_count{stage="input"} 2' in text


def test_metrics_never_contain_content_tenants_or_users():
    m = Metrics()
    g = Guardrails(Settings(), metrics=m)
    g.check_input("my key is " + fakes.AWS_KEY + " alice@example.com", tenant_id="tenant-xyz-secret", user_id="user-xyz-private")
    text = m.render()
    for leak in (fakes.AWS_KEY[:8], "alice", "tenant-xyz", "user-xyz"):
        assert leak not in text


def test_a_broken_metrics_object_never_breaks_a_decision():
    class Broken(Metrics):
        def record_decision(self, *a, **k):
            raise RuntimeError("boom")

    g = Guardrails(Settings(), metrics=Broken())
    assert g.check_input("hello").allowed


def test_audit_failure_and_degraded_are_counted_and_the_fail_closed_result_has_a_sane_time():
    m = Metrics()
    sink = MemorySink()
    g = Guardrails(Settings(), audit=AuditLogger(sink, AUDIT_KEY), metrics=m)
    sink.fail = True
    r = g.check_input("hello")
    assert not r.allowed and r.elapsed_ms < 1000                              # was a huge number before this phase
    assert m.value("guardrails_audit_failures_total", "input_check") == 1
    assert m.value("guardrails_decisions_total", "input", "block", "AUDIT_UNAVAILABLE") == 1


def test_streams_are_counted_without_an_audit_log():
    m = Metrics()
    g = Guardrails(Settings(), metrics=m)
    s = g.stream_output()
    for ch in "hello " * 100 + fakes.AWS_KEY + " tail " * 100:
        u = s.feed(ch)
        if u.decision is not None:
            break
    s.finish()
    assert 'stage="output"' in m.render() and 'guardrails_decisions_total' in m.render()
    assert "guardrails_decision_seconds_count{stage=\"output\"}" not in m.render()      # no timing for streams


# ------------------------------------------------------------------ tracing
class RecTracer:
    def __init__(self):
        self.spans = []

    def span(self, name):
        outer = self

        class CM:
            def __enter__(self_):
                self_.attrs = {}
                self_.name = name
                outer.spans.append(self_)
                return self_

            def __exit__(self_, *exc):
                self_.exc = exc[0]
                return False

            def set_attribute(self_, k, v):
                self_.attrs[k] = v
        return CM()


def test_spans_carry_only_decisions_never_content():
    t = RecTracer()
    g = Guardrails(Settings(), tracer=t)
    g.check_input("secret " + fakes.AWS_KEY + " bob@example.com", tenant_id="tenant-xyz", user_id="user-xyz", request_id="req-12345")
    g.check_output("ok answer")
    assert [s.name for s in t.spans] == ["guardrails.check_input", "guardrails.check_output"]
    a = t.spans[0].attrs
    assert a["action"] == "block" and a["stage"] == "input" and a["reason_code"] == "SECRET_DETECTED" and a["request_id"] == "req-12345"
    flat = json.dumps([s.attrs for s in t.spans])
    for leak in (fakes.AWS_KEY[:8], "bob@", "tenant-xyz", "user-xyz"):
        assert leak not in flat
    assert all(set(s.attrs) <= ALLOWED_ATTRIBUTES for s in t.spans)


def test_attributes_outside_the_allowlist_are_dropped():
    t = RecTracer()
    with safe_span(t, "x") as sp:
        sp.set_attribute("text", "my password")
        sp.set_attribute("tenant_id", "acme")
        sp.set_attribute("action", Action.BLOCK)
    assert t.spans[0].attrs == {"action": "block"}


def test_a_failing_tracer_changes_nothing_and_user_errors_still_propagate():
    class Bad:
        def span(self, name):
            raise RuntimeError("tracer down")

    class BadExit(RecTracer):
        def span(self, name):
            cm = super().span(name)
            cm.__exit__ = lambda *a: (_ for _ in ()).throw(RuntimeError("exit"))
            return type("X", (), {"__enter__": lambda s: cm.__enter__(), "__exit__": lambda s, *a: (_ for _ in ()).throw(RuntimeError("x"))})()

    for tr in (Bad(), BadExit()):
        g = Guardrails(Settings(), tracer=tr)
        assert g.check_input("hello").allowed
        assert g.check_input("key " + fakes.AWS_KEY).decision.action is Action.BLOCK      # decisions unchanged
    t = RecTracer()
    with pytest.raises(KeyError):
        with safe_span(t, "x"):
            raise KeyError("real error")
    assert t.spans[0].exc is KeyError                                                    # the tracer saw it; we did not hide it


# ------------------------------------------------------------------ API: request id, metrics, health
def test_request_id_is_accepted_when_well_formed_replaced_when_not_and_always_returned():
    c, g, m, sink = build()
    r = c.post("/v1/inspect/input", headers={**H("user"), "X-Request-ID": "trace-abc-12345"}, json={"text": "hi"})
    assert r.headers["X-Request-ID"] == "trace-abc-12345" and r.json()["request_id"] == "trace-abc-12345"
    for bad in ("short", "x" * 200, "has space and 'quotes'", "badéchars-12345"):
        try:
            r = c.get("/healthz", headers={"X-Request-ID": bad})
        except UnicodeEncodeError:
            continue
        assert r.headers["X-Request-ID"] != bad and re.fullmatch(r"[0-9a-f]{32}", r.headers["X-Request-ID"])
    r2 = c.post("/v1/inspect/input", headers={**H("user"), "X-Request-ID": "header-id-12345"}, json={"text": "hi", "request_id": "body-id-12345"})
    assert r2.json()["request_id"] == "body-id-12345"                                  # the body wins
    assert c.get("/healthz").headers["X-Request-ID"] != c.get("/healthz").headers["X-Request-ID"]
    audited = [json.loads(l)["request_id"] for l in sink.lines]
    assert "trace-abc-12345" in audited


def test_error_responses_also_carry_a_request_id():
    c, *_ = build()
    r = c.get("/v1/whoami")
    assert r.status_code == 401 and re.fullmatch(r"[0-9a-f]{32}", r.headers["X-Request-ID"])


def test_metrics_endpoint_needs_the_admin_scope():
    c, *_ = build()
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers=H("user")).status_code == 403                       # an ordinary key cannot read it
    r = c.get("/metrics", headers=H("admin"))
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain; version=0.0.4")


def test_metrics_endpoint_reflects_traffic_by_template_not_raw_path():
    c, g, m, _ = build()
    c.post("/v1/inspect/input", headers=H("user"), json={"text": "key " + fakes.AWS_KEY})
    c.get("/v1/whoami")                                                                  # 401
    c.get("/no/such/path/with/secrets-123")                                              # 404
    text = c.get("/metrics", headers=H("admin")).text
    assert 'guardrails_http_requests_total{endpoint="/v1/inspect/input",status="200"} 1' in text
    assert 'guardrails_http_requests_total{endpoint="/v1/whoami",status="401"} 1' in text
    assert 'endpoint="unmatched",status="404"' in text and "secrets-123" not in text
    assert 'stage="input",action="block",reason_code="SECRET_DETECTED"' in text
    assert 'guardrails_http_request_seconds_count{endpoint="/v1/inspect/input"} 1' in text
    for leak in ("acme-secret-tenant", "alice-private", fakes.AWS_KEY[:8]):
        assert leak not in text


def test_metrics_endpoint_is_404_when_metrics_are_not_configured():
    c, *_ = build(metrics=False)
    assert c.get("/metrics", headers=H("admin")).status_code == 404
    assert c.post("/v1/inspect/input", headers=H("user"), json={"text": "hi"}).status_code == 200


def test_limit_denials_and_oversize_bodies_are_counted():
    c, g, m, _ = build(Settings(rate_limit_burst=1, max_request_body_bytes=2000))
    c.post("/v1/inspect/input", headers=H("user"), json={"text": "hi"})
    assert c.post("/v1/inspect/input", headers=H("user"), json={"text": "hi"}).status_code == 429
    assert m.value("guardrails_limit_denials_total", "rate_limit_key") == 1
    r = c.post("/v1/inspect/input", headers={**H("admin"), "Content-Type": "application/json"}, content=b"x" * 5000)
    assert r.status_code == 413
    assert m.value("guardrails_http_requests_total", "rejected_early", 413) == 1
    assert 'guardrails_http_requests_total{endpoint="rejected_early",status="413"} 1' in m.render()     # not "other"


def test_a_crash_inside_a_route_is_a_500_with_fixed_text_and_is_counted(monkeypatch):
    c, g, m, _ = build()
    monkeypatch.setattr(g, "check_input", lambda *a, **k: 1 / 0)
    r = c.post("/v1/inspect/input", headers=H("user"), json={"text": "my secret text"})
    assert r.status_code == 500 and r.json() == {"error": {"code": "INTERNAL_ERROR", "message": "internal error"}}
    assert "X-Request-ID" in r.headers
    assert m.value("guardrails_http_requests_total", "/v1/inspect/input", 500) == 1


def test_readyz_reports_audit_state_without_details():
    c, g, m, sink = build()
    r = c.get("/readyz")
    assert r.status_code == 200 and r.json() == {"status": "ready", "checks": {"keys": "ok", "audit": "ok"}}
    sink.fail = True
    r = c.get("/readyz")
    assert r.status_code == 503 and r.json() == {"status": "not_ready", "checks": {"keys": "ok", "audit": "fail"}}
    assert c.get("/healthz").status_code == 200                                         # alive, but not ready
    sink.fail = False
    assert c.get("/readyz").status_code == 200                                          # recovers without any write
    assert len(sink.lines) == 0                                                         # probing wrote nothing


def test_readyz_in_production_without_an_audit_log_is_not_ready_but_development_is_fine():
    assert build(Settings(), audit=False)[0].get("/readyz").status_code == 503
    assert build(Settings(environment="development"), audit=False)[0].get("/readyz").json()["checks"] == {"keys": "ok"}


def test_readyz_fails_with_no_keys():
    g = Guardrails(Settings(environment="development"))
    c = TestClient(create_app(g, ApiKeyStore([])))
    assert c.get("/readyz").status_code == 503


def test_file_sink_probe_does_not_write_and_notices_a_missing_file(tmp_path):
    from guardrails import JsonlFileSink
    p = tmp_path / "a.jsonl"
    sink = JsonlFileSink(str(p))
    assert sink.healthy() and p.read_text() == ""
    p.unlink()
    assert not sink.healthy()


def test_service_config_builds_with_metrics_on(tmp_path):
    kf = tmp_path / "keys.json"
    from guardrails.api.auth import _cli
    assert _cli(["create", "--tenant", "t", "--user", "u", "--scope", "admin", "--keys-file", str(kf)]) == 0
    app = build_app({"GUARDRAILS_ENVIRONMENT": "development", "GR_API_KEYS_FILE": str(kf)})
    c = TestClient(app)
    assert c.get("/readyz").status_code == 200
    with pytest.raises(ConfigurationError):
        build_app({"GUARDRAILS_ENVIRONMENT": "production", "GR_API_KEYS_FILE": str(kf)})


# ------------------------------------------------------------------ deployment files (static checks; nothing is built here)
def test_dockerfile_basics():
    d = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^USER 10001$", d, re.M)                                          # not root
    assert "GUARDRAILS_ENVIRONMENT=production" in d                                     # strict by default
    assert "GR_AUDIT_KEY" not in d and "GR_API_KEYS_FILE" not in d                      # no secrets or key paths baked in
    assert not re.search(r"^(COPY|ADD) .*(\.env|keys|\.db|\.jsonl|tests)", d, re.M)
    assert "HEALTHCHECK" in d and "/readyz" in d and 'CMD ["python", "-m", "guardrails.api"]' in d
    assert d.index("COPY pyproject.toml") < d.index("COPY guardrails")


def test_dockerignore_keeps_secrets_and_state_out_of_the_image():
    lines = set((ROOT / ".dockerignore").read_text().split())
    assert {".env", "*.db", "keys*.json", "*.jsonl", ".git", "data/", "tests/"} <= lines


def test_gitignore_keeps_secrets_and_state_out_of_the_repo():
    lines = set((ROOT / ".gitignore").read_text().split())
    assert {".env", "*.db", "keys*.json", "*.jsonl"} <= lines


def test_compose_requires_the_audit_key_and_hardens_the_container():
    yaml = pytest.importorskip("yaml")
    c = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["guardrails"]
    assert c["environment"]["GR_AUDIT_KEY"].startswith("${GR_AUDIT_KEY:?")               # compose refuses to start without it
    assert c["read_only"] is True and c["cap_drop"] == ["ALL"] and "no-new-privileges:true" in c["security_opt"]
    assert c["ports"] == ["127.0.0.1:8000:8000"]                                         # local only by default
    assert any(v.endswith(":ro") for v in c["volumes"])


def test_ci_workflow_runs_tests_on_both_systems_with_minimal_permissions():
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert wf["permissions"] == {"contents": "read"}
    m = wf["jobs"]["test"]["strategy"]["matrix"]
    assert set(m["os"]) == {"ubuntu-latest", "windows-latest"} and {"3.11", "3.12", "3.13"} <= set(map(str, m["python"]))
    runs = " ".join(str(s.get("run", "")) for s in wf["jobs"]["test"]["steps"])
    assert 'pip install -e ".[dev]"' in runs and "pytest" in runs
    assert "docker" in wf["jobs"] and "hygiene" in wf["jobs"]
    assert "pull_request" in (wf.get("on") or wf.get(True))


def test_nothing_sensitive_is_committed_to_the_tree():
    bad = [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts
           and (p.name == ".env" or p.suffix in {".db", ".jsonl"} or re.fullmatch(r"keys.*\.json", p.name))]
    assert bad == []


def test_every_kind_of_limit_denial_is_counted():
    c, g, m, _ = build(Settings(tenant_budget_chars_per_hour=5, tenant_rate_limit_per_minute=1000, auth_failures_per_minute=2))
    assert c.post("/v1/inspect/input", headers=H("user"), json={"text": "x" * 50}).status_code == 429
    assert m.value("guardrails_limit_denials_total", "budget") == 1
    for _ in range(2):
        c.get("/v1/whoami", headers={"Authorization": "Bearer nonsense"})
    assert c.get("/v1/whoami", headers=H("user")).status_code == 429
    assert m.value("guardrails_limit_denials_total", "auth_lockout") == 1
    c2, g2, m2, _ = build(Settings(tenant_rate_limit_per_minute=1))
    c2.get("/v1/whoami", headers=H("user"))
    assert c2.get("/v1/whoami", headers=H("user")).status_code == 429
    assert m2.value("guardrails_limit_denials_total", "rate_limit_tenant") == 1


def test_tool_decisions_are_counted():
    from tests.unit.test_tools import make_registry
    settings = Settings()
    m = Metrics()
    g = Guardrails(settings, audit=AuditLogger(MemorySink(), AUDIT_KEY, settings), metrics=m)
    app = create_app(g, ApiKeyStore([r for _, r in KEYS.values()]), tool_guard=g.tool_guard(make_registry()))
    c = TestClient(app)
    run = c.post("/v1/runs", headers=H("user")).json()["run_id"]
    r = c.post("/v1/tools/check", headers=H("user"), json={"run_id": run, "tool": "no_such_tool", "arguments": {}})
    assert r.status_code == 200 and r.json()["allowed"] is False
    assert "guardrails_tool_decisions_total{action=\"block\"" in m.render()
