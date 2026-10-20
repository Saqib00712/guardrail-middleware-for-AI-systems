"""Build the service from environment variables (prefix GR_). Guardrail settings still use GUARDRAILS_*.

    GR_API_KEYS_FILE      path to the keys JSON (required)
    GR_POLICY_FILE        policy JSON (optional; built-in default otherwise)
    GR_AUDIT_FILE         audit log path (required in production)
    GR_AUDIT_KEY          audit HMAC key, 32+ chars (required with GR_AUDIT_FILE)
    GR_TOOLS_FILE         tool definitions JSON (optional; no tools otherwise)
    GR_APPROVAL_SECRET    32+ chars; enables the approvals endpoint
    GR_HOST / GR_PORT     bind address (default 127.0.0.1:8000)

Production refuses to start without keys and an audit log, and with unknown GR_* variables.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

from fastapi import FastAPI

from guardrails.api.app import create_app
from guardrails.api.auth import ApiKeyStore
from guardrails.api.toolsconfig import registry_from_json_file
from guardrails.audit import AuditLogger, JsonlFileSink
from guardrails.errors import ConfigurationError
from guardrails.metrics import Metrics
from guardrails.policy import default_policy, policy_from_json_file
from guardrails.sdk import Guardrails
from guardrails.settings import Settings
from guardrails.tools import ApprovalManager

KNOWN = {"GR_API_KEYS_FILE", "GR_POLICY_FILE", "GR_AUDIT_FILE", "GR_AUDIT_KEY", "GR_TOOLS_FILE",
         "GR_APPROVAL_SECRET", "GR_HOST", "GR_PORT"}


def build_app(environ: Mapping[str, str] | None = None) -> FastAPI:
    env = os.environ if environ is None else environ
    unknown = sorted(k for k in env if k.startswith("GR_") and k not in KNOWN)
    if unknown:
        raise ConfigurationError("unknown settings: " + ", ".join(unknown))
    settings = Settings.from_env(env)
    prod = settings.environment == "production"

    keys_file = env.get("GR_API_KEYS_FILE")
    if not keys_file:
        raise ConfigurationError("GR_API_KEYS_FILE is required")
    keys = ApiKeyStore.from_json_file(keys_file)
    if prod and len(keys) == 0:
        raise ConfigurationError("production needs at least one API key")

    audit = None
    if env.get("GR_AUDIT_FILE"):
        key = env.get("GR_AUDIT_KEY", "").encode()
        audit = AuditLogger(JsonlFileSink(env["GR_AUDIT_FILE"]), key, settings)
    elif prod:
        raise ConfigurationError("production needs GR_AUDIT_FILE (and GR_AUDIT_KEY)")

    policy = policy_from_json_file(env["GR_POLICY_FILE"]) if env.get("GR_POLICY_FILE") else default_policy()
    g = Guardrails(settings, policy=policy, audit=audit, metrics=Metrics())

    tool_guard = approvals = None
    if env.get("GR_TOOLS_FILE"):
        if env.get("GR_APPROVAL_SECRET"):
            approvals = ApprovalManager(env["GR_APPROVAL_SECRET"].encode(), audit=audit)
        tool_guard = g.tool_guard(registry_from_json_file(env["GR_TOOLS_FILE"]), approvals)
    return create_app(g, keys, tool_guard=tool_guard, approvals=approvals)
