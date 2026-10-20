"""Define tools in a JSON file (so the standalone service needs no Python code).

    {"tools": [{"name": "send_email", "description": "...", "risk": "external",
                "roles": ["user"], "tenants": ["acme"], "requires_approval": null,
                "max_arg_chars": 10000,
                "args": {"to": {"type": "string", "max_length": 200},
                         "count": {"type": "integer", "min": 1, "max": 10},
                         "mode": {"type": "string", "enum": ["a", "b"]},
                         "note": {"type": "string", "required": false}}}]}

Types: string, integer, number, boolean. Every field is required unless "required": false.
Unknown keys anywhere are errors. The generated argument model forbids extra fields.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

from guardrails.errors import ConfigurationError
from guardrails.tools import Risk, ToolRegistry, ToolSpec

MAX_TOOLS_FILE_BYTES = 500_000


class _Arg(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["string", "integer", "number", "boolean"]
    required: bool = True
    max_length: int | None = Field(default=None, ge=1, le=10_000)
    min: float | None = None
    max: float | None = None
    enum: list[str] | None = Field(default=None, min_length=1, max_length=100)


class _Tool(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = Field(max_length=300)
    risk: Risk
    roles: list[str] = Field(min_length=1)
    tenants: list[str] | None = None
    requires_approval: bool | None = None
    max_arg_chars: int = Field(default=10_000, ge=2, le=100_000)
    args: dict[str, _Arg] = Field(max_length=50)


def _field(a: _Arg) -> tuple[Any, Any]:
    kw: dict[str, Any] = {}
    if a.type == "string":
        typ: Any = str
        if a.max_length is not None:
            kw["max_length"] = a.max_length
        if a.enum is not None:
            typ = Literal[tuple(a.enum)]  # type: ignore[valid-type]
    elif a.type == "integer":
        typ = int
        if a.min is not None: kw["ge"] = int(a.min)
        if a.max is not None: kw["le"] = int(a.max)
    elif a.type == "number":
        typ = float
        if a.min is not None: kw["ge"] = a.min
        if a.max is not None: kw["le"] = a.max
    else:
        typ = bool
    if not a.required:
        return (typ | None, Field(default=None, **kw))
    return (typ, Field(**kw))


def registry_from_json_file(path: str | Path) -> ToolRegistry:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_TOOLS_FILE_BYTES:
            raise ConfigurationError("tools file is too large")
        data = json.loads(p.read_text(encoding="utf-8"))
        tools = [_Tool.model_validate(t) for t in data["tools"]]
        reg = ToolRegistry()
        for t in tools:
            model = create_model(f"Args_{t.name}", __config__=ConfigDict(extra="forbid"),
                                 **{k: _field(v) for k, v in t.args.items()})
            reg.register(ToolSpec(name=t.name, description=t.description, args_model=model, risk=t.risk,
                                  allowed_roles=frozenset(t.roles),
                                  allowed_tenants=frozenset(t.tenants) if t.tenants is not None else None,
                                  requires_approval=t.requires_approval, max_arg_chars=t.max_arg_chars))
        return reg.freeze()
    except ConfigurationError:
        raise
    except (OSError, ValueError, KeyError, TypeError, ValidationError):
        raise ConfigurationError("tools file could not be read as a valid tool list") from None
