"""Strict parsing of structured (JSON) model output against a pydantic model.

Strict on purpose: models and attackers both produce odd JSON.
* size, depth and node limits are checked BEFORE building Python objects
* duplicate keys, NaN and Infinity are rejected
* one surrounding ``` fence is tolerated (models add them); nothing else is stripped
* the schema must forbid extra fields (a programmer error is raised at the call site)
* errors never repeat the model's text
"""
from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ValidationError

from guardrails.errors import ConfigurationError, GuardrailError
from guardrails.settings import Settings
from guardrails.types import ReasonCode
from guardrails.validation import MAX_JSON_NODES, _count_nodes_exceeds, json_depth_exceeds

_FENCE = re.compile(r"\A\s*```(?:json|JSON)?[ \t]*\n(.*)\n```\s*\Z", re.S)


class OutputInvalid(GuardrailError):
    code = ReasonCode.OUTPUT_SCHEMA_INVALID
    default_public_message = "output did not match the expected format"


def require_strict_schema(schema: type[BaseModel]) -> None:
    if not (isinstance(schema, type) and issubclass(schema, BaseModel)):
        raise ConfigurationError("schema must be a pydantic model class")
    if schema.model_config.get("extra") != "forbid":
        raise ConfigurationError("schema must set extra='forbid' so unexpected fields are rejected")


def _no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _no_const(_: str) -> Any:
    raise ValueError("non-finite number")


def parse_structured(text: str, schema: type[BaseModel], settings: Settings) -> BaseModel:
    require_strict_schema(schema)
    if len(text) > settings.max_output_chars:
        raise OutputInvalid()
    m = _FENCE.match(text)
    body = m.group(1) if m else text
    try:
        if json_depth_exceeds(body, settings.max_nesting_depth):
            raise OutputInvalid()
        data = json.loads(body, object_pairs_hook=_no_dupes, parse_constant=_no_const)
        if _count_nodes_exceeds(data, MAX_JSON_NODES):
            raise OutputInvalid()
        return schema.model_validate(data)
    except OutputInvalid:
        raise
    except (ValueError, ValidationError, RecursionError):
        raise OutputInvalid(internal_detail="parse or schema validation failed") from None
