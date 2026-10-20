"""API-key authentication. Keys are random, long and shown once; only a hash is stored.

Key format:  gr_<key_id>.<secret>      sent as   Authorization: Bearer <key>
(never in a URL: URLs end up in logs). The id picks the record, the secret is compared
by hash in constant time; an unknown id still performs a dummy comparison so response
time does not reveal which ids exist.

A key record decides WHO the caller is (tenant, user, domain roles used by tool
allowlists) and WHAT it may call (scopes). The tenant is never taken from a request body.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sys
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardrails.errors import ConfigurationError
from guardrails.tools import Principal

SCOPES = frozenset({"inspect", "tools", "approve", "admin"})
MAX_KEY_CHARS = 200
MAX_KEYS_FILE_BYTES = 1_000_000
_KEY = re.compile(r"^gr_([a-z0-9]{8,16})\.([A-Za-z0-9_-]{32,128})$")
_DUMMY = hashlib.sha256(b"dummy").hexdigest()


class ApiKeyRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    key_id: str = Field(pattern=r"^[a-z0-9]{8,16}$")
    secret_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    tenant_id: str = Field(pattern=r"^[A-Za-z0-9_.@:-]{1,128}$")
    user_id: str = Field(pattern=r"^[A-Za-z0-9_.@:-]{1,128}$")
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = Field(min_length=1)
    disabled: bool = False
    expires_at: float | None = None          # unix seconds
    description: str = Field(default="", max_length=120)

    def model_post_init(self, _c: object) -> None:
        if not self.scopes <= SCOPES:
            raise ValueError("unknown scope")


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_api_key(*, tenant_id: str, user_id: str, roles: frozenset[str] = frozenset(),
                     scopes: frozenset[str] = frozenset({"inspect"}), expires_at: float | None = None,
                     description: str = "") -> tuple[str, ApiKeyRecord]:
    """Returns (plaintext key, record). Show the key ONCE; store only the record."""
    key_id = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    rec = ApiKeyRecord(key_id=key_id, secret_hash=_hash_secret(secret), tenant_id=tenant_id, user_id=user_id,
                       roles=roles, scopes=scopes, expires_at=expires_at, description=description)
    return f"gr_{key_id}.{secret}", rec


class ApiKeyStore:
    def __init__(self, records: list[ApiKeyRecord], clock: Callable[[], float] = time.time) -> None:
        ids = [r.key_id for r in records]
        if len(set(ids)) != len(ids):
            raise ConfigurationError("duplicate key ids in key store")
        self._by_id = {r.key_id: r for r in records}
        self._clock = clock

    def __len__(self) -> int:
        return len(self._by_id)

    @classmethod
    def from_json_file(cls, path: str | Path, clock: Callable[[], float] = time.time) -> "ApiKeyStore":
        p = Path(path)
        if not p.exists():
            raise ConfigurationError("keys file does not exist; create it with the auth 'create --keys-file' command")
        try:
            if p.stat().st_size > MAX_KEYS_FILE_BYTES:
                raise ConfigurationError("keys file is too large")
            data = json.loads(p.read_text(encoding="utf-8"))
            recs = [ApiKeyRecord.model_validate(x) for x in data["keys"]]
        except ConfigurationError:
            raise
        except (OSError, ValueError, KeyError, TypeError, ValidationError):
            raise ConfigurationError("keys file could not be read as a valid key list") from None
        return cls(recs, clock)

    def authenticate(self, header: str | None) -> tuple[Principal, ApiKeyRecord] | None:
        """None for ANY failure (missing, malformed, unknown, wrong secret, disabled, expired)."""
        if not header or len(header) > MAX_KEY_CHARS + 7 or not header.startswith("Bearer "):
            return None
        m = _KEY.match(header[7:].strip())
        if not m:
            return None
        rec = self._by_id.get(m.group(1))
        expected = rec.secret_hash if rec else _DUMMY
        ok = hmac.compare_digest(expected, _hash_secret(m.group(2)))
        if rec is None or not ok or rec.disabled or (rec.expires_at is not None and rec.expires_at <= self._clock()):
            return None
        return Principal(user_id=rec.user_id, tenant_id=rec.tenant_id, roles=rec.roles), rec


def append_record_to_file(path: str | Path, rec: ApiKeyRecord) -> None:
    """Add a record to the keys file (creating it). Validates what is already there; replaces atomically."""
    import os
    p = Path(path)
    existing: list[dict] = []
    if p.exists():
        existing = [r.model_dump(mode="json") for r in ApiKeyStore.from_json_file(p)._by_id.values()]  # validates
    existing.append(rec.model_dump(mode="json"))
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps({"keys": existing}, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


def _cli(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m guardrails.api.auth")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="create a key; prints the key ONCE")
    c.add_argument("--tenant", required=True); c.add_argument("--user", required=True)
    c.add_argument("--role", action="append", default=[], help="domain role (repeat for several)")
    c.add_argument("--scope", action="append", default=None, help="inspect, tools, approve, admin (repeat for several)")
    c.add_argument("--days", type=float, default=None); c.add_argument("--description", default="")
    c.add_argument("--keys-file", default=None, help="append the record to this keys file (created if missing)")
    a = ap.parse_args(argv)
    exp = time.time() + a.days * 86400 if a.days else None
    try:
        key, rec = generate_api_key(tenant_id=a.tenant, user_id=a.user, roles=frozenset(a.role),
                                    scopes=frozenset(a.scope or ["inspect"]), expires_at=exp, description=a.description)
        if a.keys_file:
            append_record_to_file(a.keys_file, rec)
    except (ValueError, ConfigurationError) as e:
        print(f"could not create key: {e.__class__.__name__}")
        return 2
    print("API KEY (shown once, store it safely):", key)
    if a.keys_file:
        print(f"Record added to {a.keys_file}")
    else:
        print("Add this record to the keys file {\"keys\": [...]}:")
        print(json.dumps(rec.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
