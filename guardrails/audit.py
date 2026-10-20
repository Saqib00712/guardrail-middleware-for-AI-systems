"""Tamper-evident audit log that never stores request content.

What a record contains: ids, time, stage, action, reason code, severity, policy id and
version, finding SUMMARIES (detector, reason, severity, category, confidence), the tool
name, lengths and counts. It has NO field for text, matched values, arguments or prompts
(`extra="forbid"`), so a bug elsewhere cannot leak them through here.
Identifiers that could be personal or low-entropy are replaced by keyed hashes (HMAC):
the user id becomes a stable pseudonym, tool-argument fingerprints are keyed so a
dictionary attack on guessable arguments needs the key.

Tamper evidence: every record carries `seq`, the previous record's hash, and its own
HMAC-SHA256 hash over both. Edit, delete or reorder a record and `verify_lines` reports
the first bad line. WITHOUT the key an attacker cannot recompute valid hashes.
Limits: deleting the END of the log cannot be detected from the file alone; store the
latest `head()` (seq + hash) somewhere else (another system) to catch truncation.
If a write fails after the line was actually written, the next record repeats a sequence
number and verification flags it: noisy, but the safe direction.

Failure: when the sink fails and `audit_failure_mode` is "closed" (production default),
the caller must not proceed (the SDK turns the result into a block). Fail-open is
only allowed outside production and the result is marked `degraded`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from guardrails.decisions import Decision, Finding, new_request_id
from guardrails.errors import ConfigurationError, GuardrailError
from guardrails.settings import Settings
from guardrails.types import Action, Confidence, ReasonCode, Severity, Stage

GENESIS = "0" * 64
MAX_LINE_BYTES = 32_768
MAX_FINDINGS = 50
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,64}$")


class AuditUnavailable(GuardrailError):
    code = ReasonCode.AUDIT_UNAVAILABLE
    default_public_message = "audit log unavailable"


class AuditFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    detector_id: str
    reason_code: ReasonCode
    severity: Severity
    category: str | None = None
    confidence: Confidence | None = None


class AuditEvent(BaseModel):
    """One record. Note what is missing: any text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Field(ge=1)
    ts: str
    prev: str = Field(min_length=64, max_length=64)
    event_type: str = Field(pattern=r"^[a-z_]{1,32}$")
    event_id: str
    request_id: str | None = None
    tenant_id: str | None = None
    actor: str | None = None               # keyed pseudonym of the user id
    stage: Stage | None = None
    action: Action | None = None
    reason_code: ReasonCode | None = None
    severity: Severity | None = None
    policy_id: str | None = None
    policy_version: int | None = None
    findings: tuple[AuditFinding, ...] = ()
    findings_total: int = 0
    tool: str | None = None
    args_fingerprint: str | None = None    # keyed hash, not the plain one
    approver: str | None = None            # keyed pseudonym
    content_chars: int | None = None
    redactions: int | None = None
    degraded: bool = False
    hash: str = ""


def _clean_id(v: str | None) -> str | None:
    """Client-supplied ids are untrusted: keep only well-formed ones, otherwise store a marker."""
    if v is None:
        return None
    return v if isinstance(v, str) and _SAFE_ID.match(v) else "invalid-id"


class AuditSink(Protocol):
    def write(self, line: str) -> None: ...


class MemorySink:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.fail = False

    def write(self, line: str) -> None:
        if self.fail:
            raise OSError("sink down")
        self.lines.append(line)

    def healthy(self) -> bool:
        return not self.fail


class JsonlFileSink:
    """Append-only JSON-lines file, flushed to disk on every write by default.

    On Linux/macOS the file is created with mode 0600 (owner only). Windows ignores POSIX
    modes, so there the file inherits its folder's permissions: put the log in a folder
    whose ACL only the service account can read and write.
    `permissions_enforced` is False on Windows.
    """

    permissions_enforced = os.name != "nt"

    def __init__(self, path: str, *, fsync: bool = True) -> None:
        self.path, self._fsync, self._lock = path, fsync, threading.Lock()
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.close(fd)

    def write(self, line: str) -> None:
        data = (line + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, data)
                if self._fsync:
                    os.fsync(fd)
            finally:
                os.close(fd)

    def healthy(self) -> bool:
        """Can the file be opened for appending right now? Writes nothing. (A full disk is NOT detected here.)"""
        try:
            os.close(os.open(self.path, os.O_WRONLY | os.O_APPEND))
            return True
        except OSError:
            return False

    def last_line(self) -> str | None:
        with open(self.path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - MAX_LINE_BYTES - 2))
            tail = f.read().decode("utf-8", "replace").rstrip("\n")
        return tail.rsplit("\n", 1)[-1] if tail else None


def _canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _chain_hash(key: bytes, body: dict[str, Any]) -> str:
    """HMAC over the whole record body. The body contains `prev`, so each hash covers the one before it."""
    return hmac.new(key, b"chain:" + _canonical(body), hashlib.sha256).hexdigest()


class AuditLogger:
    def __init__(self, sink: AuditSink, key: bytes, settings: Settings | None = None, *,
                 clock: Callable[[], float] = time.time) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ConfigurationError("audit key must be at least 32 bytes")
        self._sink, self._key, self.settings, self._clock = sink, bytes(key), settings or Settings(), clock
        self._lock = threading.Lock()
        self._seq, self._prev = 0, GENESIS
        last = sink.last_line() if hasattr(sink, "last_line") else None
        if last:
            try:
                rec = json.loads(last)
                h = rec.pop("hash")
                if not hmac.compare_digest(h, _chain_hash(self._key, rec)):
                    raise ValueError
                self._seq, self._prev = int(rec["seq"]), h
            except Exception:  # noqa: BLE001
                raise ConfigurationError("existing audit file does not end in a valid record for this key; "
                                         "rotate or verify it before starting") from None

    # ---- pseudonyms
    def _mac(self, domain: str, value: str, n: int = 24) -> str:
        return hmac.new(self._key, f"{domain}:{value}".encode(), hashlib.sha256).hexdigest()[:n]

    def pseudonym(self, user_id: str | None) -> str | None:
        return None if user_id is None else self._mac("actor", user_id, 16)

    def healthy(self) -> bool:
        """Readiness probe: asks the sink without writing a record. Never raises."""
        try:
            probe = getattr(self._sink, "healthy", None)
            return True if probe is None else bool(probe())
        except Exception:  # noqa: BLE001
            return False

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the newest record. Store it elsewhere to detect truncation."""
        with self._lock:
            return self._seq, self._prev

    # ---- core
    def record(self, event_type: str, **fields: Any) -> AuditEvent:
        with self._lock:
            seq = self._seq + 1
            ev = AuditEvent(seq=seq, ts=datetime.fromtimestamp(self._clock(), timezone.utc).isoformat(timespec="milliseconds"),
                            prev=self._prev, event_type=event_type, event_id=new_request_id(), **fields)
            body = ev.model_dump(mode="json", exclude={"hash"})
            h = _chain_hash(self._key, body)
            line = json.dumps({**body, "hash": h}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise AuditUnavailable(internal_detail="record too large")
            try:
                self._sink.write(line)
            except Exception:  # noqa: BLE001
                raise AuditUnavailable(internal_detail="sink write failed") from None
            self._seq, self._prev = seq, h  # advance only after a successful write
            return ev.model_copy(update={"hash": h})

    # ---- typed helpers (build from decisions only)
    @staticmethod
    def _summ(findings: Sequence[Finding]) -> tuple[tuple[AuditFinding, ...], int]:
        items = tuple(AuditFinding(detector_id=f.detector_id, reason_code=f.reason_code, severity=f.severity,
                                   category=f.category, confidence=f.confidence) for f in findings[:MAX_FINDINGS])
        return items, len(findings)

    def record_decision(self, event_type: str, d: Decision, *, tenant_id: str | None = None, user_id: str | None = None,
                        content_chars: int | None = None, redactions: int | None = None, degraded: bool = False,
                        tool: str | None = None, fingerprint: str | None = None) -> AuditEvent:
        items, total = self._summ(d.findings)
        return self.record(
            event_type, request_id=_clean_id(d.request_id), tenant_id=_clean_id(tenant_id), actor=self.pseudonym(user_id),
            stage=d.stage, action=d.action, reason_code=d.reason_code, severity=d.severity, policy_id=d.policy_id,
            policy_version=d.policy_version, findings=items, findings_total=total, tool=tool,
            args_fingerprint=self._mac("args", fingerprint, 32) if fingerprint else None,
            content_chars=content_chars, redactions=redactions, degraded=degraded)

    def record_approval(self, tool: str, fingerprint: str, tenant_id: str, requester: str, approver: str) -> AuditEvent:
        return self.record("approval_issued", tenant_id=_clean_id(tenant_id), actor=self.pseudonym(requester),
                           approver=self.pseudonym(approver), tool=tool, args_fingerprint=self._mac("args", fingerprint, 32))


# ---------------------------------------------------------------------------- verification
@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    bad_line: int | None = None      # 1-based
    reason: str | None = None


def verify_lines(lines: Iterable[str], key: bytes, *, start_prev: str = GENESIS, start_seq: int = 0) -> VerifyResult:
    prev, seq, n = start_prev, start_seq, 0
    for n, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        if not line:
            continue
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            return VerifyResult(False, n - 1, n, "line too long")
        try:
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec.get("seq") != seq + 1:
                return VerifyResult(False, n - 1, n, "sequence gap, repeat or reorder")
            if rec.get("prev") != prev:
                return VerifyResult(False, n - 1, n, "previous-hash mismatch")
            if not hmac.compare_digest(str(h), _chain_hash(key, rec)):
                return VerifyResult(False, n - 1, n, "hash mismatch (record altered or wrong key)")
        except Exception:  # noqa: BLE001
            return VerifyResult(False, n - 1, n, "unreadable record")
        prev, seq = h, seq + 1
    return VerifyResult(True, seq - start_seq)


def verify_file(path: str, key: bytes) -> VerifyResult:
    with open(path, encoding="utf-8") as f:
        return verify_lines(f, key)


def _main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "verify":
        print("usage: python -m guardrails.audit_cli verify FILE   (key from env GR_AUDIT_KEY)")
        return 2
    key = os.environ.get("GR_AUDIT_KEY", "").encode()
    if len(key) < 32:
        print("set GR_AUDIT_KEY (at least 32 characters)")
        return 2
    r = verify_file(argv[2], key)
    print(f"OK: {r.records} records" if r.ok else f"TAMPERED or invalid at line {r.bad_line}: {r.reason}")
    return 0 if r.ok else 1

