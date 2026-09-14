#!/usr/bin/env python3
"""macctl Transaction / Idempotency V2 primitives.

The module is intentionally stdlib-only and independent of live SSH state so
its persistence/replay rules can be tested on GitHub runners.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import fcntl
import hashlib
import json
import os
import re
import tempfile
import time
from typing import Any

TX_SCHEMA_VERSION = "macctl-transaction/v1"

PREPARED = "PREPARED"
DISPATCHED = "DISPATCHED"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
PRECONDITION_FAILED = "PRECONDITION_FAILED"
POSTCONDITION_FAILED = "POSTCONDITION_FAILED"
INDETERMINATE = "INDETERMINATE"

TERMINAL_STATES = {COMPLETED, FAILED, PRECONDITION_FAILED, POSTCONDITION_FAILED}

_REQUEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# Payload-bearing argument names are represented by a digest in operation IDs.
# This avoids writing command bodies, GUI text or AppleScript bodies into the
# transaction journal while still detecting request-id reuse for another intent.
_SENSITIVE_ARG_KEYS = {
    "command",
    "code",
    "text",
    "password",
    "token",
    "secret",
    "content",
}

# Transport/output tuning is deliberately excluded from operation identity.
# A caller may retry the same business operation with a larger timeout or
# output cap without turning the same request_id into a false conflict.
_NON_SEMANTIC_ARG_KEYS = {"fn", "request_id", "timeout", "max_bytes", "json"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def validate_request_id(request_id: str) -> str:
    value = str(request_id or "").strip()
    if not _REQUEST_RE.fullmatch(value):
        raise ValueError("request_id must match [A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}")
    return value


def validate_sha256(value: str) -> str:
    out = str(value or "").strip().lower()
    if not _HEX64_RE.fullmatch(out):
        raise ValueError("expected SHA-256 must be exactly 64 lowercase/uppercase hex characters")
    return out


def validate_remote_path(value: str) -> str:
    """Validate a remote path as data, without imposing an artificial sandbox.

    macctl intentionally supports arbitrary user-authorized Mac paths, including
    spaces and shell metacharacters. Empty strings and NUL bytes are rejected;
    command construction must still quote the returned path as one shell word.
    """
    path = str(value if value is not None else "")
    if not path:
        raise ValueError("remote path is empty")
    if "\x00" in path:
        raise ValueError("remote path contains NUL byte")
    return path


def parse_expected_sha256_spec(spec: str) -> tuple[str, str]:
    if "=" not in str(spec):
        raise ValueError("--expect-sha256 requires REMOTE_PATH=SHA256")
    path, digest = str(spec).rsplit("=", 1)
    return validate_remote_path(path), validate_sha256(digest)


def _digest_text(value: Any) -> str:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, (list, tuple)):
        raw = "\0".join(str(x) for x in value).encode("utf-8", "surrogatepass")
    else:
        raw = str(value).encode("utf-8", "surrogatepass")
    return hashlib.sha256(raw).hexdigest()


def _canonical_value(key: str, value: Any) -> Any:
    if key.startswith("_") or key in _NON_SEMANTIC_ARG_KEYS:
        return None
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if key.casefold() in _SENSITIVE_ARG_KEYS:
        return {"sha256": _digest_text(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_canonical_value("item", v) for v in value]
    if isinstance(value, dict):
        return {
            str(k): _canonical_value(str(k), v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            if _canonical_value(str(k), v) is not None
        }
    return str(value)


def build_operation_id(family: str, action: str | None, risk_class: str, attrs: dict[str, Any] | None = None) -> str:
    attrs = dict(attrs or {})
    clean: dict[str, Any] = {}
    for key in sorted(attrs):
        value = _canonical_value(str(key), attrs[key])
        if value is not None:
            clean[str(key)] = value
    payload = {
        "schema": TX_SCHEMA_VERSION,
        "family": str(family or ""),
        "action": None if action is None else str(action),
        "risk_class": str(risk_class or ""),
        "attrs": clean,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "op-" + hashlib.sha256(raw).hexdigest()[:32]


@dataclass(frozen=True)
class BeginResult:
    disposition: str
    record: dict[str, Any]


class TransactionStore:
    """Small append-by-replacement JSON transaction journal.

    One file is kept per request_id. A global advisory lock serializes record
    transitions. Writes are fsync + os.replace so a torn JSON file is not
    exposed as the latest state.
    """

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root)
        self.lock_path = self.root / ".lock"

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _record_path(self, request_id: str) -> Path:
        rid = validate_request_id(request_id)
        name = hashlib.sha256(rid.encode("utf-8")).hexdigest() + ".json"
        return self.root / name

    def _locked(self):
        self._ensure_root()
        fh = self.lock_path.open("a+")
        try:
            os.chmod(self.lock_path, 0o600)
        except OSError:
            pass
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        return fh

    def _read_unlocked(self, request_id: str) -> dict[str, Any] | None:
        path = self._record_path(request_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_unlocked(self, record: dict[str, Any]) -> dict[str, Any]:
        path = self._record_path(record["request_id"])
        self._ensure_root()
        fd, tmp_name = tempfile.mkstemp(prefix=".tx-", suffix=".json", dir=str(self.root))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                fh.write("\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
            try:
                dfd = os.open(self.root, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
        return record

    def get(self, request_id: str) -> dict[str, Any] | None:
        with self._locked():
            return self._read_unlocked(request_id)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        self._ensure_root()
        out: list[dict[str, Any]] = []
        with self._locked():
            for path in sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
                try:
                    out.append(json.loads(path.read_text(encoding="utf-8")))
                except Exception:
                    continue
                if len(out) >= max(1, int(limit)):
                    break
        return out

    def begin(
        self,
        request_id: str,
        operation_id: str,
        *,
        family: str,
        action: str | None,
        risk_class: str,
        policy_reason: str,
        target: str | None = None,
    ) -> BeginResult:
        rid = validate_request_id(request_id)
        with self._locked():
            existing = self._read_unlocked(rid)
            if existing is not None:
                existing_target = existing.get("target")
                if target is not None and existing_target is not None and existing_target != target:
                    return BeginResult("TARGET_CONFLICT", existing)
                if existing.get("operation_id") != operation_id:
                    return BeginResult("CONFLICT", existing)
                status = existing.get("status")
                if status == COMPLETED:
                    return BeginResult("ALREADY_COMPLETED", existing)
                if status == PREPARED:
                    existing["attempts"] = int(existing.get("attempts", 1)) + 1
                    existing["updated_at"] = utc_now()
                    self._write_unlocked(existing)
                    return BeginResult("RESUME_PREPARED", existing)
                if status in {DISPATCHED, INDETERMINATE}:
                    return BeginResult("INDETERMINATE", existing)
                if status in TERMINAL_STATES:
                    return BeginResult("ALREADY_TERMINAL", existing)
                return BeginResult("INDETERMINATE", existing)

            now = utc_now()
            record = {
                "schema": TX_SCHEMA_VERSION,
                "request_id": rid,
                "operation_id": operation_id,
                "family": family,
                "action": action,
                "risk_class": risk_class,
                "policy_reason": policy_reason,
                "target": target,
                "status": PREPARED,
                "attempts": 1,
                "created_at": now,
                "updated_at": now,
                "precondition": None,
                "postcondition": None,
                "result": None,
            }
            self._write_unlocked(record)
            return BeginResult("NEW", record)

    def _transition(self, request_id: str, operation_id: str, status: str, **fields: Any) -> dict[str, Any]:
        with self._locked():
            record = self._read_unlocked(request_id)
            if record is None:
                raise KeyError("transaction not found")
            if record.get("operation_id") != operation_id:
                raise ValueError("operation_id mismatch")
            record["status"] = status
            record["updated_at"] = utc_now()
            record.update(fields)
            return self._write_unlocked(record)

    def set_precondition(self, request_id: str, operation_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return self._transition(request_id, operation_id, PREPARED, precondition=evidence)

    def mark_dispatched(self, request_id: str, operation_id: str) -> dict[str, Any]:
        return self._transition(request_id, operation_id, DISPATCHED, dispatched_at=utc_now())

    def mark_completed(self, request_id: str, operation_id: str, *, postcondition: dict[str, Any], rc: int = 0) -> dict[str, Any]:
        return self._transition(
            request_id,
            operation_id,
            COMPLETED,
            postcondition=postcondition,
            result={"rc": int(rc)},
            completed_at=utc_now(),
        )

    def mark_failed(self, request_id: str, operation_id: str, *, rc: int, error_class: str = "COMMAND_FAILED") -> dict[str, Any]:
        return self._transition(
            request_id,
            operation_id,
            FAILED,
            result={"rc": int(rc), "error_class": error_class},
            completed_at=utc_now(),
        )

    def mark_precondition_failed(self, request_id: str, operation_id: str, *, evidence: dict[str, Any], rc: int = 76) -> dict[str, Any]:
        return self._transition(
            request_id,
            operation_id,
            PRECONDITION_FAILED,
            precondition=evidence,
            result={"rc": int(rc), "error_class": "PRECONDITION_FAILED"},
            completed_at=utc_now(),
        )

    def mark_postcondition_failed(self, request_id: str, operation_id: str, *, evidence: dict[str, Any], rc: int = 74) -> dict[str, Any]:
        return self._transition(
            request_id,
            operation_id,
            POSTCONDITION_FAILED,
            postcondition=evidence,
            result={"rc": int(rc), "error_class": "POSTCONDITION_FAILED"},
            completed_at=utc_now(),
        )

    def mark_indeterminate(self, request_id: str, operation_id: str, *, reason: str) -> dict[str, Any]:
        return self._transition(
            request_id,
            operation_id,
            INDETERMINATE,
            result={"rc": 75, "error_class": "INDETERMINATE", "reason": reason},
        )
