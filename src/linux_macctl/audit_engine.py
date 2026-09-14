#!/usr/bin/env python3
"""Pure audit/traceability primitives for macctl.

The audit contract deliberately stores only bounded metadata and summarized
verification evidence. Command bodies, GUI text, passwords, tokens, file
contents and other payload-bearing arguments are excluded by construction.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
import fcntl
from pathlib import Path
from typing import Any

AUDIT_SCHEMA_VERSION = "macctl-audit/v2"
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _get(attrs: Any, name: str, default=None):
    if isinstance(attrs, dict):
        return attrs.get(name, default)
    return getattr(attrs, name, default)


def validate_correlation_id(value: str) -> str:
    out = str(value or "").strip()
    if not _CORRELATION_RE.fullmatch(out):
        raise ValueError("correlation_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
    return out


def new_correlation_id() -> str:
    return "corr-" + uuid.uuid4().hex


def resolve_correlation_id(explicit: str | None = None, env_value: str | None = None) -> tuple[str, str]:
    if explicit:
        return validate_correlation_id(explicit), "cli"
    if env_value:
        return validate_correlation_id(env_value), "env"
    return new_correlation_id(), "generated"


def approval_evidence(attrs: Any) -> dict:
    required = bool(_get(attrs, "_policy_requires_confirmation", False))
    provided = bool(_get(attrs, "confirm", False)) if required else False
    if required:
        source = "--confirm" if provided else "missing"
    else:
        source = "not_required"
    return {
        "required": required,
        "provided": provided,
        "source": source,
    }


def summarize_precondition(evidence: Any) -> dict | None:
    if not isinstance(evidence, dict):
        return None
    explicit = evidence.get("explicit") if isinstance(evidence.get("explicit"), dict) else {}
    automatic = evidence.get("automatic") if isinstance(evidence.get("automatic"), dict) else {}
    checks = explicit.get("checks") if isinstance(explicit.get("checks"), list) else []
    return {
        "status": evidence.get("status"),
        "explicit_status": explicit.get("status"),
        "explicit_check_count": len(checks),
        "automatic_mode": automatic.get("mode"),
    }


def summarize_postcondition(evidence: Any) -> dict | None:
    if not isinstance(evidence, dict):
        return None
    return {
        "status": evidence.get("status"),
        "mode": evidence.get("mode"),
        "verified": bool(evidence.get("verified", False)),
    }


def classify_error(rc: int, attrs: Any) -> str:
    rc = int(rc)
    tx_status = str(_get(attrs, "_transaction_status", "") or "")
    policy_allowed = _get(attrs, "_policy_allowed", None)
    if rc == 0:
        return "SUCCESS"
    if policy_allowed is False or rc == 77:
        return "POLICY_BLOCKED"
    if tx_status == "PRECONDITION_FAILED" or rc == 76:
        return "PRECONDITION_FAILED"
    if tx_status == "POSTCONDITION_FAILED" or rc == 74:
        return "POSTCONDITION_FAILED"
    if tx_status in {"INDETERMINATE", "COMPLETED_STATE_DRIFT"} or rc == 75:
        return "INDETERMINATE"
    if rc == 78:
        return "REQUEST_CONFLICT"
    if rc == 124:
        return "TIMEOUT"
    if rc == 64:
        return "USAGE_ERROR"
    if rc == 73:
        return "TRANSACTION_JOURNAL_ERROR"
    if rc == 70:
        return "INTERNAL_ERROR"
    return "COMMAND_FAILED"


def build_audit_record(
    attrs: Any,
    rc: int,
    duration_ms: float,
    *,
    version: str,
    target: str,
    ts_utc: str | None = None,
) -> dict:
    return {
        "schema": AUDIT_SCHEMA_VERSION,
        "ts_utc": ts_utc or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": str(version),
        "target": str(target),
        "correlation_id": _get(attrs, "_correlation_id"),
        "correlation_source": _get(attrs, "_correlation_source"),
        "cmd": _get(attrs, "cmd"),
        "action": _get(attrs, "action"),
        "sudo": bool(_get(attrs, "sudo", False)),
        "risk_class": _get(attrs, "_policy_risk_class"),
        "policy_allowed": _get(attrs, "_policy_allowed"),
        "policy_reason": _get(attrs, "_policy_reason"),
        "policy_source": _get(attrs, "_policy_source"),
        "approval": approval_evidence(attrs),
        "request_id": _get(attrs, "_request_id"),
        "operation_id": _get(attrs, "_operation_id"),
        "transaction_status": _get(attrs, "_transaction_status"),
        "precondition": _get(attrs, "_audit_precondition_summary"),
        "postcondition": _get(attrs, "_audit_postcondition_summary"),
        "error_class": classify_error(rc, attrs),
        "rc": int(rc),
        "duration_ms": round(float(duration_ms), 1),
    }


def _canonical_bytes(record: dict) -> bytes:
    payload = {k: v for k, v in record.items() if k not in {"record_digest", "prev_digest"}}
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_record(record: dict, previous_digest: str | None = None) -> dict:
    if previous_digest is not None and not _DIGEST_RE.fullmatch(str(previous_digest)):
        raise ValueError("previous_digest must be 64 lowercase hex characters")
    out = dict(record)
    out["prev_digest"] = previous_digest
    digest_input = (str(previous_digest or "") + "\n").encode("ascii") + _canonical_bytes(out)
    out["record_digest"] = hashlib.sha256(digest_input).hexdigest()
    return out


def verify_record_digest(record: dict) -> bool:
    digest = record.get("record_digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        return False
    prev = record.get("prev_digest")
    if prev is not None and (not isinstance(prev, str) or not _DIGEST_RE.fullmatch(prev)):
        return False
    expected = seal_record(record, previous_digest=prev).get("record_digest")
    return digest == expected


def _rotated_path(path: Path, index: int) -> Path:
    return Path(str(path) + f".{index}")


@contextmanager
def _audit_lock(path: str | Path, *, exclusive: bool):
    base = Path(path)
    base.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(str(base) + ".lock")
    with lock_path.open("a+b") as lock_file:
        try:
            os.chmod(lock_path, 0o640)
        except OSError:
            pass
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def audit_files_oldest_first(path: str | Path, retention_files: int) -> list[Path]:
    base = Path(path)
    files = []
    for index in range(max(0, int(retention_files)), 0, -1):
        candidate = _rotated_path(base, index)
        if candidate.exists():
            files.append(candidate)
    if base.exists():
        files.append(base)
    return files


def _last_digest_from_file(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    for line in reversed(lines):
        try:
            rec = json.loads(line)
        except Exception:
            continue
        digest = rec.get("record_digest")
        if isinstance(digest, str) and _DIGEST_RE.fullmatch(digest):
            return digest
    return None


def _latest_digest(path: Path, retention_files: int) -> str | None:
    current = _last_digest_from_file(path)
    if current:
        return current
    for index in range(1, max(0, int(retention_files)) + 1):
        digest = _last_digest_from_file(_rotated_path(path, index))
        if digest:
            return digest
    return None


def rotate_audit_log(path: str | Path, retention_files: int) -> None:
    base = Path(path)
    keep = max(0, int(retention_files))
    if keep == 0:
        if base.exists():
            base.unlink()
        return
    oldest = _rotated_path(base, keep)
    if oldest.exists():
        oldest.unlink()
    for index in range(keep - 1, 0, -1):
        src = _rotated_path(base, index)
        if src.exists():
            os.replace(src, _rotated_path(base, index + 1))
    if base.exists():
        os.replace(base, _rotated_path(base, 1))


def append_audit_record(
    path: str | Path,
    record: dict,
    *,
    max_bytes: int,
    retention_files: int,
    digest_seal: bool = True,
) -> dict:
    base = Path(path)
    max_bytes = max(1024, int(max_bytes))
    retention_files = max(0, int(retention_files))

    with _audit_lock(base, exclusive=True):
        previous_digest = _latest_digest(base, retention_files) if digest_seal else None
        candidate = seal_record(record, previous_digest) if digest_seal else dict(record)
        line = json.dumps(candidate, ensure_ascii=False, separators=(",", ":")) + "\n"
        encoded = line.encode("utf-8")

        if base.exists() and base.stat().st_size > 0 and base.stat().st_size + len(encoded) > max_bytes:
            rotate_audit_log(base, retention_files)
            candidate = seal_record(record, previous_digest) if digest_seal else dict(record)
            line = json.dumps(candidate, ensure_ascii=False, separators=(",", ":")) + "\n"
            encoded = line.encode("utf-8")

        with base.open("ab") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(base, 0o640)
        except OSError:
            pass
        return candidate


def read_audit_lines(path: str | Path, *, lines: int, retention_files: int) -> list[str]:
    n = max(1, int(lines))
    all_lines: list[str] = []
    with _audit_lock(path, exclusive=False):
        for file_path in audit_files_oldest_first(path, retention_files):
            try:
                all_lines.extend(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
            except Exception:
                continue
    return all_lines[-n:]


def verify_audit_chain(path: str | Path, *, retention_files: int) -> dict:
    records = 0
    sealed_records = 0
    parse_errors = 0
    digest_errors = 0
    chain_errors = 0
    previous_seen: str | None = None
    first_sealed = True

    with _audit_lock(path, exclusive=False):
        files = audit_files_oldest_first(path, retention_files)
        for file_path in files:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                parse_errors += 1
                continue
            for line in lines:
                records += 1
                try:
                    rec = json.loads(line)
                except Exception:
                    parse_errors += 1
                    continue
                digest = rec.get("record_digest")
                if not digest:
                    continue  # historical v1/unsealed records are readable but not sealed
                sealed_records += 1
                if not verify_record_digest(rec):
                    digest_errors += 1
                    continue
                prev = rec.get("prev_digest")
                if first_sealed:
                    # Retention may remove older segments, so the first retained
                    # sealed record is allowed to reference an external anchor.
                    first_sealed = False
                elif prev != previous_seen:
                    chain_errors += 1
                previous_seen = digest

    status = "PASS" if parse_errors == 0 and digest_errors == 0 and chain_errors == 0 else "FAIL"
    return {
        "status": status,
        "schema": AUDIT_SCHEMA_VERSION,
        "files": len(files),
        "records": records,
        "sealed_records": sealed_records,
        "parse_errors": parse_errors,
        "digest_errors": digest_errors,
        "chain_errors": chain_errors,
        "digest_semantics": "integrity_chain_not_authentication",
    }
