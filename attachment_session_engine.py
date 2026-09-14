#!/usr/bin/env python3
"""Durable delivery-session state for MacCtl attachment delivery.

This module closes the project-owned control plane between immutable Artifact
Core bytes and a future/qualified ChatGPT host adapter. It deliberately does
not fabricate ChatGPT file IDs or claim host materialization that was not
observed.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from artifact_engine import ArtifactError, ArtifactStore
from attachment_delivery_engine import GRADE_A
from attachment_gateway import AttachmentGateway

SESSION_SCHEMA_VERSION = "macctl-attachment-session/v1"
SESSION_ID_RE = re.compile(r"^dlv_[A-Za-z0-9_-]{24,96}$")
PROJECT_READY = "PROJECT_READY"
ADAPTER_SELECTED = "ADAPTER_SELECTED"
HOST_ACCEPTED = "HOST_ACCEPTED"
HOST_RENDER_QUALIFIED = "HOST_RENDER_QUALIFIED"
USER_VISIBLE_CONFIRMED = "USER_VISIBLE_CONFIRMED"
FAILED = "FAILED"

_TERMINAL = {USER_VISIBLE_CONFIRMED, FAILED}


class DeliverySessionError(RuntimeError):
    def __init__(self, reason: str, detail: str | None = None):
        self.reason = reason
        self.detail = detail
        super().__init__(reason if not detail else f"{reason}: {detail}")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bounded_text(value: str, *, field: str, minimum: int = 1, maximum: int = 512) -> str:
    text = str(value or "").strip()
    if len(text) < minimum or len(text) > maximum or any(ord(ch) < 32 for ch in text):
        raise DeliverySessionError(f"invalid_{field}")
    return text


class AttachmentSessionStore:
    """Atomic, idempotent delivery evidence store.

    The store records only control-plane metadata and cryptographic hashes. It
    never stores artifact bytes, grant tokens, OAuth tokens, URLs with secrets,
    or arbitrary filesystem paths.
    """

    def __init__(
        self,
        root: str | os.PathLike,
        *,
        artifact_store: ArtifactStore,
        gateway: AttachmentGateway | None = None,
        now_fn=_utc_now,
        adapters=None,
    ):
        self.root = Path(root).resolve()
        self.sessions_dir = self.root / "sessions"
        self.idempotency_dir = self.root / "idempotency"
        self.lock_path = self.root / ".lock"
        self.artifact_store = artifact_store
        self.gateway = gateway or AttachmentGateway(artifact_store)
        self.now_fn = now_fn
        self.adapters = adapters
        for path in (self.root, self.sessions_dir, self.idempotency_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                os.chmod(path, 0o700)
            except PermissionError:
                pass
        fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)

    def _new_id(self) -> str:
        return "dlv_" + secrets.token_urlsafe(24)

    def _validate_id(self, session_id: str) -> str:
        value = str(session_id or "")
        if not SESSION_ID_RE.fullmatch(value):
            raise DeliverySessionError("invalid_delivery_session_id")
        return value

    def _path(self, session_id: str) -> Path:
        return self.sessions_dir / f"{self._validate_id(session_id)}.json"

    def _lock(self):
        fd = os.open(self.lock_path, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _unlock(self, fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _write_json_atomic(self, path: Path, obj: dict) -> None:
        tmp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            data = _canonical(obj)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def _load(self, session_id: str) -> dict:
        path = self._path(session_id)
        if path.is_symlink():
            raise DeliverySessionError("delivery_session_symlink_denied")
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise DeliverySessionError("delivery_session_not_found")
        except (OSError, json.JSONDecodeError) as exc:
            raise DeliverySessionError("delivery_session_invalid", type(exc).__name__)
        if obj.get("schema") != SESSION_SCHEMA_VERSION or obj.get("session_id") != session_id:
            raise DeliverySessionError("delivery_session_invalid")
        return obj

    def _append_event(self, record: dict, state: str, event: str, detail: dict | None = None) -> None:
        now = _iso(self.now_fn())
        record["state"] = state
        record["updated_at"] = now
        row = {"at": now, "state": state, "event": event}
        if detail:
            row["detail"] = detail
        record.setdefault("history", []).append(row)

    def create(
        self,
        artifact_id: str,
        *,
        principal: str,
        idempotency_key: str,
        presentation: str = "both",
        original_required: bool = True,
        allow_debug_fallback: bool = False,
    ) -> dict:
        principal = _bounded_text(principal, field="principal", maximum=256)
        idem = _bounded_text(idempotency_key, field="idempotency_key", minimum=8, maximum=256)
        presentation = str(presentation or "both").lower()
        if presentation not in {"auto", "inline", "attachment", "both"}:
            raise DeliverySessionError("invalid_presentation")

        binding = {
            "artifact_id": str(artifact_id),
            "principal": principal,
            "presentation": presentation,
            "original_required": bool(original_required),
            "allow_debug_fallback": bool(allow_debug_fallback),
        }
        binding_sha = hashlib.sha256(_canonical(binding)).hexdigest()
        idem_sha = _sha256_text(idem)
        index_path = self.idempotency_dir / f"{idem_sha}.json"

        lock_fd = self._lock()
        try:
            if index_path.is_symlink():
                raise DeliverySessionError("idempotency_index_symlink_denied")
            if index_path.exists():
                try:
                    index = json.loads(index_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise DeliverySessionError("idempotency_index_invalid", type(exc).__name__)
                if index.get("schema") != "macctl-attachment-idempotency/v1":
                    raise DeliverySessionError("idempotency_index_invalid")
                if not SESSION_ID_RE.fullmatch(str(index.get("session_id", ""))):
                    raise DeliverySessionError("idempotency_index_invalid")
                if index.get("binding_sha256") != binding_sha:
                    raise DeliverySessionError("idempotency_key_conflict")
                record = self._load(str(index.get("session_id", "")))
                result = dict(record)
                result["idempotent_replay"] = True
                return result

            try:
                prepared = self.gateway.prepare(
                    artifact_id,
                    principal=principal,
                    presentation=presentation,
                    original_required=bool(original_required),
                    allow_debug_fallback=bool(allow_debug_fallback),
                    adapters=self.adapters,
                )
            except ArtifactError:
                raise
            except ValueError as exc:
                raise DeliverySessionError(str(exc))

            content = prepared["content"]
            session_id = self._new_id()
            now = _iso(self.now_fn())
            plan = dict(prepared["delivery_plan"])
            selected = plan.get("selected_adapter")
            state = ADAPTER_SELECTED if plan.get("status") == "READY" and selected else PROJECT_READY
            record = {
                "schema": SESSION_SCHEMA_VERSION,
                "session_id": session_id,
                "correlation_id": session_id,
                "state": state,
                "created_at": now,
                "updated_at": now,
                "artifact": {
                    "artifact_id": artifact_id,
                    "sha256": content["sha256"],
                    "size_bytes": int(content["size_bytes"]),
                    "mime_type": content["mime_type"],
                    "filename": content["filename"],
                },
                "request": {
                    "principal": principal,
                    "presentation_requested": presentation,
                    "presentation_effective": prepared["presentation"]["effective"],
                    "original_required": bool(original_required),
                    "idempotency_key_sha256": idem_sha,
                    "binding_sha256": binding_sha,
                },
                "project_owned": {
                    "artifact_authorized": True,
                    "exact_original_verified": bool(prepared["exact_original_verified"]),
                    "arbitrary_path_exposed": False,
                    "project_delivery_plane_ready": True,
                },
                "adapter": {
                    "selected": selected,
                    "plan_status": plan.get("status"),
                    "success_grade": plan.get("success_grade"),
                    "debug_fallback": bool(selected == "PRIVATE_GITHUB_ACTIONS_ARTIFACT"),
                },
                "external_gate": None if selected else {
                    "state": "WAITING",
                    "gate": "EXTERNAL_HOST_ADAPTER_GATE",
                    "reason": "no_production_grade_a_host_adapter_qualified",
                },
                "host_receipt": None,
                "render_qualification": None,
                "user_confirmation": None,
                "history": [
                    {"at": now, "state": "REQUESTED", "event": "delivery_requested"},
                    {"at": now, "state": "AUTHORIZED", "event": "artifact_authorized"},
                    {"at": now, "state": "PROJECT_READY", "event": "exact_bytes_verified"},
                ],
            }
            if state == ADAPTER_SELECTED:
                record["history"].append({
                    "at": now,
                    "state": ADAPTER_SELECTED,
                    "event": "adapter_selected",
                    "detail": {"adapter": selected, "grade": plan.get("success_grade")},
                })
            self._write_json_atomic(self._path(session_id), record)
            self._write_json_atomic(index_path, {
                "schema": "macctl-attachment-idempotency/v1",
                "session_id": session_id,
                "binding_sha256": binding_sha,
            })
            result = dict(record)
            result["idempotent_replay"] = False
            return result
        finally:
            self._unlock(lock_fd)

    def inspect(self, session_id: str) -> dict:
        return self._load(session_id)

    def list(self, *, limit: int = 50) -> list[dict]:
        rows: list[dict] = []
        for path in self.sessions_dir.glob("dlv_*.json"):
            if path.is_symlink():
                continue
            try:
                obj = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if obj.get("schema") == SESSION_SCHEMA_VERSION and SESSION_ID_RE.fullmatch(str(obj.get("session_id", ""))):
                rows.append(obj)
        rows.sort(key=lambda row: row.get("created_at", ""), reverse=True)
        return rows[: max(1, min(int(limit), 500))]

    def record_host_acceptance(
        self,
        session_id: str,
        *,
        adapter: str,
        receipt_id: str,
        sha256: str,
        size_bytes: int,
    ) -> dict:
        adapter = _bounded_text(adapter, field="adapter", maximum=128)
        receipt_id = _bounded_text(receipt_id, field="receipt_id", maximum=512)
        lock_fd = self._lock()
        try:
            record = self._load(session_id)
            if record["state"] in _TERMINAL:
                raise DeliverySessionError("delivery_session_terminal")
            if record["state"] != ADAPTER_SELECTED:
                raise DeliverySessionError("adapter_not_selected")
            if record["adapter"].get("selected") != adapter:
                raise DeliverySessionError("adapter_mismatch")
            expected = record["artifact"]
            if str(sha256) != expected["sha256"] or int(size_bytes) != int(expected["size_bytes"]):
                raise DeliverySessionError("host_receipt_byte_mismatch")
            record["host_receipt"] = {
                "adapter": adapter,
                "receipt_id_sha256": _sha256_text(receipt_id),
                "sha256": expected["sha256"],
                "size_bytes": int(expected["size_bytes"]),
            }
            self._append_event(record, HOST_ACCEPTED, "host_accepted_exact_bytes", {"adapter": adapter})
            self._write_json_atomic(self._path(session_id), record)
            return record
        finally:
            self._unlock(lock_fd)

    def qualify_render(
        self,
        session_id: str,
        *,
        surface: str,
        native_attachment: bool,
        exact_original: bool,
        downloaded_sha256: str,
        inline_visible: bool = False,
    ) -> dict:
        surface = _bounded_text(surface, field="surface", maximum=256)
        lock_fd = self._lock()
        try:
            record = self._load(session_id)
            if record["state"] != HOST_ACCEPTED:
                raise DeliverySessionError("host_acceptance_required")
            expected_sha = record["artifact"]["sha256"]
            if not native_attachment or not exact_original or str(downloaded_sha256) != expected_sha:
                raise DeliverySessionError("host_render_not_grade_a")
            effective_presentation = record.get("request", {}).get("presentation_effective")
            if effective_presentation in {"inline", "both"} and not inline_visible:
                raise DeliverySessionError("inline_presentation_not_observed")
            record["render_qualification"] = {
                "surface": surface,
                "grade": GRADE_A,
                "native_attachment": True,
                "exact_original": True,
                "downloaded_sha256": expected_sha,
                "inline_visible": bool(inline_visible),
            }
            self._append_event(record, HOST_RENDER_QUALIFIED, "host_render_grade_a_qualified", {
                "surface": surface,
                "inline_visible": bool(inline_visible),
            })
            self._write_json_atomic(self._path(session_id), record)
            return record
        finally:
            self._unlock(lock_fd)

    def confirm_user_visible(self, session_id: str, *, confirmed_by: str) -> dict:
        confirmed_by = _bounded_text(confirmed_by, field="confirmed_by", maximum=256)
        lock_fd = self._lock()
        try:
            record = self._load(session_id)
            if record["state"] != HOST_RENDER_QUALIFIED:
                raise DeliverySessionError("host_render_qualification_required")
            record["user_confirmation"] = {
                "confirmed_by": confirmed_by,
                "confirmed_at": _iso(self.now_fn()),
            }
            self._append_event(record, USER_VISIBLE_CONFIRMED, "user_visible_confirmed")
            self._write_json_atomic(self._path(session_id), record)
            return record
        finally:
            self._unlock(lock_fd)

    def fail(self, session_id: str, *, reason: str) -> dict:
        reason = _bounded_text(reason, field="failure_reason", maximum=512)
        lock_fd = self._lock()
        try:
            record = self._load(session_id)
            if record["state"] == USER_VISIBLE_CONFIRMED:
                raise DeliverySessionError("delivery_session_terminal")
            if record["state"] != FAILED:
                record["failure"] = {"reason": reason, "at": _iso(self.now_fn())}
                self._append_event(record, FAILED, "delivery_failed", {"reason": reason})
                self._write_json_atomic(self._path(session_id), record)
            return record
        finally:
            self._unlock(lock_fd)

    def capabilities(self) -> dict:
        return {
            "schema": "macctl-attachment-session-capabilities/v1",
            "durable_delivery_sessions": True,
            "idempotency_binding": True,
            "correlation_identity": "session_id",
            "atomic_state_persistence": True,
            "exact_byte_host_receipt_required": True,
            "grade_a_render_qualification_required": True,
            "user_visible_confirmation_separate": True,
            "external_host_adapter_gate_explicit": True,
            "fabricated_chatgpt_file_id": False,
        }
