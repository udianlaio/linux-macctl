#!/usr/bin/env python3
"""Fail-closed native authenticated browser action contracts for R2 Phase 3.

This module never reads browser cookies, passwords, profiles or session tokens. It only
represents a bounded operator-authorized control envelope around visible native Chrome GUI
operations. The contract is deliberately narrower than generic GUI control:

- exact production host only; no wildcard/loopback;
- an explicit bounded authorized_action_id is mandatory;
- reversible-test scope can only touch a newly-created test object and must clean it up;
- publish/send/payment/account-security/delete-existing/credential-export are hard blocked;
- action state is private, atomic and TTL-bounded.
"""
from __future__ import annotations

import datetime as _dt
import fcntl
import ipaddress
import json
import os
import tempfile
import urllib.parse
from contextlib import contextmanager
from pathlib import Path

from browser_session_engine import (
    BrowserSessionError,
    normalize_allow_host,
    normalize_authorized_action_id,
)

NATIVE_ACTION_SCHEMA = "macctl-browser-native-action/v1"
NATIVE_PROFILE_MODE = "NATIVE_EXISTING_EXPLICIT_OPERATOR_SCOPE"
NATIVE_ACTION_INTENTS = {"read_only", "reversible_test"}
NATIVE_ACTION_RESULTS = {"verified_cleanup", "aborted_no_mutation", "cleanup_pending"}
SUPPORTED_NATIVE_BROWSERS = {
    "chrome": {"bundle_id": "com.google.Chrome", "display_name": "Google Chrome"},
    "safari": {"bundle_id": "com.apple.Safari", "display_name": "Safari"},
}
NATIVE_RECOVERY_STATES = {
    "NONE",
    "ACTIVE_VALID",
    "EXPIRED_NO_MUTATION",
    "RECONCILE_REQUIRED",
    "CLEANUP_PENDING",
}
NATIVE_ACTION_EFFECTS = {
    "observe",
    "input_plain",
    "reversible_mutation",
    "cleanup_test_object",
    "publish",
    "delete_existing",
    "send",
    "payment",
    "account_security",
    "credential_export",
    "cookie_export",
    "session_token_export",
}
HARD_FORBIDDEN_EFFECTS = {
    "publish",
    "delete_existing",
    "send",
    "payment",
    "account_security",
    "credential_export",
    "cookie_export",
    "session_token_export",
}


class NativeBrowserActionError(RuntimeError):
    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason if detail is None else f"{reason}:{detail}")
        self.reason = reason
        self.detail = detail


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso_z(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(_dt.timezone.utc)


def normalize_site_host(value: str) -> str:
    try:
        host = normalize_allow_host(value)
    except BrowserSessionError as e:
        raise NativeBrowserActionError("invalid_native_site_host", e.reason) from e
    if host.startswith("*."):
        raise NativeBrowserActionError("native_site_wildcard_forbidden")
    if host == "localhost":
        raise NativeBrowserActionError("native_site_loopback_forbidden")
    try:
        if ipaddress.ip_address(host).is_loopback:
            raise NativeBrowserActionError("native_site_loopback_forbidden")
    except ValueError:
        pass
    return host


def normalize_action_id(value: str) -> str:
    try:
        out = normalize_authorized_action_id(value)
    except BrowserSessionError as e:
        raise NativeBrowserActionError("invalid_native_action_id", e.reason) from e
    if not out:
        raise NativeBrowserActionError("native_action_id_required")
    return out


def normalize_site_path_prefix(value: str | None) -> str:
    raw = str(value or "/").strip()
    if not raw.startswith("/") or len(raw) > 512:
        raise NativeBrowserActionError("invalid_native_site_path_prefix")
    if any(ch in raw for ch in ("?", "#", "\\", "\x00", "\r", "\n", "\t")):
        raise NativeBrowserActionError("invalid_native_site_path_prefix")
    decoded = urllib.parse.unquote(raw)
    if any(part in {".", ".."} for part in decoded.split("/")):
        raise NativeBrowserActionError("native_site_path_traversal_forbidden")
    return raw


def evaluate_native_address_bar(matches, *, expected_host: str, path_prefix: str = "/") -> dict:
    """Validate Chrome's visible Accessibility address field without returning the raw URL.

    Chrome commonly hides https:// in the address bar. This proves exact displayed host/path
    scope through Accessibility; it is deliberately not described as TLS or egress proof.
    """
    host = normalize_site_host(expected_host)
    prefix = normalize_site_path_prefix(path_prefix)
    candidates = list(matches or [])
    parsed = []
    for item in candidates:
        if not isinstance(item, dict) or item.get("role") != "AXTextField":
            continue
        value = str(item.get("value") or "").strip()
        if not value or len(value) > 2048:
            continue
        displayed_scheme = None
        candidate = value
        if "://" in value:
            try:
                scheme = urllib.parse.urlsplit(value).scheme.lower()
            except Exception:
                continue
            if scheme not in {"https", "http"}:
                continue
            displayed_scheme = scheme
        else:
            candidate = "https://" + value
        try:
            url = urllib.parse.urlsplit(candidate)
            candidate_host = normalize_site_host(url.hostname or "")
            port = url.port
        except (ValueError, NativeBrowserActionError):
            continue
        if url.username or url.password:
            continue
        decoded_path = urllib.parse.unquote(url.path or "/")
        parsed.append({
            "host": candidate_host,
            "path": decoded_path,
            "displayed_scheme": displayed_scheme,
            "port": port,
        })

    exact_host = [x for x in parsed if x["host"] == host and x["port"] in (None, 443)]
    if not exact_host:
        raise NativeBrowserActionError("native_action_address_host_mismatch")
    scoped = [x for x in exact_host if x["path"].startswith(prefix)]
    if not scoped:
        raise NativeBrowserActionError("native_action_address_path_prefix_mismatch")
    if len(scoped) != 1:
        raise NativeBrowserActionError("native_action_address_field_ambiguous")
    selected = scoped[0]
    if selected["displayed_scheme"] == "http":
        raise NativeBrowserActionError("native_action_address_http_scheme_forbidden")
    return {
        "status": "PASS",
        "source": "BROWSER_ACCESSIBILITY_AXTEXTFIELD",
        "candidate_count": len(candidates),
        "url_candidate_count": len(parsed),
        "exact_host_match_count": len(exact_host),
        "path_prefix_match_count": 1,
        "site_host": host,
        "site_path_prefix": prefix,
        "displayed_scheme": selected["displayed_scheme"] or "HIDDEN_BY_CHROME_UI",
        "raw_url_returned": False,
        "network_egress_proof": False,
    }


def normalize_native_browser(value: str | None) -> dict:
    family = str(value or "chrome").strip().lower().replace("-", "_")
    if family not in SUPPORTED_NATIVE_BROWSERS:
        raise NativeBrowserActionError("unsupported_native_browser")
    meta = SUPPORTED_NATIVE_BROWSERS[family]
    return {"browser_family": family, "browser_bundle_id": meta["bundle_id"], "browser_display_name": meta["display_name"]}


def validate_native_action_plan(
    *,
    site_host: str,
    site_path_prefix: str = "/",
    authorized_action_id: str,
    browser_family: str = "chrome",
    intent: str = "reversible_test",
    resource_scope: str | None = None,
    cleanup_required: bool | None = None,
    ttl_seconds: int = 900,
) -> dict:
    host = normalize_site_host(site_host)
    path_prefix = normalize_site_path_prefix(site_path_prefix)
    action_id = normalize_action_id(authorized_action_id)
    browser = normalize_native_browser(browser_family)
    intent = str(intent or "").strip().lower().replace("-", "_")
    if intent not in NATIVE_ACTION_INTENTS:
        raise NativeBrowserActionError("invalid_native_action_intent")
    ttl = int(ttl_seconds)
    if ttl < 60 or ttl > 3600:
        raise NativeBrowserActionError("invalid_native_action_ttl")

    scope = str(resource_scope or ("none" if intent == "read_only" else "new_test_object_only")).strip().lower()
    cleanup = bool(cleanup_required) if cleanup_required is not None else intent == "reversible_test"
    if intent == "read_only":
        if scope != "none" or cleanup:
            raise NativeBrowserActionError("read_only_native_action_must_not_claim_mutation_scope")
        allowed_effects = ["observe"]
    else:
        if scope != "new_test_object_only":
            raise NativeBrowserActionError("native_reversible_test_requires_new_test_object_only")
        if not cleanup:
            raise NativeBrowserActionError("native_reversible_test_requires_cleanup")
        allowed_effects = ["observe", "input_plain", "reversible_mutation", "cleanup_test_object"]

    return {
        "schema": NATIVE_ACTION_SCHEMA,
        "site_host": host,
        "site_path_prefix": path_prefix,
        "authorized_action_id": action_id,
        "browser_family": browser["browser_family"],
        "browser_bundle_id": browser["browser_bundle_id"],
        "browser_display_name": browser["browser_display_name"],
        "intent": intent,
        "resource_scope": scope,
        "cleanup_required": cleanup,
        "ttl_seconds": ttl,
        "profile_mode": NATIVE_PROFILE_MODE,
        "allowed_effects": allowed_effects,
        "hard_forbidden_effects": sorted(HARD_FORBIDDEN_EFFECTS),
        "publish_allowed": False,
        "credential_export": "FORBIDDEN",
        "cookie_export": "FORBIDDEN",
        "session_token_export": "FORBIDDEN",
        "default_profile_cdp": "FORBIDDEN",
        "raw_runtime_evaluate": "FORBIDDEN",
    }


def build_native_action_record(plan: dict, *, now: _dt.datetime | None = None) -> dict:
    validated = validate_native_action_plan(
        site_host=plan.get("site_host"),
        site_path_prefix=plan.get("site_path_prefix", "/"),
        authorized_action_id=plan.get("authorized_action_id"),
        browser_family=plan.get("browser_family", "chrome"),
        intent=plan.get("intent"),
        resource_scope=plan.get("resource_scope"),
        cleanup_required=plan.get("cleanup_required"),
        ttl_seconds=int(plan.get("ttl_seconds", 900)),
    )
    created = now or utc_now()
    return {
        **validated,
        "status": "ACTIVE",
        "created_at": iso_z(created),
        "expires_at": iso_z(created + _dt.timedelta(seconds=validated["ttl_seconds"])),
        "event_counts": {},
        "last_event": None,
        "pending_event": None,
        "uncertain_event": None,
        "result": None,
        "cleanup_verified": False,
    }


def evaluate_native_action_effect(
    record: dict,
    effect: str,
    *,
    confirmed: bool = False,
    production_confirmed: bool = False,
    native_profile_confirmed: bool = False,
) -> dict:
    effect = str(effect or "").strip().lower()
    base = {
        "authorized_action_id": record.get("authorized_action_id"),
        "site_host": record.get("site_host"),
        "intent": record.get("intent"),
        "effect": effect,
    }
    if record.get("schema") != NATIVE_ACTION_SCHEMA:
        return {**base, "allowed": False, "reason": "native_action_state_invalid"}
    status = record.get("status")
    if status in {"RECONCILE_REQUIRED", "CLEANUP_PENDING"}:
        if effect == "observe":
            return {**base, "allowed": True, "reason": "native_action_recovery_observe_allowed"}
        if effect == "cleanup_test_object":
            allowed = bool(confirmed and production_confirmed and native_profile_confirmed)
            return {
                **base,
                "allowed": allowed,
                "reason": "native_action_recovery_cleanup_confirmation_present" if allowed else "native_action_triple_confirmation_required",
            }
        return {**base, "allowed": False, "reason": "native_action_recovery_scope_restricted"}
    if status != "ACTIVE":
        return {**base, "allowed": False, "reason": "native_action_not_active"}
    if record.get("pending_event") or record.get("uncertain_event"):
        return {**base, "allowed": False, "reason": "native_action_reconcile_required"}
    if effect not in NATIVE_ACTION_EFFECTS:
        return {**base, "allowed": False, "reason": "native_action_effect_not_exposed"}
    if effect in HARD_FORBIDDEN_EFFECTS:
        return {**base, "allowed": False, "reason": "native_action_effect_hard_forbidden"}
    if effect not in set(record.get("allowed_effects") or []):
        return {**base, "allowed": False, "reason": "native_action_effect_outside_contract"}
    if effect == "observe":
        return {**base, "allowed": True, "reason": "native_action_observe_allowed"}
    allowed = bool(confirmed and production_confirmed and native_profile_confirmed)
    return {
        **base,
        "allowed": allowed,
        "reason": "native_action_triple_confirmation_present" if allowed else "native_action_triple_confirmation_required",
    }


def record_native_action_event(record: dict, effect: str, *, status: str) -> dict:
    out = dict(record)
    counts = dict(out.get("event_counts") or {})
    counts[effect] = int(counts.get(effect, 0)) + 1
    out["event_counts"] = counts
    out["last_event"] = {
        "effect": str(effect),
        "status": str(status),
        "ts_utc": iso_z(utc_now()),
    }
    return out


def prepare_native_action_event(record: dict, effect: str, *, now: _dt.datetime | None = None) -> dict:
    """Persist write-ahead intent before a GUI mutation is attempted."""
    if record.get("schema") != NATIVE_ACTION_SCHEMA:
        raise NativeBrowserActionError("native_action_state_invalid")
    effect = str(effect or "").strip().lower()
    if effect not in {"input_plain", "reversible_mutation", "cleanup_test_object"}:
        raise NativeBrowserActionError("native_action_write_ahead_effect_invalid")
    status = record.get("status")
    recovery_cleanup = status in {"RECONCILE_REQUIRED", "CLEANUP_PENDING"} and effect == "cleanup_test_object"
    if status != "ACTIVE" and not recovery_cleanup:
        raise NativeBrowserActionError("native_action_not_active")
    if record.get("pending_event"):
        raise NativeBrowserActionError("native_action_reconcile_required")
    if record.get("uncertain_event") and not recovery_cleanup:
        raise NativeBrowserActionError("native_action_reconcile_required")
    out = dict(record)
    out["pending_event"] = {
        "effect": effect,
        "prepared_at": iso_z(now or utc_now()),
        "recovery_cleanup": recovery_cleanup,
    }
    return out


def complete_native_action_event(record: dict, effect: str, *, status: str, now: _dt.datetime | None = None) -> dict:
    effect = str(effect or "").strip().lower()
    pending = record.get("pending_event") or {}
    if pending.get("effect") != effect:
        raise NativeBrowserActionError("native_action_pending_event_mismatch")
    out = dict(record)
    counts = dict(out.get("event_counts") or {})
    counts[effect] = int(counts.get(effect, 0)) + 1
    out["event_counts"] = counts
    completed_at = iso_z(now or utc_now())
    out["last_event"] = {"effect": effect, "status": str(status), "ts_utc": completed_at}
    out["pending_event"] = None
    recovery_cleanup = bool(pending.get("recovery_cleanup"))
    prior_uncertain = record.get("uncertain_event")
    if str(status) == "PASS":
        if recovery_cleanup:
            out["status"] = record.get("status")
            out["uncertain_event"] = prior_uncertain
        else:
            out["uncertain_event"] = None
    else:
        out["status"] = "RECONCILE_REQUIRED"
        out["uncertain_event"] = {
            "effect": effect,
            "prepared_at": pending.get("prepared_at"),
            "completion_status": str(status),
            "completed_at": completed_at,
            "prior_uncertain_event_present": bool(prior_uncertain),
        }
    return out


def materialize_interrupted_native_action(record: dict, *, now: _dt.datetime | None = None) -> dict:
    """Convert a durable pending event left by process interruption into explicit uncertainty."""
    if record.get("schema") != NATIVE_ACTION_SCHEMA:
        raise NativeBrowserActionError("native_action_state_invalid")
    pending = record.get("pending_event") or {}
    effect = str(pending.get("effect") or "")
    if effect not in {"input_plain", "reversible_mutation", "cleanup_test_object"}:
        raise NativeBrowserActionError("native_action_pending_event_required")
    return complete_native_action_event(record, effect, status="PROCESS_INTERRUPTED_UNCERTAIN", now=now)


def _mutation_evidence_count(record: dict) -> int:
    counts = record.get("event_counts") or {}
    return sum(int(counts.get(x, 0)) for x in ("input_plain", "reversible_mutation", "cleanup_test_object"))


def assess_native_action_recovery(record: dict, *, now: _dt.datetime | None = None) -> dict:
    if record.get("schema") != NATIVE_ACTION_SCHEMA:
        raise NativeBrowserActionError("native_action_state_invalid")
    current = now or utc_now()
    expires = record.get("expires_at")
    expired = bool(expires and current >= parse_iso_z(expires))
    status = record.get("status")
    mutation_events = _mutation_evidence_count(record)
    pending = record.get("pending_event")
    uncertain = record.get("uncertain_event")

    if status == "CLOSED":
        state = "NONE"
    elif status == "CLEANUP_PENDING":
        state = "CLEANUP_PENDING"
    elif status == "RECONCILE_REQUIRED" or pending or uncertain:
        state = "RECONCILE_REQUIRED"
    elif status == "ACTIVE" and expired:
        state = "RECONCILE_REQUIRED" if mutation_events else "EXPIRED_NO_MUTATION"
    elif status == "ACTIVE":
        state = "ACTIVE_VALID"
    else:
        state = "RECONCILE_REQUIRED"

    return {
        "recovery_state": state,
        "expired": expired,
        "mutation_event_count": mutation_events,
        "pending_event_present": bool(pending),
        "uncertain_event_present": bool(uncertain),
        "cleanup_required": bool(record.get("cleanup_required")),
        "new_action_blocked": state in {"RECONCILE_REQUIRED", "CLEANUP_PENDING"},
    }


def finish_native_action_record(record: dict, *, result: str, cleanup_verified: bool = False) -> dict:
    result = str(result or "").strip().lower()
    if record.get("schema") != NATIVE_ACTION_SCHEMA:
        raise NativeBrowserActionError("native_action_state_invalid")
    if record.get("status") not in {"ACTIVE", "RECONCILE_REQUIRED", "CLEANUP_PENDING"}:
        raise NativeBrowserActionError("native_action_not_active")
    if result not in NATIVE_ACTION_RESULTS:
        raise NativeBrowserActionError("invalid_native_action_result")
    if result == "verified_cleanup" and record.get("cleanup_required") and not cleanup_verified:
        raise NativeBrowserActionError("native_action_cleanup_verification_required")
    if result == "aborted_no_mutation" and (
        _mutation_evidence_count(record) > 0 or record.get("pending_event") or record.get("uncertain_event")
    ):
        raise NativeBrowserActionError("native_action_abort_claim_conflicts_with_mutation_events")
    out = dict(record)
    out["status"] = "CLOSED" if result != "cleanup_pending" else "CLEANUP_PENDING"
    out["result"] = result
    out["cleanup_verified"] = bool(cleanup_verified)
    out["closed_at"] = iso_z(utc_now())
    if result == "verified_cleanup":
        out["pending_event"] = None
        out["uncertain_event"] = None
    return out


class NativeBrowserActionStore:
    def __init__(self, root: str | Path, *, now_fn=utc_now):
        self.root = Path(root)
        self.now_fn = now_fn

    def _ensure_root(self):
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _lock_root(self) -> Path:
        self._ensure_root()
        lock_root = self.root / ".locks"
        lock_root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(lock_root, 0o700)
        except OSError:
            pass
        return lock_root

    def _path(self, action_id: str) -> Path:
        return self.root / (normalize_action_id(action_id) + ".json")

    @contextmanager
    def _lock(self, name: str, *, blocking: bool = False):
        lock_path = self._lock_root() / (name + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(fd, flags)
            except BlockingIOError as e:
                raise NativeBrowserActionError("native_action_lock_busy", name) from e
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(fd)

    def action_lock(self, action_id: str, *, blocking: bool = False):
        return self._lock("action-" + normalize_action_id(action_id), blocking=blocking)

    def site_lock(self, site_host: str, *, blocking: bool = False):
        return self._lock("site-" + normalize_site_host(site_host), blocking=blocking)

    def _fsync_root(self):
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(self.root, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def save(self, record: dict, *, create_only: bool = False) -> dict:
        self._ensure_root()
        record = dict(record)
        action_id = normalize_action_id(record.get("authorized_action_id"))
        record["authorized_action_id"] = action_id
        record["schema"] = NATIVE_ACTION_SCHEMA
        path = self._path(action_id)
        if create_only and path.exists():
            raise NativeBrowserActionError("native_action_already_exists")
        fd, tmp_name = tempfile.mkstemp(prefix=".native-action-", suffix=".tmp", dir=str(self.root))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, path)
            self._fsync_root()
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass
        return record

    def load(self, action_id: str, *, allow_expired: bool = False) -> dict:
        action_id = normalize_action_id(action_id)
        try:
            record = json.loads(self._path(action_id).read_text(encoding="utf-8"))
        except FileNotFoundError as e:
            raise NativeBrowserActionError("native_action_not_found") from e
        except (OSError, json.JSONDecodeError) as e:
            raise NativeBrowserActionError("native_action_state_invalid", type(e).__name__) from e
        if record.get("schema") != NATIVE_ACTION_SCHEMA or record.get("authorized_action_id") != action_id:
            raise NativeBrowserActionError("native_action_state_invalid")
        expires = record.get("expires_at")
        if expires and not allow_expired and record.get("status") == "ACTIVE" and self.now_fn() >= parse_iso_z(expires):
            raise NativeBrowserActionError("native_action_expired")
        return record

    def list(self) -> list[dict]:
        if not self.root.exists():
            return []
        out = []
        for path in sorted(self.root.glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if record.get("schema") != NATIVE_ACTION_SCHEMA:
                    continue
                item = dict(record)
                expires = item.get("expires_at")
                item["expired"] = bool(
                    expires and item.get("status") == "ACTIVE" and self.now_fn() >= parse_iso_z(expires)
                )
                item["recovery"] = assess_native_action_recovery(item, now=self.now_fn())
                out.append(item)
            except Exception:
                continue
        return out

    def recovery_blockers(self, site_host: str | None = None) -> list[dict]:
        host = normalize_site_host(site_host) if site_host else None
        blockers = []
        for record in self.list():
            if host and record.get("site_host") != host:
                continue
            recovery = record.get("recovery") or assess_native_action_recovery(record, now=self.now_fn())
            if recovery.get("new_action_blocked"):
                blockers.append(record)
        return blockers

    def site_single_flight_blockers(self, site_host: str) -> list[dict]:
        host = normalize_site_host(site_host)
        blockers = []
        for record in self.list():
            if record.get("site_host") != host:
                continue
            recovery = record.get("recovery") or assess_native_action_recovery(record, now=self.now_fn())
            if recovery.get("recovery_state") in {"ACTIVE_VALID", "RECONCILE_REQUIRED", "CLEANUP_PENDING"}:
                blockers.append(record)
        return blockers
