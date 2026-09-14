#!/usr/bin/env python3
"""Read-only capability watch for future host-native file-return runtime support.

R3 does not qualify Grade A and does not persist raw file references. It keeps a
versioned baseline of currently verified host surfaces, compares later
capability observations against that baseline, and raises an explicit live
verification handoff when a real native-return primitive appears.
"""
from __future__ import annotations

import hashlib
import json


WATCH_SCHEMA_VERSION = "macctl-host-native-runtime-capability-watch/v1"
BASELINE_SCHEMA_VERSION = "macctl-host-native-runtime-capability-baseline/v1"
OBSERVATION_SCHEMA_VERSION = "macctl-host-native-runtime-capability-observation/v1"

REQUIRED_NATIVE_CAPABILITIES = (
    "native_file_return_primitive",
    "native_conversation_reference",
    "host_receipt_digest",
    "same_reference_redownload",
)

_ALLOWED_ORIGINS = {
    "PROJECT_VERIFIED_BASELINE",
    "LIVE_TOOL_SCHEMA",
    "LIVE_RUNTIME_OBSERVATION",
    "MANUAL_REPORTED_OBSERVATION",
    "SYNTHETIC_TEST",
}
_ALLOWED_FIELDS = {
    "schema",
    "adapter",
    "surface",
    "discovery_origin",
    "native_file_return_primitive",
    "inline_content_render",
    "native_conversation_reference",
    "host_receipt_digest",
    "same_reference_redownload",
}


class HostNativeRuntimeWatchError(ValueError):
    pass


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _text(value: object, field: str, maximum: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(ch) < 32 for ch in text):
        raise HostNativeRuntimeWatchError(f"invalid_{field}")
    return text


def _bool(value: object, field: str) -> bool:
    if value is not True and value is not False:
        raise HostNativeRuntimeWatchError(f"invalid_{field}")
    return bool(value)


def normalize_observation(value: dict) -> dict:
    if not isinstance(value, dict):
        raise HostNativeRuntimeWatchError("invalid_observation_shape")
    if value.get("schema") != OBSERVATION_SCHEMA_VERSION:
        raise HostNativeRuntimeWatchError("invalid_observation_schema")
    if set(value) - _ALLOWED_FIELDS:
        raise HostNativeRuntimeWatchError("unknown_observation_fields")
    origin = _text(value.get("discovery_origin"), "discovery_origin", 64)
    if origin not in _ALLOWED_ORIGINS:
        raise HostNativeRuntimeWatchError("invalid_discovery_origin")
    result = {
        "schema": OBSERVATION_SCHEMA_VERSION,
        "adapter": _text(value.get("adapter"), "adapter", 128),
        "surface": _text(value.get("surface"), "surface", 256),
        "discovery_origin": origin,
        "native_file_return_primitive": _bool(value.get("native_file_return_primitive"), "native_file_return_primitive"),
        "inline_content_render": _bool(value.get("inline_content_render"), "inline_content_render"),
        "native_conversation_reference": _bool(value.get("native_conversation_reference"), "native_conversation_reference"),
        "host_receipt_digest": _bool(value.get("host_receipt_digest"), "host_receipt_digest"),
        "same_reference_redownload": _bool(value.get("same_reference_redownload"), "same_reference_redownload"),
    }
    return result


def _surface_key(observation: dict) -> str:
    return f"{observation['adapter']}::{observation['surface']}"


def _fingerprint(observations: list[dict]) -> str:
    stable = sorted(observations, key=_surface_key)
    return hashlib.sha256(_canonical(stable)).hexdigest()


def current_project_baseline() -> dict:
    """Return the current verified project runtime baseline.

    The original R3 SentinelX/RDC observations are preserved, while PM3 adds
    the ChatGPT conversation-file relay only after the frozen R1 evaluator
    observed a real Grade-A native attachment and exact same-reference
    roundtrip. This remains static evidence, not magical host introspection.
    """
    surfaces = [
        {
            "schema": OBSERVATION_SCHEMA_VERSION,
            "adapter": "SentinelX",
            "surface": "current-chat-tool-runtime",
            "discovery_origin": "PROJECT_VERIFIED_BASELINE",
            "native_file_return_primitive": False,
            "inline_content_render": False,
            "native_conversation_reference": False,
            "host_receipt_digest": False,
            "same_reference_redownload": False,
        },
        {
            "schema": OBSERVATION_SCHEMA_VERSION,
            "adapter": "Remote Desktop Commander",
            "surface": "current-chat-read-file",
            "discovery_origin": "PROJECT_VERIFIED_BASELINE",
            "native_file_return_primitive": False,
            "inline_content_render": True,
            "native_conversation_reference": False,
            "host_receipt_digest": False,
            "same_reference_redownload": False,
        },
        {
            "schema": OBSERVATION_SCHEMA_VERSION,
            "adapter": "CHATGPT_CONVERSATION_FILE_RELAY",
            "surface": "chatgpt-ordinary-chat",
            "discovery_origin": "PROJECT_VERIFIED_BASELINE",
            "native_file_return_primitive": True,
            "inline_content_render": False,
            "native_conversation_reference": True,
            "host_receipt_digest": True,
            "same_reference_redownload": True,
        },
    ]
    normalized = [normalize_observation(item) for item in surfaces]
    return {
        "schema": BASELINE_SCHEMA_VERSION,
        "baseline_id": "V0.5.1-PM3-20260914-LIVE-GRADE-A-USER-VISIBLE",
        "surfaces": normalized,
        "baseline_fingerprint_sha256": _fingerprint(normalized),
        "backend_native_qualified_surface_keys": ["CHATGPT_CONVERSATION_FILE_RELAY::chatgpt-ordinary-chat"],
        "verified_grade_a_surface_keys": ["CHATGPT_CONVERSATION_FILE_RELAY::chatgpt-ordinary-chat"],
        "qualification_origin": "PM3_LIVE_USER_VISIBLE_ATTACHMENT_EXPLICIT_FEEDBACK",
        "qualification_evidence_sha256": "db148196db26a9d41e60846e3d4b9fb341b2959e4192f7aaefc3041bab230059",
        "ordinary_chat_grade_a": "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
        "user_visible_attachment": "CONFIRMED_DOWNLOADABLE_AND_CLICK_PREVIEW",
        "production_grade_a_ready": True,
    }


def _native_candidate(observation: dict) -> bool:
    return all(observation[field] is True for field in REQUIRED_NATIVE_CAPABILITIES)


def evaluate_runtime_capability_watch(observations: list[dict], *, baseline: dict | None = None) -> dict:
    """Compare a complete runtime capability snapshot with the verified baseline.

    A new native-capability candidate can only open the R2 live-verifier
    handoff; it never self-qualifies. Production Grade A may remain true only
    when a surface already qualified by external live evidence is present and
    retains every required native capability.
    """
    if not isinstance(observations, list) or not observations:
        raise HostNativeRuntimeWatchError("observations_required")
    normalized = [normalize_observation(item) for item in observations]
    keys = [_surface_key(item) for item in normalized]
    if len(keys) != len(set(keys)):
        raise HostNativeRuntimeWatchError("duplicate_surface_observation")

    baseline = current_project_baseline() if baseline is None else baseline
    if not isinstance(baseline, dict) or baseline.get("schema") != BASELINE_SCHEMA_VERSION:
        raise HostNativeRuntimeWatchError("invalid_baseline_schema")
    baseline_surfaces = [normalize_observation(item) for item in baseline.get("surfaces") or []]
    if not baseline_surfaces:
        raise HostNativeRuntimeWatchError("empty_baseline")
    baseline_map = {_surface_key(item): item for item in baseline_surfaces}
    observed_map = {_surface_key(item): item for item in normalized}

    missing = sorted(set(baseline_map) - set(observed_map))
    new_surfaces = sorted(set(observed_map) - set(baseline_map))
    changed = []
    for key in sorted(set(baseline_map) & set(observed_map)):
        before = baseline_map[key]
        after = observed_map[key]
        fields = [
            field for field in (
                "native_file_return_primitive",
                "inline_content_render",
                "native_conversation_reference",
                "host_receipt_digest",
                "same_reference_redownload",
            )
            if before[field] != after[field]
        ]
        if fields:
            changed.append({"surface_key": key, "changed_fields": fields})

    verified_raw = baseline.get("verified_grade_a_surface_keys") or []
    if not isinstance(verified_raw, list):
        raise HostNativeRuntimeWatchError("invalid_verified_grade_a_surface_keys")
    verified_keys = sorted(_text(item, "verified_grade_a_surface_key", 512) for item in verified_raw)
    if len(verified_keys) != len(set(verified_keys)):
        raise HostNativeRuntimeWatchError("duplicate_verified_grade_a_surface_key")
    if any(key not in baseline_map or not _native_candidate(baseline_map[key]) for key in verified_keys):
        raise HostNativeRuntimeWatchError("invalid_verified_grade_a_baseline")

    backend_raw = baseline.get("backend_native_qualified_surface_keys") or []
    if not isinstance(backend_raw, list):
        raise HostNativeRuntimeWatchError("invalid_backend_native_qualified_surface_keys")
    backend_keys = sorted(_text(item, "backend_native_qualified_surface_key", 512) for item in backend_raw)
    if len(backend_keys) != len(set(backend_keys)):
        raise HostNativeRuntimeWatchError("duplicate_backend_native_qualified_surface_key")
    if any(key not in baseline_map or not _native_candidate(baseline_map[key]) for key in backend_keys):
        raise HostNativeRuntimeWatchError("invalid_backend_native_baseline")

    baseline_grade_a = baseline.get("production_grade_a_ready") is True
    verified_intact = bool(
        baseline_grade_a
        and verified_keys
        and all(key in observed_map and _native_candidate(observed_map[key]) for key in verified_keys)
    )
    verified_regressed = bool(baseline_grade_a and verified_keys and not verified_intact)
    backend_intact = bool(
        backend_keys
        and all(key in observed_map and _native_candidate(observed_map[key]) for key in backend_keys)
    )

    candidate_surfaces = sorted(_surface_key(item) for item in normalized if _native_candidate(item))
    qualified_known_keys = set(verified_keys) | set(backend_keys)
    unverified_candidate_surfaces = sorted(set(candidate_surfaces) - qualified_known_keys)
    any_unverified_native_signal = any(
        any(item[field] for field in REQUIRED_NATIVE_CAPABILITIES)
        for item in normalized
        if _surface_key(item) not in qualified_known_keys
    )

    production_ready = False
    if missing:
        state = "INCOMPLETE_RUNTIME_SNAPSHOT"
        handoff = "BLOCKED_INCOMPLETE_CAPABILITY_SNAPSHOT"
        reason = "complete_snapshot_required"
    elif verified_regressed:
        state = "VERIFIED_GRADE_A_CAPABILITY_REGRESSION"
        handoff = "R2_LIVE_RUNTIME_REQUALIFICATION_REQUIRED"
        reason = "verified_grade_a_surface_missing_or_degraded"
    elif backend_keys and not backend_intact:
        state = "BACKEND_NATIVE_CAPABILITY_REGRESSION"
        handoff = "R2_LIVE_RUNTIME_REQUALIFICATION_REQUIRED"
        reason = "backend_native_qualified_surface_missing_or_degraded"
    elif unverified_candidate_surfaces:
        state = "NATIVE_RUNTIME_CAPABILITY_CANDIDATE_DETECTED"
        handoff = "R2_LIVE_RUNTIME_VERIFIER_REQUIRED"
        production_ready = verified_intact
        reason = "new_candidate_never_self_qualifies_grade_a"
    elif any_unverified_native_signal:
        state = "PARTIAL_NATIVE_RUNTIME_CAPABILITY_DETECTED"
        handoff = "BLOCKED_PENDING_COMPLETE_NATIVE_CAPABILITY"
        production_ready = verified_intact
        reason = "partial_candidate_does_not_change_verified_grade_a_baseline"
    elif changed or new_surfaces:
        state = "RUNTIME_SURFACE_CHANGE_NO_NEW_NATIVE_CAPABILITY"
        handoff = "USER_VISIBLE_ATTACHMENT_VERIFIER_REQUIRED" if backend_intact and not baseline_grade_a else "NO_GRADE_A_HANDOFF"
        production_ready = verified_intact
        reason = (
            "backend_native_exact_roundtrip_verified_user_visible_attachment_not_confirmed"
            if backend_intact and not baseline_grade_a
            else "verified_grade_a_baseline_intact"
            if verified_intact
            else "no_verified_grade_a_baseline"
        )
    elif backend_intact and not baseline_grade_a:
        state = "BACKEND_NATIVE_QUALIFIED_USER_VISIBLE_GATE"
        handoff = "USER_VISIBLE_ATTACHMENT_VERIFIER_REQUIRED"
        production_ready = False
        reason = "backend_native_exact_roundtrip_verified_user_visible_attachment_not_confirmed"
    elif verified_intact:
        state = "NO_CHANGE_LIVE_GRADE_A_QUALIFIED"
        handoff = "NO_GRADE_A_HANDOFF"
        production_ready = True
        reason = "verified_grade_a_baseline_intact"
    else:
        state = "NO_CHANGE_NO_NATIVE_RUNTIME_CAPABILITY"
        handoff = "NO_GRADE_A_HANDOFF"
        reason = "capability_watch_never_self_qualifies_grade_a"

    return {
        "schema": WATCH_SCHEMA_VERSION,
        "status": "PASS",
        "watch_state": state,
        "baseline_id": _text(baseline.get("baseline_id"), "baseline_id", 256),
        "baseline_fingerprint_sha256": _fingerprint(baseline_surfaces),
        "observation_fingerprint_sha256": _fingerprint(normalized),
        "surface_count": len(normalized),
        "missing_baseline_surfaces": missing,
        "new_surfaces": new_surfaces,
        "changed_surfaces": changed,
        "native_candidate_surfaces": candidate_surfaces,
        "unverified_native_candidate_surfaces": unverified_candidate_surfaces,
        "backend_native_qualified_surface_keys": backend_keys,
        "backend_native_baseline_intact": backend_intact,
        "verified_grade_a_surface_keys": verified_keys,
        "verified_grade_a_baseline_intact": verified_intact,
        "live_verifier_handoff": handoff,
        "production_grade_a_ready": production_ready,
        "ordinary_chat_grade_a": (
            "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED"
            if production_ready
            else "BACKEND_NATIVE_QUALIFIED_USER_VISIBLE_GATE"
            if backend_intact
            else "EXTERNAL_HOST_ADAPTER_GATE"
        ),
        "raw_file_reference_persisted": False,
        "reason": reason,
    }


def runtime_watch_capabilities() -> dict:
    return {
        "schema": "macctl-host-native-runtime-capability-watch-capabilities/v1",
        "observation_schema": OBSERVATION_SCHEMA_VERSION,
        "baseline_schema": BASELINE_SCHEMA_VERSION,
        "required_native_capabilities": list(REQUIRED_NATIVE_CAPABILITIES),
        "complete_snapshot_required": True,
        "unknown_observation_fields_fail_closed": True,
        "raw_file_reference_allowed": False,
        "capability_candidate_can_set_production_grade_a_ready": False,
        "backend_native_exact_roundtrip_can_set_production_grade_a_ready": False,
        "user_visible_attachment_confirmation_required": True,
        "verified_live_baseline_can_report_production_grade_a_ready": True,
        "verified_grade_a_regression_fails_closed": True,
        "backend_native_user_visible_handoff": "USER_VISIBLE_ATTACHMENT_VERIFIER_REQUIRED",
        "candidate_handoff": "R2_LIVE_RUNTIME_VERIFIER_REQUIRED",
    }
