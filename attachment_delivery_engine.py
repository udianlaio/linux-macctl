#!/usr/bin/env python3
"""Transport-independent delivery planning for ordinary-chat attachments."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

DELIVERY_SCHEMA_VERSION = "macctl-attachment-delivery/v1"
GRADE_A = "GRADE_A_NATIVE_ATTACHMENT"
GRADE_B = "GRADE_B_INLINE_ONLY"
GRADE_C = "GRADE_C_RESOLVABLE_RESOURCE"
GRADE_D = "GRADE_D_LINK_ONLY"
NOT_AVAILABLE = "NOT_AVAILABLE"
CHATGPT_CONVERSATION_FILE_RELAY = "CHATGPT_CONVERSATION_FILE_RELAY"


@dataclass(frozen=True)
class AdapterCapability:
    name: str
    available: bool
    qualified: bool
    grade: str
    inline_image: bool = False
    exact_original: bool = False
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "available": bool(self.available),
            "qualified": bool(self.qualified),
            "grade": self.grade,
            "inline_image": bool(self.inline_image),
            "exact_original": bool(self.exact_original),
            "reason": self.reason,
        }


DEFAULT_ADAPTERS = (
    AdapterCapability(
        CHATGPT_CONVERSATION_FILE_RELAY, False, False, GRADE_A,
        inline_image=True, exact_original=True,
        reason="runtime_profile_not_enabled",
    ),
    AdapterCapability(
        "OPENAI_NATIVE_TOOL_FILE_REF", False, False, GRADE_A,
        inline_image=True, exact_original=True,
        reason="runtime_file_return_contract_not_exposed_to_macctl",
    ),
    AdapterCapability(
        "MCP_IMAGE_CONTENT", False, False, GRADE_B,
        inline_image=True, exact_original=False,
        reason="ordinary_chat_surface_not_qualified",
    ),
    AdapterCapability(
        "MCP_RESOURCE_LINK", False, False, GRADE_C,
        inline_image=False, exact_original=True,
        reason="host_materialization_to_native_attachment_not_qualified",
    ),
    AdapterCapability(
        "SENTINELX_NATIVE_FILE_RETURN", False, False, GRADE_A,
        inline_image=True, exact_original=True,
        reason="sentinelx_public_tool_contract_has_no_binary_file_return",
    ),
    AdapterCapability(
        "SAME_GATEWAY_AUTHENTICATED_HTTPS", False, False, GRADE_D,
        inline_image=False, exact_original=True,
        reason="link_only_is_not_native_attachment_success",
    ),
    AdapterCapability(
        "PRIVATE_GITHUB_ACTIONS_ARTIFACT", True, True, GRADE_A,
        inline_image=True, exact_original=True,
        reason="debug_emergency_fallback_user_visible_confirmed_2026_09_12",
    ),
)


def _live_grade_a_evidence_valid(relay: dict, *, evidence_root: str | Path) -> bool:
    expected_sha = str(relay.get("qualification_evidence_sha256") or "").lower()
    evidence_file = str(relay.get("qualification_evidence_file") or "").strip()
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None or not evidence_file:
        return False
    raw_path = Path(evidence_file)
    if not raw_path.is_absolute() or raw_path.is_symlink():
        return False
    try:
        root = Path(evidence_root).resolve(strict=True)
        path = raw_path.resolve(strict=True)
        path.relative_to(root)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected_sha:
            return False
        obj = json.loads(data.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    evaluator = obj.get("r1_evaluator") if isinstance(obj, dict) else None
    return bool(
        obj.get("schema") == "macctl-pm3-grade-a-live-qualification/v2"
        and obj.get("status") == "CLOSED_PASS_LIVE_GRADE_A_USER_VISIBLE_ATTACHMENT"
        and obj.get("adapter") == CHATGPT_CONVERSATION_FILE_RELAY
        and obj.get("surface") == "chatgpt-ordinary-chat"
        and isinstance(evaluator, dict)
        and evaluator.get("qualification_state") == "GRADE_A_NATIVE_ATTACHMENT_QUALIFIED"
        and evaluator.get("qualified") is True
        and evaluator.get("exact_host_receipt") is True
        and evaluator.get("exact_redownload") is True
        and evaluator.get("grade_a_blockers") == []
        and isinstance(obj.get("user_visible_attachment"), dict)
        and obj["user_visible_attachment"].get("confirmed") is True
        and obj["user_visible_attachment"].get("downloadable_attachment_visible") is True
        and obj["user_visible_attachment"].get("explicit_user_feedback") is True
    )


def runtime_adapters_from_config(config: dict | None = None, *, evidence_root: str | Path = "/var/backups/macctl"):
    """Resolve host-adapter availability from a fail-closed runtime profile.

    Source defaults remain unavailable. A concrete deployment may enable the
    ChatGPT conversation-file relay only when local configuration binds the
    ordinary-chat surface to a verified live Grade-A evidence file. The file
    must live below the controlled evidence root and match its configured
    SHA-256; a syntactically valid digest alone is never sufficient.
    """
    config = config if isinstance(config, dict) else {}
    relay = config.get(CHATGPT_CONVERSATION_FILE_RELAY)
    relay = relay if isinstance(relay, dict) else {}
    enabled = relay.get("enabled") is True
    surface_ok = relay.get("surface") == "chatgpt-ordinary-chat"
    state_ok = relay.get("qualification_state") == "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED"
    evidence_ok = _live_grade_a_evidence_valid(relay, evidence_root=evidence_root)
    qualified = bool(enabled and surface_ok and state_ok and evidence_ok)

    if qualified:
        reason = "live_grade_a_evidence_file_verified"
    elif enabled:
        reason = "runtime_profile_enabled_but_grade_a_evidence_invalid"
    else:
        reason = "runtime_profile_not_enabled"

    resolved = []
    for adapter in DEFAULT_ADAPTERS:
        if adapter.name == CHATGPT_CONVERSATION_FILE_RELAY:
            resolved.append(AdapterCapability(
                CHATGPT_CONVERSATION_FILE_RELAY,
                enabled,
                qualified,
                GRADE_A,
                inline_image=True,
                exact_original=True,
                reason=reason,
            ))
        else:
            resolved.append(adapter)
    return tuple(resolved)


def delivery_probe(adapters=DEFAULT_ADAPTERS) -> dict:
    rows = [a.as_dict() for a in adapters]
    production = [a for a in adapters if a.name != "PRIVATE_GITHUB_ACTIONS_ARTIFACT" and a.available and a.qualified and a.grade == GRADE_A]
    return {
        "schema": DELIVERY_SCHEMA_VERSION,
        "status": "PASS",
        "production_grade_a_ready": bool(production),
        "current_production_state": "READY" if production else "NOT_YET_QUALIFIED",
        "debug_emergency_grade_a_ready": any(a.name == "PRIVATE_GITHUB_ACTIONS_ARTIFACT" and a.available and a.qualified for a in adapters),
        "success_contract": GRADE_A,
        "adapters": rows,
    }


def choose_adapter(*, original_required: bool = True, presentation: str = "both", adapters=DEFAULT_ADAPTERS, allow_debug_fallback: bool = False) -> dict:
    presentation = str(presentation).lower()
    if presentation not in {"auto", "inline", "attachment", "both"}:
        raise ValueError("invalid_presentation")
    candidates = []
    for a in adapters:
        if not a.available or not a.qualified:
            continue
        if a.name == "PRIVATE_GITHUB_ACTIONS_ARTIFACT" and not allow_debug_fallback:
            continue
        if original_required and not a.exact_original:
            continue
        if presentation == "inline" and not a.inline_image:
            continue
        # Asking for an attachment (or both inline+attachment) always requires
        # a native Grade-A attachment, independent of original_required.
        if presentation in {"attachment", "both"} and a.grade != GRADE_A:
            continue
        # Exact-original requests also require Grade A even for auto/inline.
        if original_required and a.grade != GRADE_A:
            continue
        candidates.append(a)
    if not candidates:
        return {
            "schema": DELIVERY_SCHEMA_VERSION,
            "status": "NOT_YET_QUALIFIED",
            "selected_adapter": None,
            "success_grade": None,
            "original_required": bool(original_required),
            "presentation": presentation,
        }
    selected = candidates[0]
    return {
        "schema": DELIVERY_SCHEMA_VERSION,
        "status": "READY",
        "selected_adapter": selected.name,
        "success_grade": selected.grade,
        "original_required": bool(original_required),
        "presentation": presentation,
        "single_source_bytes": True,
        "duplicate_full_payload_required": False,
    }
