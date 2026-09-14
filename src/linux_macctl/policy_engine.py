#!/usr/bin/env python3
"""macctl Policy Engine V2.

Pure-stdlib policy classification/evaluation so policy logic can be unit-tested
without importing the live /etc/macctl configuration or opening an SSH session.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import unicodedata

POLICY_SCHEMA_VERSION = "macctl-policy/v2"

READ_ONLY = "READ_ONLY"
MUTATE_REVERSIBLE = "MUTATE_REVERSIBLE"
MUTATE_STATEFUL = "MUTATE_STATEFUL"
HIGH_IMPACT = "HIGH_IMPACT"
FORBIDDEN_BY_POLICY = "FORBIDDEN_BY_POLICY"
BREAK_GLASS = "BREAK_GLASS"

RISK_CLASSES = (
    READ_ONLY,
    MUTATE_REVERSIBLE,
    MUTATE_STATEFUL,
    HIGH_IMPACT,
    FORBIDDEN_BY_POLICY,
    BREAK_GLASS,
)

OS_MARKERS = (
    "macos",
    "tahoe",
    "sequoia",
    "sonoma",
    "ventura",
    "monterey",
    "big sur",
    "installassistant",
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk_class: str
    reason: str
    source: str = "typed"
    requires_confirmation: bool = False

    def as_dict(self) -> dict:
        return {
            "schema": POLICY_SCHEMA_VERSION,
            "allowed": bool(self.allowed),
            "risk_class": self.risk_class,
            "reason": self.reason,
            "source": self.source,
            "requires_confirmation": bool(self.requires_confirmation),
        }


def _decision(risk: str, reason: str, *, allowed: bool = True, source: str = "typed", requires_confirmation: bool = False) -> PolicyDecision:
    return PolicyDecision(
        allowed=allowed,
        risk_class=risk,
        reason=reason,
        source=source,
        requires_confirmation=requires_confirmation,
    )


def _bool(attrs: dict, key: str, default: bool = False) -> bool:
    return bool(attrs.get(key, default))


def _text(attrs: dict, key: str) -> str:
    value = attrs.get(key)
    return "" if value is None else str(value)


def _contains_os_marker(text: str) -> bool:
    low = unicodedata.normalize("NFKC", text or "").casefold()
    return any(marker in low for marker in OS_MARKERS)


def classify_operation(family: str, action: str | None = None, attrs: dict | None = None, cfg: dict | None = None) -> PolicyDecision:
    """Classify a parsed macctl operation and enforce typed policy gates.

    This function is intentionally independent of argparse and host state.
    Unknown typed operations fail closed instead of silently inheriting a low
    risk class.
    """
    attrs = dict(attrs or {})
    cfg = dict(cfg or {})
    family = str(family or "").strip().casefold()
    action = None if action is None else str(action).strip().casefold()

    if family in {"version", "ping", "status", "health", "doctor", "auth", "logs", "system", "audit", "policy", "transaction", "capabilities"}:
        return _decision(READ_ONLY, "typed_read_only_operation")

    if family == "fleet" and action in {"list", "status", "doctor", "resolve", "plan"}:
        return _decision(READ_ONLY, "fleet_read_only_binding_operation")

    if family == "workstation" and action in {"profile", "inventory", "doctor", "qualification-plan", "qualification"}:
        return _decision(READ_ONLY, "workstation_read_only_qualification_operation")

    if family == "linux" and action in {"profile", "list", "overview", "fleet-status", "fleet-doctor", "status", "doctor", "transport", "qualification-plan", "qualification", "logs", "package", "network", "process", "systemd", "file"}:
        return _decision(READ_ONLY, "remote_linux_read_only_control_operation")
    if family == "linux" and action == "command":
        confirmed = _bool(attrs, "confirm")
        high = _bool(attrs, "confirm_high_impact")
        return _decision(
            HIGH_IMPACT if (confirmed and high) else BREAK_GLASS if confirmed else FORBIDDEN_BY_POLICY,
            "remote_linux_high_impact_command_confirmed" if (confirmed and high) else "remote_linux_command_confirmed" if confirmed else "remote_linux_command_confirmation_required",
            allowed=confirmed,
            source="break_glass",
            requires_confirmation=True,
        )

    if family == "security":
        if action in {
            "ssh-state", "sudo-state", "hostkey", "posture", "hardening-assess",
            "tcc-state", "tcc-probe", "password-probe", "full-disk-test",
        }:
            return _decision(READ_ONLY, "security_read_only_operation")
        if action in {"filevault-enable", "filevault-disable"}:
            return _decision(
                FORBIDDEN_BY_POLICY,
                "filevault_out_of_scope_requires_separate_qualification",
                allowed=False,
                requires_confirmation=True,
            )
        if action in {"firewall-enable", "firewall-disable", "firewall-set-stealth", "firewall-set-block-all"}:
            confirmed = _bool(attrs, "confirm")
            return _decision(
                HIGH_IMPACT if confirmed else FORBIDDEN_BY_POLICY,
                "explicit_confirmation_present" if confirmed else "explicit_confirmation_required",
                allowed=confirmed,
                requires_confirmation=True,
            )

    if family in {"exec", "script"}:
        return _decision(BREAK_GLASS, "generic_shell_break_glass", source="break_glass")

    if family == "wake":
        return _decision(MUTATE_STATEFUL, "wake_packet_changes_remote_power_state")

    if family == "artifact":
        if action in {"list", "inspect", "verify", "delivery-probe", "host-adapter-evaluate", "host-native-conformance-contract", "host-native-conformance-fixture", "host-native-runtime-watch-baseline", "host-native-runtime-watch-evaluate", "delivery-plan", "delivery-status", "delivery-list", "relay-status", "lan-probe", "route-auto", "route-plan"}:
            return _decision(READ_ONLY, "artifact_read_or_delivery_planning")
        if action in {"import", "delivery-create", "relay-stage"}:
            return _decision(MUTATE_REVERSIBLE, "artifact_or_delivery_record_create")
        if action in {"revoke", "gc", "grant", "revoke-grants", "delivery-host-accept", "delivery-render-qualify", "delivery-user-confirm", "delivery-fail", "relay-cleanup"}:
            return _decision(MUTATE_STATEFUL, "artifact_lifecycle_access_or_delivery_evidence_change")

    if family == "file":
        if action in {"read", "list", "stat", "sha256"}:
            return _decision(READ_ONLY, "file_read_only")
        if action in {"mkdir", "mv", "cp"}:
            return _decision(MUTATE_REVERSIBLE, "file_mutation_reversible")
        if action == "rm":
            if _bool(attrs, "recursive") or _bool(attrs, "sudo"):
                return _decision(HIGH_IMPACT, "file_delete_recursive_or_privileged")
            return _decision(MUTATE_STATEFUL, "file_delete")

    if family == "push":
        return _decision(MUTATE_REVERSIBLE, "remote_file_write")
    if family == "pull":
        return _decision(MUTATE_REVERSIBLE, "local_file_write")

    if family == "process":
        if action in {"list", "top"}:
            return _decision(READ_ONLY, "process_read_only")
        if action == "kill":
            risk = HIGH_IMPACT if _bool(attrs, "sudo") else MUTATE_STATEFUL
            return _decision(risk, "process_signal")

    if family == "launchd":
        if action in {"list", "print"}:
            return _decision(READ_ONLY, "launchd_read_only")
        if action in {"kickstart", "enable", "disable"}:
            risk = HIGH_IMPACT if _text(attrs, "scope").casefold() == "system" else MUTATE_STATEFUL
            return _decision(risk, "launchd_state_change")

    if family == "power":
        if action == "blockers":
            return _decision(READ_ONLY, "power_blocker_query")
        if action == "sleep":
            return _decision(MUTATE_STATEFUL, "sleep_changes_availability")
        if action in {"restart", "shutdown"}:
            confirmed = _bool(attrs, "confirm")
            return _decision(
                HIGH_IMPACT if confirmed else FORBIDDEN_BY_POLICY,
                "explicit_confirmation_present" if confirmed else "explicit_confirmation_required",
                allowed=confirmed,
                requires_confirmation=True,
            )

    if family == "update":
        allow_system = bool(cfg.get("allow_macos_system_update", False))
        allow_major = bool(cfg.get("allow_macos_major_upgrade", False))
        if action in {"list", "settings", "policy"}:
            return _decision(READ_ONLY, "update_read_only")
        if action in {"safari-download", "safari-install"}:
            return _decision(MUTATE_STATEFUL, "explicit_safari_only_path")
        if action == "install-all":
            if not allow_system:
                return _decision(FORBIDDEN_BY_POLICY, "macos_system_update_policy", allowed=False)
            if not allow_major:
                return _decision(FORBIDDEN_BY_POLICY, "macos_major_upgrade_policy_install_all_unsafe", allowed=False)
            return _decision(HIGH_IMPACT, "all_system_updates_explicitly_allowed")
        if action == "install":
            label = _text(attrs, "label")
            if not allow_system:
                return _decision(FORBIDDEN_BY_POLICY, "generic_system_update_install_blocked_use_safari_only_path", allowed=False)
            if _contains_os_marker(label) and not allow_major:
                return _decision(FORBIDDEN_BY_POLICY, "macos_major_upgrade_policy", allowed=False)
            return _decision(MUTATE_STATEFUL, "explicit_update_label_install")

    if family == "brew":
        if action in {"version", "list", "doctor"}:
            return _decision(READ_ONLY, "brew_read_only")
        if action in {"update", "upgrade"}:
            return _decision(MUTATE_STATEFUL, "brew_mutation")

    if family == "sync":
        if _bool(attrs, "dry_run"):
            return _decision(READ_ONLY, "rsync_dry_run")
        if _bool(attrs, "delete"):
            return _decision(HIGH_IMPACT, "rsync_delete_enabled")
        return _decision(MUTATE_REVERSIBLE, "rsync_state_change")

    if family == "backup":
        if action in {"status", "destinations", "snapshots", "apfs-snapshots"}:
            return _decision(READ_ONLY, "backup_read_only")
        if action == "create-local":
            return _decision(MUTATE_REVERSIBLE, "local_snapshot_create")
        if action == "delete-local":
            return _decision(MUTATE_STATEFUL, "local_snapshot_delete")

    if family == "job":
        if action == "start":
            return _decision(BREAK_GLASS, "background_generic_shell_break_glass", source="break_glass")
        if action in {"list", "status", "log"}:
            return _decision(READ_ONLY, "job_read_only")
        if action in {"kill", "cleanup"}:
            return _decision(MUTATE_STATEFUL, "job_state_change")

    if family == "clipboard":
        if action == "get":
            return _decision(READ_ONLY, "clipboard_read")
        if action == "set":
            return _decision(MUTATE_STATEFUL, "clipboard_write")

    if family == "messaging":
        if action in {"list", "observe", "read"}:
            return _decision(READ_ONLY, "delegated_messaging_read_only")
        if action == "bind":
            if _bool(attrs, "allow_send"):
                confirmed = _bool(attrs, "confirm")
                return _decision(
                    MUTATE_STATEFUL if confirmed else FORBIDDEN_BY_POLICY,
                    "messaging_send_binding_confirmation_present" if confirmed else "messaging_send_binding_confirmation_required",
                    allowed=confirmed,
                    requires_confirmation=True,
                )
            return _decision(MUTATE_REVERSIBLE, "messaging_read_draft_binding")
        if action == "draft":
            return _decision(MUTATE_REVERSIBLE, "messaging_draft_no_send")
        if action == "send":
            confirmed = _bool(attrs, "confirm")
            return _decision(
                MUTATE_STATEFUL if confirmed else FORBIDDEN_BY_POLICY,
                "messaging_send_confirmation_present" if confirmed else "messaging_send_confirmation_required",
                allowed=confirmed,
                requires_confirmation=True,
            )

    if family == "browser":
        if action in {"control-plan", "cdp-plan", "qualification-plan", "url-check", "session-list", "session-status", "session-query", "session-extract", "session-analyze", "session-wait", "session-pages", "native-action-plan", "native-action-list", "native-action-status", "native-action-observe", "native-action-recovery-plan", "native-action-recovery-observe"}:
            return _decision(READ_ONLY, "browser_controlled_read_only")
        if action in {"cdp-smoke", "session-start", "session-stop", "session-navigate", "session-type", "session-select", "session-search", "session-activate", "session-new-tab", "session-close-tab", "session-history", "session-reload"}:
            return _decision(MUTATE_REVERSIBLE, "browser_isolated_session_reversible")
        if action in {"session-click", "session-download", "session-key", "session-upload", "native-action-begin", "native-action-type", "native-action-click", "native-action-key", "native-action-finish", "native-action-recover-interrupted"}:
            confirmed = _bool(attrs, "confirm")
            return _decision(
                MUTATE_STATEFUL if confirmed else FORBIDDEN_BY_POLICY,
                "browser_explicit_confirmation_present" if confirmed else "browser_explicit_confirmation_required",
                allowed=confirmed,
                requires_confirmation=True,
            )

    if family == "gui":
        if action in {
            "inspect",
            "compare",
            "semantic-find",
            "event-observe",
            "event-wait",
            "helper-status",
            "helper-lifecycle-status",
            "helper-screen-capture-test",
            "helper-screen-ocr",
            "helper-automation-test",
            "helper-systemevents-test",
            "helper-accessibility-test",
            "helper-accessibility-inventory",
            "helper-frontmost",
            "helper-mouse-position",
        }:
            return _decision(READ_ONLY, "gui_observation_or_probe")
        if action == "screenshot":
            return _decision(MUTATE_REVERSIBLE, "screenshot_writes_vm_artifact")
        if action in {"helper-request-accessibility", "helper-request-screen-recording"}:
            return _decision(MUTATE_STATEFUL, "opens_or_requests_privacy_authorization")
        if action in {"helper-lifecycle-register", "helper-lifecycle-unregister"}:
            return _decision(MUTATE_STATEFUL, "helper_login_lifecycle_registration_change")
        if action in {
            "open",
            "osascript",
            "semantic-press",
            "type-text",
            "key-press",
            "mouse-move",
            "mouse-click",
            "helper-accessibility-action-test",
            "helper-mouse-nudge",
        }:
            return _decision(MUTATE_STATEFUL, "gui_state_change")

    if family == "control":
        if action == "check":
            return _decision(READ_ONLY, "transport_control_query")
        if action in {"warm", "stop"}:
            return _decision(MUTATE_STATEFUL, "transport_connection_state_change")

    return _decision(
        FORBIDDEN_BY_POLICY,
        "unknown_typed_operation_fail_closed",
        allowed=False,
    )


def _normalize_shell(command: str) -> str:
    text = unicodedata.normalize("NFKC", command or "").casefold()
    text = text.replace("\\\n", " ")
    return re.sub(r"[\t\r ]+", " ", text)


def _shell_tokens(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


def _softwareupdate_flags(tokens: list[str]) -> tuple[bool, bool, bool]:
    """Return (mutating, broad_or_major, safari_only)."""
    mutating = False
    broad = False
    safari_only = False
    for token in tokens:
        if token == "--safari-only":
            safari_only = True
        if token in {"--install", "--download", "--fetch-full-installer", "--launch-installer"}:
            mutating = True
        if token in {"--all", "--recommended", "--fetch-full-installer", "--launch-installer"}:
            broad = True
        if token.startswith("-") and not token.startswith("--") and len(token) > 1:
            chars = set(token[1:])
            if chars.intersection({"i", "d"}):
                mutating = True
            if chars.intersection({"a", "r"}):
                broad = True
    return mutating, broad, safari_only


def evaluate_break_glass(command: str, context: str, cfg: dict | None = None) -> PolicyDecision:
    """Evaluate generic shell/script/job content.

    Generic shell remains BREAK_GLASS even when allowed. This scanner is a
    conservative defense-in-depth guard for the owner's explicit macOS update
    prohibition; it is not presented as a complete shell sandbox.
    """
    cfg = dict(cfg or {})
    allow_system = bool(cfg.get("allow_macos_system_update", False))
    allow_major = bool(cfg.get("allow_macos_major_upgrade", False))
    text = _normalize_shell(command)
    tokens = _shell_tokens(text)

    has_softwareupdate = "softwareupdate" in text or any("softwareupdate" in token for token in tokens)
    mutating, broad, safari_only = _softwareupdate_flags(tokens)
    # Also inspect the normalized raw text because nested `sh -c "..."`
    # keeps the inner command as one shlex token. This remains deliberately
    # conservative for the owner's hard OS-update prohibition.
    mutating = mutating or any(flag in text for flag in (
        "--install", "--download", "--fetch-full-installer", "--launch-installer"
    )) or bool(re.search(r"(?:^|\s)-[a-z]*[id][a-z]*(?:\s|$)", text))
    broad = broad or any(flag in text for flag in (
        "--all", "--recommended", "--fetch-full-installer", "--launch-installer"
    )) or bool(re.search(r"(?:^|\s)-[a-z]*[ar][a-z]*(?:\s|$)", text))
    safari_only = safari_only or "--safari-only" in text
    has_shell_composition = bool(re.search(r"(?:;|&&|\|\||\||\n|`|\$\()", text))
    has_shell_wrapper = bool(re.search(r"(?:^|\s)(?:/bin/)?(?:sh|bash|zsh)\s+-c(?:\s|$)|(?:^|\s)eval(?:\s|$)", text))
    softwareupdate_count = text.count("softwareupdate") or sum("softwareupdate" in token for token in tokens)
    os_marker = _contains_os_marker(text)

    if has_softwareupdate and mutating:
        safe_safari = (
            safari_only
            and not broad
            and not os_marker
            and not has_shell_composition
            and not has_shell_wrapper
            and softwareupdate_count == 1
        )
        if safe_safari:
            return _decision(BREAK_GLASS, "break_glass_explicit_safari_only", source="break_glass")
        if not allow_system:
            return _decision(FORBIDDEN_BY_POLICY, "macos_system_update_policy", allowed=False, source="break_glass")
        if (broad or os_marker) and not allow_major:
            return _decision(FORBIDDEN_BY_POLICY, "macos_major_upgrade_policy", allowed=False, source="break_glass")

    major_installer_markers = (
        "startosinstall",
        "installassistant.pkg",
        "install macos",
        "--fetch-full-installer",
        "--launch-installer",
    )
    if any(marker in text for marker in major_installer_markers) and not allow_major:
        return _decision(FORBIDDEN_BY_POLICY, "macos_major_upgrade_policy", allowed=False, source="break_glass")

    return _decision(BREAK_GLASS, f"generic_shell_break_glass:{context}", source="break_glass")


def policy_status(cfg: dict | None = None) -> dict:
    cfg = dict(cfg or {})
    return {
        "status": "PASS",
        "schema": POLICY_SCHEMA_VERSION,
        "risk_classes": list(RISK_CLASSES),
        "fail_closed_unknown_typed_operation": True,
        "generic_shell_class": BREAK_GLASS,
        "allow_macos_system_update": bool(cfg.get("allow_macos_system_update", False)),
        "allow_macos_major_upgrade": bool(cfg.get("allow_macos_major_upgrade", False)),
        "safari_only_explicit_path": "ALLOWED",
    }
