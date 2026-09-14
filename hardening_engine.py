from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Iterable


SCHEMA = "macctl-host-hardening/v1"


@dataclass(frozen=True)
class HostHardeningSnapshot:
    filevault: str
    firewall: str
    firewall_block_all: str
    firewall_stealth: str
    firewall_allow_signed_builtin: str
    firewall_allow_signed_downloaded: str
    remote_login: str
    wake_on_network_access: str
    macos: str | None = None
    build: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def _enabled_disabled(text: str, enabled_markers: Iterable[str], disabled_markers: Iterable[str]) -> str:
    low = (text or "").casefold()
    if any(marker.casefold() in low for marker in enabled_markers):
        return "ENABLED"
    if any(marker.casefold() in low for marker in disabled_markers):
        return "DISABLED"
    return "UNKNOWN"


def parse_probe_output(text: str, *, macos: str | None = None, build: str | None = None) -> HostHardeningSnapshot:
    sections: dict[str, str] = {}
    current = None
    for raw in (text or "").splitlines():
        if raw.startswith("@@") and raw.endswith("@@") and len(raw) > 4:
            current = raw[2:-2]
            sections.setdefault(current, "")
            continue
        if current:
            sections[current] += raw + "\n"

    filevault_raw = sections.get("FILEVAULT", "")
    firewall_raw = sections.get("FIREWALL_GLOBAL", "")
    block_raw = sections.get("FIREWALL_BLOCK_ALL", "")
    stealth_raw = sections.get("FIREWALL_STEALTH", "")
    signed_raw = sections.get("FIREWALL_ALLOW_SIGNED", "")
    remote_raw = sections.get("REMOTE_LOGIN", "")
    pmset_raw = sections.get("PMSET_CUSTOM", "")

    filevault = _enabled_disabled(
        filevault_raw,
        ["filevault is on"],
        ["filevault is off"],
    )
    firewall = _enabled_disabled(
        firewall_raw,
        ["state = 1", "enabled"],
        ["state = 0", "disabled"],
    )
    block_all = _enabled_disabled(
        block_raw,
        ["block all state = 1", "state = 1", "enabled"],
        ["block all state = 0", "state = 0", "disabled", "state is off"],
    )
    stealth = _enabled_disabled(
        stealth_raw,
        ["stealth mode enabled", "stealth mode is on", "state = 1", "enabled"],
        ["stealth mode disabled", "stealth mode is off", "state = 0", "disabled"],
    )
    allow_signed = _enabled_disabled(
        signed_raw,
        ["automatically allow signed built-in software enabled"],
        ["automatically allow signed built-in software disabled"],
    )
    allow_downloaded = _enabled_disabled(
        signed_raw,
        ["automatically allow downloaded signed software enabled"],
        ["automatically allow downloaded signed software disabled"],
    )
    remote_login = _enabled_disabled(
        remote_raw,
        ["remote login: on", "remote login is on"],
        ["remote login: off", "remote login is off"],
    )

    womp_match = re.search(r"(?m)^\s*womp\s+(\d+)\s*$", pmset_raw)
    if womp_match:
        wake = "ENABLED" if womp_match.group(1) == "1" else "DISABLED"
    else:
        wake = "UNKNOWN"

    if macos is None:
        macos = sections.get("MACOS", "").strip() or None
    if build is None:
        build = sections.get("BUILD", "").strip() or None

    return HostHardeningSnapshot(
        filevault=filevault,
        firewall=firewall,
        firewall_block_all=block_all,
        firewall_stealth=stealth,
        firewall_allow_signed_builtin=allow_signed,
        firewall_allow_signed_downloaded=allow_downloaded,
        remote_login=remote_login,
        wake_on_network_access=wake,
        macos=macos,
        build=build,
    )


def evaluate_hardening(snapshot: HostHardeningSnapshot) -> dict:
    blockers = []
    if snapshot.remote_login != "ENABLED":
        blockers.append("remote_login_not_confirmed_enabled")
    if snapshot.wake_on_network_access != "ENABLED":
        blockers.append("wake_on_network_access_not_confirmed_enabled")
    if snapshot.firewall == "UNKNOWN":
        blockers.append("firewall_state_unknown")

    if snapshot.firewall == "DISABLED" and not blockers:
        firewall_gate = "READY_FOR_EXPLICIT_AUTHORIZATION"
    elif snapshot.firewall == "ENABLED" and not blockers:
        firewall_gate = "ALREADY_ENABLED_REVIEW_CURRENT_RULES"
    else:
        firewall_gate = "BLOCKED_BY_PREFLIGHT"

    return {
        "schema": SCHEMA,
        "status": "PASS" if not blockers else "DEGRADED",
        "snapshot": snapshot.as_dict(),
        "firewall_qualification": {
            "gate": firewall_gate,
            "requires_explicit_authorization": True,
            "requires_rollback_plan": True,
            "requires_fresh_ssh_validation": True,
            "requires_wol_validation": True,
            "requires_gui_validation": True,
            "requires_reboot_validation": True,
            "reboot_requires_separate_authorization": True,
            "candidate_change": "GLOBAL_FIREWALL_ON_ONLY_PRESERVE_OTHER_OPTIONS",
            "blockers": blockers,
        },
        "filevault_qualification": {
            "gate": "NOT_IN_SCOPE_BY_PROJECT_POLICY",
            "requires_explicit_authorization": True,
            "reason": "must_not_change_without_proving_existing_headless_recovery_semantics",
        },
        "physical_power_on_qualification": {
            "gate": "NOT_IN_SCOPE",
            "reason": "separate_out_of_band_power_recovery_project",
        },
    }
