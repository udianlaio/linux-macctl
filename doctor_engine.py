#!/usr/bin/env python3
"""Deterministic readiness evaluation for macctl doctor.

The live probe collection remains in macctl.py. This module only consumes a
plain dict of already-collected facts so recovery semantics are unit-testable
without SSH, TCC, GUI or GitHub side effects.
"""
from __future__ import annotations

DOCTOR_SCHEMA_VERSION = "macctl-doctor/v1"

READINESS_ORDER = (
    "VM_READY",
    "SSH_READY",
    "HEADLESS_READY",
    "GUI_SESSION_READY",
    "HELPER_READY",
    "TCC_READY",
    "AX_READY",
    "SCREEN_CAPTURE_READY",
    "VISION_READY",
    "POLICY_READY",
    "GITHUB_SYNC_READY",
    "BACKUP_READY",
    "FULL_READY",
)


def _b(probes: dict, key: str) -> bool:
    return bool(probes.get(key, False))


def evaluate_doctor(probes: dict) -> dict:
    """Evaluate doctor probes into stable recovery states.

    LOGIN_REQUIRED is an expected recovery condition, not a machine failure:
    headless control is already available but the configured owner has not yet
    established the macOS GUI session. Downstream GUI layers are therefore
    intentionally not treated as independent faults in that state.
    """
    p = dict(probes or {})
    expected_user = str(p.get("expected_user") or "")
    console_user = str(p.get("console_user") or "")

    vm_ready = _b(p, "vm_runtime")
    ssh_ready = vm_ready and _b(p, "tcp22") and _b(p, "fresh_publickey")
    headless_ready = ssh_ready and _b(p, "sudo_nopasswd") and _b(p, "remote_identity")

    if not vm_ready:
        transport_state = "LOCAL_RUNTIME_NOT_READY"
    elif not _b(p, "tcp22"):
        transport_state = "TCP22_UNREACHABLE"
    elif not _b(p, "fresh_publickey"):
        transport_state = "PUBLICKEY_AUTH_NOT_READY"
    else:
        transport_state = "SSH_AUTHENTICATED"

    expected_console_user = bool(expected_user) and console_user == expected_user
    gui_session_ready = headless_ready and expected_console_user and _b(p, "gui_domain")
    login_required = headless_ready and not gui_session_ready and console_user in {
        "", "root", "loginwindow", "_mbsetupuser", "unknown"
    }

    helper_ready = (
        gui_session_ready
        and _b(p, "helper_probe")
        and _b(p, "helper_service_enabled")
        and _b(p, "helper_marker_current_boot")
    )
    tcc_ready = (
        helper_ready
        and _b(p, "tcc_accessibility_allow")
        and _b(p, "tcc_screen_capture_allow")
        and _b(p, "tcc_finder_automation_allow")
        and _b(p, "tcc_systemevents_automation_allow")
        and _b(p, "tcc_runtime_automation_probe")
    )
    ax_ready = tcc_ready and _b(p, "ax_probe")
    screen_ready = tcc_ready and _b(p, "screen_capture_probe")
    vision_ready = screen_ready and _b(p, "vision_probe")

    policy_ready = (
        vm_ready
        and _b(p, "policy_fail_closed")
        and _b(p, "policy_system_update_blocked")
        and _b(p, "policy_major_upgrade_blocked")
    )
    github_ready = (
        vm_ready
        and _b(p, "github_repo_present")
        and _b(p, "github_branch_main")
        and _b(p, "github_sync_path_active")
        and _b(p, "github_sync_path_enabled")
        and _b(p, "github_sync_timer_active")
        and _b(p, "github_sync_timer_enabled")
        and _b(p, "github_remote_reachable")
        and _b(p, "github_remote_matches_head")
    )
    backup_ready = vm_ready and _b(p, "backup_health")

    full_ready = all((
        vm_ready,
        ssh_ready,
        headless_ready,
        gui_session_ready,
        helper_ready,
        tcc_ready,
        ax_ready,
        screen_ready,
        vision_ready,
        policy_ready,
        github_ready,
        backup_ready,
    ))

    readiness = {
        "VM_READY": vm_ready,
        "SSH_READY": ssh_ready,
        "HEADLESS_READY": headless_ready,
        "LOGIN_REQUIRED": login_required,
        "GUI_SESSION_READY": gui_session_ready,
        "HELPER_READY": helper_ready,
        "TCC_READY": tcc_ready,
        "AX_READY": ax_ready,
        "SCREEN_CAPTURE_READY": screen_ready,
        "VISION_READY": vision_ready,
        "POLICY_READY": policy_ready,
        "GITHUB_SYNC_READY": github_ready,
        "BACKUP_READY": backup_ready,
        "FULL_READY": full_ready,
    }

    if full_ready:
        overall_state = "FULL_READY"
        status = "PASS"
        exit_code = 0
        recovery_hint = "none"
    elif login_required:
        overall_state = "LOGIN_REQUIRED"
        status = "WAITING"
        exit_code = 0
        recovery_hint = "normal_user_login_required_no_auto_login"
    elif not vm_ready:
        overall_state = "VM_NOT_READY"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "repair_vm_runtime_before_remote_recovery"
    elif not ssh_ready:
        overall_state = "SSH_NOT_READY"
        status = "FAIL"
        exit_code = 1
        if transport_state == "TCP22_UNREACHABLE":
            recovery_hint = "restore_lan_route_or_tcp22_without_changing_pinned_auth"
        else:
            recovery_hint = "restore_pinned_publickey_auth_without_bypassing_hostkey_verification"
    elif not headless_ready:
        overall_state = "HEADLESS_DEGRADED"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "restore_sudo_nopasswd_or_remote_identity_without_gui_changes"
    elif not gui_session_ready:
        overall_state = "GUI_SESSION_NOT_READY"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "verify_expected_console_user_and_gui_domain_do_not_enable_auto_login"
    elif not helper_ready:
        overall_state = "HELPER_NOT_READY"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "repair_helper_login_item_or_current_boot_marker_preserve_signing_identity"
    elif not tcc_ready:
        overall_state = "TCC_NOT_READY"
        status = "FAIL"
        exit_code = 2
        recovery_hint = "user_review_tcc_grants_do_not_reset_tcc_automatically"
    elif not ax_ready:
        overall_state = "AX_NOT_READY"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "revalidate_accessibility_probe_without_bypassing_tcc"
    elif not screen_ready:
        overall_state = "SCREEN_CAPTURE_NOT_READY"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "revalidate_screencapturekit_and_screen_recording_grant"
    elif not vision_ready:
        overall_state = "VISION_NOT_READY"
        status = "FAIL"
        exit_code = 1
        recovery_hint = "revalidate_apple_vision_ocr_after_capture_layer"
    elif not policy_ready:
        overall_state = "POLICY_NOT_READY"
        status = "FAIL"
        exit_code = 77
        recovery_hint = "restore_fail_closed_policy_and_keep_system_major_updates_blocked"
    elif not github_ready:
        overall_state = "GITHUB_SYNC_NOT_READY"
        status = "DEGRADED"
        exit_code = 1
        recovery_hint = "repair_verified_commit_sync_without_auto_committing_dirty_state"
    else:
        overall_state = "BACKUP_NOT_READY"
        status = "DEGRADED"
        exit_code = 1
        recovery_hint = "repair_committed_source_backup_without_copying_runtime_credentials"

    # Highest sequential readiness is useful in recovery logs even if an
    # independent later layer (policy/GitHub sync) is the actual blocker.
    highest = "NONE"
    for stage in READINESS_ORDER:
        if readiness.get(stage):
            highest = stage
        else:
            break

    blockers = []
    if not login_required:
        for stage in READINESS_ORDER[:-1]:
            if not readiness.get(stage):
                blockers.append(stage)

    return {
        "schema": DOCTOR_SCHEMA_VERSION,
        "status": status,
        "overall_state": overall_state,
        "transport_state": transport_state,
        "highest_ready_stage": highest,
        "readiness": readiness,
        "blocking_stages": blockers,
        "recovery_hint": recovery_hint,
        "exit_code": exit_code,
    }
