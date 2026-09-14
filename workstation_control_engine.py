#!/usr/bin/env python3
"""Machine-readable production-workstation qualification contract.

This module is intentionally side-effect free. Installation remains an explicit
operator-authorized action; the contract only describes and evaluates observed
runtime capabilities and explicit live qualification evidence for the selected
Mac target.
"""
from __future__ import annotations

import re

WORKSTATION_SCHEMA = "macctl-production-workstation/v1"
LIVE_EVIDENCE_SCHEMA = "macctl-production-workstation-live-evidence/v1"

REQUIRED_TOOLS = (
    "brew",
    "git",
    "git_lfs",
    "gh",
    "clang",
    "swift",
    "python312",
    "node",
    "npm",
    "go",
    "rustc",
    "cargo",
    "java",
    "javac",
    "maven",
    "gradle",
    "pnpm",
    "uv",
    "pipx",
    "cmake",
    "ninja",
    "pkg_config",
    "protoc",
    "shellcheck",
    "shfmt",
    "docker",
    "colima",
)

REQUIRED_APPS = (
    "safari",
    "chrome",
    "vscode",
)

SPECIALIZED_OPTIONAL = (
    "full_xcode",
    "developer_id_signing",
    "notarization",
)


def workstation_profile_contract() -> dict:
    return {
        "schema": WORKSTATION_SCHEMA,
        "phase": "V0.6-R2",
        "profile": "GENERAL_PRODUCTION_WORKSTATION",
        "required_tools": list(REQUIRED_TOOLS),
        "required_apps": list(REQUIRED_APPS),
        "required_runtime_assets": ["production_python_venv"],
        "specialized_optional": list(SPECIALIZED_OPTIONAL),
        "live_qualification_required": [
            "remote_source_create_edit",
            "c_build_run",
            "cpp_build_run",
            "swift_build_run",
            "python_common_dependency_import",
            "node_dependency_install_run",
            "go_build_test_run",
            "rust_build_test_run",
            "java_maven_dependency_build",
            "cmake_ninja_build_run",
            "git_create_commit",
            "container_run",
            "vscode_gui_open_and_observe",
            "artifact_exact_pull_and_return",
        ],
        "live_evidence_schema": LIVE_EVIDENCE_SCHEMA,
        "boundaries": {
            "full_xcode_required_for_general_profile": False,
            "developer_id_required_for_general_profile": False,
            "notarization_required_for_general_profile": False,
            "apple_account_gate_must_not_be_faked": True,
            "notarization_boolean_requires_authenticated_credential_probe": True,
            "notarytool_binary_presence_is_not_notarization_readiness": True,
            "system_update_required": False,
            "reboot_required": False,
        },
    }


def _missing_live_evidence_result(expected_target: str | None = None) -> dict:
    return {
        "schema": LIVE_EVIDENCE_SCHEMA,
        "status": "BLOCKED",
        "qualification_state": "LIVE_EVIDENCE_MISSING",
        "production_workstation_live_qualified": False,
        "expected_target": expected_target,
        "observed_target": None,
        "schema_valid": False,
        "profile_valid": False,
        "target_match": False if expected_target else True,
        "missing_checks": list(workstation_profile_contract()["live_qualification_required"]),
        "malformed_checks": [],
        "artifact_verified": False,
        "reason": "canonical_live_evidence_missing",
    }


def evaluate_workstation_live_evidence(evidence: dict | None, *, expected_target: str | None = None) -> dict:
    if not isinstance(evidence, dict):
        return _missing_live_evidence_result(expected_target)

    contract = workstation_profile_contract()
    required = contract["live_qualification_required"]
    schema_valid = evidence.get("schema") == LIVE_EVIDENCE_SCHEMA
    profile_valid = evidence.get("profile") == contract["profile"]
    observed_target = str(evidence.get("target") or "") or None
    target_match = expected_target is None or observed_target == expected_target

    checks = evidence.get("checks") if isinstance(evidence.get("checks"), dict) else {}
    missing_checks = []
    malformed_checks = []
    for name in required:
        item = checks.get(name)
        if not isinstance(item, dict):
            missing_checks.append(name)
            continue
        if item.get("status") != "PASS":
            missing_checks.append(name)
        if not str(item.get("evidence") or "").strip():
            malformed_checks.append(name)

    artifact = evidence.get("artifact") if isinstance(evidence.get("artifact"), dict) else {}
    artifact_sha = str(artifact.get("sha256") or "").lower()
    try:
        artifact_size = int(artifact.get("size_bytes") or 0)
    except (TypeError, ValueError):
        artifact_size = 0
    artifact_verified = bool(
        artifact.get("exact_pull_verified") is True
        and artifact_size > 0
        and re.fullmatch(r"[0-9a-f]{64}", artifact_sha)
    )

    qualified = bool(
        schema_valid
        and profile_valid
        and target_match
        and not missing_checks
        and not malformed_checks
        and artifact_verified
    )
    reasons = []
    if not schema_valid:
        reasons.append("schema_mismatch")
    if not profile_valid:
        reasons.append("profile_mismatch")
    if not target_match:
        reasons.append("target_mismatch")
    if missing_checks:
        reasons.append("required_checks_missing_or_not_pass")
    if malformed_checks:
        reasons.append("required_check_evidence_missing")
    if not artifact_verified:
        reasons.append("artifact_exact_pull_not_verified")

    return {
        "schema": LIVE_EVIDENCE_SCHEMA,
        "status": "PASS" if qualified else "BLOCKED",
        "qualification_state": "LIVE_QUALIFIED" if qualified else "LIVE_EVIDENCE_INCOMPLETE",
        "production_workstation_live_qualified": qualified,
        "expected_target": expected_target,
        "observed_target": observed_target,
        "schema_valid": schema_valid,
        "profile_valid": profile_valid,
        "target_match": target_match,
        "missing_checks": missing_checks,
        "malformed_checks": malformed_checks,
        "artifact_verified": artifact_verified,
        "artifact": {
            "size_bytes": artifact_size,
            "sha256": artifact_sha or None,
            "exact_pull_verified": bool(artifact.get("exact_pull_verified") is True),
        },
        "security_policy_mutation_performed": bool(evidence.get("security_policy_mutation_performed", False)),
        "reason": "qualified" if qualified else ",".join(reasons),
    }


def evaluate_workstation_observation(
    observed: dict,
    *,
    live_evidence: dict | None = None,
    expected_target: str | None = None,
) -> dict:
    tools = observed.get("tools") or {}
    apps = observed.get("apps") or {}
    runtime = observed.get("runtime_assets") or {}

    missing_tools = [name for name in REQUIRED_TOOLS if not bool((tools.get(name) or {}).get("available"))]
    missing_apps = [name for name in REQUIRED_APPS if not bool((apps.get(name) or {}).get("available"))]
    missing_runtime = [] if bool((runtime.get("production_python_venv") or {}).get("available")) else ["production_python_venv"]

    inventory_ready = not missing_tools and not missing_apps and not missing_runtime
    live = (
        evaluate_workstation_live_evidence(live_evidence, expected_target=expected_target)
        if live_evidence is not None
        else _missing_live_evidence_result(expected_target)
    )
    live_qualified = bool(inventory_ready and live["production_workstation_live_qualified"])
    qualification_state = (
        "LIVE_QUALIFIED"
        if live_qualified
        else "INVENTORY_READY_LIVE_QUALIFICATION_REQUIRED"
        if inventory_ready
        else "INVENTORY_INCOMPLETE"
    )
    return {
        "schema": WORKSTATION_SCHEMA,
        "status": "PASS" if inventory_ready else "BLOCKED",
        "qualification_state": qualification_state,
        "production_workstation_inventory_ready": inventory_ready,
        "production_workstation_live_qualified": live_qualified,
        "missing_tools": missing_tools,
        "missing_apps": missing_apps,
        "missing_runtime_assets": missing_runtime,
        "specialized_optional": {
            name: bool((observed.get("specialized_optional") or {}).get(name, False))
            for name in SPECIALIZED_OPTIONAL
        },
        "live_qualification": live,
        "network_contact_performed": bool(observed.get("network_contact_performed", False)),
        "stateful_mutation_performed": False,
        "note": "inventory readiness never substitutes for explicit live build/run/GUI/artifact qualification evidence",
    }
