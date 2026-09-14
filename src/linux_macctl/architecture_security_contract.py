"""Machine-readable V0.6 architecture and security invariants.

This module is deliberately side-effect free.  It describes the control-plane
trust model that later V0.6 phases must preserve; it does not authorize a
release, a new target, a network/security mutation, or any host action.
"""

from __future__ import annotations


SCHEMA_VERSION = "macctl-architecture-security-contract/v1"
PHASE = "V0.6-R0"


def architecture_security_contract() -> dict:
    """Return the deterministic V0.6 architecture/security contract."""

    return {
        "schema": SCHEMA_VERSION,
        "status": "PASS",
        "phase": PHASE,
        "contract_kind": "DESIGN_AND_REGRESSION_GATE_ONLY",
        "side_effect_free": True,
        "topology": {
            "control_path": [
                "ChatGPT_orchestrator",
                "SentinelX",
                "Linux_gateway_hermes_vm",
                "macctl_policy_transaction_runtime",
                "pinned_OpenSSH",
                "remote_mac_target",
            ],
            "runtime_mode": "REMOTE_SSH",
            "remote_linux_control_path": [
                "Linux_gateway_hermes_vm",
                "production_mac_gateway",
                "mac_user_ssh_config_and_credential_reference",
                "pinned_OpenSSH",
                "explicit_remote_linux_target",
            ],
            "remote_linux_private_key_material_on_hermes": False,
            "local_macos_direct_host": "PAUSED_BY_PROJECT_SCOPE",
            "auto_backend_selection": "PAUSED_BY_PROJECT_SCOPE",
        },
        "product_scope": {
            "completed_priorities": [
                "PRODUCTION_WORKSTATION_CONTROL",
                "REMOTE_LINUX_ROOT_OPERATIONS",
            ],
            "current_priority_order": [
                "BROWSER_PRODUCTION_AUTOMATION",
                "WECHAT_FEISHU_DELEGATED_MESSAGING",
                "WINDOWS_REVERSE_CONTROL",
            ],
            "optional_backlog": {
                "NEW_MAC_BOOTSTRAP_ORCHESTRATOR": "WAITING_FOR_SECOND_MAC",
                "PHYSICAL_ETHERNET_WIFI_FAILOVER_QUALIFICATION": "NOT_CURRENT_PRIORITY",
            },
            "removed_from_scope": ["COLD_POWER_OOB_RECOVERY"],
            "scope_change_does_not_rewrite_historical_qualification": True,
        },
        "trust_boundaries": [
            {
                "id": "TB01",
                "name": "orchestrator",
                "rule": "LLM_OR_CHAT_CONTEXT_IS_NOT_A_SECURITY_KERNEL_OR_AUTHORIZATION_SOURCE",
            },
            {
                "id": "TB02",
                "name": "linux_gateway",
                "rule": "VM_IS_THE_PROJECT_EXECUTION_AND_EVIDENCE_CONTROL_PLANE",
            },
            {
                "id": "TB03",
                "name": "policy_transaction",
                "rule": "UNKNOWN_TYPED_OPERATION_FAILS_CLOSED_AND_GENERIC_SHELL_IS_BREAK_GLASS",
            },
            {
                "id": "TB04",
                "name": "per_target_ssh_trust",
                "rule": "HOST_IDENTITY_AND_CLIENT_IDENTITY_ARE_TARGET_SCOPED_AND_MUST_NOT_ALIAS",
            },
            {
                "id": "TB05",
                "name": "mac_user_root",
                "rule": "REMOTE_LOGIN_IS_NON_ROOT_AND_PRIVILEGE_ESCALATION_IS_EXPLICIT_SUDO_N",
            },
            {
                "id": "TB06",
                "name": "gui_tcc_helper",
                "rule": "GUI_PRIVACY_AUTHORITY_IS_BOUND_TO_STABLE_HELPER_IDENTITY_AND_CURRENT_TARGET",
            },
            {
                "id": "TB07",
                "name": "artifact_delivery",
                "rule": "USER_VISIBLE_ATTACHMENT_SUCCESS_REQUIRES_EXACT_BYTES_AND_LIVE_SURFACE_QUALIFICATION",
            },
            {
                "id": "TB08",
                "name": "github_release_mirror",
                "rule": "IMMUTABLE_RELEASE_EVIDENCE_IS_RECOVERY_AUTHORITY_NOT_RUNTIME_SECRET_STORAGE",
            },
            {
                "id": "TB09",
                "name": "continuity",
                "rule": "CONTINUITY_RESTORES_KNOWLEDGE_NOT_AUTHORIZATION",
            },
            {
                "id": "TB10",
                "name": "remote_linux_mac_credential_gateway",
                "rule": "REMOTE_LINUX_PRIVATE_KEY_BODY_STAYS_ON_MAC; HERMES_STORES_ONLY_TARGET_AND_CREDENTIAL_REFERENCES",
            },
        ],
        "multi_target_invariants": {
            "explicit_nonproduction_selection_required": True,
            "unknown_explicit_target_fallback": "FORBIDDEN",
            "duplicate_target_id": "FORBIDDEN",
            "duplicate_host_port_endpoint": "FORBIDDEN",
            "legacy_production_endpoint_alias": "FORBIDDEN",
            "per_target_identity_reuse": "FORBIDDEN",
            "per_target_known_hosts_reuse": "FORBIDDEN",
            "per_target_ssh_config_reuse": "FORBIDDEN",
            "host_key_scan_is_trust": False,
            "host_key_out_of_band_verification_required": True,
            "existing_target_pass_inheritance": "FORBIDDEN",
            "remote_linux_unknown_target_fallback": "FORBIDDEN",
            "remote_linux_cross_target_credential_body_copy": "FORBIDDEN",
            "remote_linux_cross_target_evidence_inheritance": "FORBIDDEN",
        },
        "bootstrap_invariants": {
            "bundle_type": "SOURCE_ONLY",
            "secret_material_in_bundle": False,
            "target_mutation_authorized_by_bundle": False,
            "final_adhoc_signing_accepted": False,
            "target_local_durable_signing_required": True,
            "helper_install_is_target_stateful": True,
            "helper_registration_is_target_stateful": True,
            "tcc_workflow_is_target_stateful": True,
            "real_new_target_requires_fresh_explicit_authorization": True,
        },
        "attachment_invariants": {
            "native_downloadable_attachment_required_for_grade_a": True,
            "exact_original_sha256_and_size_required": True,
            "stable_conversation_reference_required": True,
            "same_reference_exact_redownload_required": True,
            "explicit_user_visible_confirmation_required": True,
            "automatic_inline_render_required": False,
            "raw_runtime_file_reference_persisted": False,
            "new_runtime_candidate_can_self_qualify": False,
            "verified_runtime_regression_fails_closed": True,
        },
        "authorization_gates": {
            "formal_release": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "reboot_or_shutdown": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "real_network_mutation_or_switching": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "firewall_filevault_macos_update_mutation": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "hermes_formal_mutation": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "first_real_new_target_stateful_bootstrap": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "remote_linux_reboot_shutdown": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
            "remote_linux_network_or_security_policy_mutation": "FRESH_EXPLICIT_AUTHORIZATION_REQUIRED",
        },
        "transport_and_transfer_claims": {
            "remote_ssh": "LIVE_QUALIFIED",
            "strict_host_key_pinning_required": True,
            "public_key_only_steady_state": True,
            "scp_regular_file_atomic_finalization": "LIVE_QUALIFIED",
            "scp_recursive_tree_atomicity": "NOT_CLAIMED",
            "rsync_per_file_partial_isolation": "LIVE_QUALIFIED",
            "rsync_tree_atomicity": "NOT_CLAIMED",
        },
        "explicit_non_claims": [
            "ARBITRARY_AUTHENTICATED_SITE_GENERALIZATION",
            "NETWORK_SUBRESOURCE_EGRESS_CONTAINMENT",
            "PHYSICAL_ETHERNET_WIFI_FAILOVER_QUALIFICATION",
            "REAL_SECOND_MAC_STATEFUL_BOOTSTRAP_QUALIFICATION",
            "RECURSIVE_TRANSFER_WHOLE_TREE_ATOMICITY",
            "LOCAL_MACOS_DIRECT_HOST_PRODUCTION_SUPPORT",
        ],
        "regression_rules": {
            "unknown_typed_operation": "FAIL_CLOSED",
            "indeterminate_transaction_replay": "DO_NOT_REPEAT_MUTATION",
            "verified_grade_a_attachment_regression": "FAIL_CLOSED_REQUALIFICATION_REQUIRED",
            "host_key_mismatch": "DO_NOT_AUTO_REPLACE_TRUST",
            "target_identity_or_endpoint_alias": "FAIL_CLOSED",
            "continuity_head_mismatch": "HOLD_STALE_TARGET",
            "immutable_release_tag_move": "FORBIDDEN",
        },
    }
