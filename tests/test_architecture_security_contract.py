import json
import unittest

from architecture_security_contract import (
    PHASE,
    SCHEMA_VERSION,
    architecture_security_contract,
)
from host_native_runtime_capability_watch import (
    current_project_baseline,
    runtime_watch_capabilities,
)


class ArchitectureSecurityContractTests(unittest.TestCase):
    def setUp(self):
        self.contract = architecture_security_contract()

    def test_contract_is_deterministic_and_json_safe(self):
        first = architecture_security_contract()
        second = architecture_security_contract()
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], SCHEMA_VERSION)
        self.assertEqual(first["phase"], PHASE)
        self.assertEqual(first["status"], "PASS")
        self.assertTrue(first["side_effect_free"])
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )

    def test_remote_gateway_topology_is_frozen(self):
        topology = self.contract["topology"]
        self.assertEqual(topology["runtime_mode"], "REMOTE_SSH")
        self.assertEqual(topology["local_macos_direct_host"], "PAUSED_BY_PROJECT_SCOPE")
        self.assertEqual(topology["auto_backend_selection"], "PAUSED_BY_PROJECT_SCOPE")
        self.assertIn("Linux_gateway_hermes_vm", topology["control_path"])
        self.assertIn("pinned_OpenSSH", topology["control_path"])
        self.assertEqual(topology["remote_linux_control_path"][1], "production_mac_gateway")
        self.assertIn("explicit_remote_linux_target", topology["remote_linux_control_path"])
        self.assertFalse(topology["remote_linux_private_key_material_on_hermes"])

    def test_current_product_scope_moves_to_browser_after_r3(self):
        scope = self.contract["product_scope"]
        self.assertIn("PRODUCTION_WORKSTATION_CONTROL", scope["completed_priorities"])
        self.assertIn("REMOTE_LINUX_ROOT_OPERATIONS", scope["completed_priorities"])
        self.assertEqual(scope["current_priority_order"][0], "BROWSER_PRODUCTION_AUTOMATION")
        self.assertEqual(scope["current_priority_order"][1], "WECHAT_FEISHU_DELEGATED_MESSAGING")
        self.assertEqual(
            scope["optional_backlog"]["NEW_MAC_BOOTSTRAP_ORCHESTRATOR"],
            "WAITING_FOR_SECOND_MAC",
        )
        self.assertEqual(
            scope["optional_backlog"]["PHYSICAL_ETHERNET_WIFI_FAILOVER_QUALIFICATION"],
            "NOT_CURRENT_PRIORITY",
        )
        self.assertIn("COLD_POWER_OOB_RECOVERY", scope["removed_from_scope"])
        self.assertTrue(scope["scope_change_does_not_rewrite_historical_qualification"])

    def test_multi_target_trust_material_cannot_alias(self):
        multi = self.contract["multi_target_invariants"]
        self.assertEqual(multi["unknown_explicit_target_fallback"], "FORBIDDEN")
        self.assertEqual(multi["legacy_production_endpoint_alias"], "FORBIDDEN")
        self.assertEqual(multi["per_target_identity_reuse"], "FORBIDDEN")
        self.assertEqual(multi["per_target_known_hosts_reuse"], "FORBIDDEN")
        self.assertEqual(multi["per_target_ssh_config_reuse"], "FORBIDDEN")
        self.assertFalse(multi["host_key_scan_is_trust"])
        self.assertTrue(multi["host_key_out_of_band_verification_required"])
        self.assertEqual(multi["existing_target_pass_inheritance"], "FORBIDDEN")
        self.assertEqual(multi["remote_linux_unknown_target_fallback"], "FORBIDDEN")
        self.assertEqual(multi["remote_linux_cross_target_credential_body_copy"], "FORBIDDEN")
        self.assertEqual(multi["remote_linux_cross_target_evidence_inheritance"], "FORBIDDEN")
        remote_linux = next(
            item for item in self.contract["trust_boundaries"] if item["id"] == "TB10"
        )
        self.assertIn("PRIVATE_KEY_BODY_STAYS_ON_MAC", remote_linux["rule"])

    def test_bootstrap_bundle_never_grants_stateful_authority(self):
        bootstrap = self.contract["bootstrap_invariants"]
        self.assertEqual(bootstrap["bundle_type"], "SOURCE_ONLY")
        self.assertFalse(bootstrap["secret_material_in_bundle"])
        self.assertFalse(bootstrap["target_mutation_authorized_by_bundle"])
        self.assertFalse(bootstrap["final_adhoc_signing_accepted"])
        self.assertTrue(bootstrap["target_local_durable_signing_required"])
        self.assertTrue(bootstrap["real_new_target_requires_fresh_explicit_authorization"])

    def test_attachment_contract_matches_live_watch_safety_rules(self):
        attachment = self.contract["attachment_invariants"]
        watch = runtime_watch_capabilities()
        baseline = current_project_baseline()
        self.assertTrue(attachment["native_downloadable_attachment_required_for_grade_a"])
        self.assertTrue(attachment["explicit_user_visible_confirmation_required"])
        self.assertFalse(attachment["automatic_inline_render_required"])
        self.assertFalse(attachment["raw_runtime_file_reference_persisted"])
        self.assertFalse(attachment["new_runtime_candidate_can_self_qualify"])
        self.assertTrue(attachment["verified_runtime_regression_fails_closed"])
        self.assertFalse(watch["raw_file_reference_allowed"])
        self.assertFalse(watch["capability_candidate_can_set_production_grade_a_ready"])
        self.assertTrue(watch["user_visible_attachment_confirmation_required"])
        self.assertTrue(watch["verified_grade_a_regression_fails_closed"])
        self.assertTrue(baseline["production_grade_a_ready"])
        self.assertEqual(
            baseline["ordinary_chat_grade_a"],
            "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED",
        )

    def test_high_impact_authority_is_never_inherited(self):
        gates = self.contract["authorization_gates"]
        self.assertEqual(
            set(gates.values()),
            {"FRESH_EXPLICIT_AUTHORIZATION_REQUIRED"},
        )
        continuity = next(
            item for item in self.contract["trust_boundaries"] if item["id"] == "TB09"
        )
        self.assertEqual(
            continuity["rule"],
            "CONTINUITY_RESTORES_KNOWLEDGE_NOT_AUTHORIZATION",
        )

    def test_existing_non_claims_remain_explicit(self):
        claims = set(self.contract["explicit_non_claims"])
        self.assertIn("RECURSIVE_TRANSFER_WHOLE_TREE_ATOMICITY", claims)
        self.assertIn("PHYSICAL_ETHERNET_WIFI_FAILOVER_QUALIFICATION", claims)
        self.assertIn("REAL_SECOND_MAC_STATEFUL_BOOTSTRAP_QUALIFICATION", claims)
        self.assertIn("ARBITRARY_AUTHENTICATED_SITE_GENERALIZATION", claims)
        self.assertIn("NETWORK_SUBRESOURCE_EGRESS_CONTAINMENT", claims)

    def test_regression_rules_are_fail_closed(self):
        rules = self.contract["regression_rules"]
        self.assertEqual(rules["unknown_typed_operation"], "FAIL_CLOSED")
        self.assertEqual(rules["indeterminate_transaction_replay"], "DO_NOT_REPEAT_MUTATION")
        self.assertEqual(
            rules["verified_grade_a_attachment_regression"],
            "FAIL_CLOSED_REQUALIFICATION_REQUIRED",
        )
        self.assertEqual(rules["host_key_mismatch"], "DO_NOT_AUTO_REPLACE_TRUST")
        self.assertEqual(rules["target_identity_or_endpoint_alias"], "FAIL_CLOSED")
        self.assertEqual(rules["immutable_release_tag_move"], "FORBIDDEN")


if __name__ == "__main__":
    unittest.main()
