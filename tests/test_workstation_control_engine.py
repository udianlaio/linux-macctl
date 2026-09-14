import unittest

from workstation_control_engine import (
    LIVE_EVIDENCE_SCHEMA,
    REQUIRED_APPS,
    REQUIRED_TOOLS,
    WORKSTATION_SCHEMA,
    evaluate_workstation_live_evidence,
    evaluate_workstation_observation,
    workstation_profile_contract,
)


class WorkstationControlEngineTests(unittest.TestCase):
    def complete_observation(self):
        return {
            "tools": {name: {"available": True} for name in REQUIRED_TOOLS},
            "apps": {name: {"available": True} for name in REQUIRED_APPS},
            "runtime_assets": {"production_python_venv": {"available": True}},
            "specialized_optional": {
                "full_xcode": False,
                "developer_id_signing": False,
                "notarization": False,
            },
            "network_contact_performed": True,
        }

    def complete_live_evidence(self):
        required = workstation_profile_contract()["live_qualification_required"]
        return {
            "schema": LIVE_EVIDENCE_SCHEMA,
            "profile": "GENERAL_PRODUCTION_WORKSTATION",
            "target": "macmini",
            "checks": {
                name: {"status": "PASS", "evidence": f"evidence:{name}"}
                for name in required
            },
            "artifact": {
                "size_bytes": 1136,
                "sha256": "f" * 64,
                "exact_pull_verified": True,
            },
            "security_policy_mutation_performed": False,
        }

    def test_contract_is_general_profile_and_keeps_specialized_apple_gates_optional(self):
        c = workstation_profile_contract()
        self.assertEqual(c["schema"], WORKSTATION_SCHEMA)
        self.assertEqual(c["profile"], "GENERAL_PRODUCTION_WORKSTATION")
        self.assertEqual(c["live_evidence_schema"], LIVE_EVIDENCE_SCHEMA)
        self.assertFalse(c["boundaries"]["full_xcode_required_for_general_profile"])
        self.assertTrue(c["boundaries"]["apple_account_gate_must_not_be_faked"])
        self.assertTrue(c["boundaries"]["notarization_boolean_requires_authenticated_credential_probe"])
        self.assertTrue(c["boundaries"]["notarytool_binary_presence_is_not_notarization_readiness"])
        self.assertIn("artifact_exact_pull_and_return", c["live_qualification_required"])

    def test_complete_inventory_is_not_live_qualification(self):
        r = evaluate_workstation_observation(self.complete_observation())
        self.assertEqual(r["status"], "PASS")
        self.assertTrue(r["production_workstation_inventory_ready"])
        self.assertFalse(r["production_workstation_live_qualified"])
        self.assertEqual(r["qualification_state"], "INVENTORY_READY_LIVE_QUALIFICATION_REQUIRED")
        self.assertEqual(r["live_qualification"]["qualification_state"], "LIVE_EVIDENCE_MISSING")
        self.assertTrue(r["network_contact_performed"])
        self.assertFalse(r["stateful_mutation_performed"])

    def test_complete_live_evidence_qualifies_expected_target(self):
        evidence = self.complete_live_evidence()
        r = evaluate_workstation_live_evidence(evidence, expected_target="macmini")
        self.assertEqual(r["status"], "PASS")
        self.assertTrue(r["production_workstation_live_qualified"])
        self.assertTrue(r["artifact_verified"])
        self.assertEqual(r["missing_checks"], [])

    def test_observation_becomes_live_qualified_only_with_complete_evidence(self):
        r = evaluate_workstation_observation(
            self.complete_observation(),
            live_evidence=self.complete_live_evidence(),
            expected_target="macmini",
        )
        self.assertEqual(r["qualification_state"], "LIVE_QUALIFIED")
        self.assertTrue(r["production_workstation_inventory_ready"])
        self.assertTrue(r["production_workstation_live_qualified"])

    def test_live_evidence_fails_closed_on_missing_check(self):
        evidence = self.complete_live_evidence()
        evidence["checks"].pop("container_run")
        r = evaluate_workstation_live_evidence(evidence, expected_target="macmini")
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn("container_run", r["missing_checks"])
        self.assertFalse(r["production_workstation_live_qualified"])

    def test_live_evidence_fails_closed_on_target_mismatch(self):
        r = evaluate_workstation_live_evidence(self.complete_live_evidence(), expected_target="other-mac")
        self.assertEqual(r["status"], "BLOCKED")
        self.assertFalse(r["target_match"])
        self.assertFalse(r["production_workstation_live_qualified"])

    def test_live_evidence_requires_exact_artifact_proof(self):
        evidence = self.complete_live_evidence()
        evidence["artifact"]["exact_pull_verified"] = False
        r = evaluate_workstation_live_evidence(evidence, expected_target="macmini")
        self.assertEqual(r["status"], "BLOCKED")
        self.assertFalse(r["artifact_verified"])

    def test_missing_required_tool_fails_closed(self):
        o = self.complete_observation()
        o["tools"]["node"]["available"] = False
        r = evaluate_workstation_observation(o)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn("node", r["missing_tools"])

    def test_missing_vscode_fails_closed(self):
        o = self.complete_observation()
        o["apps"]["vscode"]["available"] = False
        r = evaluate_workstation_observation(o)
        self.assertIn("vscode", r["missing_apps"])
        self.assertFalse(r["production_workstation_inventory_ready"])

    def test_full_xcode_not_required_for_general_profile(self):
        o = self.complete_observation()
        o["specialized_optional"]["full_xcode"] = False
        r = evaluate_workstation_observation(o)
        self.assertEqual(r["status"], "PASS")
        self.assertFalse(r["specialized_optional"]["full_xcode"])


if __name__ == "__main__":
    unittest.main()
