import copy
import unittest

from linux_macctl.host_native_runtime_capability_watch import (
    OBSERVATION_SCHEMA_VERSION,
    HostNativeRuntimeWatchError,
    current_project_baseline,
    evaluate_runtime_capability_watch,
    runtime_watch_capabilities,
)


class HostNativeRuntimeCapabilityWatchTests(unittest.TestCase):
    def setUp(self):
        self.baseline = current_project_baseline()
        self.observations = copy.deepcopy(self.baseline["surfaces"])

    def test_baseline_is_stable_and_live_grade_a_user_visible(self):
        first = current_project_baseline()
        second = current_project_baseline()
        self.assertEqual(first, second)
        self.assertEqual(first["baseline_fingerprint_sha256"], second["baseline_fingerprint_sha256"])
        self.assertTrue(first["production_grade_a_ready"])
        self.assertEqual(first["ordinary_chat_grade_a"], "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED")
        self.assertEqual(first["qualification_origin"], "PM3_LIVE_USER_VISIBLE_ATTACHMENT_EXPLICIT_FEEDBACK")
        self.assertEqual(first["qualification_evidence_sha256"], "db148196db26a9d41e60846e3d4b9fb341b2959e4192f7aaefc3041bab230059")
        self.assertEqual(first["verified_grade_a_surface_keys"], ["CHATGPT_CONVERSATION_FILE_RELAY::chatgpt-ordinary-chat"])
        self.assertEqual(first["backend_native_qualified_surface_keys"], ["CHATGPT_CONVERSATION_FILE_RELAY::chatgpt-ordinary-chat"])
        self.assertEqual(first["user_visible_attachment"], "CONFIRMED_DOWNLOADABLE_AND_CLICK_PREVIEW")

    def test_current_baseline_reports_live_grade_a(self):
        result = evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(result["watch_state"], "NO_CHANGE_LIVE_GRADE_A_QUALIFIED")
        self.assertEqual(result["live_verifier_handoff"], "NO_GRADE_A_HANDOFF")
        self.assertTrue(result["production_grade_a_ready"])
        self.assertTrue(result["verified_grade_a_baseline_intact"])
        self.assertTrue(result["backend_native_baseline_intact"])
        self.assertEqual(result["ordinary_chat_grade_a"], "GRADE_A_USER_VISIBLE_ATTACHMENT_QUALIFIED")
        self.assertEqual(result["missing_baseline_surfaces"], [])

    def test_complete_native_candidate_opens_verifier_only(self):
        candidate = self.observations[1]
        candidate["discovery_origin"] = "LIVE_TOOL_SCHEMA"
        candidate["native_file_return_primitive"] = True
        candidate["native_conversation_reference"] = True
        candidate["host_receipt_digest"] = True
        candidate["same_reference_redownload"] = True
        result = evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(result["watch_state"], "NATIVE_RUNTIME_CAPABILITY_CANDIDATE_DETECTED")
        self.assertEqual(result["live_verifier_handoff"], "R2_LIVE_RUNTIME_VERIFIER_REQUIRED")
        self.assertTrue(result["production_grade_a_ready"])
        self.assertTrue(result["verified_grade_a_baseline_intact"])
        self.assertTrue(result["backend_native_baseline_intact"])
        self.assertTrue(result["unverified_native_candidate_surfaces"])

    def test_synthetic_candidate_still_cannot_set_grade_a(self):
        candidate = self.observations[0]
        candidate["discovery_origin"] = "SYNTHETIC_TEST"
        for field in (
            "native_file_return_primitive",
            "native_conversation_reference",
            "host_receipt_digest",
            "same_reference_redownload",
        ):
            candidate[field] = True
        result = evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(result["watch_state"], "NATIVE_RUNTIME_CAPABILITY_CANDIDATE_DETECTED")
        self.assertTrue(result["production_grade_a_ready"])
        self.assertTrue(result["verified_grade_a_baseline_intact"])
        self.assertTrue(result["backend_native_baseline_intact"])

    def test_partial_native_signal_is_not_ready_for_verifier(self):
        candidate = self.observations[1]
        candidate["discovery_origin"] = "LIVE_TOOL_SCHEMA"
        candidate["native_file_return_primitive"] = True
        result = evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(result["watch_state"], "PARTIAL_NATIVE_RUNTIME_CAPABILITY_DETECTED")
        self.assertEqual(result["live_verifier_handoff"], "BLOCKED_PENDING_COMPLETE_NATIVE_CAPABILITY")
        self.assertTrue(result["production_grade_a_ready"])
        self.assertTrue(result["verified_grade_a_baseline_intact"])
        self.assertTrue(result["backend_native_baseline_intact"])

    def test_incomplete_snapshot_fails_closed(self):
        result = evaluate_runtime_capability_watch(self.observations[:1])
        self.assertEqual(result["watch_state"], "INCOMPLETE_RUNTIME_SNAPSHOT")
        self.assertEqual(result["live_verifier_handoff"], "BLOCKED_INCOMPLETE_CAPABILITY_SNAPSHOT")
        self.assertFalse(result["production_grade_a_ready"])

    def test_new_inline_only_surface_does_not_open_grade_a(self):
        self.observations.append({
            "schema": OBSERVATION_SCHEMA_VERSION,
            "adapter": "Example Adapter",
            "surface": "ordinary-chat-inline",
            "discovery_origin": "LIVE_TOOL_SCHEMA",
            "native_file_return_primitive": False,
            "inline_content_render": True,
            "native_conversation_reference": False,
            "host_receipt_digest": False,
            "same_reference_redownload": False,
        })
        result = evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(result["watch_state"], "RUNTIME_SURFACE_CHANGE_NO_NEW_NATIVE_CAPABILITY")
        self.assertEqual(result["live_verifier_handoff"], "NO_GRADE_A_HANDOFF")
        self.assertTrue(result["production_grade_a_ready"])
        self.assertTrue(result["verified_grade_a_baseline_intact"])
        self.assertTrue(result["backend_native_baseline_intact"])

    def test_backend_native_surface_regression_fails_closed(self):
        relay = next(item for item in self.observations if item["adapter"] == "CHATGPT_CONVERSATION_FILE_RELAY")
        relay["same_reference_redownload"] = False
        result = evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(result["watch_state"], "VERIFIED_GRADE_A_CAPABILITY_REGRESSION")
        self.assertEqual(result["live_verifier_handoff"], "R2_LIVE_RUNTIME_REQUALIFICATION_REQUIRED")
        self.assertFalse(result["production_grade_a_ready"])
        self.assertFalse(result["backend_native_baseline_intact"])
        self.assertFalse(result["verified_grade_a_baseline_intact"])
        self.assertEqual(result["ordinary_chat_grade_a"], "EXTERNAL_HOST_ADAPTER_GATE")

    def test_duplicate_surface_fails_closed(self):
        self.observations.append(copy.deepcopy(self.observations[0]))
        with self.assertRaises(HostNativeRuntimeWatchError) as cm:
            evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(str(cm.exception), "duplicate_surface_observation")

    def test_unknown_field_fails_closed(self):
        self.observations[0]["raw_file_id"] = "opaque"
        with self.assertRaises(HostNativeRuntimeWatchError) as cm:
            evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(str(cm.exception), "unknown_observation_fields")

    def test_boolean_fields_must_be_real_booleans(self):
        self.observations[0]["native_file_return_primitive"] = 1
        with self.assertRaises(HostNativeRuntimeWatchError) as cm:
            evaluate_runtime_capability_watch(self.observations)
        self.assertEqual(str(cm.exception), "invalid_native_file_return_primitive")

    def test_capabilities_never_allow_self_qualification(self):
        caps = runtime_watch_capabilities()
        self.assertTrue(caps["complete_snapshot_required"])
        self.assertFalse(caps["raw_file_reference_allowed"])
        self.assertFalse(caps["capability_candidate_can_set_production_grade_a_ready"])
        self.assertFalse(caps["backend_native_exact_roundtrip_can_set_production_grade_a_ready"])
        self.assertTrue(caps["user_visible_attachment_confirmation_required"])
        self.assertTrue(caps["verified_live_baseline_can_report_production_grade_a_ready"])
        self.assertTrue(caps["verified_grade_a_regression_fails_closed"])
        self.assertEqual(caps["backend_native_user_visible_handoff"], "USER_VISIBLE_ATTACHMENT_VERIFIER_REQUIRED")
        self.assertEqual(caps["candidate_handoff"], "R2_LIVE_RUNTIME_VERIFIER_REQUIRED")


if __name__ == "__main__":
    unittest.main()
