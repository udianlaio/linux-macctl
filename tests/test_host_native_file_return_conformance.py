import unittest

from attachment_delivery_engine import GRADE_A
from host_native_file_return_conformance import (
    EVIDENCE_SCHEMA_VERSION,
    HostNativeConformanceError,
    REFERENCE_KIND,
    build_synthetic_conformance_fixture,
    conformance_contract_capabilities,
    evaluate_conformance_evidence,
)


SHA = "a" * 64
SIZE = 3543988


class HostNativeFileReturnConformanceTests(unittest.TestCase):
    def _fixture(self):
        return build_synthetic_conformance_fixture(
            adapter="FUTURE_NATIVE_ADAPTER",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            inline_visible=True,
        )

    def _evaluate(self, evidence):
        return evaluate_conformance_evidence(
            evidence,
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
        )

    def test_synthetic_fixture_is_deterministic(self):
        first = self._fixture()
        second = self._fixture()
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(first["observation"]["reference_kind"], REFERENCE_KIND)
        self.assertNotIn("file_id", str(first))

    def test_conformant_fixture_never_grants_production_grade_a(self):
        result = self._evaluate(self._fixture())
        self.assertTrue(result["conformant"])
        self.assertEqual(result["candidate_grade"], GRADE_A)
        self.assertEqual(result["conformance_state"], "CONFORMANT_FOR_LIVE_RUNTIME_VERIFICATION")
        self.assertTrue(result["fixture_only"])
        self.assertFalse(result["live_runtime_evidence_verified"])
        self.assertFalse(result["production_grade_a_ready"])
        self.assertEqual(result["grade_a_evaluator_handoff"], "BLOCKED_PENDING_LIVE_RUNTIME_VERIFIER")

    def test_live_origin_string_still_cannot_self_attest_grade_a(self):
        evidence = self._fixture()
        evidence["evidence_origin"] = "LIVE_HOST_RUNTIME"
        result = self._evaluate(evidence)
        self.assertTrue(result["conformant"])
        self.assertFalse(result["production_grade_a_ready"])
        self.assertFalse(result["live_runtime_evidence_verified"])

    def test_wrong_host_receipt_bytes_are_nonconformant(self):
        evidence = self._fixture()
        evidence["observation"]["host_receipt"]["sha256"] = "b" * 64
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("host_receipt_exact", result["failures"])
        self.assertIsNone(result["candidate_grade"])

    def test_wrong_redownload_size_is_nonconformant(self):
        evidence = self._fixture()
        evidence["observation"]["redownload"]["size_bytes"] = SIZE - 1
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("redownload_exact", result["failures"])

    def test_redownload_must_be_bound_to_same_reference(self):
        evidence = self._fixture()
        evidence["observation"]["redownload"]["via_same_reference"] = False
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("redownload_bound_to_same_reference", result["failures"])

    def test_resource_link_reference_kind_cannot_pass_native_contract(self):
        evidence = self._fixture()
        evidence["observation"]["reference_kind"] = "RESOURCE_LINK"
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("reference_kind_native_conversation_attachment", result["failures"])

    def test_raw_file_reference_is_rejected_from_persisted_envelope(self):
        evidence = self._fixture()
        evidence["observation"]["file_id"] = "file-secret-opaque"
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("raw_reference_not_persisted", result["failures"])

    def test_raw_receipt_id_is_rejected_from_persisted_envelope(self):
        evidence = self._fixture()
        evidence["observation"]["host_receipt"]["receipt_id"] = "host-receipt-raw"
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("raw_receipt_not_persisted", result["failures"])

    def test_unknown_evidence_field_fails_closed(self):
        evidence = self._fixture()
        evidence["observation"]["download_url"] = "https://example.invalid/raw"
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("observation_fields_allowlisted", result["failures"])

    def test_expected_artifact_binding_is_required(self):
        evidence = self._fixture()
        evidence["artifact"]["sha256"] = "c" * 64
        result = self._evaluate(evidence)
        self.assertFalse(result["conformant"])
        self.assertIn("artifact_matches_expected", result["failures"])

    def test_invalid_schema_fails_closed(self):
        evidence = self._fixture()
        evidence["schema"] = "future/unknown"
        with self.assertRaises(HostNativeConformanceError) as cm:
            self._evaluate(evidence)
        self.assertEqual(str(cm.exception), "invalid_evidence_schema")

    def test_missing_reference_hash_fails_closed(self):
        evidence = self._fixture()
        del evidence["observation"]["reference_id_sha256"]
        with self.assertRaises(HostNativeConformanceError) as cm:
            self._evaluate(evidence)
        self.assertEqual(str(cm.exception), "invalid_reference_id_sha256")

    def test_contract_capabilities_forbid_fixture_self_qualification(self):
        caps = conformance_contract_capabilities()
        self.assertTrue(caps["requires_redownload_via_same_reference"])
        self.assertFalse(caps["persists_raw_file_reference"])
        self.assertFalse(caps["synthetic_fixture_can_set_production_grade_a_ready"])
        self.assertFalse(caps["manual_evidence_can_set_production_grade_a_ready"])
        self.assertTrue(caps["live_runtime_verifier_required_for_grade_a_handoff"])


if __name__ == "__main__":
    unittest.main()
