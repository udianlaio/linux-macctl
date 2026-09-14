import unittest

from linux_macctl.attachment_delivery_engine import GRADE_A, GRADE_B, GRADE_C, GRADE_D
from linux_macctl.host_adapter_qualification_engine import (
    HostAdapterQualificationError,
    evaluate_host_adapter_observation,
    qualification_contract_capabilities,
)


SHA = "a" * 64
SIZE = 12345


class HostAdapterQualificationTests(unittest.TestCase):
    def test_inline_render_only_is_grade_b_not_grade_a(self):
        row = evaluate_host_adapter_observation(
            adapter="REMOTE_DESKTOP_COMMANDER_IMAGE_CONTENT",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            inline_visible=True,
        )
        self.assertTrue(row["qualified"])
        self.assertEqual(row["observed_grade"], GRADE_B)
        self.assertFalse(row["production_grade_a_ready"])
        self.assertIn("native_attachment_not_observed", row["grade_a_blockers"])
        self.assertIn("stable_file_reference_not_observed", row["grade_a_blockers"])

    def test_native_reference_without_exact_roundtrip_is_not_grade_a(self):
        row = evaluate_host_adapter_observation(
            adapter="NATIVE_REF",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            native_attachment=True,
            stable_file_reference=True,
        )
        self.assertFalse(row["qualified"])
        self.assertIsNone(row["observed_grade"])
        self.assertFalse(row["production_grade_a_ready"])
        self.assertIn("exact_host_receipt_not_observed", row["grade_a_blockers"])
        self.assertIn("exact_redownload_not_verified", row["grade_a_blockers"])

    def test_grade_a_requires_native_reference_receipt_and_redownload(self):
        row = evaluate_host_adapter_observation(
            adapter="NATIVE_REF",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            inline_visible=True,
            native_attachment=True,
            stable_file_reference=True,
            host_reported_sha256=SHA,
            host_reported_size_bytes=SIZE,
            redownload_sha256=SHA,
        )
        self.assertTrue(row["qualified"])
        self.assertEqual(row["observed_grade"], GRADE_A)
        self.assertTrue(row["production_grade_a_ready"])
        self.assertEqual(row["grade_a_blockers"], [])

    def test_wrong_receipt_downgrades_to_observed_inline_grade_b(self):
        row = evaluate_host_adapter_observation(
            adapter="NATIVE_REF",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            inline_visible=True,
            native_attachment=True,
            stable_file_reference=True,
            host_reported_sha256="b" * 64,
            host_reported_size_bytes=SIZE,
            redownload_sha256=SHA,
        )
        self.assertEqual(row["observed_grade"], GRADE_B)
        self.assertFalse(row["production_grade_a_ready"])
        self.assertIn("exact_host_receipt_not_observed", row["grade_a_blockers"])

    def test_exact_resource_link_without_native_attachment_is_grade_c(self):
        row = evaluate_host_adapter_observation(
            adapter="RESOURCE_LINK",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            resource_link=True,
            redownload_sha256=SHA,
        )
        self.assertEqual(row["observed_grade"], GRADE_C)
        self.assertTrue(row["qualified"])
        self.assertFalse(row["production_grade_a_ready"])

    def test_link_only_is_grade_d(self):
        row = evaluate_host_adapter_observation(
            adapter="HTTPS_LINK",
            surface="chatgpt-ordinary-chat",
            expected_sha256=SHA,
            expected_size_bytes=SIZE,
            link_only=True,
        )
        self.assertEqual(row["observed_grade"], GRADE_D)
        self.assertFalse(row["production_grade_a_ready"])

    def test_invalid_hash_fails_closed(self):
        with self.assertRaises(HostAdapterQualificationError):
            evaluate_host_adapter_observation(
                adapter="X",
                surface="Y",
                expected_sha256="not-a-hash",
                expected_size_bytes=SIZE,
            )

    def test_capabilities_freeze_grade_a_contract(self):
        caps = qualification_contract_capabilities()
        self.assertTrue(caps["grade_a_requires_native_attachment"])
        self.assertTrue(caps["grade_a_requires_stable_file_reference"])
        self.assertTrue(caps["grade_a_requires_exact_host_receipt"])
        self.assertTrue(caps["grade_a_requires_exact_redownload_sha256"])
        self.assertEqual(caps["inline_render_alone_max_grade"], GRADE_B)
        self.assertFalse(caps["fabricated_file_id_allowed"])


if __name__ == "__main__":
    unittest.main()
