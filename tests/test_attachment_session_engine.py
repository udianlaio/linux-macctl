import hashlib
from pathlib import Path
import tempfile
import unittest

from linux_macctl.artifact_engine import ArtifactStore
from linux_macctl.attachment_delivery_engine import AdapterCapability, GRADE_A
from linux_macctl.attachment_session_engine import (
    ADAPTER_SELECTED,
    FAILED,
    HOST_ACCEPTED,
    HOST_RENDER_QUALIFIED,
    PROJECT_READY,
    USER_VISIBLE_CONFIRMED,
    AttachmentSessionStore,
    DeliverySessionError,
)


class AttachmentSessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.src = self.root / "src"
        self.src.mkdir()
        self.artifacts = ArtifactStore(
            self.root / "artifacts",
            import_roots=[self.src],
            default_principal="user:test",
        )

    def tearDown(self):
        self.td.cleanup()

    def _artifact(self, name="screen.png", payload=b"\x89PNG\r\n\x1a\nexact-bytes"):
        path = self.src / name
        path.write_bytes(payload)
        return self.artifacts.create_snapshot(
            path,
            classification="SCREEN_CAPTURE",
            owner_principal="user:test",
        )

    def _native_store(self):
        adapters = (
            AdapterCapability(
                "TEST_NATIVE_FILE_REF",
                True,
                True,
                GRADE_A,
                inline_image=True,
                exact_original=True,
                reason="deterministic_test_adapter",
            ),
        )
        return AttachmentSessionStore(
            self.root / "deliveries-native",
            artifact_store=self.artifacts,
            adapters=adapters,
        )

    def test_default_runtime_stops_at_explicit_external_gate(self):
        artifact = self._artifact()
        sessions = AttachmentSessionStore(self.root / "deliveries", artifact_store=self.artifacts)
        row = sessions.create(
            artifact["artifact_id"],
            principal="user:test",
            idempotency_key="request-0001",
        )
        self.assertEqual(row["state"], PROJECT_READY)
        self.assertEqual(row["correlation_id"], row["session_id"])
        self.assertTrue(row["project_owned"]["project_delivery_plane_ready"])
        self.assertTrue(row["project_owned"]["exact_original_verified"])
        self.assertEqual(row["external_gate"]["gate"], "EXTERNAL_HOST_ADAPTER_GATE")
        self.assertIsNone(row["adapter"]["selected"])
        serialized = str(row)
        self.assertNotIn("request-0001", serialized)
        self.assertNotIn(str(self.src), serialized)

    def test_idempotent_replay_returns_same_session(self):
        artifact = self._artifact()
        sessions = AttachmentSessionStore(self.root / "deliveries", artifact_store=self.artifacts)
        first = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0002"
        )
        second = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0002"
        )
        self.assertEqual(first["session_id"], second["session_id"])
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(second["idempotent_replay"])
        self.assertEqual(len(sessions.list()), 1)

    def test_idempotency_key_reuse_with_different_binding_fails_closed(self):
        first_artifact = self._artifact("a.png", b"\x89PNG\r\n\x1a\na")
        second_artifact = self._artifact("b.png", b"\x89PNG\r\n\x1a\nb")
        sessions = AttachmentSessionStore(self.root / "deliveries", artifact_store=self.artifacts)
        sessions.create(
            first_artifact["artifact_id"], principal="user:test", idempotency_key="request-0003"
        )
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.create(
                second_artifact["artifact_id"], principal="user:test", idempotency_key="request-0003"
            )
        self.assertEqual(cm.exception.reason, "idempotency_key_conflict")

    def test_native_adapter_full_grade_a_lifecycle(self):
        artifact = self._artifact()
        sessions = self._native_store()
        row = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0004"
        )
        self.assertEqual(row["state"], ADAPTER_SELECTED)
        self.assertEqual(row["adapter"]["selected"], "TEST_NATIVE_FILE_REF")

        accepted = sessions.record_host_acceptance(
            row["session_id"],
            adapter="TEST_NATIVE_FILE_REF",
            receipt_id="host-receipt-opaque-123",
            sha256=artifact["content"]["sha256"],
            size_bytes=artifact["content"]["size_bytes"],
        )
        self.assertEqual(accepted["state"], HOST_ACCEPTED)
        self.assertEqual(
            accepted["host_receipt"]["receipt_id_sha256"],
            hashlib.sha256(b"host-receipt-opaque-123").hexdigest(),
        )
        self.assertNotIn("host-receipt-opaque-123", str(accepted))

        qualified = sessions.qualify_render(
            row["session_id"],
            surface="chatgpt-web-test-surface",
            native_attachment=True,
            exact_original=True,
            downloaded_sha256=artifact["content"]["sha256"],
            inline_visible=True,
        )
        self.assertEqual(qualified["state"], HOST_RENDER_QUALIFIED)
        self.assertEqual(qualified["render_qualification"]["grade"], GRADE_A)

        confirmed = sessions.confirm_user_visible(row["session_id"], confirmed_by="operator")
        self.assertEqual(confirmed["state"], USER_VISIBLE_CONFIRMED)
        self.assertEqual(confirmed["user_confirmation"]["confirmed_by"], "operator")

    def test_host_receipt_must_match_exact_bytes(self):
        artifact = self._artifact()
        sessions = self._native_store()
        row = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0005"
        )
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.record_host_acceptance(
                row["session_id"],
                adapter="TEST_NATIVE_FILE_REF",
                receipt_id="receipt-0005",
                sha256="0" * 64,
                size_bytes=artifact["content"]["size_bytes"],
            )
        self.assertEqual(cm.exception.reason, "host_receipt_byte_mismatch")
        self.assertEqual(sessions.inspect(row["session_id"])["state"], ADAPTER_SELECTED)

    def test_render_qualification_cannot_fake_grade_a(self):
        artifact = self._artifact()
        sessions = self._native_store()
        row = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0006"
        )
        sessions.record_host_acceptance(
            row["session_id"],
            adapter="TEST_NATIVE_FILE_REF",
            receipt_id="receipt-0006",
            sha256=artifact["content"]["sha256"],
            size_bytes=artifact["content"]["size_bytes"],
        )
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.qualify_render(
                row["session_id"],
                surface="chatgpt-web-test-surface",
                native_attachment=False,
                exact_original=True,
                downloaded_sha256=artifact["content"]["sha256"],
            )
        self.assertEqual(cm.exception.reason, "host_render_not_grade_a")
        self.assertEqual(sessions.inspect(row["session_id"])["state"], HOST_ACCEPTED)

    def test_both_presentation_requires_inline_observation_for_image(self):
        artifact = self._artifact()
        sessions = self._native_store()
        row = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0009"
        )
        sessions.record_host_acceptance(
            row["session_id"],
            adapter="TEST_NATIVE_FILE_REF",
            receipt_id="receipt-0009",
            sha256=artifact["content"]["sha256"],
            size_bytes=artifact["content"]["size_bytes"],
        )
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.qualify_render(
                row["session_id"],
                surface="chatgpt-web-test-surface",
                native_attachment=True,
                exact_original=True,
                downloaded_sha256=artifact["content"]["sha256"],
                inline_visible=False,
            )
        self.assertEqual(cm.exception.reason, "inline_presentation_not_observed")

    def test_symlinked_idempotency_index_is_denied(self):
        artifact = self._artifact()
        sessions = AttachmentSessionStore(self.root / "deliveries-symlink", artifact_store=self.artifacts)
        idem = "request-0010"
        outside = self.root / "outside-index.json"
        outside.write_text("{}", encoding="utf-8")
        index_name = hashlib.sha256(idem.encode("utf-8")).hexdigest() + ".json"
        (sessions.idempotency_dir / index_name).symlink_to(outside)
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.create(artifact["artifact_id"], principal="user:test", idempotency_key=idem)
        self.assertEqual(cm.exception.reason, "idempotency_index_symlink_denied")

    def test_user_confirmation_requires_host_render_qualification(self):
        artifact = self._artifact()
        sessions = self._native_store()
        row = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0007"
        )
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.confirm_user_visible(row["session_id"], confirmed_by="operator")
        self.assertEqual(cm.exception.reason, "host_render_qualification_required")

    def test_failure_is_durable_and_terminal_for_host_acceptance(self):
        artifact = self._artifact()
        sessions = self._native_store()
        row = sessions.create(
            artifact["artifact_id"], principal="user:test", idempotency_key="request-0008"
        )
        failed = sessions.fail(row["session_id"], reason="adapter_transport_failed")
        self.assertEqual(failed["state"], FAILED)
        with self.assertRaises(DeliverySessionError) as cm:
            sessions.record_host_acceptance(
                row["session_id"],
                adapter="TEST_NATIVE_FILE_REF",
                receipt_id="receipt-after-fail",
                sha256=artifact["content"]["sha256"],
                size_bytes=artifact["content"]["size_bytes"],
            )
        self.assertEqual(cm.exception.reason, "delivery_session_terminal")

    def test_capabilities_truthfully_separate_project_and_external_gate(self):
        sessions = AttachmentSessionStore(self.root / "deliveries", artifact_store=self.artifacts)
        caps = sessions.capabilities()
        self.assertTrue(caps["durable_delivery_sessions"])
        self.assertTrue(caps["external_host_adapter_gate_explicit"])
        self.assertFalse(caps["fabricated_chatgpt_file_id"])


if __name__ == "__main__":
    unittest.main()
