import datetime as dt
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from linux_macctl.artifact_engine import ArtifactError, ArtifactStore, ARTIFACT_SCHEMA_VERSION


class Clock:
    def __init__(self):
        self.value = dt.datetime(2026, 9, 12, 0, 0, tzinfo=dt.timezone.utc)
    def __call__(self):
        return self.value


class ArtifactStoreTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = Path(self.td.name)
        self.source_root = self.root / "source"
        self.store_root = self.root / "store"
        self.source_root.mkdir()
        self.clock = Clock()
        self.store = ArtifactStore(
            self.store_root,
            import_roots=[self.source_root],
            default_ttl_seconds=120,
            max_artifact_bytes=1024 * 1024,
            now_fn=self.clock,
        )

    def tearDown(self):
        self.td.cleanup()

    def test_snapshot_is_immutable_and_exact(self):
        src = self.source_root / "screen.png"
        original = b"\x89PNG\r\n\x1a\n" + b"exact-original" * 10
        src.write_bytes(original)
        manifest = self.store.create_snapshot(src, classification="SCREEN_CAPTURE")
        self.assertEqual(manifest["schema"], ARTIFACT_SCHEMA_VERSION)
        self.assertTrue(manifest["immutable"])
        self.assertTrue(manifest["original_preserved"])
        self.assertEqual(manifest["content"]["mime_type"], "image/png")
        self.assertEqual(manifest["content"]["sha256"], hashlib.sha256(original).hexdigest())
        src.write_bytes(b"mutated-source")
        verify = self.store.verify(manifest["artifact_id"])
        self.assertEqual(verify["status"], "PASS")
        payload = self.store.payload_path_for_gateway(manifest["artifact_id"]).read_bytes()
        self.assertEqual(payload, original)

    def test_symlink_source_is_denied(self):
        target = self.source_root / "target.bin"
        target.write_bytes(b"safe")
        link = self.source_root / "link.bin"
        link.symlink_to(target)
        with self.assertRaises(ArtifactError) as cm:
            self.store.create_snapshot(link)
        self.assertEqual(cm.exception.reason, "source_symlink_denied")

    def test_outside_import_root_is_denied(self):
        outside = self.root / "outside.bin"
        outside.write_bytes(b"outside")
        with self.assertRaises(ArtifactError) as cm:
            self.store.create_snapshot(outside)
        self.assertEqual(cm.exception.reason, "source_path_not_allowed")

    def test_private_key_signature_forces_secret_and_denies_delivery(self):
        src = self.source_root / "innocent.txt"
        src.write_bytes(b"-----BEGIN " + "OPENSSH PRIVATE".encode("ascii") + b" KEY-----\nabc")
        manifest = self.store.create_snapshot(src, classification="USER_SELECTED")
        self.assertEqual(manifest["classification"], "SECRET")
        self.assertFalse(manifest["delivery_allowed"])
        with self.assertRaises(ArtifactError) as cm:
            self.store.authorize_delivery(manifest["artifact_id"])
        self.assertEqual(cm.exception.reason, "artifact_delivery_denied")

    def test_integrity_failure_is_detected(self):
        src = self.source_root / "a.bin"
        src.write_bytes(b"abc")
        manifest = self.store.create_snapshot(src)
        payload = self.store_root / manifest["artifact_id"] / "payload"
        payload.write_bytes(b"tampered")
        self.assertEqual(self.store.verify(manifest["artifact_id"])["status"], "FAIL")
        with self.assertRaises(ArtifactError) as cm:
            self.store.authorize_delivery(manifest["artifact_id"])
        self.assertEqual(cm.exception.reason, "artifact_integrity_failed")

    def test_expiry_and_gc(self):
        src = self.source_root / "a.bin"
        src.write_bytes(b"abc")
        manifest = self.store.create_snapshot(src, ttl_seconds=60)
        self.clock.value += dt.timedelta(seconds=61)
        with self.assertRaises(ArtifactError) as cm:
            self.store.authorize_delivery(manifest["artifact_id"])
        self.assertEqual(cm.exception.reason, "artifact_expired")
        result = self.store.gc()
        self.assertEqual(result["removed_count"], 1)

    def test_revoke_denies_delivery_and_gc_removes(self):
        src = self.source_root / "a.bin"
        src.write_bytes(b"abc")
        manifest = self.store.create_snapshot(src)
        revoked = self.store.revoke(manifest["artifact_id"])
        self.assertEqual(revoked["state"], "REVOKED")
        with self.assertRaises(ArtifactError):
            self.store.authorize_delivery(manifest["artifact_id"])
        self.assertEqual(self.store.gc()["removed_count"], 1)

    def test_filename_does_not_preserve_path(self):
        src = self.source_root / "a.bin"
        src.write_bytes(b"abc")
        manifest = self.store.create_snapshot(src, filename="../../secret.png")
        self.assertEqual(manifest["content"]["filename"], "secret.png")
        serialized = str(manifest)
        self.assertNotIn(str(self.source_root), serialized)

    def test_size_limit_is_fail_closed(self):
        small_store = ArtifactStore(self.store_root / "small", import_roots=[self.source_root], max_artifact_bytes=4)
        src = self.source_root / "big.bin"
        src.write_bytes(b"12345")
        with self.assertRaises(ArtifactError) as cm:
            small_store.create_snapshot(src)
        self.assertEqual(cm.exception.reason, "artifact_size_limit_exceeded")

    def test_principal_acl_and_short_lived_grant(self):
        src = self.source_root / "a.bin"
        src.write_bytes(b"abc")
        manifest = self.store.create_snapshot(src, owner_principal="user:owner")
        with self.assertRaises(ArtifactError) as cm:
            self.store.authorize_delivery(manifest["artifact_id"], principal="user:other")
        self.assertEqual(cm.exception.reason, "artifact_access_denied")
        grant = self.store.issue_grant(manifest["artifact_id"], principal="user:owner", ttl_seconds=60)
        self.assertTrue(grant["grant_token"].startswith("agt_"))
        self.store.authorize_delivery(manifest["artifact_id"], principal="user:other", grant_token=grant["grant_token"])
        self.assertNotIn(grant["grant_token"], str(self.store.inspect(manifest["artifact_id"])))

    def test_common_attachment_mime_detection(self):
        fixtures = {
            "sample.json": (b'{"ok":true}\n', "application/json"),
            "sample.mp3": (b"ID3" + b"\x04\x00\x00" + b"x" * 32, "audio/mpeg"),
            "sample.mp4": (b"\x00\x00\x00\x18ftypisom" + b"\x00" * 32, "video/mp4"),
        }
        for name, (payload, expected) in fixtures.items():
            with self.subTest(name=name):
                src = self.source_root / name
                src.write_bytes(payload)
                manifest = self.store.create_snapshot(src)
                self.assertEqual(manifest["content"]["mime_type"], expected)

    def test_ooxml_mime_requires_expected_container_member(self):
        cases = {
            "sample.docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            "sample.xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            "sample.pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
        }
        for name, (member, expected) in cases.items():
            with self.subTest(name=name):
                src = self.source_root / name
                with zipfile.ZipFile(src, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("[Content_Types].xml", "<Types/>")
                    archive.writestr(member, "<root/>")
                manifest = self.store.create_snapshot(src)
                self.assertEqual(manifest["content"]["mime_type"], expected)

        disguised = self.source_root / "fake.docx"
        with zipfile.ZipFile(disguised, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("README.txt", "not a docx")
        manifest = self.store.create_snapshot(disguised)
        self.assertEqual(manifest["content"]["mime_type"], "application/zip")


if __name__ == "__main__":
    unittest.main()
