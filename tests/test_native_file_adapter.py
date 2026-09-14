import hashlib
from pathlib import Path
import tempfile
import unittest

from artifact_engine import ArtifactStore
from attachment_gateway import AttachmentGateway
from native_file_adapter import deliver_native_tool_file


class FakeRuntime:
    runtime_name = "fake-qualified-runtime"
    qualified = True
    def __init__(self):
        self.data = b""
    def create_tool_file(self, *, filename, mime_type, size_bytes, sha256, chunks):
        self.data = b"".join(chunks)
        if len(self.data) != size_bytes or hashlib.sha256(self.data).hexdigest() != sha256:
            raise AssertionError("runtime received corrupted bytes")
        return {"file_reference": "fake-file-ref-1"}


class UnqualifiedRuntime(FakeRuntime):
    runtime_name = "fake-unqualified-runtime"
    qualified = False


class NativeFileAdapterTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        root = Path(self.td.name)
        self.src = root / "src"
        self.src.mkdir()
        self.store = ArtifactStore(root / "store", import_roots=[self.src], default_principal="user:test")
        self.gateway = AttachmentGateway(self.store)

    def tearDown(self):
        self.td.cleanup()

    def test_exact_single_stream_reaches_qualified_runtime(self):
        data = b"\x89PNG\r\n\x1a\n" + b"payload" * 1000
        source = self.src / "screen.png"
        source.write_bytes(data)
        m = self.store.create_snapshot(source, classification="SCREEN_CAPTURE", owner_principal="user:test")
        rt = FakeRuntime()
        result = deliver_native_tool_file(self.gateway, m["artifact_id"], principal="user:test", runtime=rt)
        self.assertEqual(result["status"], "HOST_ACCEPTED")
        self.assertTrue(result["host_accepted"])
        self.assertFalse(result["user_visible_confirmed"])
        self.assertEqual(rt.data, data)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())

    def test_unqualified_runtime_is_fail_closed_before_streaming(self):
        source = self.src / "a.bin"
        source.write_bytes(b"abc")
        m = self.store.create_snapshot(source, owner_principal="user:test")
        rt = UnqualifiedRuntime()
        result = deliver_native_tool_file(self.gateway, m["artifact_id"], principal="user:test", runtime=rt)
        self.assertEqual(result["status"], "NOT_YET_QUALIFIED")
        self.assertFalse(result["host_accepted"])
        self.assertEqual(rt.data, b"")


if __name__ == "__main__":
    unittest.main()
