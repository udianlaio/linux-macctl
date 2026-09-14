from pathlib import Path
import tempfile
import unittest

from linux_macctl.transfer_engine import (
    TransferPlanError,
    effective_remote_file_path,
    local_stage_sibling,
    remote_stage_sibling,
    resolve_remote_user_path,
    sha256_file,
)


class TransferEngineTests(unittest.TestCase):
    def test_resolve_remote_user_paths(self):
        home = "/Users/tester"
        self.assertEqual(resolve_remote_user_path("~", home=home), home)
        self.assertEqual(resolve_remote_user_path("~/Desktop/a.txt", home=home), "/Users/tester/Desktop/a.txt")
        self.assertEqual(resolve_remote_user_path("relative/a.txt", home=home), "/Users/tester/relative/a.txt")
        self.assertEqual(resolve_remote_user_path("/tmp/a.txt", home=home), "/tmp/a.txt")
        with self.assertRaisesRegex(TransferPlanError, "~other"):
            resolve_remote_user_path("~other/a.txt", home=home)

    def test_effective_remote_file_path_for_directory_destination(self):
        self.assertEqual(
            effective_remote_file_path(
                "/tmp/out", home="/Users/tester", local_name="a.bin", destination_is_dir=True
            ),
            "/tmp/out/a.bin",
        )
        with self.assertRaisesRegex(TransferPlanError, "ends with /"):
            effective_remote_file_path(
                "/tmp/missing/", home="/Users/tester", local_name="a.bin", destination_is_dir=False
            )

    def test_stage_paths_are_hidden_siblings(self):
        self.assertEqual(
            remote_stage_sibling("/tmp/final.bin", token="abc"),
            "/tmp/.final.bin.macctl-partial-abc",
        )
        self.assertEqual(
            local_stage_sibling(Path("/tmp/final.bin"), token="xyz"),
            Path("/tmp/.final.bin.macctl-partial-xyz"),
        )

    def test_sha256_file_streaming(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "payload.bin"
            p.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(p, chunk_size=1),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )


if __name__ == "__main__":
    unittest.main()
