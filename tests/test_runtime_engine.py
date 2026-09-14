import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

from runtime_engine import bounded_run


class BoundedRunTests(unittest.TestCase):
    def test_success_contract_and_input_bytes(self):
        result = bounded_run(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().upper())"],
            timeout=2,
            cap=1024,
            input_bytes=b"hello",
        )
        self.assertEqual(result["rc"], 0)
        self.assertEqual(result["output"], "HELLO")
        self.assertFalse(result["truncated"])
        self.assertEqual(result["bytes"], 5)

    def test_output_cap_is_deterministic(self):
        result = bounded_run(
            [sys.executable, "-c", "print('x' * 50, end='')"],
            timeout=2,
            cap=10,
        )
        self.assertEqual(result["rc"], 0)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["bytes"], 50)
        self.assertTrue(result["output"].startswith("x" * 10))
        self.assertIn("MACCTL_OUTPUT_TRUNCATED bytes=50 cap=10", result["output"])

    def test_large_output_reports_exact_bytes_without_returning_full_payload(self):
        size = 2 * 1024 * 1024
        cap = 4096
        result = bounded_run(
            [sys.executable, "-c", f"import sys; sys.stdout.buffer.write(b'x' * {size})"],
            timeout=5,
            cap=cap,
        )
        self.assertEqual(result["rc"], 0)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["bytes"], size)
        self.assertLess(len(result["output"]), cap + 100)
        self.assertIn(f"MACCTL_OUTPUT_TRUNCATED bytes={size} cap={cap}", result["output"])

    def test_timeout_maps_to_rc_124_without_exception(self):
        result = bounded_run(
            [sys.executable, "-c", "import time; print('started', flush=True); time.sleep(2)"],
            timeout=0.1,
            cap=1024,
        )
        self.assertEqual(result["rc"], 124)
        self.assertEqual(result["error"], "timeout")
        self.assertIn("started", result["output"])
        self.assertGreaterEqual(result["duration_ms"], 50)

    @unittest.skipUnless(hasattr(os, "killpg"), "requires POSIX process groups")
    def test_timeout_kills_local_descendant_process_group(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "child-survived.txt"
            child_code = (
                "import pathlib,time; "
                "time.sleep(0.6); "
                f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
            )
            parent_code = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                "print('parent-started', flush=True); "
                "time.sleep(30)"
            )
            result = bounded_run(
                [sys.executable, "-c", parent_code],
                timeout=0.1,
                cap=1024,
            )
            self.assertEqual(result["rc"], 124)
            self.assertIn("parent-started", result["output"])
            time.sleep(0.8)
            self.assertFalse(marker.exists(), "descendant survived bounded_run timeout")


if __name__ == "__main__":
    unittest.main()
