import json
import os
import stat
import tempfile
import unittest

from linux_macctl.transaction_engine import (
    COMPLETED,
    DISPATCHED,
    FAILED,
    POSTCONDITION_FAILED,
    PRECONDITION_FAILED,
    PREPARED,
    TransactionStore,
    build_operation_id,
    parse_expected_sha256_spec,
    validate_remote_path,
    validate_request_id,
    validate_sha256,
)


class OperationIdTests(unittest.TestCase):
    def test_operation_id_is_stable(self):
        attrs = {"path": "/tmp/a", "recursive": False, "command": ["printf", "secret-ish"]}
        a = build_operation_id("file", "rm", "MUTATE_STATEFUL", attrs)
        b = build_operation_id("file", "rm", "MUTATE_STATEFUL", dict(reversed(list(attrs.items()))))
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("op-"))

    def test_payload_change_changes_operation_id(self):
        a = build_operation_id("exec", None, "BREAK_GLASS", {"command": ["echo", "one"]})
        b = build_operation_id("exec", None, "BREAK_GLASS", {"command": ["echo", "two"]})
        self.assertNotEqual(a, b)

    def test_transport_tuning_does_not_change_operation_id(self):
        a = build_operation_id("file", "cp", "MUTATE_REVERSIBLE", {"src": "/tmp/a", "dst": "/tmp/b", "timeout": 30, "max_bytes": 4096})
        b = build_operation_id("file", "cp", "MUTATE_REVERSIBLE", {"src": "/tmp/a", "dst": "/tmp/b", "timeout": 300, "max_bytes": 999999})
        self.assertEqual(a, b)

    def test_request_id_validation(self):
        self.assertEqual(validate_request_id("req-01:abc"), "req-01:abc")
        with self.assertRaises(ValueError):
            validate_request_id("../escape")
        with self.assertRaises(ValueError):
            validate_request_id("")

    def test_sha256_validation(self):
        digest = "A" * 64
        self.assertEqual(validate_sha256(digest), "a" * 64)
        with self.assertRaises(ValueError):
            validate_sha256("xyz")

    def test_remote_path_validation_treats_shell_metacharacters_as_data(self):
        path = "/tmp/a file;$(echo harmless)"
        self.assertEqual(validate_remote_path(path), path)
        with self.assertRaises(ValueError):
            validate_remote_path("")
        with self.assertRaises(ValueError):
            validate_remote_path("/tmp/a\x00b")

    def test_expected_sha256_spec_validation_and_normalization(self):
        path, digest = parse_expected_sha256_spec("/tmp/a=b=" + "A" * 64)
        self.assertEqual(path, "/tmp/a=b")
        self.assertEqual(digest, "a" * 64)
        with self.assertRaises(ValueError):
            parse_expected_sha256_spec("missing-separator")
        with self.assertRaises(ValueError):
            parse_expected_sha256_spec("=" + "a" * 64)
        with self.assertRaises(ValueError):
            parse_expected_sha256_spec("/tmp/x=bad-hash")


class TransactionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TransactionStore(self.tmp.name)
        self.op = build_operation_id("file", "mkdir", "MUTATE_REVERSIBLE", {"path": "/tmp/x"})

    def tearDown(self):
        self.tmp.cleanup()

    def begin(self, request_id="req-1", operation_id=None, target=None):
        return self.store.begin(
            request_id,
            operation_id or self.op,
            family="file",
            action="mkdir",
            risk_class="MUTATE_REVERSIBLE",
            policy_reason="file_mutation_reversible",
            target=target,
        )

    def test_new_record_is_prepared_and_mode_0600(self):
        result = self.begin()
        self.assertEqual(result.disposition, "NEW")
        self.assertEqual(result.record["status"], PREPARED)
        files = [p for p in os.listdir(self.tmp.name) if p.endswith(".json")]
        self.assertEqual(len(files), 1)
        mode = stat.S_IMODE(os.stat(os.path.join(self.tmp.name, files[0])).st_mode)
        self.assertEqual(mode, 0o600)

    def test_prepared_record_can_resume_before_dispatch(self):
        self.begin()
        second = self.begin()
        self.assertEqual(second.disposition, "RESUME_PREPARED")
        self.assertEqual(second.record["attempts"], 2)

    def test_completed_request_replays_without_new_execution(self):
        self.begin()
        self.store.set_precondition("req-1", self.op, {"status": "PASS"})
        self.store.mark_dispatched("req-1", self.op)
        self.store.mark_completed("req-1", self.op, postcondition={"status": "PASS", "verified": True})
        replay = self.begin()
        self.assertEqual(replay.disposition, "ALREADY_COMPLETED")
        self.assertEqual(replay.record["status"], COMPLETED)

    def test_same_request_different_operation_conflicts(self):
        self.begin()
        other = build_operation_id("file", "mkdir", "MUTATE_REVERSIBLE", {"path": "/tmp/other"})
        replay = self.begin(operation_id=other)
        self.assertEqual(replay.disposition, "CONFLICT")

    def test_target_binding_blocks_cross_target_replay(self):
        first = self.begin(target="macmini")
        self.assertEqual(first.record["target"], "macmini")
        replay = self.begin(target="labmac")
        self.assertEqual(replay.disposition, "TARGET_CONFLICT")
        self.assertEqual(replay.record["target"], "macmini")

    def test_legacy_unbound_record_remains_replay_compatible(self):
        first = self.begin(target=None)
        self.assertIsNone(first.record["target"])
        replay = self.begin(target="macmini")
        self.assertEqual(replay.disposition, "RESUME_PREPARED")

    def test_dispatched_request_is_indeterminate_on_replay(self):
        self.begin()
        self.store.mark_dispatched("req-1", self.op)
        replay = self.begin()
        self.assertEqual(replay.disposition, "INDETERMINATE")
        self.assertEqual(replay.record["status"], DISPATCHED)

    def test_failed_request_is_terminal_and_not_reexecuted(self):
        self.begin()
        self.store.mark_dispatched("req-1", self.op)
        self.store.mark_failed("req-1", self.op, rc=7)
        replay = self.begin()
        self.assertEqual(replay.disposition, "ALREADY_TERMINAL")
        self.assertEqual(replay.record["status"], FAILED)
        self.assertEqual(replay.record["result"]["rc"], 7)

    def test_precondition_failure_is_terminal(self):
        self.begin()
        self.store.mark_precondition_failed("req-1", self.op, evidence={"status": "FAIL"})
        replay = self.begin()
        self.assertEqual(replay.disposition, "ALREADY_TERMINAL")
        self.assertEqual(replay.record["status"], PRECONDITION_FAILED)

    def test_postcondition_failure_is_terminal(self):
        self.begin()
        self.store.mark_dispatched("req-1", self.op)
        self.store.mark_postcondition_failed("req-1", self.op, evidence={"status": "FAIL"})
        replay = self.begin()
        self.assertEqual(replay.disposition, "ALREADY_TERMINAL")
        self.assertEqual(replay.record["status"], POSTCONDITION_FAILED)

    def test_list_is_newest_first_and_bounded(self):
        self.begin("req-a")
        self.begin("req-b")
        records = self.store.list(limit=1)
        self.assertEqual(len(records), 1)
        self.assertIn(records[0]["request_id"], {"req-a", "req-b"})

    def test_record_contains_no_command_payload(self):
        op = build_operation_id("exec", None, "BREAK_GLASS", {"command": ["echo", "TOP_SECRET_VALUE"]})
        result = self.store.begin(
            "req-secret",
            op,
            family="exec",
            action=None,
            risk_class="BREAK_GLASS",
            policy_reason="generic_shell_break_glass",
        )
        encoded = json.dumps(result.record, ensure_ascii=False)
        self.assertNotIn("TOP_SECRET_VALUE", encoded)


if __name__ == "__main__":
    unittest.main()
