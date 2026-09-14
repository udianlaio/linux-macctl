import json
import multiprocessing
from pathlib import Path
import tempfile
import unittest

from audit_engine import (
    AUDIT_SCHEMA_VERSION,
    append_audit_record,
    approval_evidence,
    build_audit_record,
    classify_error,
    read_audit_lines,
    resolve_correlation_id,
    seal_record,
    summarize_postcondition,
    summarize_precondition,
    validate_correlation_id,
    verify_audit_chain,
    verify_record_digest,
)


def _concurrent_append_worker(args):
    path, index = args
    append_audit_record(
        path,
        {"schema": AUDIT_SCHEMA_VERSION, "index": index},
        max_bytes=1024 * 1024,
        retention_files=2,
        digest_seal=True,
    )
    return index


class AuditContractTests(unittest.TestCase):
    def test_bounded_metadata_contract_excludes_payloads(self):
        attrs = {
            "cmd": "exec",
            "action": None,
            "sudo": True,
            "_correlation_id": "corr-test-1",
            "_correlation_source": "cli",
            "_policy_risk_class": "BREAK_GLASS",
            "_policy_allowed": True,
            "_policy_reason": "generic_shell_break_glass",
            "_policy_source": "break_glass",
            "_policy_requires_confirmation": False,
            "_request_id": "req-1",
            "_operation_id": "op-1",
            "_transaction_status": "COMPLETED",
            "_audit_precondition_summary": {"status": "PASS", "explicit_check_count": 1},
            "_audit_postcondition_summary": {"status": "PASS", "mode": "SHA256", "verified": True},
            "command": "echo TOP_SECRET_COMMAND",
            "text": "TOP_SECRET_TEXT",
            "password": "TOP_SECRET_PASSWORD",
            "token": "TOP_SECRET_TOKEN",
            "content": "TOP_SECRET_CONTENT",
        }
        record = build_audit_record(
            attrs,
            0,
            12.345,
            version="0.4.0-dev",
            target="macmini",
            ts_utc="2026-09-11T00:00:00Z",
        )
        self.assertEqual(record["schema"], AUDIT_SCHEMA_VERSION)
        self.assertEqual(record["duration_ms"], 12.3)
        self.assertEqual(record["request_id"], "req-1")
        self.assertEqual(record["correlation_id"], "corr-test-1")
        self.assertEqual(record["error_class"], "SUCCESS")
        encoded = json.dumps(record, ensure_ascii=False, sort_keys=True)
        for secret in (
            "TOP_SECRET_COMMAND",
            "TOP_SECRET_TEXT",
            "TOP_SECRET_PASSWORD",
            "TOP_SECRET_TOKEN",
            "TOP_SECRET_CONTENT",
        ):
            self.assertNotIn(secret, encoded)
        for forbidden_key in ("command", "text", "password", "token", "content"):
            self.assertNotIn(forbidden_key, record)

    def test_output_is_json_roundtrip_safe(self):
        record = build_audit_record({}, 7, 1.0, version="x", target="y", ts_utc="fixed")
        self.assertEqual(json.loads(json.dumps(record, ensure_ascii=False)), record)
        self.assertEqual(record["rc"], 7)
        self.assertEqual(record["error_class"], "COMMAND_FAILED")

    def test_correlation_id_validation_and_sources(self):
        self.assertEqual(validate_correlation_id("abc-01:run.test"), "abc-01:run.test")
        with self.assertRaises(ValueError):
            validate_correlation_id("bad id with spaces")
        with self.assertRaises(ValueError):
            validate_correlation_id("../escape")
        explicit, source = resolve_correlation_id("cli-1", "env-1")
        self.assertEqual((explicit, source), ("cli-1", "cli"))
        env, source = resolve_correlation_id(None, "env-1")
        self.assertEqual((env, source), ("env-1", "env"))
        generated, source = resolve_correlation_id()
        self.assertTrue(generated.startswith("corr-"))
        self.assertEqual(source, "generated")

    def test_approval_evidence_is_bounded_and_explicit(self):
        required = approval_evidence({"_policy_requires_confirmation": True, "confirm": True})
        self.assertEqual(required, {"required": True, "provided": True, "source": "--confirm"})
        missing = approval_evidence({"_policy_requires_confirmation": True, "confirm": False})
        self.assertEqual(missing["source"], "missing")
        not_required = approval_evidence({"confirm": True})
        self.assertEqual(not_required, {"required": False, "provided": False, "source": "not_required"})

    def test_pre_post_evidence_summaries_never_copy_paths_or_payloads(self):
        pre = summarize_precondition({
            "status": "PASS",
            "explicit": {
                "status": "PASS",
                "checks": [{"path": "/secret/path", "expected": "SECRET_HASH"}],
            },
            "automatic": {"mode": "FILE_SOURCE_DESTINATION", "source": {"path": "/secret/source"}},
        })
        self.assertEqual(pre["explicit_check_count"], 1)
        self.assertEqual(pre["automatic_mode"], "FILE_SOURCE_DESTINATION")
        self.assertNotIn("secret", json.dumps(pre).lower())
        post = summarize_postcondition({
            "status": "PASS",
            "mode": "SHA256",
            "verified": True,
            "path": "/secret/path",
            "expected_sha256": "SECRET_HASH",
        })
        self.assertEqual(post, {"status": "PASS", "mode": "SHA256", "verified": True})

    def test_error_class_mapping(self):
        cases = [
            (0, {}, "SUCCESS"),
            (77, {}, "POLICY_BLOCKED"),
            (76, {}, "PRECONDITION_FAILED"),
            (74, {}, "POSTCONDITION_FAILED"),
            (75, {}, "INDETERMINATE"),
            (78, {}, "REQUEST_CONFLICT"),
            (124, {}, "TIMEOUT"),
            (64, {}, "USAGE_ERROR"),
            (73, {}, "TRANSACTION_JOURNAL_ERROR"),
            (70, {}, "INTERNAL_ERROR"),
            (2, {}, "COMMAND_FAILED"),
        ]
        for rc, attrs, expected in cases:
            with self.subTest(rc=rc):
                self.assertEqual(classify_error(rc, attrs), expected)
        self.assertEqual(classify_error(1, {"_policy_allowed": False}), "POLICY_BLOCKED")


class AuditDigestAndRetentionTests(unittest.TestCase):
    def test_concurrent_appends_keep_one_valid_chain(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "audit.jsonl")
            with multiprocessing.Pool(processes=4) as pool:
                result = pool.map(_concurrent_append_worker, [(path, i) for i in range(24)])
            self.assertEqual(sorted(result), list(range(24)))
            verify = verify_audit_chain(path, retention_files=2)
            self.assertEqual(verify["status"], "PASS")
            self.assertEqual(verify["records"], 24)
            self.assertEqual(verify["sealed_records"], 24)
            self.assertEqual(verify["chain_errors"], 0)

    def test_digest_detects_tampering(self):
        sealed = seal_record({"schema": AUDIT_SCHEMA_VERSION, "value": 1})
        self.assertTrue(verify_record_digest(sealed))
        sealed["value"] = 2
        self.assertFalse(verify_record_digest(sealed))

    def test_append_rotation_retention_and_chain_verification(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            for index in range(8):
                append_audit_record(
                    path,
                    {"schema": AUDIT_SCHEMA_VERSION, "index": index, "padding": "x" * 500},
                    max_bytes=1024,
                    retention_files=2,
                    digest_seal=True,
                )
            self.assertTrue(path.exists())
            self.assertTrue(Path(str(path) + ".1").exists())
            self.assertTrue(Path(str(path) + ".2").exists())
            self.assertFalse(Path(str(path) + ".3").exists())
            verify = verify_audit_chain(path, retention_files=2)
            self.assertEqual(verify["status"], "PASS")
            self.assertGreater(verify["sealed_records"], 0)
            self.assertEqual(verify["digest_errors"], 0)
            self.assertEqual(verify["chain_errors"], 0)

    def test_chain_verifier_detects_line_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            append_audit_record(path, {"schema": AUDIT_SCHEMA_VERSION, "index": 1}, max_bytes=4096, retention_files=2)
            append_audit_record(path, {"schema": AUDIT_SCHEMA_VERSION, "index": 2}, max_bytes=4096, retention_files=2)
            lines = path.read_text(encoding="utf-8").splitlines()
            first = json.loads(lines[0])
            first["index"] = 99
            lines[0] = json.dumps(first, ensure_ascii=False, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            verify = verify_audit_chain(path, retention_files=2)
            self.assertEqual(verify["status"], "FAIL")
            self.assertGreaterEqual(verify["digest_errors"], 1)

    def test_read_tail_crosses_rotation_boundary(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "audit.jsonl"
            for index in range(5):
                append_audit_record(
                    path,
                    {"schema": AUDIT_SCHEMA_VERSION, "index": index, "padding": "y" * 500},
                    max_bytes=1024,
                    retention_files=3,
                )
            lines = read_audit_lines(path, lines=3, retention_files=3)
            indexes = [json.loads(line)["index"] for line in lines]
            self.assertEqual(indexes, [2, 3, 4])


if __name__ == "__main__":
    unittest.main()
