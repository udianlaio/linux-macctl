#!/usr/bin/env python3
import datetime as dt
import os
import tempfile
import unittest

from browser_session_engine import (
    BrowserSessionError,
    BrowserSessionStore,
    build_session_record,
    evaluate_session_action_policy,
    evaluate_url_policy,
    sanitize_url_for_output,
    normalize_allow_host,
    normalize_allow_hosts,
    validate_qualification_config,
    pid_alive,
    pid_matches,
    validate_session_id,
)


class UrlPolicyTests(unittest.TestCase):
    def test_exact_host_allow(self):
        r = evaluate_url_policy("https://example.com/a", allow_hosts=["example.com"])
        self.assertTrue(r["allowed"])
        self.assertEqual(r["reason"], "host_allowlist_match")

    def test_subdomain_does_not_match_exact_host(self):
        r = evaluate_url_policy("https://www.example.com/", allow_hosts=["example.com"])
        self.assertFalse(r["allowed"])

    def test_wildcard_matches_subdomain_but_not_base(self):
        self.assertTrue(evaluate_url_policy("https://a.example.com/", allow_hosts=["*.example.com"])["allowed"])
        self.assertFalse(evaluate_url_policy("https://example.com/", allow_hosts=["*.example.com"])["allowed"])

    def test_loopback_requires_explicit_gate(self):
        self.assertFalse(evaluate_url_policy("http://127.0.0.1:8080/", allow_loopback=False)["allowed"])
        self.assertTrue(evaluate_url_policy("http://127.0.0.1:8080/", allow_loopback=True)["allowed"])
        self.assertTrue(evaluate_url_policy("http://localhost:8080/", allow_loopback=True)["allowed"])

    def test_about_blank_only_non_http_special_case(self):
        self.assertTrue(evaluate_url_policy("about:blank")["allowed"])
        for value in ("file:///tmp/x", "javascript:alert(1)", "data:text/plain,x"):
            self.assertFalse(evaluate_url_policy(value, allow_hosts=["example.com"])["allowed"], value)

    def test_embedded_credentials_denied(self):
        r = evaluate_url_policy("https://user:pass@example.com/", allow_hosts=["example.com"])
        self.assertFalse(r["allowed"])
        self.assertEqual(r["reason"], "embedded_credentials_denied")

    def test_url_output_redacts_query_fragment_and_userinfo(self):
        r=evaluate_url_policy("https://example.com/path?token=secret#frag",allow_hosts=["example.com"])
        self.assertTrue(r["allowed"])
        self.assertEqual(r["url"],"https://example.com/path")
        self.assertTrue(r["query_redacted"])
        denied=evaluate_url_policy("https://user:pass@example.com/private?x=y",allow_hosts=["example.com"])
        self.assertFalse(denied["allowed"])
        self.assertNotIn("user",denied["url"] or "")
        self.assertNotIn("pass",denied["url"] or "")
        self.assertNotIn("x=y",denied["url"] or "")
        self.assertEqual(sanitize_url_for_output("https://example.com:443/a?b=c#d"),"https://example.com/a")

    def test_allow_host_normalization(self):
        self.assertEqual(normalize_allow_host("Example.COM."), "example.com")
        self.assertEqual(normalize_allow_hosts(["example.com", "EXAMPLE.COM"]), ["example.com"])
        with self.assertRaises(BrowserSessionError):
            normalize_allow_host("example.com:443")


class SessionIdTests(unittest.TestCase):
    def test_session_id_validation(self):
        self.assertEqual(validate_session_id("R2-test_123"), "r2-test_123")
        for value in ("short", "../escape", "bad space", "A" * 65):
            with self.assertRaises(BrowserSessionError):
                validate_session_id(value)


class SessionStoreTests(unittest.TestCase):
    def test_atomic_roundtrip_and_permissions(self):
        now = dt.datetime(2026, 9, 12, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            store = BrowserSessionStore(td, now_fn=lambda: now)
            record = build_session_record(
                session_id="r2-test01", local_port=40001, remote_port=50001, tunnel_pid=123,
                remote_profile="/tmp/macctl-r2-session-r2-test01",
                remote_download_dir="/tmp/macctl-r2-download-r2-test01",
                allow_hosts=["example.com"], allow_loopback=False, ttl_seconds=300,
                chrome_product="Chrome/test", protocol_version="1.3",
            )
            # build_session_record uses real UTC; replace expiry for deterministic store test.
            record["created_at"] = "2026-09-12T12:00:00Z"
            record["expires_at"] = "2026-09-12T12:05:00Z"
            store.save(record, create_only=True)
            loaded = store.load("r2-test01")
            self.assertEqual(loaded["allow_hosts"], ["example.com"])
            mode = os.stat(os.path.join(td, "r2-test01.json")).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            with self.assertRaisesRegex(BrowserSessionError, "session_already_exists"):
                store.save(record, create_only=True)
            store.delete("r2-test01")
            with self.assertRaisesRegex(BrowserSessionError, "session_not_found"):
                store.load("r2-test01")

    def test_expiry_fail_closed_but_list_reports_expired(self):
        now = dt.datetime(2026, 9, 12, 12, 10, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            store = BrowserSessionStore(td, now_fn=lambda: now)
            record = {
                "schema": "macctl-browser-session/v1",
                "session_id": "r2-expired1",
                "created_at": "2026-09-12T12:00:00Z",
                "expires_at": "2026-09-12T12:05:00Z",
            }
            store.save(record)
            with self.assertRaisesRegex(BrowserSessionError, "session_expired"):
                store.load("r2-expired1")
            self.assertTrue(store.load("r2-expired1", allow_expired=True))
            self.assertTrue(store.list()[0]["expired"])

    def test_ttl_bounds(self):
        common = dict(
            session_id="r2-ttltest", local_port=1, remote_port=2, tunnel_pid=3,
            remote_profile="/tmp/p", remote_download_dir="/tmp/d",
        )
        with self.assertRaisesRegex(BrowserSessionError, "invalid_session_ttl"):
            build_session_record(**common, ttl_seconds=59)
        with self.assertRaisesRegex(BrowserSessionError, "invalid_session_ttl"):
            build_session_record(**common, ttl_seconds=14401)


class ProductionQualificationTests(unittest.TestCase):
    def test_production_requires_exact_allow_host_and_no_loopback(self):
        with self.assertRaisesRegex(BrowserSessionError, "production_allow_host_required"):
            validate_qualification_config(site_class="production")
        with self.assertRaisesRegex(BrowserSessionError, "production_loopback_forbidden"):
            validate_qualification_config(site_class="production", allow_hosts=["example.com"], allow_loopback=True)
        with self.assertRaisesRegex(BrowserSessionError, "production_wildcard_host_forbidden"):
            validate_qualification_config(site_class="production", allow_hosts=["*.example.com"])
        cfg = validate_qualification_config(site_class="production", allow_hosts=["Example.com"])
        self.assertEqual(cfg["allow_hosts"], ["example.com"])
        self.assertEqual(cfg["qualification_scope"], "read_only")

    def test_stateful_mutation_requires_bounded_action_id(self):
        with self.assertRaisesRegex(BrowserSessionError, "production_authorized_action_id_required"):
            validate_qualification_config(
                site_class="production", qualification_scope="stateful_mutation", allow_hosts=["example.com"]
            )
        cfg = validate_qualification_config(
            site_class="production", qualification_scope="stateful_mutation",
            allow_hosts=["example.com"], authorized_action_id="phase3.test-action:01",
        )
        self.assertEqual(cfg["authorized_action_id"], "phase3.test-action:01")

    def test_nonproduction_scope_stays_read_only(self):
        with self.assertRaisesRegex(BrowserSessionError, "nonproduction_scope_must_be_read_only"):
            validate_qualification_config(site_class="public", qualification_scope="controlled_input", allow_hosts=["example.com"])

    def test_production_read_only_blocks_type_and_click(self):
        record = {
            "site_class": "production", "qualification_scope": "read_only",
            "authorized_action_id": None,
        }
        self.assertTrue(evaluate_session_action_policy(record, "session-query")["allowed"])
        self.assertFalse(evaluate_session_action_policy(record, "session-type", production_confirmed=True)["allowed"])
        self.assertFalse(evaluate_session_action_policy(record, "session-click", confirmed=True, production_confirmed=True)["allowed"])
        self.assertTrue(evaluate_session_action_policy(record, "session-download", confirmed=True)["allowed"])

    def test_production_credential_input_requires_stateful_scope_and_action_id(self):
        controlled = {"site_class": "production", "qualification_scope": "controlled_input"}
        r = evaluate_session_action_policy(
            controlled, "session-type", production_confirmed=True, input_class="credential"
        )
        self.assertFalse(r["allowed"])
        self.assertEqual(r["reason"], "production_credential_requires_stateful_mutation_scope")

        stateful_missing_id = {"site_class": "production", "qualification_scope": "stateful_mutation"}
        r = evaluate_session_action_policy(
            stateful_missing_id, "session-type", production_confirmed=True, input_class="credential"
        )
        self.assertFalse(r["allowed"])
        self.assertEqual(r["reason"], "production_authorized_action_id_missing")

        stateful = {
            "site_class": "production", "qualification_scope": "stateful_mutation",
            "authorized_action_id": "phase3.credential.01",
        }
        self.assertFalse(evaluate_session_action_policy(
            stateful, "session-type", input_class="credential"
        )["allowed"])
        self.assertTrue(evaluate_session_action_policy(
            stateful, "session-type", production_confirmed=True, input_class="credential"
        )["allowed"])

    def test_stateful_click_needs_action_id_and_double_confirmation(self):
        record = {
            "site_class": "production", "qualification_scope": "stateful_mutation",
            "authorized_action_id": "phase3.action.01",
        }
        self.assertFalse(evaluate_session_action_policy(record, "session-click", confirmed=True)["allowed"])
        self.assertFalse(evaluate_session_action_policy(record, "session-click", production_confirmed=True)["allowed"])
        self.assertTrue(evaluate_session_action_policy(
            record, "session-click", confirmed=True, production_confirmed=True
        )["allowed"])

    def test_record_persists_phase3_envelope(self):
        record = build_session_record(
            session_id="r2-prod001", local_port=1, remote_port=2, tunnel_pid=3,
            remote_profile="/tmp/p", remote_download_dir="/tmp/d",
            allow_hosts=["github.com"], site_class="production", qualification_scope="read_only",
        )
        self.assertEqual(record["site_class"], "production")
        self.assertEqual(record["qualification_scope"], "read_only")
        self.assertEqual(record["credential_entry"], "NOT_EXPOSED_FOR_SCOPE")
        self.assertFalse(record["default_profile_touched"])

        stateful = build_session_record(
            session_id="r2-prod002", local_port=1, remote_port=2, tunnel_pid=3,
            remote_profile="/tmp/p", remote_download_dir="/tmp/d",
            allow_hosts=["example.com"], site_class="production",
            qualification_scope="stateful_mutation", authorized_action_id="phase3.credential.02",
        )
        self.assertEqual(stateful["credential_entry"], "EPHEMERAL_FILE_GATED")


class PidIdentityTests(unittest.TestCase):
    def test_current_python_pid_identity(self):
        self.assertTrue(pid_alive(os.getpid()))
        self.assertTrue(pid_matches(os.getpid(), ["python"]))
        self.assertFalse(pid_matches(os.getpid(), ["definitely-not-in-command-line-xyz"]))
        self.assertFalse(pid_alive(99999999))


if __name__ == "__main__":
    unittest.main()
