import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path

from native_browser_engine import (
    NATIVE_ACTION_SCHEMA,
    NativeBrowserActionError,
    NativeBrowserActionStore,
    assess_native_action_recovery,
    build_native_action_record,
    complete_native_action_event,
    evaluate_native_address_bar,
    evaluate_native_action_effect,
    finish_native_action_record,
    materialize_interrupted_native_action,
    prepare_native_action_event,
    record_native_action_event,
    validate_native_action_plan,
)


class NativeBrowserPlanTests(unittest.TestCase):
    def test_reversible_plan_is_exact_host_new_test_object_cleanup_only(self):
        plan = validate_native_action_plan(
            site_host="Blog.Udianliao.com",
            authorized_action_id="phase3.native.ghost.01",
            intent="reversible_test",
        )
        self.assertEqual(plan["site_host"], "blog.udianliao.com")
        self.assertEqual(plan["site_path_prefix"], "/")
        self.assertEqual(plan["resource_scope"], "new_test_object_only")
        self.assertTrue(plan["cleanup_required"])
        self.assertFalse(plan["publish_allowed"])
        self.assertIn("cleanup_test_object", plan["allowed_effects"])
        self.assertIn("publish", plan["hard_forbidden_effects"])
        self.assertEqual(plan["credential_export"], "FORBIDDEN")
        self.assertEqual(plan["default_profile_cdp"], "FORBIDDEN")

    def test_wildcard_and_loopback_hosts_fail_closed(self):
        for host in ("*.example.com", "localhost", "127.0.0.1"):
            with self.assertRaises(NativeBrowserActionError, msg=host):
                validate_native_action_plan(site_host=host, authorized_action_id="phase3.native.test.01")

    def test_action_id_is_mandatory_and_bounded(self):
        with self.assertRaisesRegex(NativeBrowserActionError, "native_action_id_required"):
            validate_native_action_plan(site_host="example.com", authorized_action_id="")
        with self.assertRaises(NativeBrowserActionError):
            validate_native_action_plan(site_host="example.com", authorized_action_id="x/../bad")

    def test_reversible_plan_requires_new_test_object_and_cleanup(self):
        with self.assertRaisesRegex(NativeBrowserActionError, "new_test_object_only"):
            validate_native_action_plan(
                site_host="example.com", authorized_action_id="phase3.native.test.02",
                resource_scope="existing_content",
            )
        with self.assertRaisesRegex(NativeBrowserActionError, "requires_cleanup"):
            validate_native_action_plan(
                site_host="example.com", authorized_action_id="phase3.native.test.03",
                cleanup_required=False,
            )

    def test_read_only_plan_cannot_claim_mutation_scope(self):
        plan = validate_native_action_plan(
            site_host="example.com", authorized_action_id="phase3.native.read.01", intent="read_only",
        )
        self.assertEqual(plan["allowed_effects"], ["observe"])
        self.assertFalse(plan["cleanup_required"])
        with self.assertRaisesRegex(NativeBrowserActionError, "must_not_claim_mutation_scope"):
            validate_native_action_plan(
                site_host="example.com", authorized_action_id="phase3.native.read.02",
                intent="read_only", resource_scope="new_test_object_only",
            )

    def test_chrome_and_safari_browser_families(self):
        chrome = validate_native_action_plan(
            site_host="example.com", authorized_action_id="r4.native.chrome.01", intent="read_only", browser_family="chrome",
        )
        safari = validate_native_action_plan(
            site_host="example.com", authorized_action_id="r4.native.safari.01", intent="read_only", browser_family="safari",
        )
        self.assertEqual(chrome["browser_bundle_id"], "com.google.Chrome")
        self.assertEqual(safari["browser_bundle_id"], "com.apple.Safari")
        self.assertEqual(safari["browser_family"], "safari")

    def test_unknown_native_browser_fails_closed(self):
        with self.assertRaisesRegex(NativeBrowserActionError, "unsupported_native_browser"):
            validate_native_action_plan(
                site_host="example.com", authorized_action_id="r4.native.bad.01", intent="read_only", browser_family="firefox",
            )

    def test_ttl_is_bounded(self):
        for ttl in (59, 3601):
            with self.assertRaisesRegex(NativeBrowserActionError, "invalid_native_action_ttl"):
                validate_native_action_plan(
                    site_host="example.com", authorized_action_id="phase3.native.ttl.01", ttl_seconds=ttl,
                )

    def test_path_prefix_is_bounded_and_traversal_fails_closed(self):
        plan = validate_native_action_plan(
            site_host="blog.udianliao.com", site_path_prefix="/ghost/",
            authorized_action_id="phase3.native.path.01", intent="read_only",
        )
        self.assertEqual(plan["site_path_prefix"], "/ghost/")
        for prefix in ("ghost/", "/ghost/?x=1", "/ghost/#x", "/ghost/../admin", "/ghost/%2e%2e/admin"):
            with self.assertRaises(NativeBrowserActionError, msg=prefix):
                validate_native_action_plan(
                    site_host="blog.udianliao.com", site_path_prefix=prefix,
                    authorized_action_id="phase3.native.path.02", intent="read_only",
                )


class NativeBrowserAddressBarTests(unittest.TestCase):
    @staticmethod
    def match(value):
        return {"role":"AXTextField", "value":value, "description":"Address and search bar"}

    def test_exact_host_and_path_prefix_pass_without_echoing_raw_url(self):
        evidence = evaluate_native_address_bar(
            [self.match("blog.udianliao.com/ghost/#/posts")],
            expected_host="blog.udianliao.com", path_prefix="/ghost/",
        )
        self.assertEqual(evidence["status"], "PASS")
        self.assertEqual(evidence["site_host"], "blog.udianliao.com")
        self.assertEqual(evidence["site_path_prefix"], "/ghost/")
        self.assertFalse(evidence["raw_url_returned"])
        self.assertFalse(evidence["network_egress_proof"])

    def test_wrong_host_or_path_fails_closed(self):
        with self.assertRaisesRegex(NativeBrowserActionError, "host_mismatch"):
            evaluate_native_address_bar(
                [self.match("example.com/ghost/")],
                expected_host="blog.udianliao.com", path_prefix="/ghost/",
            )
        with self.assertRaisesRegex(NativeBrowserActionError, "path_prefix_mismatch"):
            evaluate_native_address_bar(
                [self.match("blog.udianliao.com/wp-admin/")],
                expected_host="blog.udianliao.com", path_prefix="/ghost/",
            )

    def test_http_and_ambiguous_address_fields_fail_closed(self):
        with self.assertRaisesRegex(NativeBrowserActionError, "http_scheme_forbidden"):
            evaluate_native_address_bar(
                [self.match("http://blog.udianliao.com/ghost/")],
                expected_host="blog.udianliao.com", path_prefix="/ghost/",
            )
        with self.assertRaisesRegex(NativeBrowserActionError, "ambiguous"):
            evaluate_native_address_bar(
                [self.match("blog.udianliao.com/ghost/"), self.match("blog.udianliao.com/ghost/#/posts")],
                expected_host="blog.udianliao.com", path_prefix="/ghost/",
            )


class NativeBrowserPolicyTests(unittest.TestCase):
    def record(self):
        plan = validate_native_action_plan(
            site_host="blog.udianliao.com",
            authorized_action_id="phase3.native.policy.01",
            intent="reversible_test",
        )
        return build_native_action_record(plan)

    def test_observe_is_allowed_without_mutation_confirmation(self):
        self.assertTrue(evaluate_native_action_effect(self.record(), "observe")["allowed"])

    def test_mutation_requires_triple_confirmation(self):
        record = self.record()
        self.assertFalse(evaluate_native_action_effect(record, "reversible_mutation", confirmed=True)["allowed"])
        self.assertFalse(evaluate_native_action_effect(
            record, "reversible_mutation", confirmed=True, production_confirmed=True
        )["allowed"])
        decision = evaluate_native_action_effect(
            record, "reversible_mutation", confirmed=True, production_confirmed=True, native_profile_confirmed=True
        )
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["reason"], "native_action_triple_confirmation_present")

    def test_hard_forbidden_effects_stay_blocked_even_with_all_confirmations(self):
        record = self.record()
        for effect in ("publish", "delete_existing", "send", "payment", "account_security", "credential_export", "cookie_export", "session_token_export"):
            decision = evaluate_native_action_effect(
                record, effect, confirmed=True, production_confirmed=True, native_profile_confirmed=True
            )
            self.assertFalse(decision["allowed"], effect)
            self.assertEqual(decision["reason"], "native_action_effect_hard_forbidden")

    def test_finish_requires_cleanup_evidence_after_reversible_mutation(self):
        record = record_native_action_event(self.record(), "reversible_mutation", status="PASS")
        record = record_native_action_event(record, "cleanup_test_object", status="PASS")
        with self.assertRaisesRegex(NativeBrowserActionError, "cleanup_verification_required"):
            finish_native_action_record(record, result="verified_cleanup", cleanup_verified=False)
        final = finish_native_action_record(record, result="verified_cleanup", cleanup_verified=True)
        self.assertEqual(final["status"], "CLOSED")
        self.assertTrue(final["cleanup_verified"])

    def test_abort_no_mutation_rejects_conflicting_event_history(self):
        record = record_native_action_event(self.record(), "input_plain", status="PASS")
        with self.assertRaisesRegex(NativeBrowserActionError, "abort_claim_conflicts"):
            finish_native_action_record(record, result="aborted_no_mutation")


class NativeBrowserRecoveryTests(unittest.TestCase):
    def record(self, *, intent="reversible_test", now=None, ttl=900):
        plan = validate_native_action_plan(
            site_host="blog.udianliao.com",
            site_path_prefix="/ghost/",
            authorized_action_id="phase3.native.recovery.01",
            intent=intent,
            ttl_seconds=ttl,
        )
        return build_native_action_record(plan, now=now)

    def test_write_ahead_pending_event_forces_reconcile_before_gui_completion(self):
        record = prepare_native_action_event(self.record(), "reversible_mutation")
        recovery = assess_native_action_recovery(record)
        self.assertEqual(recovery["recovery_state"], "RECONCILE_REQUIRED")
        self.assertTrue(recovery["pending_event_present"])
        self.assertTrue(recovery["new_action_blocked"])
        decision = evaluate_native_action_effect(
            record, "reversible_mutation", confirmed=True,
            production_confirmed=True, native_profile_confirmed=True,
        )
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["reason"], "native_action_reconcile_required")

    def test_interrupted_pending_event_can_be_materialized_as_explicit_uncertainty(self):
        pending = prepare_native_action_event(self.record(), "input_plain")
        recovered = materialize_interrupted_native_action(pending)
        self.assertEqual(recovered["status"], "RECONCILE_REQUIRED")
        self.assertIsNone(recovered["pending_event"])
        self.assertIsNotNone(recovered["uncertain_event"])
        self.assertEqual(recovered["last_event"]["status"], "PROCESS_INTERRUPTED_UNCERTAIN")
        self.assertEqual(recovered["event_counts"]["input_plain"], 1)
        self.assertEqual(assess_native_action_recovery(recovered)["recovery_state"], "RECONCILE_REQUIRED")
        self.assertTrue(evaluate_native_action_effect(
            recovered, "cleanup_test_object", confirmed=True,
            production_confirmed=True, native_profile_confirmed=True,
        )["allowed"])

    def test_completed_write_ahead_pass_clears_pending_and_counts_event(self):
        record = prepare_native_action_event(self.record(), "input_plain")
        record = complete_native_action_event(record, "input_plain", status="PASS")
        self.assertIsNone(record["pending_event"])
        self.assertIsNone(record["uncertain_event"])
        self.assertEqual(record["event_counts"]["input_plain"], 1)
        self.assertEqual(assess_native_action_recovery(record)["recovery_state"], "ACTIVE_VALID")

    def test_failed_attempt_becomes_reconcile_required_and_only_cleanup_is_allowed(self):
        record = prepare_native_action_event(self.record(), "reversible_mutation")
        record = complete_native_action_event(record, "reversible_mutation", status="FAIL")
        self.assertEqual(record["status"], "RECONCILE_REQUIRED")
        self.assertIsNotNone(record["uncertain_event"])
        recovery = assess_native_action_recovery(record)
        self.assertEqual(recovery["recovery_state"], "RECONCILE_REQUIRED")
        blocked = evaluate_native_action_effect(
            record, "reversible_mutation", confirmed=True,
            production_confirmed=True, native_profile_confirmed=True,
        )
        self.assertFalse(blocked["allowed"])
        cleanup = evaluate_native_action_effect(
            record, "cleanup_test_object", confirmed=True,
            production_confirmed=True, native_profile_confirmed=True,
        )
        self.assertTrue(cleanup["allowed"])

    def test_recovery_cleanup_can_execute_but_requires_final_cleanup_verification(self):
        record = prepare_native_action_event(self.record(), "reversible_mutation")
        record = complete_native_action_event(record, "reversible_mutation", status="FAIL")
        cleanup_prepared = prepare_native_action_event(record, "cleanup_test_object")
        self.assertTrue(cleanup_prepared["pending_event"]["recovery_cleanup"])
        cleanup_done = complete_native_action_event(cleanup_prepared, "cleanup_test_object", status="PASS")
        self.assertEqual(cleanup_done["status"], "RECONCILE_REQUIRED")
        self.assertIsNotNone(cleanup_done["uncertain_event"])
        self.assertEqual(assess_native_action_recovery(cleanup_done)["recovery_state"], "RECONCILE_REQUIRED")
        final = finish_native_action_record(cleanup_done, result="verified_cleanup", cleanup_verified=True)
        self.assertEqual(final["status"], "CLOSED")

    def test_expired_no_mutation_is_distinct_from_expired_after_mutation(self):
        created = dt.datetime(2026, 9, 13, 0, 0, tzinfo=dt.timezone.utc)
        after = created + dt.timedelta(seconds=61)
        read_only = self.record(intent="read_only", now=created, ttl=60)
        safe = assess_native_action_recovery(read_only, now=after)
        self.assertEqual(safe["recovery_state"], "EXPIRED_NO_MUTATION")
        self.assertFalse(safe["new_action_blocked"])

        mutated = self.record(now=created, ttl=60)
        mutated = record_native_action_event(mutated, "reversible_mutation", status="PASS")
        risky = assess_native_action_recovery(mutated, now=after)
        self.assertEqual(risky["recovery_state"], "RECONCILE_REQUIRED")
        self.assertTrue(risky["new_action_blocked"])

    def test_pending_or_uncertain_record_cannot_claim_aborted_no_mutation(self):
        pending = prepare_native_action_event(self.record(), "reversible_mutation")
        with self.assertRaisesRegex(NativeBrowserActionError, "abort_claim_conflicts"):
            finish_native_action_record(pending, result="aborted_no_mutation")
        uncertain = complete_native_action_event(pending, "reversible_mutation", status="FAIL")
        with self.assertRaisesRegex(NativeBrowserActionError, "abort_claim_conflicts"):
            finish_native_action_record(uncertain, result="aborted_no_mutation")

    def test_verified_cleanup_can_close_reconcile_required_record(self):
        record = prepare_native_action_event(self.record(), "reversible_mutation")
        record = complete_native_action_event(record, "reversible_mutation", status="FAIL")
        final = finish_native_action_record(record, result="verified_cleanup", cleanup_verified=True)
        self.assertEqual(final["status"], "CLOSED")
        self.assertTrue(final["cleanup_verified"])
        self.assertIsNone(final["pending_event"])
        self.assertIsNone(final["uncertain_event"])
        self.assertEqual(assess_native_action_recovery(final)["recovery_state"], "NONE")


class NativeBrowserStoreTests(unittest.TestCase):
    def test_store_is_private_atomic_and_create_only(self):
        with tempfile.TemporaryDirectory() as td:
            store = NativeBrowserActionStore(Path(td) / "actions")
            plan = validate_native_action_plan(
                site_host="example.com", authorized_action_id="phase3.native.store.01", intent="read_only",
            )
            record = build_native_action_record(plan)
            store.save(record, create_only=True)
            root_mode = os.stat(store.root).st_mode & 0o777
            file_mode = os.stat(store.root / "phase3.native.store.01.json").st_mode & 0o777
            self.assertEqual(root_mode, 0o700)
            self.assertEqual(file_mode, 0o600)
            self.assertEqual(store.load("phase3.native.store.01")["schema"], NATIVE_ACTION_SCHEMA)
            with self.assertRaisesRegex(NativeBrowserActionError, "already_exists"):
                store.save(record, create_only=True)

    def test_store_save_fsyncs_directory_after_atomic_replace(self):
        class ProbeStore(NativeBrowserActionStore):
            def __init__(self, root):
                super().__init__(root)
                self.root_fsync_calls = 0

            def _fsync_root(self):
                self.root_fsync_calls += 1
                return super()._fsync_root()

        with tempfile.TemporaryDirectory() as td:
            store = ProbeStore(Path(td) / "actions")
            plan = validate_native_action_plan(
                site_host="example.com", authorized_action_id="phase3.native.fsync.01", intent="read_only",
            )
            store.save(build_native_action_record(plan), create_only=True)
            self.assertEqual(store.root_fsync_calls, 1)

    def test_store_expires_active_record(self):
        created = dt.datetime(2026, 9, 13, 0, 0, tzinfo=dt.timezone.utc)
        now = created + dt.timedelta(seconds=61)
        with tempfile.TemporaryDirectory() as td:
            store = NativeBrowserActionStore(Path(td) / "actions", now_fn=lambda: now)
            plan = validate_native_action_plan(
                site_host="example.com", authorized_action_id="phase3.native.expire.01",
                intent="read_only", ttl_seconds=60,
            )
            record = build_native_action_record(plan, now=created)
            store.save(record)
            with self.assertRaisesRegex(NativeBrowserActionError, "expired"):
                store.load("phase3.native.expire.01")
            listed = store.list()[0]
            self.assertTrue(listed["expired"])
            self.assertEqual(listed["recovery"]["recovery_state"], "EXPIRED_NO_MUTATION")

    def test_store_reports_same_site_recovery_blocker(self):
        with tempfile.TemporaryDirectory() as td:
            store = NativeBrowserActionStore(Path(td) / "actions")
            plan = validate_native_action_plan(
                site_host="blog.udianliao.com",
                site_path_prefix="/ghost/",
                authorized_action_id="phase3.native.store.recovery01",
                intent="reversible_test",
            )
            record = prepare_native_action_event(build_native_action_record(plan), "reversible_mutation")
            store.save(record)
            blockers = store.recovery_blockers("blog.udianliao.com")
            self.assertEqual(len(blockers), 1)
            self.assertEqual(blockers[0]["authorized_action_id"], "phase3.native.store.recovery01")
            self.assertEqual(store.recovery_blockers("example.com"), [])

    def test_action_and_site_locks_are_private_and_fail_closed_when_busy(self):
        with tempfile.TemporaryDirectory() as td:
            store = NativeBrowserActionStore(Path(td) / "actions")
            with store.action_lock("phase3.native.lock.01"):
                lock_root = store.root / ".locks"
                self.assertEqual(os.stat(lock_root).st_mode & 0o777, 0o700)
                lock_file = lock_root / "action-phase3.native.lock.01.lock"
                self.assertEqual(os.stat(lock_file).st_mode & 0o777, 0o600)
                with self.assertRaisesRegex(NativeBrowserActionError, "lock_busy"):
                    with store.action_lock("phase3.native.lock.01"):
                        pass
            with store.site_lock("blog.udianliao.com"):
                with self.assertRaisesRegex(NativeBrowserActionError, "lock_busy"):
                    with store.site_lock("blog.udianliao.com"):
                        pass

    def test_site_single_flight_blocks_active_and_recovery_but_not_expired_no_mutation(self):
        created = dt.datetime(2026, 9, 13, 0, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as td:
            store = NativeBrowserActionStore(Path(td) / "actions", now_fn=lambda: created)
            active_plan = validate_native_action_plan(
                site_host="blog.udianliao.com", site_path_prefix="/ghost/",
                authorized_action_id="phase3.native.singleflight.active", intent="read_only",
            )
            active = build_native_action_record(active_plan, now=created)
            store.save(active)
            blockers = store.site_single_flight_blockers("blog.udianliao.com")
            self.assertEqual([x["authorized_action_id"] for x in blockers], ["phase3.native.singleflight.active"])

            store.now_fn = lambda: created + dt.timedelta(seconds=901)
            self.assertEqual(store.site_single_flight_blockers("blog.udianliao.com"), [])

            recovery_plan = validate_native_action_plan(
                site_host="blog.udianliao.com", site_path_prefix="/ghost/",
                authorized_action_id="phase3.native.singleflight.recovery", intent="reversible_test",
            )
            recovery = build_native_action_record(recovery_plan, now=created)
            recovery = finish_native_action_record(recovery, result="cleanup_pending")
            store.save(recovery)
            blockers = store.site_single_flight_blockers("blog.udianliao.com")
            self.assertEqual([x["authorized_action_id"] for x in blockers], ["phase3.native.singleflight.recovery"])


if __name__ == "__main__":
    unittest.main()
