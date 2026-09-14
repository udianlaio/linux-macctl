import unittest

from policy_engine import (
    BREAK_GLASS,
    FORBIDDEN_BY_POLICY,
    HIGH_IMPACT,
    MUTATE_REVERSIBLE,
    MUTATE_STATEFUL,
    READ_ONLY,
    classify_operation,
    evaluate_break_glass,
    policy_status,
)

BLOCKED_CFG = {
    "allow_macos_system_update": False,
    "allow_macos_major_upgrade": False,
}


class TypedPolicyTests(unittest.TestCase):
    def test_read_only_classification(self):
        self.assertEqual(classify_operation("system", "network-summary", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("doctor", None, {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("file", "sha256", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("gui", "semantic-find", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("gui", "event-observe", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("gui", "event-wait", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("gui", "helper-lifecycle-status", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("artifact", "host-adapter-evaluate", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("artifact", "host-native-conformance-contract", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("artifact", "host-native-conformance-fixture", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("artifact", "host-native-runtime-watch-baseline", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("artifact", "host-native-runtime-watch-evaluate", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("artifact", "relay-status", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("browser", "cdp-plan", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("browser", "qualification-plan", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("browser", "url-check", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("browser", "session-query", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("browser", "cdp-smoke", {}, BLOCKED_CFG).risk_class, MUTATE_REVERSIBLE)
        self.assertEqual(classify_operation("browser", "session-start", {}, BLOCKED_CFG).risk_class, MUTATE_REVERSIBLE)
        self.assertEqual(classify_operation("browser", "session-type", {}, BLOCKED_CFG).risk_class, MUTATE_REVERSIBLE)
        self.assertEqual(classify_operation("transaction", "status", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("fleet", "list", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("fleet", "status", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("fleet", "doctor", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("fleet", "resolve", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        self.assertEqual(classify_operation("fleet", "plan", {}, BLOCKED_CFG).risk_class, READ_ONLY)
        unknown_fleet = classify_operation("fleet", "future-mutation", {}, BLOCKED_CFG)
        self.assertFalse(unknown_fleet.allowed)
        self.assertEqual(unknown_fleet.reason, "unknown_typed_operation_fail_closed")
        self.assertEqual(classify_operation("gui", "helper-lifecycle-register", {}, BLOCKED_CFG).risk_class, MUTATE_STATEFUL)
        self.assertEqual(classify_operation("gui", "helper-lifecycle-unregister", {}, BLOCKED_CFG).risk_class, MUTATE_STATEFUL)

    def test_browser_click_and_download_require_explicit_confirmation(self):
        for action in ("session-click", "session-download"):
            denied = classify_operation("browser", action, {"confirm": False}, BLOCKED_CFG)
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.risk_class, FORBIDDEN_BY_POLICY)
            self.assertTrue(denied.requires_confirmation)
            allowed = classify_operation("browser", action, {"confirm": True}, BLOCKED_CFG)
            self.assertTrue(allowed.allowed)
            self.assertEqual(allowed.risk_class, MUTATE_STATEFUL)
            self.assertTrue(allowed.requires_confirmation)

    def test_native_browser_contract_actions_are_policy_gated(self):
        for action in ("native-action-plan", "native-action-list", "native-action-status", "native-action-observe", "native-action-recovery-plan", "native-action-recovery-observe"):
            d = classify_operation("browser", action, {}, BLOCKED_CFG)
            self.assertTrue(d.allowed, action)
            self.assertEqual(d.risk_class, READ_ONLY)
        for action in ("native-action-begin", "native-action-type", "native-action-click", "native-action-key", "native-action-finish", "native-action-recover-interrupted"):
            denied = classify_operation("browser", action, {"confirm": False}, BLOCKED_CFG)
            self.assertFalse(denied.allowed, action)
            self.assertEqual(denied.risk_class, FORBIDDEN_BY_POLICY)
            allowed = classify_operation("browser", action, {"confirm": True}, BLOCKED_CFG)
            self.assertTrue(allowed.allowed, action)
            self.assertEqual(allowed.risk_class, MUTATE_STATEFUL)

    def test_relay_mutation_classification(self):
        self.assertEqual(classify_operation("artifact", "relay-stage", {}, BLOCKED_CFG).risk_class, MUTATE_REVERSIBLE)
        self.assertEqual(classify_operation("artifact", "relay-cleanup", {}, BLOCKED_CFG).risk_class, MUTATE_STATEFUL)

    def test_file_mutation_classification(self):
        self.assertEqual(classify_operation("file", "mkdir", {}, BLOCKED_CFG).risk_class, MUTATE_REVERSIBLE)
        self.assertEqual(classify_operation("file", "rm", {}, BLOCKED_CFG).risk_class, MUTATE_STATEFUL)
        self.assertEqual(
            classify_operation("file", "rm", {"recursive": True}, BLOCKED_CFG).risk_class,
            HIGH_IMPACT,
        )

    def test_restart_requires_existing_confirmation_contract(self):
        denied = classify_operation("power", "restart", {"confirm": False}, BLOCKED_CFG)
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.risk_class, FORBIDDEN_BY_POLICY)
        self.assertTrue(denied.requires_confirmation)
        allowed = classify_operation("power", "restart", {"confirm": True}, BLOCKED_CFG)
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.risk_class, HIGH_IMPACT)

    def test_generic_update_install_is_fail_closed_when_system_updates_blocked(self):
        d = classify_operation("update", "install", {"label": "Some Update"}, BLOCKED_CFG)
        self.assertFalse(d.allowed)
        self.assertEqual(d.risk_class, FORBIDDEN_BY_POLICY)
        self.assertEqual(d.reason, "generic_system_update_install_blocked_use_safari_only_path")

    def test_install_all_is_blocked(self):
        d = classify_operation("update", "install-all", {}, BLOCKED_CFG)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "macos_system_update_policy")

    def test_safari_only_typed_path_remains_allowed(self):
        for action in ("safari-download", "safari-install"):
            d = classify_operation("update", action, {}, BLOCKED_CFG)
            self.assertTrue(d.allowed)
            self.assertEqual(d.risk_class, MUTATE_STATEFUL)
            self.assertEqual(d.reason, "explicit_safari_only_path")

    def test_major_upgrade_stays_blocked_even_if_system_updates_are_enabled(self):
        cfg = {"allow_macos_system_update": True, "allow_macos_major_upgrade": False}
        d = classify_operation("update", "install", {"label": "macOS Tahoe 26.1"}, cfg)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "macos_major_upgrade_policy")
        all_d = classify_operation("update", "install-all", {}, cfg)
        self.assertFalse(all_d.allowed)
        self.assertEqual(all_d.reason, "macos_major_upgrade_policy_install_all_unsafe")

    def test_security_hardening_read_only_and_future_mutations_are_gated(self):
        assess = classify_operation("security", "hardening-assess", {}, BLOCKED_CFG)
        self.assertTrue(assess.allowed)
        self.assertEqual(assess.risk_class, READ_ONLY)

        denied_fw = classify_operation("security", "firewall-enable", {"confirm": False}, BLOCKED_CFG)
        self.assertFalse(denied_fw.allowed)
        self.assertEqual(denied_fw.risk_class, FORBIDDEN_BY_POLICY)
        self.assertTrue(denied_fw.requires_confirmation)

        allowed_fw = classify_operation("security", "firewall-enable", {"confirm": True}, BLOCKED_CFG)
        self.assertTrue(allowed_fw.allowed)
        self.assertEqual(allowed_fw.risk_class, HIGH_IMPACT)
        self.assertTrue(allowed_fw.requires_confirmation)

        filevault = classify_operation("security", "filevault-enable", {"confirm": True}, BLOCKED_CFG)
        self.assertFalse(filevault.allowed)
        self.assertEqual(filevault.risk_class, FORBIDDEN_BY_POLICY)
        self.assertEqual(filevault.reason, "filevault_out_of_scope_requires_separate_qualification")

        unknown_security = classify_operation("security", "future-security-mutation", {}, BLOCKED_CFG)
        self.assertFalse(unknown_security.allowed)
        self.assertEqual(unknown_security.reason, "unknown_typed_operation_fail_closed")

    def test_unknown_typed_operation_fails_closed(self):
        d = classify_operation("future-family", "mystery", {}, BLOCKED_CFG)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "unknown_typed_operation_fail_closed")

    def test_generic_shell_is_break_glass(self):
        self.assertEqual(classify_operation("exec", None, {}, BLOCKED_CFG).risk_class, BREAK_GLASS)
        self.assertEqual(classify_operation("job", "start", {}, BLOCKED_CFG).risk_class, BREAK_GLASS)

    def test_sync_delete_is_high_impact_but_dry_run_is_read_only(self):
        d = classify_operation("sync", "push", {"delete": True}, BLOCKED_CFG)
        self.assertEqual(d.risk_class, HIGH_IMPACT)
        dry = classify_operation("sync", "push", {"delete": True, "dry_run": True}, BLOCKED_CFG)
        self.assertEqual(dry.risk_class, READ_ONLY)

    def test_current_cli_surface_has_explicit_policy_classification(self):
        permissive = {"allow_macos_system_update": True, "allow_macos_major_upgrade": True}
        surface = {
            "version": [None], "ping": [None], "status": [None], "health": [None], "doctor": [None], "wake": [None], "auth": [None], "capabilities": [None],
            "fleet": ["list", "status", "doctor", "resolve", "plan"],
            "workstation": ["profile", "inventory", "doctor", "qualification-plan", "qualification"],
            "linux": ["profile", "list", "overview", "fleet-status", "fleet-doctor", "status", "doctor", "transport", "qualification-plan", "qualification", "command", "logs", "package", "network", "process", "systemd", "file"],
            "exec": [None], "script": [None], "push": [None], "pull": [None], "logs": [None],
            "file": ["read", "list", "stat", "sha256", "mkdir", "rm", "mv", "cp"],
            "artifact": ["import", "list", "inspect", "verify", "revoke", "gc", "grant", "revoke-grants", "delivery-probe", "host-adapter-evaluate", "host-native-conformance-contract", "host-native-conformance-fixture", "host-native-runtime-watch-baseline", "host-native-runtime-watch-evaluate", "delivery-plan", "delivery-create", "delivery-status", "delivery-list", "delivery-host-accept", "delivery-render-qualify", "delivery-user-confirm", "delivery-fail", "relay-stage", "relay-status", "relay-cleanup", "lan-probe", "route-auto", "route-plan"],
            "process": ["list", "top", "kill"],
            "launchd": ["list", "print", "kickstart", "enable", "disable"],
            "system": ["info", "disk", "memory", "network", "network-summary", "dns", "proxy", "storage-health", "power", "thermal", "power-schedule", "network-quality", "reachability"],
            "power": ["sleep", "blockers", "restart", "shutdown"],
            "update": ["list", "settings", "policy", "install", "safari-download", "safari-install", "install-all"],
            "brew": ["version", "list", "doctor", "update", "upgrade"],
            "sync": ["push", "pull"],
            "backup": ["status", "destinations", "snapshots", "apfs-snapshots", "create-local", "delete-local"],
            "job": ["start", "list", "status", "log", "kill", "cleanup"],
            "clipboard": ["get", "set"],
            "browser": ["cdp-plan", "cdp-smoke", "qualification-plan", "native-action-plan", "native-action-begin", "native-action-list", "native-action-status", "native-action-observe", "native-action-type", "native-action-click", "native-action-key", "native-action-finish", "native-action-recovery-plan", "native-action-recovery-observe", "native-action-recover-interrupted", "url-check", "session-start", "session-list", "session-status", "session-stop", "session-navigate", "session-query", "session-type", "session-click", "session-download"],
            "gui": ["open", "osascript", "screenshot", "inspect", "compare", "semantic-find", "semantic-press", "event-observe", "event-wait", "type-text", "key-press", "mouse-move", "mouse-click", "helper-status", "helper-lifecycle-status", "helper-lifecycle-register", "helper-lifecycle-unregister", "helper-request-accessibility", "helper-request-screen-recording", "helper-screen-capture-test", "helper-screen-ocr", "helper-automation-test", "helper-systemevents-test", "helper-accessibility-test", "helper-accessibility-action-test", "helper-accessibility-inventory", "helper-frontmost", "helper-mouse-position", "helper-mouse-nudge"],
            "security": ["ssh-state", "sudo-state", "hostkey", "posture", "hardening-assess", "tcc-state", "tcc-probe", "password-probe", "full-disk-test", "firewall-enable", "firewall-disable"],
            "audit": ["tail", "stats"],
            "control": ["check", "warm", "stop"],
            "policy": ["status", "classify"],
            "transaction": ["status", "list"],
        }
        for family, actions in surface.items():
            for action in actions:
                attrs = {"confirm": True, "scope": "user", "label": "Non-OS Test Update"}
                d = classify_operation(family, action, attrs, permissive)
                self.assertTrue(d.allowed, f"unclassified current CLI surface: {family} {action}: {d}")
                self.assertNotEqual(d.reason, "unknown_typed_operation_fail_closed")


class BreakGlassPolicyTests(unittest.TestCase):
    def assertBlocked(self, command, reason=None):
        d = evaluate_break_glass(command, "test", BLOCKED_CFG)
        self.assertFalse(d.allowed, command)
        self.assertEqual(d.risk_class, FORBIDDEN_BY_POLICY)
        if reason is not None:
            self.assertEqual(d.reason, reason)

    def test_harmless_shell_is_break_glass_allowed(self):
        d = evaluate_break_glass("echo hello", "exec", BLOCKED_CFG)
        self.assertTrue(d.allowed)
        self.assertEqual(d.risk_class, BREAK_GLASS)

    def test_softwareupdate_list_is_not_mutating(self):
        d = evaluate_break_glass("/usr/sbin/softwareupdate --list", "exec", BLOCKED_CFG)
        self.assertTrue(d.allowed)
        self.assertEqual(d.risk_class, BREAK_GLASS)

    def test_direct_update_install_all_blocked(self):
        self.assertBlocked("/usr/sbin/softwareupdate --install --all", "macos_system_update_policy")

    def test_short_combined_update_flags_blocked(self):
        self.assertBlocked("sudo /usr/sbin/softwareupdate -ia", "macos_system_update_policy")

    def test_indirect_env_invocation_blocked(self):
        self.assertBlocked("env softwareupdate --download --all", "macos_system_update_policy")

    def test_nested_shell_invocation_blocked(self):
        self.assertBlocked("sh -c '/usr/sbin/softwareupdate --install --all'", "macos_system_update_policy")

    def test_quoted_executable_name_does_not_bypass_policy(self):
        self.assertBlocked("/usr/sbin/soft'ware'update --install --all", "macos_system_update_policy")

    def test_nested_shell_safari_only_is_not_treated_as_direct_safe_path(self):
        self.assertBlocked("sh -c '/usr/sbin/softwareupdate --install --safari-only'", "macos_system_update_policy")

    def test_variable_indirection_is_conservatively_blocked(self):
        self.assertBlocked("s=softwareupdate; $s --install --all", "macos_system_update_policy")

    def test_startosinstall_blocked(self):
        self.assertBlocked("/Applications/Install\\ macOS\\ Tahoe.app/Contents/Resources/startosinstall --agreetolicense", "macos_major_upgrade_policy")

    def test_installassistant_pkg_blocked(self):
        self.assertBlocked("installer -pkg /tmp/InstallAssistant.pkg -target /", "macos_major_upgrade_policy")

    def test_explicit_direct_safari_only_is_allowed(self):
        for command in (
            "/usr/sbin/softwareupdate --download --safari-only",
            "/usr/sbin/softwareupdate --install --safari-only",
            "/usr/sbin/softwareupdate -i --safari-only",
        ):
            d = evaluate_break_glass(command, "exec", BLOCKED_CFG)
            self.assertTrue(d.allowed, command)
            self.assertEqual(d.risk_class, BREAK_GLASS)
            self.assertEqual(d.reason, "break_glass_explicit_safari_only")

    def test_safari_token_does_not_mask_second_update_command(self):
        self.assertBlocked(
            "/usr/sbin/softwareupdate --install --safari-only; /usr/sbin/softwareupdate --install --all",
            "macos_system_update_policy",
        )

    def test_safari_only_with_os_marker_is_not_allowed(self):
        self.assertBlocked(
            "/usr/sbin/softwareupdate --install --safari-only 'macOS Tahoe'",
            "macos_system_update_policy",
        )


class PolicyStatusTests(unittest.TestCase):
    def test_status_exposes_v2_contract(self):
        s = policy_status(BLOCKED_CFG)
        self.assertEqual(s["schema"], "macctl-policy/v2")
        self.assertTrue(s["fail_closed_unknown_typed_operation"])
        self.assertEqual(s["generic_shell_class"], BREAK_GLASS)
        self.assertFalse(s["allow_macos_system_update"])
        self.assertFalse(s["allow_macos_major_upgrade"])


if __name__ == "__main__":
    unittest.main()
