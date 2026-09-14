import unittest

from hardening_engine import HostHardeningSnapshot, evaluate_hardening, parse_probe_output


SAMPLE = """@@MACOS@@
14.8.9
@@BUILD@@
23J631
@@FILEVAULT@@
FileVault is Off.
@@FIREWALL_GLOBAL@@
Firewall is disabled. (State = 0)
@@FIREWALL_BLOCK_ALL@@
Firewall block all state is off. (State = 0)
@@FIREWALL_STEALTH@@
Firewall stealth mode is off
@@FIREWALL_ALLOW_SIGNED@@
Automatically allow signed built-in software ENABLED
Automatically allow downloaded signed software ENABLED
@@REMOTE_LOGIN@@
Remote Login: On
@@PMSET_CUSTOM@@
 Battery Power:
  womp                 1
 AC Power:
  womp                 1
"""


class HostHardeningEngineTests(unittest.TestCase):
    def test_parse_current_r9_baseline_shape(self):
        s = parse_probe_output(SAMPLE)
        self.assertEqual(s.filevault, "DISABLED")
        self.assertEqual(s.firewall, "DISABLED")
        self.assertEqual(s.firewall_block_all, "DISABLED")
        self.assertEqual(s.firewall_stealth, "DISABLED")
        self.assertEqual(s.firewall_allow_signed_builtin, "ENABLED")
        self.assertEqual(s.firewall_allow_signed_downloaded, "ENABLED")
        self.assertEqual(s.remote_login, "ENABLED")
        self.assertEqual(s.wake_on_network_access, "ENABLED")
        self.assertEqual(s.macos, "14.8.9")
        self.assertEqual(s.build, "23J631")

    def test_firewall_gate_requires_explicit_authorization(self):
        result = evaluate_hardening(parse_probe_output(SAMPLE))
        self.assertEqual(result["status"], "PASS")
        fw = result["firewall_qualification"]
        self.assertEqual(fw["gate"], "READY_FOR_EXPLICIT_AUTHORIZATION")
        self.assertTrue(fw["requires_explicit_authorization"])
        self.assertTrue(fw["requires_rollback_plan"])
        self.assertTrue(fw["requires_reboot_validation"])
        self.assertTrue(fw["reboot_requires_separate_authorization"])

    def test_filevault_and_physical_power_stay_out_of_scope(self):
        result = evaluate_hardening(parse_probe_output(SAMPLE))
        self.assertEqual(result["filevault_qualification"]["gate"], "NOT_IN_SCOPE_BY_PROJECT_POLICY")
        self.assertEqual(result["physical_power_on_qualification"]["gate"], "NOT_IN_SCOPE")

    def test_missing_recovery_prerequisites_block_firewall_gate(self):
        s = HostHardeningSnapshot(
            filevault="DISABLED",
            firewall="DISABLED",
            firewall_block_all="DISABLED",
            firewall_stealth="DISABLED",
            firewall_allow_signed_builtin="ENABLED",
            firewall_allow_signed_downloaded="ENABLED",
            remote_login="DISABLED",
            wake_on_network_access="UNKNOWN",
            macos="14.8.9",
            build="23J631",
        )
        result = evaluate_hardening(s)
        self.assertEqual(result["status"], "DEGRADED")
        self.assertEqual(result["firewall_qualification"]["gate"], "BLOCKED_BY_PREFLIGHT")
        self.assertIn("remote_login_not_confirmed_enabled", result["firewall_qualification"]["blockers"])
        self.assertIn("wake_on_network_access_not_confirmed_enabled", result["firewall_qualification"]["blockers"])


if __name__ == "__main__":
    unittest.main()
