import json
import tempfile
import unittest
from pathlib import Path

from remote_linux_control_engine import (
    REMOTE_LINUX_EVIDENCE_SCHEMA,
    REMOTE_LINUX_REGISTRY_SCHEMA,
    REQUIRED_LIVE_CHECKS,
    evaluate_remote_linux_live_evidence,
    load_remote_linux_registry,
    remote_linux_high_impact_reason,
    remote_linux_profile_contract,
    resolve_remote_linux_target,
    select_remote_linux_targets,
)


class RemoteLinuxControlEngineTests(unittest.TestCase):
    def target(self):
        return {
            "id": "cloud-a",
            "ssh_alias": "cloud-a",
            "host": "203.0.113.10",
            "port": 22,
            "user": "debian",
            "gateway_target": "macmini",
            "credential_ref": "~/.ssh/common_key",
            "host_key_fingerprints": ["SHA256:DCEFqDrc1LDDzeqsQRh1cqP8E4RGSVi+LvQ4pa/JtoI"],
            "authorized": True,
        }

    def evidence(self):
        return {
            "schema": REMOTE_LINUX_EVIDENCE_SCHEMA,
            "profile": "REMOTE_LINUX_ROOT_OPERATIONS",
            "target": "cloud-a",
            "checks": {name: {"status": "PASS", "evidence": f"e:{name}"} for name in REQUIRED_LIVE_CHECKS},
            "security_policy_mutation_performed": False,
            "reboot_shutdown_performed": False,
        }

    def test_contract_fail_closed_boundaries(self):
        c = remote_linux_profile_contract()
        self.assertEqual(c["phase"], "V0.6-R3")
        self.assertEqual(c["transport"]["unknown_target_fallback"], "FORBIDDEN")
        self.assertTrue(c["boundaries"]["security_policy_mutation_requires_separate_authorization"])
        self.assertIn("exact_roundtrip_transfer", c["required_live_checks"])

    def test_registry_load_and_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "targets.json"
            p.write_text(json.dumps({"schema": REMOTE_LINUX_REGISTRY_SCHEMA, "targets": [self.target()]}), encoding="utf-8")
            r = load_remote_linux_registry(p)
            t = resolve_remote_linux_target(r, "cloud-a")
            self.assertEqual(t["user"], "debian")
            self.assertEqual(t["port"], 22)

    def test_registry_metadata_transport_and_filters_support_multi_server_fleet(self):
        a = self.target()
        a["metadata"] = {"provider": "google-cloud", "region": "asia-northeast1-a", "role": "gateway", "environment": "production", "tags": ["region-a", "gcp"]}
        a["transport"] = {"primary_route": "DIRECT", "fallback_ssh_aliases": [], "connection_reuse_required": True}
        b = self.target()
        b.update({"id": "cloud-b", "ssh_alias": "cloud-b", "host": "198.51.100.20", "user": "root"})
        b["metadata"] = {"provider": "tencent-cloud", "region": "unknown", "role": "general", "environment": "production", "tags": ["tencent", "cvm"]}
        b["transport"] = {"primary_route": "DIRECT", "fallback_ssh_aliases": ["cloud-b-via-tokyo"], "connection_reuse_required": True}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "targets.json"
            p.write_text(json.dumps({"schema": REMOTE_LINUX_REGISTRY_SCHEMA, "targets": [a, b]}), encoding="utf-8")
            registry = load_remote_linux_registry(p)
        self.assertEqual(len(select_remote_linux_targets(registry, provider="tencent-cloud")), 1)
        self.assertEqual(select_remote_linux_targets(registry, tag="region-a")[0]["id"], "cloud-a")
        self.assertEqual(select_remote_linux_targets(registry, role="gateway")[0]["metadata"]["provider"], "google-cloud")
        self.assertEqual(select_remote_linux_targets(registry, region="does-not-exist"), [])

    def test_missing_registry_is_empty_not_implicit_target(self):
        r = load_remote_linux_registry("/definitely/not/here")
        self.assertEqual(r["targets"], [])
        with self.assertRaisesRegex(ValueError, "unknown_remote_linux_target"):
            resolve_remote_linux_target(r, "whatever")

    def test_registry_rejects_secret_material(self):
        t = self.target()
        t["credential_ref"] = "BEGIN CREDENTIAL BODY"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "targets.json"
            p.write_text(json.dumps({"schema": REMOTE_LINUX_REGISTRY_SCHEMA, "targets": [t]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "credential_material_forbidden"):
                load_remote_linux_registry(p)

    def test_registry_requires_authorized_and_pinned_hostkey(self):
        for mutate in ("authorized", "hostkey"):
            t = self.target()
            if mutate == "authorized":
                t["authorized"] = False
            else:
                t["host_key_fingerprints"] = []
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / "targets.json"
                p.write_text(json.dumps({"schema": REMOTE_LINUX_REGISTRY_SCHEMA, "targets": [t]}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_remote_linux_registry(p)

    def test_complete_live_evidence_qualifies(self):
        r = evaluate_remote_linux_live_evidence(self.evidence(), expected_target="cloud-a")
        self.assertEqual(r["status"], "PASS")
        self.assertTrue(r["remote_linux_live_qualified"])
        self.assertEqual(r["missing_checks"], [])

    def test_live_evidence_missing_check_fails_closed(self):
        e = self.evidence()
        e["checks"].pop("sudo_nopasswd_root")
        r = evaluate_remote_linux_live_evidence(e, expected_target="cloud-a")
        self.assertEqual(r["status"], "BLOCKED")
        self.assertIn("sudo_nopasswd_root", r["missing_checks"])

    def test_live_evidence_target_mismatch_fails_closed(self):
        r = evaluate_remote_linux_live_evidence(self.evidence(), expected_target="other")
        self.assertFalse(r["remote_linux_live_qualified"])
        self.assertFalse(r["target_match"])

    def test_live_evidence_requires_nonempty_evidence_string(self):
        e = self.evidence()
        e["checks"]["journal_read"]["evidence"] = ""
        r = evaluate_remote_linux_live_evidence(e, expected_target="cloud-a")
        self.assertIn("journal_read", r["malformed_checks"])
        self.assertFalse(r["remote_linux_live_qualified"])

    def test_high_impact_command_gate_catches_power_network_and_identity_mutations(self):
        self.assertEqual(remote_linux_high_impact_reason("reboot"), "availability_power_change")
        self.assertEqual(remote_linux_high_impact_reason("iptables -F"), "firewall_or_packet_filter_mutation")
        self.assertEqual(remote_linux_high_impact_reason("ip route del default"), "network_route_policy_mutation")
        self.assertEqual(remote_linux_high_impact_reason("passwd debian"), "identity_or_privilege_policy_mutation")
        self.assertEqual(remote_linux_high_impact_reason("systemctl restart xray"), "service_state_mutation")
        self.assertEqual(remote_linux_high_impact_reason("systemctl restart nginx"), "service_state_mutation")
        self.assertIsNone(remote_linux_high_impact_reason("apt-cache policy bash"))
        self.assertIsNone(remote_linux_high_impact_reason("systemctl status xray"))


if __name__ == "__main__":
    unittest.main()
