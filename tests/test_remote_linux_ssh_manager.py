import unittest

from remote_linux_ssh_manager import (
    SSH_MANAGER_SCHEMA,
    bounded_batch_parallelism,
    classify_transport_failure,
    default_transport_policy,
    evaluate_ssh_transport_config,
    normalize_transport_policy,
    parse_ssh_g_output,
)


class RemoteLinuxSshManagerTests(unittest.TestCase):
    def target(self):
        return {
            "id": "cloud-b",
            "ssh_alias": "cloud-b",
            "host": "198.51.100.20",
            "port": 22,
            "user": "root",
            "transport": {
                "primary_route": "DIRECT",
                "fallback_ssh_aliases": ["cloud-b-via-tokyo"],
                "connection_reuse_required": True,
                "control_persist_min_seconds": 60,
            },
        }

    def effective(self):
        return parse_ssh_g_output(
            """
            user root
            hostname 198.51.100.20
            port 22
            stricthostkeychecking true
            identityfile ~/.ssh/common_key
            userknownhostsfile /Users/u/.ssh/known_hosts_remote
            controlmaster auto
            controlpersist 600
            controlpath /Users/u/.ssh/cm-abc
            connecttimeout 8
            serveraliveinterval 15
            serveralivecountmax 3
            """
        )

    def test_default_policy_is_rate_limit_aware_and_reuses_connections(self):
        p = default_transport_policy()
        self.assertEqual(p["schema"], SSH_MANAGER_SCHEMA)
        self.assertTrue(p["rate_limit_aware"])
        self.assertTrue(p["connection_reuse_required"])
        self.assertFalse(p["automatic_fallback"])

    def test_normalize_policy_bounds_and_deduplicates_fallbacks(self):
        p = normalize_transport_policy({
            "fallback_ssh_aliases": ["fallback-a", "fallback-a"],
            "batch_parallelism": 4,
        })
        self.assertEqual(p["fallback_ssh_aliases"], ["fallback-a"])
        self.assertEqual(p["batch_parallelism"], 4)
        with self.assertRaises(ValueError):
            normalize_transport_policy({"batch_parallelism": 99})
        with self.assertRaises(ValueError):
            normalize_transport_policy({"primary_route": "MAGIC"})

    def test_effective_direct_transport_passes_with_reuse_and_pinning(self):
        r = evaluate_ssh_transport_config(self.target(), self.effective())
        self.assertEqual(r["status"], "PASS")
        self.assertTrue(all(r["checks"].values()))
        self.assertEqual(r["fallback_ssh_aliases"], ["cloud-b-via-tokyo"])

    def test_direct_policy_rejects_primary_proxyjump(self):
        e = self.effective()
        e["proxyjump"] = "cloud-a"
        r = evaluate_ssh_transport_config(self.target(), e)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertFalse(r["checks"]["primary_route"])

    def test_connection_reuse_is_required(self):
        e = self.effective()
        e["controlmaster"] = "no"
        e["controlpersist"] = "0"
        r = evaluate_ssh_transport_config(self.target(), e)
        self.assertEqual(r["status"], "BLOCKED")
        self.assertFalse(r["checks"]["control_master"])
        self.assertFalse(r["checks"]["control_persist"])

    def test_failure_classification_does_not_overclaim_rate_limit(self):
        self.assertEqual(classify_transport_failure("Permission denied (publickey)", 255), "AUTH_REJECTED")
        self.assertEqual(classify_transport_failure("Connection closed by 1.2.3.4 port 22", 255), "PREAUTH_CONNECTION_CLOSED_OR_RATE_LIMIT")
        self.assertEqual(classify_transport_failure("Connection refused", 255), "CONNECTION_REFUSED_OR_RATE_LIMIT")
        self.assertEqual(classify_transport_failure("", 0), "SUCCESS")

    def test_batch_parallelism_is_bounded_for_small_fleets(self):
        self.assertEqual(bounded_batch_parallelism(None, 10), 3)
        self.assertEqual(bounded_batch_parallelism(99, 10), 8)
        self.assertEqual(bounded_batch_parallelism(4, 2), 2)


if __name__ == "__main__":
    unittest.main()
