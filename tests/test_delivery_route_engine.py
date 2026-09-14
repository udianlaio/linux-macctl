import unittest
from linux_macctl.delivery_route_engine import PathProbe, plan_failover, select_path


class DeliveryRouteTests(unittest.TestCase):
    def test_lan_wins_when_measured_faster(self):
        probes = [
            PathProbe("lan", "LAN_DIRECT", True, True, True, rtt_ms=1, throughput_mbps=800),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=35, throughput_mbps=100),
        ]
        result = select_path(probes, size_bytes=20 * 1024 * 1024)
        self.assertEqual(result["selected"], "lan")
        self.assertEqual(result["fallback_order"], ["relay"])

    def test_relay_wins_if_lan_is_slow(self):
        probes = [
            PathProbe("lan", "LAN_DIRECT", True, True, True, rtt_ms=2, throughput_mbps=5),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=30, throughput_mbps=200),
        ]
        result = select_path(probes, size_bytes=50 * 1024 * 1024)
        self.assertEqual(result["selected"], "relay")

    def test_unauthenticated_lan_is_never_selected(self):
        probes = [
            PathProbe("lan", "LAN_DIRECT", True, False, True, rtt_ms=1, throughput_mbps=1000),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=40, throughput_mbps=50),
        ]
        result = select_path(probes, size_bytes=1024)
        self.assertEqual(result["selected"], "relay")

    def test_no_eligible_path_is_fail_closed(self):
        result = select_path([PathProbe("lan", "LAN_DIRECT", False, False, True)], size_bytes=1024)
        self.assertEqual(result["status"], "NOT_AVAILABLE")
        self.assertIsNone(result["selected"])

    def test_first_byte_latency_is_used_when_available(self):
        probe = PathProbe(
            "lan", "LAN_DIRECT", True, True, True,
            rtt_ms=1, first_byte_ms=12, throughput_mbps=800,
        )
        self.assertEqual(probe.startup_ms(), 12)
        self.assertGreater(probe.estimated_transfer_ms(1024), 12)

    def test_lan_to_relay_failover_preserves_artifact(self):
        route = select_path([
            PathProbe("lan", "LAN_DIRECT", True, True, True, rtt_ms=1, throughput_mbps=900),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=40, throughput_mbps=80),
        ], size_bytes=8 * 1024 * 1024)
        failover = plan_failover(route, failed_route="lan", artifact_id="art_example")
        self.assertEqual(failover["status"], "READY")
        self.assertEqual(failover["next_route"], "relay")
        self.assertEqual(failover["artifact_id"], "art_example")
        self.assertFalse(failover["recapture_required"])
        self.assertTrue(failover["same_artifact_id_required"])

    def test_vlan_isolation_falls_back(self):
        route = select_path([
            PathProbe("lan", "LAN_DIRECT", False, False, True, reason="isolated_vlan"),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=30, throughput_mbps=100),
        ], size_bytes=1024 * 1024)
        self.assertEqual(route["selected"], "relay")

    def test_vpn_route_change_falls_back(self):
        before = select_path([
            PathProbe("lan", "LAN_DIRECT", True, True, True, rtt_ms=1, throughput_mbps=700),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=40, throughput_mbps=100),
        ], size_bytes=4 * 1024 * 1024)
        after = select_path([
            PathProbe("lan", "LAN_DIRECT", False, False, True, reason="route_changed"),
            PathProbe("relay", "CLOUD_RELAY", True, True, True, rtt_ms=40, throughput_mbps=100),
        ], size_bytes=4 * 1024 * 1024)
        self.assertEqual(before["selected"], "lan")
        self.assertEqual(after["selected"], "relay")

    def test_wifi_to_cell_transition_does_not_recapture(self):
        route = {
            "selected": "lan",
            "fallback_order": ["relay"],
        }
        result = plan_failover(route, failed_route="lan", artifact_id="art_immutable")
        self.assertEqual(result["next_route"], "relay")
        self.assertEqual(result["artifact_id"], "art_immutable")
        self.assertFalse(result["recapture_required"])


if __name__ == "__main__":
    unittest.main()
