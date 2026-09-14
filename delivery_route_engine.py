#!/usr/bin/env python3
"""Adaptive source-to-gateway path selection for MacCtl artifacts.

The route engine never decides authorization. It only ranks already-authenticated,
policy-allowed transport probes by measured transfer cost and produces a failover
plan that preserves the same immutable artifact id.
"""
from __future__ import annotations

from dataclasses import dataclass

ROUTE_SCHEMA_VERSION = "macctl-delivery-route/v1"
FAILOVER_SCHEMA_VERSION = "macctl-delivery-failover/v1"


@dataclass(frozen=True)
class PathProbe:
    name: str
    kind: str  # LAN_DIRECT | PRIVATE_OVERLAY | CLOUD_RELAY
    ready: bool
    authenticated: bool
    policy_allowed: bool
    rtt_ms: float | None = None
    first_byte_ms: float | None = None
    throughput_mbps: float | None = None
    recent_success_rate: float = 1.0
    reason: str = ""

    def startup_ms(self) -> float | None:
        """Prefer measured first-byte latency; fall back to TCP RTT."""
        if self.first_byte_ms is not None:
            return max(0.0, float(self.first_byte_ms))
        if self.rtt_ms is not None:
            return max(0.0, float(self.rtt_ms))
        return None

    def estimated_transfer_ms(self, size_bytes: int) -> float:
        if not (self.ready and self.authenticated and self.policy_allowed):
            return float("inf")
        startup = self.startup_ms()
        if startup is None or self.throughput_mbps is None or self.throughput_mbps <= 0:
            return float("inf")
        payload_ms = (max(0, int(size_bytes)) * 8.0 / (self.throughput_mbps * 1_000_000.0)) * 1000.0
        reliability_penalty = 1.0 + max(0.0, 1.0 - min(1.0, max(0.0, self.recent_success_rate)))
        return (startup + payload_ms) * reliability_penalty

    def as_dict(self, size_bytes: int) -> dict:
        estimate = self.estimated_transfer_ms(size_bytes)
        return {
            "name": self.name,
            "kind": self.kind,
            "ready": bool(self.ready),
            "authenticated": bool(self.authenticated),
            "policy_allowed": bool(self.policy_allowed),
            "rtt_ms": self.rtt_ms,
            "first_byte_ms": self.first_byte_ms,
            "throughput_mbps": self.throughput_mbps,
            "recent_success_rate": self.recent_success_rate,
            "estimated_transfer_ms": None if estimate == float("inf") else round(estimate, 3),
            "reason": self.reason,
        }


def select_path(probes: list[PathProbe], *, size_bytes: int) -> dict:
    eligible = [p for p in probes if p.estimated_transfer_ms(size_bytes) != float("inf")]
    # Stable tie-break only; measured cost is primary.
    kind_priority = {"LAN_DIRECT": 0, "PRIVATE_OVERLAY": 1, "CLOUD_RELAY": 2}
    eligible.sort(key=lambda p: (p.estimated_transfer_ms(size_bytes), kind_priority.get(p.kind, 9), p.name))
    return {
        "schema": ROUTE_SCHEMA_VERSION,
        "status": "READY" if eligible else "NOT_AVAILABLE",
        "selected": eligible[0].name if eligible else None,
        "selected_kind": eligible[0].kind if eligible else None,
        "fallback_order": [p.name for p in eligible[1:]],
        "size_bytes": max(0, int(size_bytes)),
        "probes": [p.as_dict(size_bytes) for p in probes],
        "selection_rule": "lowest_measured_estimated_transfer_time_among_authenticated_policy_allowed_paths",
    }


def plan_failover(route_result: dict, *, failed_route: str, artifact_id: str) -> dict:
    """Choose the next already-qualified path without recapturing the artifact."""
    order = []
    selected = route_result.get("selected")
    if selected:
        order.append(str(selected))
    order.extend(str(item) for item in route_result.get("fallback_order", []))
    if failed_route not in order:
        return {
            "schema": FAILOVER_SCHEMA_VERSION,
            "status": "FAIL",
            "reason": "failed_route_not_in_plan",
            "artifact_id": artifact_id,
            "failed_route": failed_route,
            "next_route": None,
            "recapture_required": False,
        }
    idx = order.index(failed_route)
    next_route = order[idx + 1] if idx + 1 < len(order) else None
    return {
        "schema": FAILOVER_SCHEMA_VERSION,
        "status": "READY" if next_route else "EXHAUSTED",
        "artifact_id": artifact_id,
        "failed_route": failed_route,
        "next_route": next_route,
        "remaining_routes": order[idx + 2 :] if next_route else [],
        "recapture_required": False,
        "same_artifact_id_required": True,
    }
