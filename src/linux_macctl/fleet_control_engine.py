#!/usr/bin/env python3
"""Side-effect-free V0.6-R1 fleet control-plane contracts.

The fleet layer is deliberately observation/binding only. It never scans a LAN,
contacts a target, reads private-key bytes, mutates the registry, or inherits a
production Mac's qualification into another target.
"""
from __future__ import annotations

from .target_registry_engine import (
    TargetSpecError,
    resolve_runtime_target,
    validate_registry,
)

FLEET_SCHEMA = "macctl-fleet-control-plane/v1"
FLEET_TARGET_SCHEMA = "macctl-fleet-target/v1"
FLEET_RESOLUTION_SCHEMA = "macctl-fleet-target-resolution/v1"
FLEET_PLAN_SCHEMA = "macctl-fleet-operation-plan/v1"
FLEET_STATUS_SCHEMA = "macctl-fleet-status/v1"
FLEET_DOCTOR_SCHEMA = "macctl-fleet-doctor/v1"


def _target_namespaces(target_id: str) -> dict:
    tid = str(target_id or "").strip()
    if not tid:
        raise TargetSpecError("target_namespace_requires_target_id")
    return {
        "health": f"target:{tid}:health",
        "qualification": f"target:{tid}:qualification",
        "evidence": f"target:{tid}:evidence",
        "transaction_binding": f"target:{tid}:transaction",
        "audit_binding": f"target:{tid}:audit",
    }


def fleet_control_capabilities() -> dict:
    return {
        "schema": FLEET_SCHEMA,
        "phase": "V0.6-R1",
        "status": "IMPLEMENTED_READ_ONLY_BINDING_PLANE",
        "operations": ["list", "status", "doctor", "resolve", "plan"],
        "side_effect_free": True,
        "lan_discovery": "FORBIDDEN",
        "unknown_explicit_target": "FAIL_CLOSED_NO_FALLBACK",
        "cross_target_qualification_inheritance": "FORBIDDEN",
        "cross_target_trust_material_aliasing": "FORBIDDEN",
        "registry_presence_is_live_qualification": False,
        "new_target_stateful_mutation_authorized": False,
    }


def _legacy_target(legacy_config: dict) -> dict:
    target_id = str((legacy_config or {}).get("target") or "").strip()
    if not target_id:
        raise TargetSpecError("legacy_target_missing")
    return {
        "schema": FLEET_TARGET_SCHEMA,
        "target_id": target_id,
        "source": "LEGACY_PRODUCTION",
        "default_target": True,
        "host": str(legacy_config.get("host") or ""),
        "port": int(legacy_config.get("port") or 22),
        "user": str(legacy_config.get("user") or ""),
        "trust_paths": {
            "identity_file": str(legacy_config.get("identity_file") or ""),
            "known_hosts_file": str(legacy_config.get("known_hosts_file") or ""),
            "ssh_config_file": str(legacy_config.get("ssh_config_file") or ""),
        },
        "qualification": "CURRENT_PRODUCTION_BASELINE",
        "namespaces": _target_namespaces(target_id),
        "qualification_inherited_from_other_target": False,
        "stateful_bootstrap_authorized": False,
    }


def _registry_target(spec) -> dict:
    return {
        "schema": FLEET_TARGET_SCHEMA,
        "target_id": spec.target_id,
        "source": "REGISTRY_ISOLATED",
        "default_target": False,
        "host": spec.host,
        "port": int(spec.port),
        "user": spec.user,
        "trust_paths": {
            "identity_file": spec.identity_file,
            "known_hosts_file": spec.known_hosts_file,
            "ssh_config_file": spec.ssh_config_file,
        },
        "qualification": "NOT_INHERITED_REGISTERED_METADATA_ONLY",
        "namespaces": _target_namespaces(spec.target_id),
        "qualification_inherited_from_other_target": False,
        "stateful_bootstrap_authorized": False,
    }


def fleet_inventory(legacy_config: dict, registry_document: dict | None = None, *, registry_present: bool = True) -> dict:
    legacy = _legacy_target(legacy_config)
    if registry_document is None:
        specs = []
        registry_state = "MISSING_NOT_ASSUMED_EMPTY" if not registry_present else "UNAVAILABLE"
    else:
        specs = validate_registry(registry_document, legacy_config=legacy_config)
        registry_state = "PRESENT_VALID"
    targets = [legacy] + [_registry_target(s) for s in sorted(specs, key=lambda x: x.target_id)]
    return {
        "schema": FLEET_SCHEMA,
        "status": "PASS",
        "phase": "V0.6-R1",
        "default_target": legacy["target_id"],
        "registry_state": registry_state,
        "target_count": len(targets),
        "registry_target_count": len(specs),
        "targets": targets,
        "safety": {
            "lan_discovery_performed": False,
            "network_contact_performed": False,
            "secret_material_read": False,
            "stateful_mutation_performed": False,
            "unknown_explicit_target_fallback": False,
            "cross_target_qualification_inheritance": "FORBIDDEN",
        },
    }


def fleet_status(legacy_config: dict, registry_document: dict | None = None, *, registry_present: bool = True) -> dict:
    inv = fleet_inventory(legacy_config, registry_document, registry_present=registry_present)
    return {
        "schema": FLEET_STATUS_SCHEMA,
        "status": "PASS",
        "phase": "V0.6-R1",
        "default_target": inv["default_target"],
        "registry_state": inv["registry_state"],
        "target_count": inv["target_count"],
        "registry_target_count": inv["registry_target_count"],
        "fleet_mode": "LEGACY_ONLY" if inv["registry_target_count"] == 0 else "MULTI_TARGET_METADATA_READY",
        "network_contact_performed": False,
        "stateful_mutation_performed": False,
    }


def fleet_doctor(legacy_config: dict, registry_document: dict | None = None, *, registry_present: bool = True) -> dict:
    inv = fleet_inventory(legacy_config, registry_document, registry_present=registry_present)
    namespaces = [t["namespaces"] for t in inv["targets"]]
    flat = [value for row in namespaces for value in row.values()]
    namespace_unique = len(flat) == len(set(flat))
    trust_path_sets = [set(t["trust_paths"].values()) - {""} for t in inv["targets"]]
    trust_paths_disjoint = all(
        not trust_path_sets[i].intersection(trust_path_sets[j])
        for i in range(len(trust_path_sets))
        for j in range(i + 1, len(trust_path_sets))
    )
    checks = {
        "legacy_default_present": bool(inv["default_target"]),
        "registry_valid_if_present": inv["registry_state"] in {"PRESENT_VALID", "MISSING_NOT_ASSUMED_EMPTY"},
        "per_target_namespaces_unique": namespace_unique,
        "trust_paths_disjoint": trust_paths_disjoint,
        "unknown_explicit_target_fallback_forbidden": inv["safety"]["unknown_explicit_target_fallback"] is False,
        "qualification_inheritance_forbidden": inv["safety"]["cross_target_qualification_inheritance"] == "FORBIDDEN",
        "network_contact_performed": False,
        "stateful_mutation_performed": False,
    }
    passed = all(v is True for k, v in checks.items() if not k.endswith("_performed")) and not checks["network_contact_performed"] and not checks["stateful_mutation_performed"]
    return {
        "schema": FLEET_DOCTOR_SCHEMA,
        "status": "PASS" if passed else "FAIL",
        "overall_state": "FLEET_METADATA_READY" if registry_present else "LEGACY_ONLY_READY_REGISTRY_MISSING",
        "phase": "V0.6-R1",
        "checks": checks,
        "target_count": inv["target_count"],
        "registry_target_count": inv["registry_target_count"],
        "network_contact_performed": False,
        "stateful_mutation_performed": False,
    }


def fleet_resolve(legacy_config: dict, requested_target: str | None, registry_document: dict | None = None) -> dict:
    requested = str(requested_target or "").strip()
    selection = resolve_runtime_target(
        legacy_config,
        requested_target=requested or None,
        registry_document=registry_document,
    )
    if selection["source"] == "LEGACY_PRODUCTION":
        target = _legacy_target(legacy_config)
    else:
        specs = validate_registry(registry_document, legacy_config=legacy_config)
        spec = next(s for s in specs if s.target_id == selection["selected_target"])
        target = _registry_target(spec)
    return {
        "schema": FLEET_RESOLUTION_SCHEMA,
        "status": "PASS",
        "requested_target": requested or None,
        "selected_target": selection["selected_target"],
        "source": selection["source"],
        "fallback_used": False,
        "explicit_target": bool(requested),
        "target": target,
        "network_contact_performed": False,
        "stateful_mutation_performed": False,
    }


def fleet_operation_plan(legacy_config: dict, requested_target: str, registry_document: dict | None = None) -> dict:
    requested = str(requested_target or "").strip()
    if not requested:
        raise TargetSpecError("fleet_plan_requires_explicit_target")
    resolution = fleet_resolve(legacy_config, requested, registry_document)
    is_legacy = resolution["source"] == "LEGACY_PRODUCTION"
    return {
        "schema": FLEET_PLAN_SCHEMA,
        "status": "PLAN_ONLY",
        "phase": "V0.6-R1",
        "target_binding": {
            "requested_target": requested,
            "selected_target": resolution["selected_target"],
            "source": resolution["source"],
            "explicit_target_required": True,
            "fallback_used": False,
            "fanout": "FORBIDDEN",
            "wildcard_target": "FORBIDDEN",
        },
        "qualification_gate": (
            "CURRENT_PRODUCTION_BASELINE"
            if is_legacy
            else "REGISTERED_METADATA_ONLY_REQUIRES_SEPARATE_LIVE_QUALIFICATION"
        ),
        "execution_contract": {
            "future_mutation_must_bind_target_id": True,
            "future_transaction_must_bind_target_id": True,
            "future_audit_record_must_bind_target_id": True,
            "cross_target_transaction_replay": "FORBIDDEN",
            "cross_target_qualification_inheritance": "FORBIDDEN",
        },
        "authorization": {
            "this_plan_authorizes_network_contact": False,
            "this_plan_authorizes_stateful_mutation": False,
            "real_new_target_stateful_bootstrap_requires_fresh_explicit_authorization": True,
        },
        "side_effects": {
            "lan_discovery_performed": False,
            "network_contact_performed": False,
            "registry_mutation_performed": False,
            "stateful_mutation_performed": False,
        },
    }
