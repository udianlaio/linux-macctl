#!/usr/bin/env python3
"""Pure remote-Linux target registry and qualification contracts for V0.6-R3."""
from __future__ import annotations

import json
import re
from pathlib import Path

from remote_linux_ssh_manager import SSH_MANAGER_SCHEMA, normalize_transport_policy

REMOTE_LINUX_SCHEMA = "macctl-remote-linux/v1"
REMOTE_LINUX_REGISTRY_SCHEMA = "macctl-remote-linux-target-registry/v1"
REMOTE_LINUX_EVIDENCE_SCHEMA = "macctl-remote-linux-live-evidence/v1"

TARGET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_FP_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{20,}={0,2}$")

REQUIRED_LIVE_CHECKS = (
    "ssh_publickey_auth",
    "sudo_nopasswd_root",
    "inventory",
    "user_file_mutation",
    "root_file_mutation",
    "process_term",
    "systemd_transient_root",
    "journal_read",
    "package_inspection",
    "network_route_dns_https",
    "exact_roundtrip_transfer",
)


def remote_linux_profile_contract() -> dict:
    return {
        "schema": REMOTE_LINUX_SCHEMA,
        "phase": "V0.6-R3",
        "profile": "REMOTE_LINUX_ROOT_OPERATIONS",
        "required_live_checks": list(REQUIRED_LIVE_CHECKS),
        "registry_schema": REMOTE_LINUX_REGISTRY_SCHEMA,
        "live_evidence_schema": REMOTE_LINUX_EVIDENCE_SCHEMA,
        "transport": {
            "path": ["Linux_gateway_hermes_vm", "production_mac_gateway", "pinned_OpenSSH", "explicit_remote_linux_target"],
            "ssh_manager_schema": SSH_MANAGER_SCHEMA,
            "credential_body_on_gateway": False,
            "credential_reference_only": True,
            "unknown_target_fallback": "FORBIDDEN",
            "host_key_pinning_required": True,
            "connection_reuse_expected": True,
            "rate_limit_aware": True,
            "primary_and_fallback_paths_are_explicit": True,
            "designed_target_scale": "10_TO_50_SERVERS",
        },
        "boundaries": {
            "public_internet_scan": "FORBIDDEN",
            "implicit_target_guessing": "FORBIDDEN",
            "credential_material_in_registry": "FORBIDDEN",
            "cross_target_trust_inheritance": "FORBIDDEN",
            "cross_target_evidence_inheritance": "FORBIDDEN",
            "security_policy_mutation_requires_separate_authorization": True,
            "reboot_shutdown_requires_separate_authorization": True,
        },
    }


def _validate_target(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("target_not_object")
    target_id = str(raw.get("id") or "")
    if not TARGET_ID_RE.fullmatch(target_id):
        raise ValueError("invalid_target_id")
    alias = str(raw.get("ssh_alias") or "")
    if not SSH_ALIAS_RE.fullmatch(alias):
        raise ValueError(f"invalid_ssh_alias:{target_id}")
    host = str(raw.get("host") or "").strip()
    user = str(raw.get("user") or "").strip()
    gateway_target = str(raw.get("gateway_target") or "").strip()
    credential_ref = str(raw.get("credential_ref") or "").strip()
    if not host or not user or not gateway_target or not credential_ref:
        raise ValueError(f"missing_required_target_field:{target_id}")
    if "PRIVATE KEY" in credential_ref or "BEGIN " in credential_ref:
        raise ValueError(f"credential_material_forbidden:{target_id}")
    try:
        port = int(raw.get("port", 22))
    except (TypeError, ValueError):
        raise ValueError(f"invalid_port:{target_id}")
    if port < 1 or port > 65535:
        raise ValueError(f"invalid_port:{target_id}")
    fingerprints = raw.get("host_key_fingerprints")
    if not isinstance(fingerprints, list) or not fingerprints:
        raise ValueError(f"host_key_fingerprints_required:{target_id}")
    if any(not SHA256_FP_RE.fullmatch(str(fp)) for fp in fingerprints):
        raise ValueError(f"invalid_host_key_fingerprint:{target_id}")
    if raw.get("authorized") is not True:
        raise ValueError(f"target_not_authorized:{target_id}")
    metadata_raw = raw.get("metadata") or {}
    if not isinstance(metadata_raw, dict):
        raise ValueError(f"metadata_not_object:{target_id}")
    tags_raw = metadata_raw.get("tags") or []
    if not isinstance(tags_raw, list):
        raise ValueError(f"metadata_tags_not_list:{target_id}")
    tags = []
    for value in tags_raw:
        tag = str(value or "").strip()
        if not tag or len(tag) > 64 or not re.fullmatch(r"[A-Za-z0-9._:-]+", tag):
            raise ValueError(f"invalid_metadata_tag:{target_id}")
        if tag not in tags:
            tags.append(tag)
    metadata = {
        "provider": str(metadata_raw.get("provider") or "unknown").strip()[:64],
        "region": str(metadata_raw.get("region") or "unknown").strip()[:64],
        "role": str(metadata_raw.get("role") or "general").strip()[:64],
        "environment": str(metadata_raw.get("environment") or "production").strip()[:64],
        "tags": tags,
    }
    transport = normalize_transport_policy(raw.get("transport"))
    if alias in transport["fallback_ssh_aliases"]:
        raise ValueError(f"primary_alias_cannot_be_fallback:{target_id}")
    protected_raw = raw.get("protected_services") or []
    if not isinstance(protected_raw, list):
        raise ValueError(f"protected_services_not_list:{target_id}")
    protected_services = []
    for value in protected_raw:
        service = str(value or "").strip()
        if not service or not re.fullmatch(r"[A-Za-z0-9@_.:-]+", service):
            raise ValueError(f"invalid_protected_service:{target_id}")
        if service not in protected_services:
            protected_services.append(service)
    return {
        "id": target_id,
        "ssh_alias": alias,
        "host": host,
        "port": port,
        "user": user,
        "gateway_target": gateway_target,
        "credential_ref": credential_ref,
        "host_key_fingerprints": [str(fp) for fp in fingerprints],
        "authorized": True,
        "metadata": metadata,
        "transport": transport,
        "protected_services": protected_services,
        "notes": str(raw.get("notes") or ""),
    }


def load_remote_linux_registry(path: str | Path) -> dict:
    p = Path(path)
    if not p.is_file():
        return {"schema": REMOTE_LINUX_REGISTRY_SCHEMA, "targets": [], "source": "MISSING_OPTIONAL_REGISTRY"}
    data = json.loads(p.read_text(encoding="utf-8"))
    if data.get("schema") != REMOTE_LINUX_REGISTRY_SCHEMA:
        raise ValueError("registry_schema_mismatch")
    raw_targets = data.get("targets")
    if not isinstance(raw_targets, list):
        raise ValueError("targets_not_list")
    targets = [_validate_target(item) for item in raw_targets]
    ids = [t["id"] for t in targets]
    aliases = [t["ssh_alias"] for t in targets]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_target_id")
    if len(aliases) != len(set(aliases)):
        raise ValueError("duplicate_ssh_alias")
    path_aliases = []
    for target in targets:
        path_aliases.append(target["ssh_alias"])
        path_aliases.extend(target["transport"]["fallback_ssh_aliases"])
    if len(path_aliases) != len(set(path_aliases)):
        raise ValueError("duplicate_ssh_path_alias")
    return {"schema": REMOTE_LINUX_REGISTRY_SCHEMA, "targets": targets, "source": str(p)}


def resolve_remote_linux_target(registry: dict, target_id: str) -> dict:
    target_id = str(target_id or "")
    for target in registry.get("targets") or []:
        if target.get("id") == target_id:
            return target
    raise ValueError("unknown_remote_linux_target")


def select_remote_linux_targets(
    registry: dict,
    *,
    provider: str | None = None,
    region: str | None = None,
    role: str | None = None,
    environment: str | None = None,
    tag: str | None = None,
) -> list[dict]:
    filters = {
        "provider": None if provider is None else str(provider).strip().casefold(),
        "region": None if region is None else str(region).strip().casefold(),
        "role": None if role is None else str(role).strip().casefold(),
        "environment": None if environment is None else str(environment).strip().casefold(),
    }
    wanted_tag = None if tag is None else str(tag).strip().casefold()
    selected = []
    for target in registry.get("targets") or []:
        metadata = target.get("metadata") or {}
        if any(
            wanted is not None and str(metadata.get(key) or "").casefold() != wanted
            for key, wanted in filters.items()
        ):
            continue
        if wanted_tag is not None:
            tags = {str(value).casefold() for value in (metadata.get("tags") or [])}
            if wanted_tag not in tags:
                continue
        selected.append(target)
    return selected


def evaluate_remote_linux_live_evidence(evidence: dict | None, *, expected_target: str) -> dict:
    if not isinstance(evidence, dict):
        return {
            "schema": REMOTE_LINUX_EVIDENCE_SCHEMA,
            "status": "BLOCKED",
            "qualification_state": "LIVE_EVIDENCE_MISSING",
            "remote_linux_live_qualified": False,
            "expected_target": expected_target,
            "observed_target": None,
            "missing_checks": list(REQUIRED_LIVE_CHECKS),
            "malformed_checks": [],
            "reason": "canonical_live_evidence_missing",
        }
    schema_valid = evidence.get("schema") == REMOTE_LINUX_EVIDENCE_SCHEMA
    profile_valid = evidence.get("profile") == "REMOTE_LINUX_ROOT_OPERATIONS"
    observed_target = str(evidence.get("target") or "") or None
    target_match = observed_target == expected_target
    checks = evidence.get("checks") if isinstance(evidence.get("checks"), dict) else {}
    missing = []
    malformed = []
    for name in REQUIRED_LIVE_CHECKS:
        item = checks.get(name)
        if not isinstance(item, dict) or item.get("status") != "PASS":
            missing.append(name)
        if isinstance(item, dict) and not str(item.get("evidence") or "").strip():
            malformed.append(name)
    qualified = bool(schema_valid and profile_valid and target_match and not missing and not malformed)
    reasons = []
    if not schema_valid:
        reasons.append("schema_mismatch")
    if not profile_valid:
        reasons.append("profile_mismatch")
    if not target_match:
        reasons.append("target_mismatch")
    if missing:
        reasons.append("required_checks_missing_or_not_pass")
    if malformed:
        reasons.append("required_check_evidence_missing")
    return {
        "schema": REMOTE_LINUX_EVIDENCE_SCHEMA,
        "status": "PASS" if qualified else "BLOCKED",
        "qualification_state": "LIVE_QUALIFIED" if qualified else "LIVE_EVIDENCE_INCOMPLETE",
        "remote_linux_live_qualified": qualified,
        "expected_target": expected_target,
        "observed_target": observed_target,
        "schema_valid": schema_valid,
        "profile_valid": profile_valid,
        "target_match": target_match,
        "missing_checks": missing,
        "malformed_checks": malformed,
        "security_policy_mutation_performed": bool(evidence.get("security_policy_mutation_performed", False)),
        "reboot_shutdown_performed": bool(evidence.get("reboot_shutdown_performed", False)),
        "reason": "qualified" if qualified else ",".join(reasons),
    }


REMOTE_LINUX_HIGH_IMPACT_PATTERNS = (
    (r"(^|[;&|]\s*)(reboot|shutdown|poweroff|halt)(\s|$)", "availability_power_change"),
    (r"systemctl\s+(reboot|poweroff|halt)\b", "availability_power_change"),
    (r"\b(iptables|ip6tables|nft|ufw|firewall-cmd)\b", "firewall_or_packet_filter_mutation"),
    (r"\bip\s+(route|rule)\s+(add|del|delete|replace|flush)\b", "network_route_policy_mutation"),
    (r"\bip\s+link\s+set\b", "network_interface_mutation"),
    (r"\bnmcli\b.*\b(up|down|connect|disconnect)\b", "network_interface_mutation"),
    (r"/etc/ssh/sshd_config|\bauthorized_keys\b", "ssh_security_policy_mutation"),
    (r"\b(passwd|chpasswd|useradd|userdel|usermod|groupadd|groupdel|visudo)\b|/etc/sudoers", "identity_or_privilege_policy_mutation"),
    (r"\b(systemctl|service)\b.*\b(start|stop|restart|reload|enable|disable|mask|unmask)\b", "service_state_mutation"),
)


def remote_linux_high_impact_reason(command: str) -> str | None:
    low = str(command or "").strip().casefold()
    for pattern, reason in REMOTE_LINUX_HIGH_IMPACT_PATTERNS:
        if re.search(pattern, low):
            return reason
    return None
