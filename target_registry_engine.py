#!/usr/bin/env python3
"""Pure contracts for isolated remote-Mac target registration and bootstrap planning.

R4 deliberately keeps new-target trust material separate from the deployed M2 target.
This module does not read secrets, run ssh-keyscan, mutate a Mac, or write files.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from pathlib import PurePosixPath

TARGET_SCHEMA = "macctl-target/v1"
BOOTSTRAP_SCHEMA = "macctl-new-target-bootstrap/v1"
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")


class TargetSpecError(ValueError):
    pass


def _absolute_clean_path(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not text.startswith("/"):
        raise TargetSpecError(f"{field}_must_be_absolute")
    p = PurePosixPath(text)
    if ".." in p.parts:
        raise TargetSpecError(f"{field}_parent_traversal_forbidden")
    return str(p)


def _validate_host(host: str) -> str:
    text = str(host or "").strip()
    if not text or any(ch.isspace() for ch in text) or text.startswith("-"):
        raise TargetSpecError("invalid_host")
    # IP literals are accepted exactly; DNS-ish names stay deliberately conservative.
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass
    if len(text) > 253 or not re.fullmatch(r"[A-Za-z0-9._:-]+", text):
        raise TargetSpecError("invalid_host")
    return text


@dataclass(frozen=True)
class TargetSpec:
    target_id: str
    host: str
    user: str
    port: int = 22
    identity_file: str = ""
    known_hosts_file: str = ""
    ssh_config_file: str = ""
    helper_bundle: str = "app.openai.macctl.helper"

    def validate(self, *, require_isolated_paths: bool = True) -> "TargetSpec":
        target_id = str(self.target_id or "").strip()
        if not _TARGET_RE.fullmatch(target_id) or target_id in {"*", "all"}:
            raise TargetSpecError("invalid_target_id")
        _validate_host(self.host)
        if not _USER_RE.fullmatch(str(self.user or "").strip()):
            raise TargetSpecError("invalid_user")
        if not 1 <= int(self.port) <= 65535:
            raise TargetSpecError("invalid_port")
        ident = _absolute_clean_path(self.identity_file, "identity_file")
        kh = _absolute_clean_path(self.known_hosts_file, "known_hosts_file")
        sshcfg = _absolute_clean_path(self.ssh_config_file, "ssh_config_file")
        if len({ident, kh, sshcfg}) != 3:
            raise TargetSpecError("target_paths_must_be_distinct")
        if require_isolated_paths:
            expected = default_target_paths(target_id)
            for key, actual in (
                ("identity_file", ident),
                ("known_hosts_file", kh),
                ("ssh_config_file", sshcfg),
            ):
                if actual != expected[key]:
                    raise TargetSpecError(f"{key}_must_be_per_target")
        return self

    def as_dict(self) -> dict:
        self.validate()
        return {
            "schema": TARGET_SCHEMA,
            "target_id": self.target_id,
            "host": self.host,
            "port": int(self.port),
            "user": self.user,
            "identity_file": self.identity_file,
            "known_hosts_file": self.known_hosts_file,
            "ssh_config_file": self.ssh_config_file,
            "helper_bundle": self.helper_bundle,
        }


def default_target_paths(target_id: str, *, root: str = "/etc/macctl") -> dict:
    if not _TARGET_RE.fullmatch(str(target_id or "").strip()):
        raise TargetSpecError("invalid_target_id")
    tid = str(target_id).strip()
    base = str(PurePosixPath(root))
    return {
        "identity_file": f"{base}/identities/{tid}_ed25519",
        "known_hosts_file": f"{base}/known_hosts.d/{tid}",
        "ssh_config_file": f"{base}/targets/{tid}.conf",
    }


def build_target_spec(target_id: str, host: str, user: str, *, port: int = 22) -> TargetSpec:
    paths = default_target_paths(target_id)
    spec = TargetSpec(target_id=target_id, host=host, user=user, port=int(port), **paths)
    return spec.validate()


def render_ssh_config(spec: TargetSpec, *, control_dir: str = "/run/macctl") -> str:
    spec.validate()
    control_dir = _absolute_clean_path(control_dir, "control_dir")
    return "\n".join([
        f"Host {spec.target_id}",
        f"    HostName {spec.host}",
        f"    Port {int(spec.port)}",
        f"    User {spec.user}",
        f"    IdentityFile {spec.identity_file}",
        "    IdentitiesOnly yes",
        "    BatchMode yes",
        "    PreferredAuthentications publickey",
        "    PubkeyAuthentication yes",
        "    PasswordAuthentication no",
        "    KbdInteractiveAuthentication no",
        "    StrictHostKeyChecking yes",
        f"    UserKnownHostsFile {spec.known_hosts_file}",
        "    CheckHostIP yes",
        "    VerifyHostKeyDNS no",
        "    ControlMaster auto",
        f"    ControlPath {control_dir}/%C",
        "    ControlPersist 600",
        "    ConnectTimeout 5",
        "    ConnectionAttempts 1",
        "    ServerAliveInterval 15",
        "    ServerAliveCountMax 2",
        "    ForwardAgent no",
        "    ForwardX11 no",
        "    RequestTTY no",
        "    LogLevel ERROR",
        "",
    ])


BOOTSTRAP_GATES = (
    "TARGET_SPEC_VALID",
    "HOST_KEY_OUT_OF_BAND_VERIFIED",
    "DEDICATED_IDENTITY_PRESENT",
    "FRESH_PUBLICKEY_SSH",
    "SUDO_NOPASSWD",
    "HELPER_INSTALLED",
    "HELPER_REGISTERED",
    "TCC_ACCESSIBILITY",
    "TCC_SCREEN_CAPTURE",
    "TCC_FINDER_AUTOMATION",
    "TCC_SYSTEMEVENTS_AUTOMATION",
    "SCREEN_CAPTUREKIT",
    "VISION",
    "DOCTOR_FULL_READY",
    "SMOKE_PASS",
    "QUALIFICATION_REPORT_SEALED",
)


def evaluate_bootstrap_state(spec: TargetSpec, observations: dict | None = None) -> dict:
    """Evaluate a new-Mac bootstrap without performing any mutation.

    Crucially, `host_key_scanned` never satisfies the trust gate. A key must be
    independently/out-of-band verified before it may become a pinned key.
    """
    spec.validate()
    obs = dict(observations or {})
    values = {
        "TARGET_SPEC_VALID": True,
        "HOST_KEY_OUT_OF_BAND_VERIFIED": bool(obs.get("host_key_out_of_band_verified")),
        "DEDICATED_IDENTITY_PRESENT": bool(obs.get("dedicated_identity_present")),
        "FRESH_PUBLICKEY_SSH": bool(obs.get("fresh_publickey_ssh")),
        "SUDO_NOPASSWD": bool(obs.get("sudo_nopasswd")),
        "HELPER_INSTALLED": bool(obs.get("helper_installed")),
        "HELPER_REGISTERED": bool(obs.get("helper_registered")),
        "TCC_ACCESSIBILITY": bool(obs.get("tcc_accessibility")),
        "TCC_SCREEN_CAPTURE": bool(obs.get("tcc_screen_capture")),
        "TCC_FINDER_AUTOMATION": bool(obs.get("tcc_finder_automation")),
        "TCC_SYSTEMEVENTS_AUTOMATION": bool(obs.get("tcc_systemevents_automation")),
        "SCREEN_CAPTUREKIT": bool(obs.get("screen_capturekit")),
        "VISION": bool(obs.get("vision")),
        "DOCTOR_FULL_READY": bool(obs.get("doctor_full_ready")),
        "SMOKE_PASS": bool(obs.get("smoke_pass")),
        "QUALIFICATION_REPORT_SEALED": bool(obs.get("qualification_report_sealed")),
    }
    first_blocking = next((g for g in BOOTSTRAP_GATES if not values[g]), None)
    passed = [g for g in BOOTSTRAP_GATES if values[g]]
    status = "PASS" if first_blocking is None else "WAITING"
    return {
        "schema": BOOTSTRAP_SCHEMA,
        "status": status,
        "target": spec.as_dict(),
        "highest_ready_stage": BOOTSTRAP_GATES[len(passed)-1] if passed else None,
        "first_blocking_gate": first_blocking,
        "gates": values,
        "host_key_scanned_is_trust": False,
        "m2_pass_inheritance": "FORBIDDEN",
        "new_target_stateful_mutation_authorized": False,
    }


def build_bootstrap_plan(spec: TargetSpec) -> dict:
    spec.validate()
    return {
        "schema": BOOTSTRAP_SCHEMA,
        "status": "PLAN_ONLY",
        "target": spec.as_dict(),
        "ssh_config_preview": render_ssh_config(spec),
        "ordered_steps": [
            {"step": "REGISTER_TARGET_SPEC", "scope": "VM_LOCAL_STATEFUL", "requires_new_mac_mutation": False},
            {"step": "VERIFY_HOST_KEY_OUT_OF_BAND", "scope": "TRUST_ESTABLISHMENT", "requires_new_mac_mutation": False, "note": "ssh-keyscan alone is discovery, never trust proof"},
            {"step": "PROVISION_DEDICATED_IDENTITY", "scope": "SECRET_PROVISIONING", "requires_new_mac_mutation": True},
            {"step": "VERIFY_FRESH_PUBLICKEY_SSH", "scope": "REMOTE_READ_ONLY", "requires_new_mac_mutation": False},
            {"step": "INSTALL_AND_REGISTER_HELPER", "scope": "NEW_TARGET_STATEFUL", "requires_new_mac_mutation": True},
            {"step": "HUMAN_TCC_APPROVAL", "scope": "HUMAN_APPROVAL", "requires_new_mac_mutation": True},
            {"step": "DOCTOR_AND_SMOKE", "scope": "QUALIFICATION", "requires_new_mac_mutation": False},
            {"step": "SEAL_QUALIFICATION_REPORT", "scope": "VM_LOCAL_STATEFUL", "requires_new_mac_mutation": False},
        ],
        "authorization_boundary": "plan/dry-run does not authorize new-target stateful mutation",
    }


REGISTRY_SCHEMA = "macctl-target-registry/v1"


def empty_registry() -> dict:
    return {"schema": REGISTRY_SCHEMA, "targets": []}


def target_from_dict(data: dict) -> TargetSpec:
    if not isinstance(data, dict):
        raise TargetSpecError("target_record_must_be_object")
    if data.get("schema") not in {None, TARGET_SCHEMA}:
        raise TargetSpecError("unsupported_target_schema")
    try:
        spec = TargetSpec(
            target_id=data["target_id"], host=data["host"], user=data["user"],
            port=int(data.get("port", 22)), identity_file=data["identity_file"],
            known_hosts_file=data["known_hosts_file"], ssh_config_file=data["ssh_config_file"],
            helper_bundle=data.get("helper_bundle", "app.openai.macctl.helper"),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise TargetSpecError("invalid_target_record") from e
    return spec.validate()


def _legacy_sensitive_paths(legacy_config: dict | None) -> set[str]:
    if not legacy_config:
        return set()
    return {
        str(legacy_config.get("identity_file") or ""),
        str(legacy_config.get("known_hosts_file") or ""),
        str(legacy_config.get("ssh_config_file") or ""),
    } - {""}


def validate_registry(document: dict, *, legacy_config: dict | None = None) -> list[TargetSpec]:
    if not isinstance(document, dict) or document.get("schema") != REGISTRY_SCHEMA:
        raise TargetSpecError("unsupported_registry_schema")
    rows = document.get("targets")
    if not isinstance(rows, list):
        raise TargetSpecError("registry_targets_must_be_list")
    specs = [target_from_dict(row) for row in rows]
    ids: set[str] = set()
    endpoints: set[tuple[str, int]] = set()
    sensitive_paths: set[str] = set()
    legacy_paths = _legacy_sensitive_paths(legacy_config)
    legacy_target = str((legacy_config or {}).get("target") or "")
    legacy_endpoint = (
        str((legacy_config or {}).get("host") or ""),
        int((legacy_config or {}).get("port") or 22),
    ) if legacy_config else None
    for spec in specs:
        if spec.target_id in ids:
            raise TargetSpecError("duplicate_target_id")
        ids.add(spec.target_id)
        endpoint = (spec.host, int(spec.port))
        if endpoint in endpoints:
            raise TargetSpecError("duplicate_target_endpoint")
        endpoints.add(endpoint)
        if legacy_target and spec.target_id == legacy_target:
            raise TargetSpecError("registry_must_not_shadow_legacy_target")
        if legacy_endpoint and endpoint == legacy_endpoint:
            raise TargetSpecError("registry_must_not_alias_legacy_endpoint")
        for path in (spec.identity_file, spec.known_hosts_file, spec.ssh_config_file):
            if path in sensitive_paths:
                raise TargetSpecError("duplicate_target_sensitive_path")
            if path in legacy_paths:
                raise TargetSpecError("registry_must_not_reuse_legacy_sensitive_path")
            sensitive_paths.add(path)
    return specs


def registry_add(document: dict, spec: TargetSpec, *, legacy_config: dict | None = None) -> dict:
    existing = validate_registry(document, legacy_config=legacy_config)
    spec.validate()
    candidate = {
        "schema": REGISTRY_SCHEMA,
        "targets": [row.as_dict() for row in existing] + [spec.as_dict()],
    }
    validate_registry(candidate, legacy_config=legacy_config)
    return candidate


def resolve_runtime_target(
    legacy_config: dict,
    *,
    requested_target: str | None = None,
    registry_document: dict | None = None,
) -> dict:
    """Select production legacy target or one explicit isolated registry target.

    Unknown explicit targets fail closed and never fall back to the production Mac.
    """
    if not isinstance(legacy_config, dict):
        raise TargetSpecError("legacy_config_must_be_object")
    legacy_target = str(legacy_config.get("target") or "").strip()
    if not legacy_target:
        raise TargetSpecError("legacy_target_missing")
    requested = str(requested_target or "").strip()
    if not requested or requested == legacy_target:
        return {
            "schema": "macctl-runtime-target-selection/v1",
            "requested_target": requested or None,
            "selected_target": legacy_target,
            "source": "LEGACY_PRODUCTION",
            "runtime_config": dict(legacy_config),
            "fallback_used": False,
        }
    if registry_document is None:
        raise TargetSpecError("explicit_target_requires_registry")
    specs = validate_registry(registry_document, legacy_config=legacy_config)
    match = next((s for s in specs if s.target_id == requested), None)
    if match is None:
        raise TargetSpecError("unknown_explicit_target_no_fallback")
    runtime = dict(legacy_config)
    runtime.update({
        "target": match.target_id,
        "host": match.host,
        "port": int(match.port),
        "user": match.user,
        "identity_file": match.identity_file,
        "known_hosts_file": match.known_hosts_file,
        "ssh_config_file": match.ssh_config_file,
        "wake_broadcast": None,
        "wake_mac": None,
    })
    return {
        "schema": "macctl-runtime-target-selection/v1",
        "requested_target": requested,
        "selected_target": match.target_id,
        "source": "REGISTRY_ISOLATED",
        "runtime_config": runtime,
        "fallback_used": False,
    }
