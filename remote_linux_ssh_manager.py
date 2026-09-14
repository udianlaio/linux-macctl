#!/usr/bin/env python3
"""Pure SSH transport-management contracts for remote Linux targets."""
from __future__ import annotations

import re

SSH_MANAGER_SCHEMA = "macctl-remote-linux-ssh-manager/v1"
SSH_TRANSPORT_OBSERVATION_SCHEMA = "macctl-remote-linux-ssh-transport/v1"

PRIMARY_ROUTES = {"DIRECT", "PROXYJUMP"}
DEFAULT_BATCH_PARALLELISM = 3
MAX_BATCH_PARALLELISM = 8


def default_transport_policy() -> dict:
    return {
        "schema": SSH_MANAGER_SCHEMA,
        "primary_route": "DIRECT",
        "fallback_ssh_aliases": [],
        "connection_reuse_required": True,
        "control_persist_min_seconds": 60,
        "connect_timeout_seconds": 8,
        "server_alive_interval_seconds": 15,
        "server_alive_count_max": 3,
        "rate_limit_aware": True,
        "automatic_fallback": False,
        "batch_parallelism": DEFAULT_BATCH_PARALLELISM,
    }


def normalize_transport_policy(raw: dict | None) -> dict:
    data = dict(default_transport_policy())
    raw = dict(raw or {})
    route = str(raw.get("primary_route", data["primary_route"])).upper()
    if route not in PRIMARY_ROUTES:
        raise ValueError("invalid_primary_route")
    fallbacks = raw.get("fallback_ssh_aliases", data["fallback_ssh_aliases"])
    if not isinstance(fallbacks, list):
        raise ValueError("fallback_ssh_aliases_not_list")
    cleaned = []
    for alias in fallbacks:
        alias = str(alias or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", alias):
            raise ValueError("invalid_fallback_ssh_alias")
        if alias not in cleaned:
            cleaned.append(alias)
    data.update({
        "primary_route": route,
        "fallback_ssh_aliases": cleaned,
        "connection_reuse_required": bool(raw.get("connection_reuse_required", data["connection_reuse_required"])),
        "rate_limit_aware": bool(raw.get("rate_limit_aware", data["rate_limit_aware"])),
        "automatic_fallback": bool(raw.get("automatic_fallback", data["automatic_fallback"])),
    })
    for key, low, high in (
        ("control_persist_min_seconds", 1, 86400),
        ("connect_timeout_seconds", 1, 120),
        ("server_alive_interval_seconds", 1, 3600),
        ("server_alive_count_max", 1, 20),
        ("batch_parallelism", 1, MAX_BATCH_PARALLELISM),
    ):
        try:
            value = int(raw.get(key, data[key]))
        except (TypeError, ValueError):
            raise ValueError(f"invalid_{key}")
        if value < low or value > high:
            raise ValueError(f"invalid_{key}")
        data[key] = value
    return data


def parse_ssh_g_output(text: str) -> dict:
    fields = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        key, value = line.split(None, 1)
        key = key.casefold()
        if key not in fields:
            fields[key] = value.strip()
    return fields


def _persist_seconds(value: str | None) -> int | None:
    if value is None:
        return None
    value = str(value).strip().casefold()
    if value == "yes":
        return 2**31 - 1
    if value == "no":
        return 0
    if value.isdigit():
        return int(value)
    m = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", value)
    if not m or not any(m.groups()):
        return None
    h, mnt, sec = (int(x or 0) for x in m.groups())
    return h * 3600 + mnt * 60 + sec


def evaluate_ssh_transport_config(target: dict, effective: dict, *, alias: str | None = None) -> dict:
    policy = normalize_transport_policy(target.get("transport"))
    alias = str(alias or target.get("ssh_alias") or "")
    checks = {
        "hostname_match": str(effective.get("hostname") or "") == str(target.get("host") or ""),
        "user_match": str(effective.get("user") or "") == str(target.get("user") or ""),
        "port_match": str(effective.get("port") or "") == str(target.get("port") or 22),
        "strict_host_key": str(effective.get("stricthostkeychecking") or "").casefold() in {"yes", "true"},
        "known_hosts_configured": bool(str(effective.get("userknownhostsfile") or "").strip()),
        "identity_configured": bool(str(effective.get("identityfile") or "").strip()),
    }
    if policy["connection_reuse_required"]:
        checks["control_master"] = str(effective.get("controlmaster") or "").casefold() in {"auto", "yes"}
        persist = _persist_seconds(effective.get("controlpersist"))
        checks["control_persist"] = persist is not None and persist >= policy["control_persist_min_seconds"]
        checks["control_path"] = bool(str(effective.get("controlpath") or "").strip())
    proxyjump = str(effective.get("proxyjump") or "").strip()
    checks["primary_route"] = (not proxyjump) if policy["primary_route"] == "DIRECT" else bool(proxyjump)
    ready = all(checks.values())
    return {
        "schema": SSH_TRANSPORT_OBSERVATION_SCHEMA,
        "status": "PASS" if ready else "BLOCKED",
        "target": target.get("id"),
        "ssh_alias": alias,
        "primary_route": policy["primary_route"],
        "fallback_ssh_aliases": list(policy["fallback_ssh_aliases"]),
        "connection_reuse_required": policy["connection_reuse_required"],
        "rate_limit_aware": policy["rate_limit_aware"],
        "automatic_fallback": policy["automatic_fallback"],
        "checks": checks,
        "effective": {
            key: effective.get(key)
            for key in (
                "hostname", "user", "port", "stricthostkeychecking", "identityfile",
                "userknownhostsfile", "controlmaster", "controlpersist", "controlpath",
                "proxyjump", "connecttimeout", "serveraliveinterval", "serveralivecountmax",
            )
            if key in effective
        },
    }


def classify_transport_failure(output: str, rc: int) -> str:
    text = str(output or "").casefold()
    if rc == 0:
        return "SUCCESS"
    if "permission denied" in text or "authentication failed" in text:
        return "AUTH_REJECTED"
    if "host key verification failed" in text or "remote host identification has changed" in text:
        return "HOST_KEY_REJECTED"
    if "could not resolve hostname" in text or "nodename nor servname provided" in text:
        return "DNS_RESOLUTION_FAILED"
    if "connection timed out" in text or "operation timed out" in text:
        return "CONNECT_TIMEOUT"
    if "banner exchange" in text:
        return "PREAUTH_BANNER_TIMEOUT"
    if "connection refused" in text:
        return "CONNECTION_REFUSED_OR_RATE_LIMIT"
    if "connection closed" in text or "kex_exchange_identification" in text:
        return "PREAUTH_CONNECTION_CLOSED_OR_RATE_LIMIT"
    if "no route to host" in text or "network is unreachable" in text:
        return "NETWORK_UNREACHABLE"
    return "SSH_TRANSPORT_FAILED"


def bounded_batch_parallelism(requested: int | None, target_count: int) -> int:
    if target_count <= 0:
        return 1
    value = DEFAULT_BATCH_PARALLELISM if requested is None else int(requested)
    value = max(1, min(value, MAX_BATCH_PARALLELISM, target_count))
    return value
