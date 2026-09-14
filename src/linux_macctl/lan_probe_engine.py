#!/usr/bin/env python3
"""Authenticated LAN fast-path probing for MacCtl attachment transport.

This module does not expose files and does not create a listener. It only
qualifies an already-registered SSH target as a LAN_DIRECT candidate when:

1. the kernel route is direct (no gateway hop),
2. TCP reachability is measured,
3. strict-host-key / public-key SSH authentication succeeds with a nonce
   challenge, and
4. a bounded synthetic throughput probe succeeds.

The resulting PathProbe can be fed to delivery_route_engine. A successful
probe means the current Mac<->gateway hop is LAN-qualified; it does NOT mean a
ChatGPT client can directly reach the Mac over the LAN.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import select
import socket
import statistics
import subprocess
import time
from pathlib import Path

LAN_PROBE_SCHEMA_VERSION = "macctl-lan-probe/v1"
_TARGET_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_MIB = 1024 * 1024


class LanProbeError(RuntimeError):
    def __init__(self, reason: str, detail: str | None = None):
        self.reason = reason
        self.detail = detail
        super().__init__(reason if not detail else f"{reason}: {detail}")


def parse_route_get(output: str, host: str) -> dict:
    """Parse Linux `ip route get` output without treating it as authority.

    Route information is discovery/performance context only. Authentication is
    established separately by the SSH nonce challenge.
    """
    text = " ".join(str(output or "").strip().split())
    tokens = text.split()
    dev = None
    src = None
    via = None
    for idx, token in enumerate(tokens[:-1]):
        if token == "dev":
            dev = tokens[idx + 1]
        elif token == "src":
            src = tokens[idx + 1]
        elif token == "via":
            via = tokens[idx + 1]
    try:
        private = ipaddress.ip_address(host).is_private
    except ValueError:
        private = False
    direct = bool(dev and via is None)
    return {
        "host": host,
        "route_text": text,
        "interface": dev,
        "source_address": src,
        "gateway": via,
        "direct_route": direct,
        "host_private": private,
        "same_lan_candidate": direct,
    }


def _validate_inputs(host: str, port: int, target: str, ssh_config: str) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise LanProbeError("invalid_host_address") from exc
    if not 1 <= int(port) <= 65535:
        raise LanProbeError("invalid_port")
    if not _TARGET_RE.fullmatch(str(target or "")):
        raise LanProbeError("invalid_ssh_target")
    path = Path(ssh_config)
    if not path.is_absolute() or not path.is_file():
        raise LanProbeError("invalid_ssh_config")


def _route_probe(host: str, timeout: float) -> dict:
    try:
        cp = subprocess.run(
            ["ip", "route", "get", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(1.0, timeout),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LanProbeError("route_probe_failed", type(exc).__name__) from exc
    if cp.returncode != 0:
        raise LanProbeError("route_probe_failed", "nonzero_exit")
    return parse_route_get(cp.stdout, host)


def _tcp_rtt(host: str, port: int, attempts: int, timeout: float) -> dict:
    samples: list[float] = []
    errors = 0
    for _ in range(max(1, min(10, int(attempts)))):
        started = time.perf_counter()
        try:
            with socket.create_connection((host, int(port)), timeout=max(0.2, timeout)):
                samples.append((time.perf_counter() - started) * 1000.0)
        except OSError:
            errors += 1
    if not samples:
        return {"pass": False, "samples_ms": [], "median_ms": None, "errors": errors}
    return {
        "pass": True,
        "samples_ms": [round(v, 3) for v in samples],
        "median_ms": round(statistics.median(samples), 3),
        "errors": errors,
    }


def _ssh_command(ssh_config: str, target: str, *, fresh: bool) -> list[str]:
    command = [
        "ssh",
        "-F",
        ssh_config,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
    ]
    if fresh:
        command += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    command.append(target)
    return command


def _ssh_nonce_probe(ssh_config: str, target: str, timeout: float) -> dict:
    nonce = secrets.token_hex(16)
    marker = f"MACCTL_LAN_PROBE_V1:{nonce}"
    argv = _ssh_command(ssh_config, target, fresh=True) + ["/bin/echo", marker]
    started = time.perf_counter()
    try:
        cp = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(1.0, timeout),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "pass": False,
            "method": "openssh_publickey_strict_hostkey_nonce",
            "nonce_verified": False,
            "auth_ms": None,
            "reason": type(exc).__name__,
        }
    elapsed = (time.perf_counter() - started) * 1000.0
    verified = cp.returncode == 0 and cp.stdout.strip() == marker
    return {
        "pass": bool(verified),
        "method": "openssh_publickey_strict_hostkey_nonce",
        "nonce_verified": bool(verified),
        "auth_ms": round(elapsed, 3),
        "reason": "" if verified else "ssh_auth_or_nonce_failed",
    }


def _throughput_probe(ssh_config: str, target: str, sample_bytes: int, timeout: float) -> dict:
    requested = max(_MIB, min(64 * _MIB, int(sample_bytes)))
    blocks = (requested + _MIB - 1) // _MIB
    expected = blocks * _MIB
    argv = _ssh_command(ssh_config, target, fresh=False) + [
        "/bin/dd",
        "if=/dev/zero",
        f"bs={_MIB}",
        f"count={blocks}",
    ]
    started = time.perf_counter()
    first_byte_ms = None
    received = 0
    proc = None
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.stdout is not None
        deadline = started + max(1.0, timeout)
        wait_for_first = max(0.0, deadline - time.perf_counter())
        readable, _, _ = select.select([proc.stdout], [], [], wait_for_first)
        if not readable:
            proc.kill()
            proc.communicate(timeout=2)
            return {
                "pass": False,
                "sample_bytes": expected,
                "received_bytes": 0,
                "first_byte_ms": None,
                "throughput_mbps": None,
                "reason": "throughput_first_byte_timeout",
            }
        first = os.read(proc.stdout.fileno(), min(256 * 1024, expected))
        if first:
            first_byte_ms = (time.perf_counter() - started) * 1000.0
            received += len(first)
        remaining_timeout = max(0.1, deadline - time.perf_counter())
        rest, _stderr = proc.communicate(timeout=remaining_timeout)
        received += len(rest)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        if proc is not None:
            proc.kill()
            proc.communicate(timeout=2)
        return {
            "pass": False,
            "sample_bytes": expected,
            "received_bytes": received,
            "first_byte_ms": round(first_byte_ms, 3) if first_byte_ms is not None else None,
            "throughput_mbps": None,
            "reason": "throughput_probe_timeout",
        }
    except (OSError, subprocess.SubprocessError) as exc:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=2)
        return {
            "pass": False,
            "sample_bytes": expected,
            "received_bytes": received,
            "first_byte_ms": None,
            "throughput_mbps": None,
            "reason": type(exc).__name__,
        }
    elapsed = max(1e-9, time.perf_counter() - started)
    passed = rc == 0 and received == expected
    mbps = (received * 8.0 / 1_000_000.0) / elapsed if passed else None
    return {
        "pass": bool(passed),
        "sample_bytes": expected,
        "received_bytes": received,
        "first_byte_ms": round(first_byte_ms, 3) if first_byte_ms is not None else None,
        "total_ms": round(elapsed * 1000.0, 3),
        "throughput_mbps": round(mbps, 3) if mbps is not None else None,
        "reason": "" if passed else "throughput_probe_failed",
    }


def probe_registered_ssh_lan(
    *,
    host: str,
    port: int,
    target: str,
    ssh_config: str,
    sample_bytes: int = 8 * _MIB,
    tcp_attempts: int = 3,
    timeout: float = 8.0,
    policy_allowed: bool = False,
    recent_success_rate: float = 1.0,
) -> dict:
    """Actively qualify the registered MacCtl SSH path as LAN_DIRECT."""
    _validate_inputs(host, port, target, ssh_config)
    route = _route_probe(host, timeout)
    tcp = _tcp_rtt(host, port, tcp_attempts, min(timeout, 3.0))
    auth = _ssh_nonce_probe(ssh_config, target, timeout)
    throughput = (
        _throughput_probe(ssh_config, target, sample_bytes, timeout)
        if route["same_lan_candidate"] and tcp["pass"] and auth["pass"]
        else {
            "pass": False,
            "sample_bytes": max(_MIB, int(sample_bytes)),
            "received_bytes": 0,
            "first_byte_ms": None,
            "throughput_mbps": None,
            "reason": "prerequisite_failed",
        }
    )
    ready = bool(
        route["same_lan_candidate"]
        and tcp["pass"]
        and auth["pass"]
        and throughput["pass"]
        and policy_allowed
    )
    authenticated = bool(auth["pass"])
    path_probe = {
        "name": f"lan:{target}",
        "kind": "LAN_DIRECT",
        "ready": ready,
        "authenticated": authenticated,
        "policy_allowed": bool(policy_allowed),
        "rtt_ms": tcp["median_ms"],
        "first_byte_ms": throughput.get("first_byte_ms"),
        "throughput_mbps": throughput.get("throughput_mbps"),
        "recent_success_rate": max(0.0, min(1.0, float(recent_success_rate))),
        "reason": (
            "registered_target_direct_route_ssh_authenticated"
            if ready
            else "lan_probe_not_ready"
        ),
    }
    return {
        "schema": LAN_PROBE_SCHEMA_VERSION,
        "status": "PASS" if ready else "NOT_READY",
        "discovery": {
            "source": "registered_macctl_target",
            **route,
        },
        "tcp": tcp,
        "authentication": auth,
        "performance": throughput,
        "policy_allowed": bool(policy_allowed),
        "path_probe": path_probe,
        "security_boundary": (
            "qualifies_registered_mac_to_gateway_ssh_lan_hop_only;"
            "does_not_imply_chatgpt_client_private_ip_reachability"
        ),
    }
