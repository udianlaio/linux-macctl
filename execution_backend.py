#!/usr/bin/env python3
"""Execution Backend V2 pure planning primitives.

This module deliberately separates backend *selection and argv construction*
from Policy / Transaction / Audit.  It is safe to unit-test without live SSH,
TCC, or macOS state.

R0 phase-1 keeps the deployed runtime on REMOTE_SSH while establishing the
contract once prepared for a future LOCAL_MACOS backend.  Project scope was
corrected on 2026-09-12: LOCAL_MACOS/AUTO are PAUSED_BY_PROJECT_SCOPE. These
helpers remain historical deterministic contracts only and do not qualify or
enable local deployment.
"""
from __future__ import annotations

from dataclasses import dataclass
import shlex

BACKEND_SCHEMA_VERSION = "macctl-execution-backend/v2"
REMOTE_SSH = "REMOTE_SSH"
LOCAL_MACOS = "LOCAL_MACOS"
AUTO = "AUTO"
_VALID_MODES = {REMOTE_SSH, LOCAL_MACOS, AUTO}


class BackendError(ValueError):
    """Raised when a backend request is unsafe or unsupported."""


@dataclass(frozen=True)
class BackendResolution:
    requested: str
    selected: str
    host_os: str
    target_is_self: bool
    reason: str

    def as_dict(self) -> dict:
        return {
            "schema": BACKEND_SCHEMA_VERSION,
            "requested": self.requested,
            "selected": self.selected,
            "host_os": self.host_os,
            "target_is_self": self.target_is_self,
            "reason": self.reason,
        }


def normalize_mode(value: str | None) -> str:
    mode = str(value or REMOTE_SSH).strip().upper()
    if mode not in _VALID_MODES:
        raise BackendError(f"unknown_execution_backend:{mode}")
    return mode


def resolve_backend_mode(
    requested: str | None,
    *,
    host_os: str,
    target_is_self: bool,
) -> BackendResolution:
    """Resolve a backend without silently treating LOCAL as REMOTE or vice versa.

    AUTO selects LOCAL_MACOS only when the controller itself is running on
    macOS *and* the registered target is explicitly self.  Everything else
    remains REMOTE_SSH, preserving the deployed v0.4 topology.
    """
    mode = normalize_mode(requested)
    os_name = str(host_os or "").strip().lower()
    is_darwin = os_name in {"darwin", "macos", "mac os", "mac os x"}

    if mode == REMOTE_SSH:
        return BackendResolution(mode, REMOTE_SSH, host_os, bool(target_is_self), "explicit_remote_ssh")

    if mode == LOCAL_MACOS:
        if not is_darwin:
            raise BackendError("local_macos_requires_darwin_host")
        if not target_is_self:
            raise BackendError("local_macos_requires_explicit_self_target")
        return BackendResolution(mode, LOCAL_MACOS, host_os, True, "explicit_local_macos_self")

    if is_darwin and target_is_self:
        return BackendResolution(mode, LOCAL_MACOS, host_os, True, "auto_local_macos_self")
    return BackendResolution(mode, REMOTE_SSH, host_os, bool(target_is_self), "auto_remote_ssh_fallback")


def remote_ssh_argv(
    *,
    ssh_config: str,
    target: str,
    remote: str | None = None,
    fresh: bool = False,
    op: str | None = None,
) -> list[str]:
    """Build the exact OpenSSH argv used by the existing deployed runtime."""
    if not str(ssh_config).strip():
        raise BackendError("missing_ssh_config")
    if not str(target).strip():
        raise BackendError("missing_ssh_target")
    argv = ["ssh", "-F", str(ssh_config)]
    if fresh:
        argv += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    if op:
        argv += ["-O", str(op)]
    argv.append(str(target))
    if remote is not None:
        argv.append(str(remote))
    return argv


def remote_shell_argv(
    command: str,
    *,
    sudo: bool = False,
    shell: str = "/bin/zsh",
    remote_timeout: int | None = None,
) -> list[str]:
    """Wrap a command for the remote Mac with the existing timeout semantics."""
    argv = [str(shell), "-lc", str(command)]
    if remote_timeout:
        perl_alarm = (
            "use POSIX qw(setsid); $t=shift; $p=fork(); die qq(fork failed) unless defined $p; "
            "if(!$p){setsid(); exec @ARGV; exit 127} "
            "$SIG{ALRM}=sub{kill q(TERM), -$p; select undef,undef,undef,0.2; "
            "kill q(KILL), -$p; exit 124}; alarm $t; waitpid($p,0); alarm 0; $s=$?; "
            "exit(($s & 127) ? 128+($s & 127) : ($s >> 8));"
        )
        argv = ["/usr/bin/perl", "-e", perl_alarm, str(max(1, int(remote_timeout)))] + argv
    if sudo:
        argv = ["/usr/bin/sudo", "-n"] + argv
    return argv


def local_macos_shell_argv(
    command: str,
    *,
    sudo: bool = False,
    shell: str = "/bin/zsh",
) -> list[str]:
    """Build a bounded-run-compatible local macOS command argv.

    The caller's bounded local runner owns the timeout, so no nested remote
    alarm wrapper is required.  This function does not execute anything.
    """
    argv = [str(shell), "-lc", str(command)]
    if sudo:
        argv = ["/usr/bin/sudo", "-n"] + argv
    return argv


def remote_command_string(
    command: str,
    *,
    sudo: bool = False,
    shell: str = "/bin/zsh",
    remote_timeout: int | None = None,
) -> str:
    """Return shell-quoted remote argv for passing as one SSH command arg."""
    return shlex.join(
        remote_shell_argv(
            command,
            sudo=sudo,
            shell=shell,
            remote_timeout=remote_timeout,
        )
    )


def remote_scp_argv(
    *,
    ssh_config: str,
    target: str,
    local_path: str,
    remote_path: str,
    direction: str,
    recursive: bool = False,
    quiet: bool = True,
) -> list[str]:
    """Build the deployed SCP transport argv without changing path semantics."""
    if direction not in {"push", "pull"}:
        raise BackendError(f"invalid_scp_direction:{direction}")
    if not str(ssh_config).strip():
        raise BackendError("missing_ssh_config")
    if not str(target).strip():
        raise BackendError("missing_ssh_target")
    argv = ["scp", "-F", str(ssh_config)]
    if quiet:
        argv.append("-q")
    if recursive:
        argv.append("-r")
    remote_spec = f"{target}:{remote_path}"
    if direction == "push":
        argv += [str(local_path), remote_spec]
    else:
        argv += [remote_spec, str(local_path)]
    return argv


def remote_rsync_argv(
    *,
    ssh_config: str,
    target: str,
    local_path: str,
    remote_path: str,
    direction: str,
    delete: bool = False,
    dry_run: bool = False,
) -> list[str]:
    """Build the deployed rsync-over-SSH argv with exact current flags."""
    if direction not in {"push", "pull"}:
        raise BackendError(f"invalid_rsync_direction:{direction}")
    if not str(ssh_config).strip():
        raise BackendError("missing_ssh_config")
    if not str(target).strip():
        raise BackendError("missing_ssh_target")
    ssh_transport = f"ssh -F {shlex.quote(str(ssh_config))}"
    # Never expose an interrupted transfer at the requested final filename.
    # A dedicated partial directory keeps resumable bytes out of the visible
    # final path; rsync atomically renames a completed file into place.
    argv = [
        "rsync", "-a", "--partial-dir=.macctl-partial", "--stats",
        "-e", ssh_transport,
    ]
    if delete:
        argv.append("--delete")
    if dry_run:
        argv.append("--dry-run")
    remote_spec = f"{target}:{remote_path}"
    if direction == "push":
        argv += [str(local_path), remote_spec]
    else:
        argv += [remote_spec, str(local_path)]
    return argv
