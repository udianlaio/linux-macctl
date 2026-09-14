#!/usr/bin/env python3
"""Pure transfer planning helpers for Linux-macctl.

These helpers contain no SSH or live-host state.  They exist so file-transfer
staging, path resolution and streaming hashes can be tested deterministically.
"""
from __future__ import annotations

import hashlib
import posixpath
from pathlib import Path


class TransferPlanError(ValueError):
    """Raised when an atomic transfer path cannot be planned safely."""


def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    """Return a streaming SHA-256 without loading the whole file in memory."""
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        while True:
            chunk = fh.read(max(1, int(chunk_size)))
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def resolve_remote_user_path(path: str, *, home: str) -> str:
    """Resolve the path semantics used by a normal non-interactive SSH login.

    ``~`` and ``~/...`` are resolved against the authenticated user's HOME;
    relative paths are also rooted at HOME.  ``~other`` is deliberately
    rejected because staging it correctly would require another account lookup
    and would weaken the simple same-user transfer contract.
    """
    value = str(path if path is not None else "")
    home_s = str(home or "")
    if not value:
        raise TransferPlanError("remote path is empty")
    if "\x00" in value or "\x00" in home_s:
        raise TransferPlanError("remote path contains NUL byte")
    if not home_s.startswith("/"):
        raise TransferPlanError("remote HOME is not absolute")
    if value == "~":
        return home_s
    if value.startswith("~/"):
        return posixpath.join(home_s, value[2:])
    if value.startswith("~"):
        raise TransferPlanError("~other remote paths are not supported by atomic transfer")
    if value.startswith("/"):
        return value
    return posixpath.join(home_s, value)


def effective_remote_file_path(
    requested: str,
    *,
    home: str,
    local_name: str,
    destination_is_dir: bool,
) -> str:
    resolved = resolve_remote_user_path(requested, home=home)
    if destination_is_dir:
        return posixpath.join(resolved, str(local_name))
    if requested.endswith("/"):
        raise TransferPlanError("remote destination ends with / but is not a directory")
    return resolved


def remote_stage_sibling(final_path: str, *, token: str) -> str:
    final_s = str(final_path or "")
    base = posixpath.basename(final_s)
    parent = posixpath.dirname(final_s) or "."
    if not base or base in {".", ".."}:
        raise TransferPlanError("remote final path has no file basename")
    return posixpath.join(parent, f".{base}.macctl-partial-{token}")


def local_stage_sibling(final_path: str | Path, *, token: str) -> Path:
    final = Path(final_path)
    if not final.name:
        raise TransferPlanError("local final path has no file basename")
    return final.with_name(f".{final.name}.macctl-partial-{token}")
