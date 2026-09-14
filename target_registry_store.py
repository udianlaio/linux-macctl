#!/usr/bin/env python3
"""Atomic VM-local persistence for the R4 target registry.

The registry contains target metadata and paths, never private-key bytes or passwords.
Writes are same-directory + fsync + os.replace and refuse symlink destinations.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from target_registry_engine import empty_registry, validate_registry


class TargetRegistryStoreError(ValueError):
    pass


def load_registry(path: str | Path, *, legacy_config: dict, allow_missing: bool = False) -> dict:
    p = Path(path)
    if p.is_symlink():
        raise TargetRegistryStoreError("target_registry_symlink_forbidden")
    if not p.exists():
        if allow_missing:
            return empty_registry()
        raise TargetRegistryStoreError("target_registry_missing")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise TargetRegistryStoreError("target_registry_invalid_json") from e
    validate_registry(doc, legacy_config=legacy_config)
    return doc


def write_registry_atomic(path: str | Path, document: dict, *, legacy_config: dict, mode: int = 0o640) -> dict:
    validate_registry(document, legacy_config=legacy_config)
    p = Path(path)
    if p.is_symlink():
        raise TargetRegistryStoreError("target_registry_symlink_forbidden")
    if not p.parent.is_dir():
        raise TargetRegistryStoreError("target_registry_parent_missing")
    payload = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd = None
    tmp_name = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{p.name}.", dir=str(p.parent))
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as f:
            fd = None
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, p)
        tmp_name = None
        dir_fd = os.open(str(p.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
    return load_registry(p, legacy_config=legacy_config)


def initialize_empty_registry(path: str | Path, *, legacy_config: dict) -> tuple[dict, bool]:
    p = Path(path)
    if p.exists():
        return load_registry(p, legacy_config=legacy_config), False
    return write_registry_atomic(p, empty_registry(), legacy_config=legacy_config), True
