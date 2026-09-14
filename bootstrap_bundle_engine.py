#!/usr/bin/env python3
"""Deterministic, secret-free source bundle for onboarding a new remote Mac.

The Linux gateway can package audited Helper source, but it must never export the
existing Mac's signing keychain/private keys or pretend to pre-build a qualified
macOS app. The target Mac creates its own durable signing identity later.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile

from target_registry_engine import TargetSpec

BUNDLE_SCHEMA = "macctl-new-target-bootstrap-bundle/v1"
MANIFEST_NAME = "BOOTSTRAP_MANIFEST.json"
SOURCE_ALLOWLIST = (
    "macos-helper/Info.plist",
    "macos-helper/MacCtlHelper.entitlements",
    "macos-helper/MacCtlHelper.m",
    "macos-helper/build.sh",
    "macos-helper/setup-signing.sh",
)
EXECUTABLE_SOURCE_PATHS = {
    "macos-helper/build.sh",
    "macos-helper/setup-signing.sh",
}
FORBIDDEN_BUNDLE_SUFFIXES = (
    ".key", ".pem", ".p12", ".pfx", ".keychain", ".keychain-db",
)
FORBIDDEN_BUNDLE_BASENAMES = {
    "id_ed25519", "id_rsa", "known_hosts", "keychain.pass", "token", "credentials.json",
}


class BootstrapBundleError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative(path: str) -> str:
    p = PurePosixPath(str(path))
    if p.is_absolute() or ".." in p.parts or not p.parts:
        raise BootstrapBundleError("unsafe_bundle_path")
    return str(p)


def _assert_source_path_allowed(path: str) -> None:
    rel = _safe_relative(path)
    base = PurePosixPath(rel).name.lower()
    low = rel.lower()
    if base in FORBIDDEN_BUNDLE_BASENAMES or low.endswith(FORBIDDEN_BUNDLE_SUFFIXES):
        raise BootstrapBundleError("secret_or_trust_material_path_forbidden")
    if rel not in SOURCE_ALLOWLIST:
        raise BootstrapBundleError("source_path_not_allowlisted")


def collect_source_entries(root: str | Path) -> list[dict]:
    rootp = Path(root)
    out: list[dict] = []
    for rel in SOURCE_ALLOWLIST:
        _assert_source_path_allowed(rel)
        p = rootp / rel
        if p.is_symlink():
            raise BootstrapBundleError("source_symlink_forbidden")
        if not p.is_file():
            raise BootstrapBundleError(f"required_source_missing:{rel}")
        data = p.read_bytes()
        out.append({
            "path": rel,
            "bytes": len(data),
            "sha256": sha256_bytes(data),
            "mode": "0755" if rel in EXECUTABLE_SOURCE_PATHS else "0644",
            "role": "helper_source",
        })
    return out


def build_manifest(
    root: str | Path,
    target: TargetSpec,
    *,
    controller_head: str,
    controller_tree: str,
) -> dict:
    target.validate()
    head = str(controller_head or "").strip()
    tree = str(controller_tree or "").strip()
    if len(head) != 40 or any(c not in "0123456789abcdef" for c in head.lower()):
        raise BootstrapBundleError("invalid_controller_head")
    if len(tree) != 40 or any(c not in "0123456789abcdef" for c in tree.lower()):
        raise BootstrapBundleError("invalid_controller_tree")
    entries = collect_source_entries(root)
    return {
        "schema": BUNDLE_SCHEMA,
        "bundle_type": "SOURCE_ONLY",
        "target": target.as_dict(),
        "controller": {"head": head, "tree": tree},
        "artifacts": entries,
        "secret_policy": {
            "private_key_material_included": False,
            "password_material_included": False,
            "token_material_included": False,
            "existing_m2_signing_identity_included": False,
            "existing_m2_ssh_identity_included": False,
        },
        "signing_contract": {
            "target_local_durable_identity_required": True,
            "identity_label": "MacCtl Local Code Signing",
            "setup_source": "macos-helper/setup-signing.sh",
            "adhoc_signing_final_qualification_allowed": False,
            "qualified_helper_bundle_id": "app.openai.macctl.helper",
        },
        "stateful_gate": {
            "new_target_mutation_authorized": False,
            "requires_fresh_explicit_authorization": True,
        },
        "tcc_contract": {
            "automatic_grant_allowed": False,
            "required_human_review": [
                "Accessibility",
                "Screen Recording",
                "Finder Automation",
                "System Events Automation",
            ],
        },
    }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    return (json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _tar_info(name: str, size: int, mode: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=_safe_relative(name))
    info.size = size
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def build_bundle_bytes(root: str | Path, manifest: dict) -> bytes:
    if manifest.get("schema") != BUNDLE_SCHEMA:
        raise BootstrapBundleError("unsupported_bundle_schema")
    expected = {x["path"]: x for x in manifest.get("artifacts") or []}
    if tuple(expected) != SOURCE_ALLOWLIST:
        raise BootstrapBundleError("manifest_artifact_set_mismatch")
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        mbytes = canonical_manifest_bytes(manifest)
        tf.addfile(_tar_info(MANIFEST_NAME, len(mbytes), 0o644), io.BytesIO(mbytes))
        for rel in SOURCE_ALLOWLIST:
            _assert_source_path_allowed(rel)
            p = Path(root) / rel
            if p.is_symlink() or not p.is_file():
                raise BootstrapBundleError(f"required_source_missing:{rel}")
            data = p.read_bytes()
            meta = expected[rel]
            if len(data) != int(meta["bytes"]) or sha256_bytes(data) != meta["sha256"]:
                raise BootstrapBundleError(f"source_changed_after_manifest:{rel}")
            mode = 0o755 if rel in EXECUTABLE_SOURCE_PATHS else 0o644
            tf.addfile(_tar_info(rel, len(data), mode), io.BytesIO(data))
    gz_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, compresslevel=9, mtime=0) as gz:
        gz.write(tar_buf.getvalue())
    return gz_buf.getvalue()


def verify_bundle_bytes(blob: bytes) -> dict:
    try:
        raw = gzip.decompress(blob)
    except (OSError, EOFError) as e:
        raise BootstrapBundleError("invalid_gzip_bundle") from e
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
            members = tf.getmembers()
            for m in members:
                name = _safe_relative(m.name)
                if not m.isfile():
                    raise BootstrapBundleError("non_regular_bundle_member_forbidden")
                if name in files:
                    raise BootstrapBundleError("duplicate_bundle_member")
                f = tf.extractfile(m)
                if f is None:
                    raise BootstrapBundleError("bundle_member_unreadable")
                files[name] = f.read()
                modes[name] = stat.S_IMODE(m.mode)
    except tarfile.TarError as e:
        raise BootstrapBundleError("invalid_tar_bundle") from e
    expected_names = {MANIFEST_NAME, *SOURCE_ALLOWLIST}
    if set(files) != expected_names:
        raise BootstrapBundleError("bundle_member_set_mismatch")
    try:
        manifest = json.loads(files[MANIFEST_NAME].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BootstrapBundleError("invalid_bundle_manifest") from e
    if canonical_manifest_bytes(manifest) != files[MANIFEST_NAME]:
        raise BootstrapBundleError("manifest_not_canonical")
    if manifest.get("schema") != BUNDLE_SCHEMA or manifest.get("bundle_type") != "SOURCE_ONLY":
        raise BootstrapBundleError("unsupported_bundle_schema")
    meta = {x["path"]: x for x in manifest.get("artifacts") or []}
    if tuple(meta) != SOURCE_ALLOWLIST:
        raise BootstrapBundleError("manifest_artifact_set_mismatch")
    for rel in SOURCE_ALLOWLIST:
        _assert_source_path_allowed(rel)
        data = files[rel]
        row = meta[rel]
        if len(data) != int(row["bytes"]) or sha256_bytes(data) != row["sha256"]:
            raise BootstrapBundleError(f"bundle_digest_mismatch:{rel}")
        want_mode = 0o755 if rel in EXECUTABLE_SOURCE_PATHS else 0o644
        if modes[rel] != want_mode:
            raise BootstrapBundleError(f"bundle_mode_mismatch:{rel}")
    secret = manifest.get("secret_policy") or {}
    if any(bool(v) for v in secret.values()):
        raise BootstrapBundleError("secret_policy_must_be_all_false")
    signing = manifest.get("signing_contract") or {}
    if not signing.get("target_local_durable_identity_required") or signing.get("adhoc_signing_final_qualification_allowed"):
        raise BootstrapBundleError("unsafe_signing_contract")
    gate = manifest.get("stateful_gate") or {}
    if gate.get("new_target_mutation_authorized") or not gate.get("requires_fresh_explicit_authorization"):
        raise BootstrapBundleError("unsafe_stateful_gate")
    return {
        "status": "PASS",
        "schema": BUNDLE_SCHEMA,
        "bundle_sha256": sha256_bytes(blob),
        "manifest_sha256": sha256_bytes(files[MANIFEST_NAME]),
        "artifact_count": len(SOURCE_ALLOWLIST),
        "target_id": (manifest.get("target") or {}).get("target_id"),
        "controller_head": (manifest.get("controller") or {}).get("head"),
        "secrets_included": False,
        "final_adhoc_signing_allowed": False,
        "new_target_mutation_authorized": False,
    }
