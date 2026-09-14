#!/usr/bin/env python3
"""Immutable artifact store for MacCtl V0.5 attachment delivery.

This module intentionally has no ChatGPT/OpenAI transport dependency. It owns
only exact-byte snapshotting, integrity, lifecycle and delivery authorization.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import mimetypes
import os
import re
import secrets
import shutil
import stat
import tempfile
import unicodedata
import zipfile
from pathlib import Path
from typing import Callable, Iterable

ARTIFACT_SCHEMA_VERSION = "macctl-artifact/v1"
ARTIFACT_ID_RE = re.compile(r"^art_[A-Za-z0-9_-]{32,96}$")
DENY_DELIVERY_CLASSES = {"SECRET", "DENY_EXPORT"}
DEFAULT_ALLOWED_CLASSES = {
    "SCREEN_CAPTURE",
    "GENERATED_FILE",
    "USER_SELECTED",
    "BROWSER_DOWNLOAD",
    "DIAGNOSTIC",
    "SENSITIVE",
    "SECRET",
    "DENY_EXPORT",
}


class ArtifactError(RuntimeError):
    def __init__(self, reason: str, detail: str | None = None):
        self.reason = reason
        self.detail = detail
        super().__init__(reason if not detail else f"{reason}: {detail}")


def _utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _safe_filename(name: str) -> str:
    name = unicodedata.normalize("NFKC", os.path.basename(str(name or "artifact.bin")))
    name = "".join(ch for ch in name if ch >= " " and ch not in {"/", "\\", "\x7f"})
    name = name.strip(" .")[:180]
    return name or "artifact.bin"


def _is_within(path: Path, roots: Iterable[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _detect_ooxml_mime(payload_path: Path, filename: str) -> str | None:
    """Detect OOXML containers without trusting the extension alone.

    DOCX/XLSX/PPTX are ZIP containers, so the generic PK signature is not
    enough. We require both the expected extension and the canonical package
    member for that document family. Listing ZIP members does not extract the
    archive and therefore avoids decompression side effects during import.
    """
    ext = Path(filename).suffix.lower()
    expected = {
        ".docx": ("word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ".xlsx": ("xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ".pptx": ("ppt/presentation.xml", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    }.get(ext)
    if expected is None:
        return None
    member, mime = expected
    try:
        with zipfile.ZipFile(payload_path, "r") as archive:
            names = set(archive.namelist())
    except (OSError, zipfile.BadZipFile):
        return None
    return mime if member in names else None


def _detect_mime(head: bytes, filename: str, payload_path: Path | None = None) -> str:
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"PK\x03\x04"):
        if payload_path is not None:
            ooxml = _detect_ooxml_mime(payload_path, filename)
            if ooxml:
                return ooxml
        return "application/zip"
    if head.startswith(b"\x1f\x8b"):
        return "application/gzip"
    # MPEG audio commonly starts with ID3 metadata or an MPEG frame sync.
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return "audio/mpeg"
    # ISO Base Media File Format (MP4/M4V/etc.) carries an `ftyp` box at
    # bytes 4..7. For .mp4 we classify the container as video/mp4.
    if len(head) >= 12 and head[4:8] == b"ftyp" and Path(filename).suffix.lower() == ".mp4":
        return "video/mp4"
    guessed, _ = mimetypes.guess_type(filename)
    # Extension inference is deliberately restricted to passive textual and
    # JSON content after signature-based formats have been handled above.
    if guessed and (guessed.startswith(("image/", "text/")) or guessed == "application/json"):
        return guessed
    return "application/octet-stream"


def _looks_like_private_key(head: bytes) -> bool:
    upper = head.upper()
    prefix = b"-----BEGIN "
    suffix = b" KEY-----"
    markers = tuple(prefix + name.encode("ascii") + suffix for name in (
        "OPENSSH PRIVATE", "PRIVATE", "RSA PRIVATE", "EC PRIVATE", "DSA PRIVATE"
    ))
    return any(marker in upper for marker in markers)


class ArtifactStore:
    def __init__(
        self,
        root: str | os.PathLike,
        *,
        import_roots: Iterable[str | os.PathLike] = ("/tmp",),
        default_ttl_seconds: int = 86400,
        max_artifact_bytes: int = 512 * 1024 * 1024,
        now_fn: Callable[[], _dt.datetime] = _utc_now,
        default_principal: str = "local-owner",
    ):
        self.root = Path(root).resolve()
        self.import_roots = tuple(Path(p).resolve() for p in import_roots)
        self.default_ttl_seconds = max(60, int(default_ttl_seconds))
        self.max_artifact_bytes = max(1, int(max_artifact_bytes))
        self.now_fn = now_fn
        self.default_principal = str(default_principal or "local-owner")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except PermissionError:
            pass

    def _new_id(self) -> str:
        return "art_" + secrets.token_urlsafe(32)

    def _validate_id(self, artifact_id: str) -> str:
        value = str(artifact_id or "")
        if not ARTIFACT_ID_RE.fullmatch(value):
            raise ArtifactError("invalid_artifact_id")
        return value

    def _dir(self, artifact_id: str) -> Path:
        return self.root / self._validate_id(artifact_id)

    def _manifest_path(self, artifact_id: str) -> Path:
        return self._dir(artifact_id) / "manifest.json"

    def _payload_path(self, artifact_id: str) -> Path:
        return self._dir(artifact_id) / "payload"

    def _write_manifest(self, directory: Path, manifest: dict) -> None:
        tmp = directory / ".manifest.tmp"
        data = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, directory / "manifest.json")

    def _load_manifest(self, artifact_id: str) -> dict:
        path = self._manifest_path(artifact_id)
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ArtifactError("artifact_not_found")
        except (OSError, json.JSONDecodeError) as e:
            raise ArtifactError("artifact_manifest_invalid", type(e).__name__)
        if manifest.get("schema") != ARTIFACT_SCHEMA_VERSION or manifest.get("artifact_id") != artifact_id:
            raise ArtifactError("artifact_manifest_invalid")
        return manifest

    def _assert_not_expired(self, manifest: dict) -> None:
        expires_at = manifest.get("expires_at")
        if expires_at and self.now_fn() >= _parse_iso(expires_at):
            raise ArtifactError("artifact_expired")

    def create_snapshot(
        self,
        source_path: str | os.PathLike,
        *,
        classification: str = "GENERATED_FILE",
        filename: str | None = None,
        ttl_seconds: int | None = None,
        producer: str = "artifact.import",
        producer_metadata: dict | None = None,
        owner_principal: str | None = None,
    ) -> dict:
        classification = str(classification or "GENERATED_FILE").upper()
        if classification not in DEFAULT_ALLOWED_CLASSES:
            raise ArtifactError("invalid_classification")

        raw_path = Path(source_path)
        try:
            lst = os.lstat(raw_path)
        except FileNotFoundError:
            raise ArtifactError("source_not_found")
        if stat.S_ISLNK(lst.st_mode):
            raise ArtifactError("source_symlink_denied")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            src_fd = os.open(raw_path, flags)
        except OSError as e:
            raise ArtifactError("source_open_failed", e.__class__.__name__)

        directory: Path | None = None
        try:
            before = os.fstat(src_fd)
            if not stat.S_ISREG(before.st_mode):
                raise ArtifactError("source_not_regular_file")
            if before.st_size > self.max_artifact_bytes:
                raise ArtifactError("artifact_size_limit_exceeded")

            # Verify the opened object, rather than only the pre-open path.
            fd_link = Path(f"/proc/self/fd/{src_fd}")
            try:
                opened_path = Path(os.path.realpath(os.readlink(fd_link))).resolve()
            except OSError:
                opened_path = raw_path.resolve(strict=True)
            if not _is_within(opened_path, self.import_roots):
                raise ArtifactError("source_path_not_allowed")

            artifact_id = self._new_id()
            directory = self.root / artifact_id
            directory.mkdir(mode=0o700)
            tmp_payload = directory / ".payload.tmp"
            out_fd = os.open(tmp_payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            digest = hashlib.sha256()
            total = 0
            head = bytearray()
            try:
                while True:
                    chunk = os.read(src_fd, 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_artifact_bytes:
                        raise ArtifactError("artifact_size_limit_exceeded")
                    if len(head) < 8192:
                        head.extend(chunk[: 8192 - len(head)])
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(out_fd, view)
                        view = view[written:]
                os.fsync(out_fd)
            finally:
                os.close(out_fd)

            after = os.fstat(src_fd)
            identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            if identity_before != identity_after or total != before.st_size:
                raise ArtifactError("source_changed_during_snapshot")

            final_payload = directory / "payload"
            os.replace(tmp_payload, final_payload)
            safe_name = _safe_filename(filename or raw_path.name)
            mime_type = _detect_mime(bytes(head), safe_name, final_payload)
            effective_class = "SECRET" if _looks_like_private_key(bytes(head)) else classification
            now = self.now_fn()
            ttl = self.default_ttl_seconds if ttl_seconds is None else max(60, int(ttl_seconds))
            expires = now + _dt.timedelta(seconds=ttl)
            metadata = dict(producer_metadata or {})
            # Never allow producer metadata to smuggle source paths/secrets into manifests.
            metadata = {str(k): v for k, v in metadata.items() if str(k) not in {"source_path", "path", "secret", "token"}}
            manifest = {
                "schema": ARTIFACT_SCHEMA_VERSION,
                "artifact_id": artifact_id,
                "state": "READY",
                "created_at": _iso(now),
                "expires_at": _iso(expires),
                "content": {
                    "filename": safe_name,
                    "mime_type": mime_type,
                    "size_bytes": total,
                    "sha256": digest.hexdigest(),
                },
                "classification": effective_class,
                "delivery_allowed": effective_class not in DENY_DELIVERY_CLASSES,
                "access": {
                    "owner_principal": str(owner_principal or self.default_principal),
                    "allowed_principals": [str(owner_principal or self.default_principal)],
                    "grants": [],
                },
                "immutable": True,
                "original_preserved": True,
                "producer": {"operation": str(producer), "metadata": metadata},
            }
            self._write_manifest(directory, manifest)
            return manifest
        except Exception:
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)
            raise
        finally:
            os.close(src_fd)

    def inspect(self, artifact_id: str, *, require_live: bool = False) -> dict:
        manifest = self._load_manifest(artifact_id)
        if require_live:
            self._assert_not_expired(manifest)
        return manifest

    def verify(self, artifact_id: str) -> dict:
        manifest = self._load_manifest(artifact_id)
        payload = self._payload_path(artifact_id)
        if not payload.is_file() or payload.is_symlink():
            return {"status": "FAIL", "reason": "payload_missing_or_invalid", "artifact_id": artifact_id}
        digest = hashlib.sha256()
        total = 0
        with payload.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                total += len(chunk)
                digest.update(chunk)
        expected = manifest.get("content", {})
        ok = total == expected.get("size_bytes") and digest.hexdigest() == expected.get("sha256")
        return {
            "status": "PASS" if ok else "FAIL",
            "artifact_id": artifact_id,
            "size_bytes": total,
            "sha256": digest.hexdigest(),
            "expected_size_bytes": expected.get("size_bytes"),
            "expected_sha256": expected.get("sha256"),
        }

    def _grant_authorized(self, manifest: dict, token: str, purpose: str) -> bool:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = self.now_fn()
        for grant in manifest.get("access", {}).get("grants", []):
            if grant.get("revoked"):
                continue
            try:
                if now >= _parse_iso(grant["expires_at"]):
                    continue
            except Exception:
                continue
            if grant.get("scope") not in {purpose, "download" if purpose == "view" else "__none__"}:
                continue
            if secrets.compare_digest(str(grant.get("token_sha256", "")), token_hash):
                return True
        return False

    def authorize_delivery(
        self,
        artifact_id: str,
        *,
        purpose: str = "download",
        principal: str | None = None,
        grant_token: str | None = None,
    ) -> dict:
        manifest = self._load_manifest(artifact_id)
        self._assert_not_expired(manifest)
        if manifest.get("state") != "READY":
            raise ArtifactError("artifact_not_ready")
        if not manifest.get("delivery_allowed", False):
            raise ArtifactError("artifact_delivery_denied")
        if purpose not in {"view", "download"}:
            raise ArtifactError("invalid_delivery_purpose")
        access = manifest.get("access", {})
        effective_principal = str(principal or self.default_principal)
        principal_allowed = effective_principal in set(access.get("allowed_principals", []))
        grant_allowed = bool(grant_token) and self._grant_authorized(manifest, grant_token, purpose)
        if not (principal_allowed or grant_allowed):
            raise ArtifactError("artifact_access_denied")
        verified = self.verify(artifact_id)
        if verified.get("status") != "PASS":
            raise ArtifactError("artifact_integrity_failed")
        return manifest

    def issue_grant(
        self,
        artifact_id: str,
        *,
        scope: str = "download",
        ttl_seconds: int = 300,
        principal: str | None = None,
    ) -> dict:
        if scope not in {"view", "download"}:
            raise ArtifactError("invalid_grant_scope")
        manifest = self.authorize_delivery(artifact_id, purpose=scope, principal=principal)
        token = "agt_" + secrets.token_urlsafe(32)
        grant = {
            "grant_id": "grt_" + secrets.token_urlsafe(12),
            "scope": scope,
            "expires_at": _iso(self.now_fn() + _dt.timedelta(seconds=max(60, int(ttl_seconds)))),
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "revoked": False,
        }
        manifest.setdefault("access", {}).setdefault("grants", []).append(grant)
        self._write_manifest(self._dir(artifact_id), manifest)
        return {
            "status": "PASS",
            "artifact_id": artifact_id,
            "grant_id": grant["grant_id"],
            "scope": scope,
            "expires_at": grant["expires_at"],
            "grant_token": token,
        }

    def revoke_grants(self, artifact_id: str, *, principal: str | None = None) -> dict:
        manifest = self.authorize_delivery(artifact_id, purpose="download", principal=principal)
        count = 0
        for grant in manifest.setdefault("access", {}).setdefault("grants", []):
            if not grant.get("revoked"):
                grant["revoked"] = True
                count += 1
        self._write_manifest(self._dir(artifact_id), manifest)
        return {"status": "PASS", "artifact_id": artifact_id, "revoked_grants": count}

    def payload_path_for_gateway(
        self,
        artifact_id: str,
        *,
        purpose: str = "download",
        principal: str | None = None,
        grant_token: str | None = None,
    ) -> Path:
        self.authorize_delivery(artifact_id, purpose=purpose, principal=principal, grant_token=grant_token)
        return self._payload_path(artifact_id)

    def stream_payload(
        self,
        artifact_id: str,
        *,
        principal: str | None = None,
        grant_token: str | None = None,
        purpose: str = "download",
        chunk_size: int = 1024 * 1024,
    ):
        if chunk_size <= 0 or chunk_size > 8 * 1024 * 1024:
            raise ArtifactError("invalid_chunk_size")
        manifest = self.authorize_delivery(
            artifact_id, purpose=purpose, principal=principal, grant_token=grant_token
        )
        path = self._payload_path(artifact_id)
        def _iterator():
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        return manifest, _iterator()

    def revoke(self, artifact_id: str) -> dict:
        manifest = self._load_manifest(artifact_id)
        if manifest.get("state") != "REVOKED":
            manifest["state"] = "REVOKED"
            manifest["revoked_at"] = _iso(self.now_fn())
            manifest["delivery_allowed"] = False
            self._write_manifest(self._dir(artifact_id), manifest)
        return manifest

    def list(self, *, limit: int = 50) -> list[dict]:
        items: list[dict] = []
        for directory in self.root.iterdir():
            if not directory.is_dir() or not ARTIFACT_ID_RE.fullmatch(directory.name):
                continue
            try:
                items.append(self._load_manifest(directory.name))
            except ArtifactError:
                continue
        items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return items[: max(1, min(int(limit), 500))]

    def gc(self, *, include_revoked: bool = True) -> dict:
        now = self.now_fn()
        removed: list[str] = []
        kept = 0
        for manifest in self.list(limit=500):
            artifact_id = manifest["artifact_id"]
            expired = bool(manifest.get("expires_at")) and now >= _parse_iso(manifest["expires_at"])
            revoked = manifest.get("state") == "REVOKED"
            if expired or (include_revoked and revoked):
                shutil.rmtree(self._dir(artifact_id), ignore_errors=True)
                removed.append(artifact_id)
            else:
                kept += 1
        return {"status": "PASS", "removed": removed, "removed_count": len(removed), "kept_count": kept}

    def capabilities(self) -> dict:
        return {
            "schema": "macctl-artifact-capabilities/v1",
            "artifact_core": True,
            "immutable_snapshot": True,
            "sha256": True,
            "opaque_artifact_id": True,
            "arbitrary_path_delivery": False,
            "default_import_roots": [str(p) for p in self.import_roots],
            "default_ttl_seconds": self.default_ttl_seconds,
            "max_artifact_bytes": self.max_artifact_bytes,
            "principal_acl": True,
            "short_lived_grants": True,
        }
