#!/usr/bin/env python3
"""Narrow in-process gateway contract between Artifact Core and host adapters.

It intentionally exposes artifact IDs, receipts and bounded bytes only. There
is no arbitrary filesystem path API, shell, SSH or GUI/TCC capability here.
"""
from __future__ import annotations

from artifact_engine import ArtifactStore
from attachment_delivery_engine import choose_adapter

GATEWAY_SCHEMA_VERSION = "macctl-attachment-gateway/v1"
ACTIVE_OR_UNSAFE_INLINE = {
    "text/html",
    "image/svg+xml",
    "application/javascript",
    "text/javascript",
    "application/x-sh",
    "application/x-executable",
}
SAFE_INLINE_IMAGES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
MAX_CHUNK_BYTES = 4 * 1024 * 1024


def presentation_policy(mime_type: str, requested: str) -> dict:
    requested = str(requested or "both").lower()
    if requested not in {"auto", "inline", "attachment", "both"}:
        raise ValueError("invalid_presentation")
    if mime_type in ACTIVE_OR_UNSAFE_INLINE or mime_type not in SAFE_INLINE_IMAGES:
        effective = "attachment" if requested in {"auto", "both", "inline"} else requested
        reason = "active_or_non_image_attachment_only"
    else:
        effective = "both" if requested == "auto" else requested
        reason = "safe_image_inline_allowed"
    return {"requested": requested, "effective": effective, "reason": reason}


class AttachmentGateway:
    def __init__(self, store: ArtifactStore):
        self.store = store

    def prepare(
        self,
        artifact_id: str,
        *,
        principal: str,
        presentation: str = "both",
        original_required: bool = True,
        allow_debug_fallback: bool = False,
        adapters=None,
    ) -> dict:
        manifest = self.store.authorize_delivery(artifact_id, principal=principal, purpose="download")
        policy = presentation_policy(manifest["content"]["mime_type"], presentation)
        kwargs = {
            "original_required": original_required,
            "presentation": policy["effective"],
            "allow_debug_fallback": allow_debug_fallback,
        }
        if adapters is not None:
            kwargs["adapters"] = adapters
        plan = choose_adapter(**kwargs)
        return {
            "schema": GATEWAY_SCHEMA_VERSION,
            "status": plan["status"],
            "artifact_id": artifact_id,
            "content": dict(manifest["content"]),
            "classification": manifest["classification"],
            "presentation": policy,
            "delivery_plan": plan,
            "exact_original_verified": True,
            "arbitrary_path_exposed": False,
        }

    def stream(
        self,
        artifact_id: str,
        *,
        principal: str | None = None,
        grant_token: str | None = None,
        chunk_size: int = 1024 * 1024,
    ):
        return self.store.stream_payload(
            artifact_id,
            principal=principal,
            grant_token=grant_token,
            purpose="download",
            chunk_size=chunk_size,
        )

    def read_chunk(
        self,
        artifact_id: str,
        *,
        principal: str | None = None,
        grant_token: str | None = None,
        offset: int = 0,
        length: int = MAX_CHUNK_BYTES,
    ) -> dict:
        if offset < 0 or length <= 0 or length > MAX_CHUNK_BYTES:
            raise ValueError("invalid_range")
        manifest = self.store.authorize_delivery(
            artifact_id,
            principal=principal,
            grant_token=grant_token,
            purpose="download",
        )
        path = self.store.payload_path_for_gateway(
            artifact_id,
            principal=principal,
            grant_token=grant_token,
            purpose="download",
        )
        with path.open("rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
        total = int(manifest["content"]["size_bytes"])
        return {
            "schema": GATEWAY_SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "offset": offset,
            "length": len(data),
            "eof": offset + len(data) >= total,
            "total_size_bytes": total,
            "sha256": manifest["content"]["sha256"],
            "mime_type": manifest["content"]["mime_type"],
            "filename": manifest["content"]["filename"],
            "data": data,
        }
