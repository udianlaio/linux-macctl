#!/usr/bin/env python3
"""Host-native tool-file adapter seam.

MacCtl cannot mint ChatGPT/OpenAI file IDs. A connector/plugin runtime must
provide create_tool_file(). This module guarantees that the runtime receives a
single verified immutable byte stream and records only HOST_ACCEPTED, never
USER_VISIBLE_CONFIRMED.
"""
from __future__ import annotations

import hashlib
from typing import Protocol, Iterable

from attachment_gateway import AttachmentGateway

ADAPTER_SCHEMA_VERSION = "macctl-native-file-adapter/v1"


class ToolFileRuntime(Protocol):
    runtime_name: str
    qualified: bool

    def create_tool_file(
        self,
        *,
        filename: str,
        mime_type: str,
        size_bytes: int,
        sha256: str,
        chunks: Iterable[bytes],
    ) -> dict:
        ...


def deliver_native_tool_file(
    gateway: AttachmentGateway,
    artifact_id: str,
    *,
    principal: str,
    runtime: ToolFileRuntime,
) -> dict:
    if not bool(getattr(runtime, "qualified", False)):
        return {
            "schema": ADAPTER_SCHEMA_VERSION,
            "status": "NOT_YET_QUALIFIED",
            "artifact_id": artifact_id,
            "runtime": getattr(runtime, "runtime_name", type(runtime).__name__),
            "host_accepted": False,
            "user_visible_confirmed": False,
        }

    manifest, chunks = gateway.stream(artifact_id, principal=principal)
    content = manifest["content"]

    # Wrap the generator to independently count/hash what is handed to runtime.
    observed = hashlib.sha256()
    count = 0

    def checked_chunks():
        nonlocal count
        for chunk in chunks:
            count += len(chunk)
            observed.update(chunk)
            yield chunk

    result = runtime.create_tool_file(
        filename=content["filename"],
        mime_type=content["mime_type"],
        size_bytes=int(content["size_bytes"]),
        sha256=content["sha256"],
        chunks=checked_chunks(),
    )
    if count != int(content["size_bytes"]) or observed.hexdigest() != content["sha256"]:
        raise RuntimeError("native_runtime_stream_integrity_mismatch")
    if not isinstance(result, dict) or not result.get("file_reference"):
        raise RuntimeError("native_runtime_missing_file_reference")

    return {
        "schema": ADAPTER_SCHEMA_VERSION,
        "status": "HOST_ACCEPTED",
        "artifact_id": artifact_id,
        "runtime": getattr(runtime, "runtime_name", type(runtime).__name__),
        "file_reference": result["file_reference"],
        "size_bytes": count,
        "sha256": observed.hexdigest(),
        "host_accepted": True,
        "user_visible_confirmed": False,
        "success_contract_note": "HOST_ACCEPTED is not USER_VISIBLE_CONFIRMED",
    }
