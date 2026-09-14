#!/usr/bin/env python3
"""Deterministic conformance fixture for a future host-native file-return adapter.

This module does NOT qualify a live ChatGPT attachment.  It validates the
shape and byte-binding requirements that a future runtime adapter must satisfy
before its evidence is handed to the live host-adapter qualification path.
Synthetic or manually supplied fixture evidence can never set production
Grade-A readiness by itself.
"""
from __future__ import annotations

import hashlib
import json
import re

from .attachment_delivery_engine import GRADE_A

CONFORMANCE_SCHEMA_VERSION = "macctl-host-native-file-return-conformance/v1"
EVIDENCE_SCHEMA_VERSION = "macctl-host-native-file-return-evidence/v1"
REFERENCE_KIND = "NATIVE_CONVERSATION_ATTACHMENT"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class HostNativeConformanceError(ValueError):
    pass


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _text(value: object, field: str, maximum: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum or any(ord(ch) < 32 for ch in text):
        raise HostNativeConformanceError(f"invalid_{field}")
    return text


def _sha(value: object, field: str) -> str:
    text = str(value or "").strip().lower()
    if not SHA256_RE.fullmatch(text):
        raise HostNativeConformanceError(f"invalid_{field}")
    return text


def _size(value: object, field: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise HostNativeConformanceError(f"invalid_{field}")
    if result < 0:
        raise HostNativeConformanceError(f"invalid_{field}")
    return result


def _synthetic_hash(label: str, *, adapter: str, surface: str, sha256: str, size_bytes: int) -> str:
    return hashlib.sha256(
        _canonical({
            "label": label,
            "adapter": adapter,
            "surface": surface,
            "artifact_sha256": sha256,
            "artifact_size_bytes": size_bytes,
        })
    ).hexdigest()


def build_synthetic_conformance_fixture(
    *,
    adapter: str,
    surface: str,
    expected_sha256: str,
    expected_size_bytes: int,
    inline_visible: bool = True,
) -> dict:
    """Build deterministic *synthetic* evidence for contract testing only."""
    adapter = _text(adapter, "adapter", 128)
    surface = _text(surface, "surface", 256)
    expected_sha256 = _sha(expected_sha256, "expected_sha256")
    expected_size_bytes = _size(expected_size_bytes, "expected_size_bytes")
    reference_hash = _synthetic_hash(
        "synthetic-native-file-reference",
        adapter=adapter,
        surface=surface,
        sha256=expected_sha256,
        size_bytes=expected_size_bytes,
    )
    receipt_hash = _synthetic_hash(
        "synthetic-host-receipt",
        adapter=adapter,
        surface=surface,
        sha256=expected_sha256,
        size_bytes=expected_size_bytes,
    )
    return {
        "schema": EVIDENCE_SCHEMA_VERSION,
        "evidence_origin": "SYNTHETIC_FIXTURE",
        "adapter": adapter,
        "surface": surface,
        "artifact": {
            "sha256": expected_sha256,
            "size_bytes": expected_size_bytes,
        },
        "observation": {
            "native_attachment": True,
            "stable_file_reference": True,
            "reference_kind": REFERENCE_KIND,
            "reference_id_sha256": reference_hash,
            "host_receipt": {
                "receipt_id_sha256": receipt_hash,
                "sha256": expected_sha256,
                "size_bytes": expected_size_bytes,
            },
            "redownload": {
                "sha256": expected_sha256,
                "size_bytes": expected_size_bytes,
                "via_same_reference": True,
            },
            "inline_visible": bool(inline_visible),
        },
    }


def evaluate_conformance_evidence(
    evidence: dict,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
) -> dict:
    """Evaluate contract conformance without granting live Grade-A authority."""
    if not isinstance(evidence, dict) or evidence.get("schema") != EVIDENCE_SCHEMA_VERSION:
        raise HostNativeConformanceError("invalid_evidence_schema")
    expected_sha256 = _sha(expected_sha256, "expected_sha256")
    expected_size_bytes = _size(expected_size_bytes, "expected_size_bytes")
    adapter = _text(evidence.get("adapter"), "adapter", 128)
    surface = _text(evidence.get("surface"), "surface", 256)
    origin = _text(evidence.get("evidence_origin"), "evidence_origin", 64)

    artifact = evidence.get("artifact")
    observation = evidence.get("observation")
    if not isinstance(artifact, dict) or not isinstance(observation, dict):
        raise HostNativeConformanceError("invalid_evidence_shape")

    artifact_sha = _sha(artifact.get("sha256"), "artifact_sha256")
    artifact_size = _size(artifact.get("size_bytes"), "artifact_size_bytes")
    reference_hash = _sha(observation.get("reference_id_sha256"), "reference_id_sha256")
    reference_kind = _text(observation.get("reference_kind"), "reference_kind", 96)

    receipt = observation.get("host_receipt")
    redownload = observation.get("redownload")
    if not isinstance(receipt, dict) or not isinstance(redownload, dict):
        raise HostNativeConformanceError("invalid_roundtrip_evidence")
    receipt_id_hash = _sha(receipt.get("receipt_id_sha256"), "receipt_id_sha256")
    receipt_sha = _sha(receipt.get("sha256"), "host_receipt_sha256")
    receipt_size = _size(receipt.get("size_bytes"), "host_receipt_size_bytes")
    redownload_sha = _sha(redownload.get("sha256"), "redownload_sha256")
    redownload_size = _size(redownload.get("size_bytes"), "redownload_size_bytes")

    allowed_top = {"schema", "evidence_origin", "adapter", "surface", "artifact", "observation"}
    allowed_artifact = {"sha256", "size_bytes"}
    allowed_observation = {
        "native_attachment",
        "stable_file_reference",
        "reference_kind",
        "reference_id_sha256",
        "host_receipt",
        "redownload",
        "inline_visible",
    }
    allowed_receipt = {"receipt_id_sha256", "sha256", "size_bytes"}
    allowed_redownload = {"sha256", "size_bytes", "via_same_reference"}

    checks = {
        "top_level_fields_allowlisted": set(evidence) <= allowed_top,
        "artifact_fields_allowlisted": set(artifact) <= allowed_artifact,
        "observation_fields_allowlisted": set(observation) <= allowed_observation,
        "host_receipt_fields_allowlisted": set(receipt) <= allowed_receipt,
        "redownload_fields_allowlisted": set(redownload) <= allowed_redownload,
        "artifact_matches_expected": artifact_sha == expected_sha256 and artifact_size == expected_size_bytes,
        "native_attachment_observed": observation.get("native_attachment") is True,
        "stable_file_reference_observed": observation.get("stable_file_reference") is True,
        "reference_kind_native_conversation_attachment": reference_kind == REFERENCE_KIND,
        "reference_identifier_is_hashed": bool(reference_hash),
        "host_receipt_identifier_is_hashed": bool(receipt_id_hash),
        "host_receipt_exact": receipt_sha == expected_sha256 and receipt_size == expected_size_bytes,
        "redownload_exact": redownload_sha == expected_sha256 and redownload_size == expected_size_bytes,
        "redownload_bound_to_same_reference": redownload.get("via_same_reference") is True,
        "raw_reference_not_persisted": "reference_id" not in observation and "file_id" not in observation,
        "raw_receipt_not_persisted": "receipt_id" not in receipt,
    }
    failures = [name for name, passed in checks.items() if not passed]
    conformant = not failures
    state = "CONFORMANT_FOR_LIVE_RUNTIME_VERIFICATION" if conformant else "NONCONFORMANT"

    return {
        "schema": CONFORMANCE_SCHEMA_VERSION,
        "status": "PASS",
        "adapter": adapter,
        "surface": surface,
        "evidence_origin": origin,
        "conformance_state": state,
        "conformant": conformant,
        "candidate_grade": GRADE_A if conformant else None,
        "checks": checks,
        "failures": failures,
        "fixture_only": True,
        "live_runtime_evidence_verified": False,
        "production_grade_a_ready": False,
        "grade_a_evaluator_handoff": "BLOCKED_PENDING_LIVE_RUNTIME_VERIFIER",
        "reason": (
            "shape_and_exact_byte_bindings_satisfy_fixture_contract_but_live_runtime_provenance_is_not_verified"
            if conformant
            else "fixture_contract_requirements_not_met"
        ),
    }


def conformance_contract_capabilities() -> dict:
    return {
        "schema": "macctl-host-native-file-return-conformance-capabilities/v1",
        "evidence_schema": EVIDENCE_SCHEMA_VERSION,
        "reference_kind_required": REFERENCE_KIND,
        "requires_native_attachment": True,
        "requires_stable_file_reference": True,
        "requires_exact_host_receipt_sha256_and_size": True,
        "requires_exact_redownload_sha256_and_size": True,
        "requires_redownload_via_same_reference": True,
        "unknown_evidence_fields_fail_closed": True,
        "persists_raw_file_reference": False,
        "persists_raw_receipt_id": False,
        "synthetic_fixture_can_set_production_grade_a_ready": False,
        "manual_evidence_can_set_production_grade_a_ready": False,
        "live_runtime_verifier_required_for_grade_a_handoff": True,
    }
