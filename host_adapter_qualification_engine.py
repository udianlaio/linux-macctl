#!/usr/bin/env python3
"""Fail-closed qualification of host-side attachment adapter observations.

The evaluator classifies what was actually observed on a ChatGPT/plugin host
surface. Inline rendering alone can qualify only Grade B. Grade A requires a
native attachment/file reference plus exact-byte host receipt and an exact
re-download whose SHA-256 matches the immutable Artifact Core payload.
"""
from __future__ import annotations

import re

from attachment_delivery_engine import GRADE_A, GRADE_B, GRADE_C, GRADE_D

QUALIFICATION_SCHEMA_VERSION = "macctl-host-adapter-qualification/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class HostAdapterQualificationError(ValueError):
    pass


def _text(value: str, field: str, maximum: int = 256) -> str:
    value = str(value or "").strip()
    if not value or len(value) > maximum or any(ord(ch) < 32 for ch in value):
        raise HostAdapterQualificationError(f"invalid_{field}")
    return value


def _sha(value: str | None, field: str, *, required: bool = False) -> str | None:
    if value in {None, ""}:
        if required:
            raise HostAdapterQualificationError(f"invalid_{field}")
        return None
    value = str(value).strip().lower()
    if not SHA256_RE.fullmatch(value):
        raise HostAdapterQualificationError(f"invalid_{field}")
    return value


def evaluate_host_adapter_observation(
    *,
    adapter: str,
    surface: str,
    expected_sha256: str,
    expected_size_bytes: int,
    inline_visible: bool = False,
    native_attachment: bool = False,
    stable_file_reference: bool = False,
    host_reported_sha256: str | None = None,
    host_reported_size_bytes: int | None = None,
    redownload_sha256: str | None = None,
    resource_link: bool = False,
    link_only: bool = False,
) -> dict:
    """Classify one observed host adapter outcome without upgrading evidence.

    `qualified` means the *observed grade* is qualified. It does not mean
    production Grade-A readiness. `production_grade_a_ready` is the only field
    that represents the ordinary-chat native attachment success contract.
    """
    adapter = _text(adapter, "adapter", 128)
    surface = _text(surface, "surface", 256)
    expected_sha256 = _sha(expected_sha256, "expected_sha256", required=True)
    try:
        expected_size_bytes = int(expected_size_bytes)
    except (TypeError, ValueError):
        raise HostAdapterQualificationError("invalid_expected_size_bytes")
    if expected_size_bytes < 0:
        raise HostAdapterQualificationError("invalid_expected_size_bytes")

    host_reported_sha256 = _sha(host_reported_sha256, "host_reported_sha256")
    redownload_sha256 = _sha(redownload_sha256, "redownload_sha256")
    if host_reported_size_bytes is not None:
        try:
            host_reported_size_bytes = int(host_reported_size_bytes)
        except (TypeError, ValueError):
            raise HostAdapterQualificationError("invalid_host_reported_size_bytes")
        if host_reported_size_bytes < 0:
            raise HostAdapterQualificationError("invalid_host_reported_size_bytes")

    receipt_exact = (
        host_reported_sha256 == expected_sha256
        and host_reported_size_bytes == expected_size_bytes
    )
    redownload_exact = redownload_sha256 == expected_sha256

    grade_a = bool(
        native_attachment
        and stable_file_reference
        and receipt_exact
        and redownload_exact
    )

    blockers = []
    if not native_attachment:
        blockers.append("native_attachment_not_observed")
    if not stable_file_reference:
        blockers.append("stable_file_reference_not_observed")
    if not receipt_exact:
        blockers.append("exact_host_receipt_not_observed")
    if not redownload_exact:
        blockers.append("exact_redownload_not_verified")

    if grade_a:
        grade = GRADE_A
        state = "GRADE_A_NATIVE_ATTACHMENT_QUALIFIED"
        reason = "native_file_reference_and_exact_roundtrip_verified"
        qualified = True
    elif inline_visible:
        grade = GRADE_B
        state = "GRADE_B_INLINE_ONLY_QUALIFIED"
        reason = "inline_render_observed_without_grade_a_file_contract"
        qualified = True
    elif resource_link and redownload_exact:
        grade = GRADE_C
        state = "GRADE_C_RESOLVABLE_RESOURCE_QUALIFIED"
        reason = "resolvable_exact_resource_without_native_attachment"
        qualified = True
    elif link_only:
        grade = GRADE_D
        state = "GRADE_D_LINK_ONLY_QUALIFIED"
        reason = "link_only_observed"
        qualified = True
    else:
        grade = None
        state = "NOT_QUALIFIED"
        reason = "insufficient_host_surface_evidence"
        qualified = False

    return {
        "schema": QUALIFICATION_SCHEMA_VERSION,
        "status": "PASS",
        "adapter": adapter,
        "surface": surface,
        "observed_grade": grade,
        "qualification_state": state,
        "qualified": qualified,
        "production_grade_a_ready": grade_a,
        "reason": reason,
        "evidence": {
            "inline_visible": bool(inline_visible),
            "native_attachment": bool(native_attachment),
            "stable_file_reference": bool(stable_file_reference),
            "resource_link": bool(resource_link),
            "link_only": bool(link_only),
            "exact_host_receipt": receipt_exact,
            "exact_redownload": redownload_exact,
            "expected_sha256": expected_sha256,
            "expected_size_bytes": expected_size_bytes,
        },
        "grade_a_blockers": [] if grade_a else blockers,
    }


def qualification_contract_capabilities() -> dict:
    return {
        "schema": "macctl-host-adapter-qualification-capabilities/v1",
        "grade_a_requires_native_attachment": True,
        "grade_a_requires_stable_file_reference": True,
        "grade_a_requires_exact_host_receipt": True,
        "grade_a_requires_exact_redownload_sha256": True,
        "inline_render_alone_max_grade": GRADE_B,
        "resource_link_without_native_attachment_max_grade": GRADE_C,
        "link_only_max_grade": GRADE_D,
        "fabricated_file_id_allowed": False,
    }
