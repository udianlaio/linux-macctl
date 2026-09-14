#!/usr/bin/env python3
"""Deterministic Accessibility semantic selector primitives for macctl.

This module is deliberately stdlib-only and independent of live macOS/SSH
state.  It contains the pure normalization, ranking and ambiguity decisions
used by the GUI layer so they can be exercised on Linux/GitHub runners.
"""
from __future__ import annotations

from difflib import SequenceMatcher
import unicodedata
from typing import Any, Iterator

SELECTOR_SCHEMA_VERSION = "macctl-selector/v1"


def normalize_text(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return " ".join(text.split())


def text_score(actual: Any, wanted: Any) -> tuple[int, str]:
    actual_n = normalize_text(actual)
    wanted_n = normalize_text(wanted)
    if not wanted_n or not actual_n:
        return -1, "none"
    if actual_n == wanted_n:
        return 100, "exact"
    if actual_n.startswith(wanted_n):
        return 90, "prefix"
    if wanted_n in actual_n:
        return 82, "contains"
    tokens = [t for t in wanted_n.split(" ") if t]
    if len(tokens) > 1 and all(t in actual_n for t in tokens):
        return 76, "tokens"
    ratio = SequenceMatcher(None, wanted_n, actual_n).ratio()
    if ratio >= 0.88:
        score = min(80, 70 + int(round((ratio - 0.88) / 0.12 * 10)))
        return score, "similar"
    return -1, "none"


def iter_nodes(nodes: Any) -> Iterator[dict[str, Any]]:
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        yield node
        yield from iter_nodes(node.get("children") or [])


def rank_ax_inventory(
    payload: dict[str, Any],
    selector: dict[str, Any],
    *,
    min_score: int = 70,
    min_margin: int = 10,
) -> dict[str, Any]:
    """Rank a bounded AX inventory without touching a live Accessibility tree."""
    min_score = int(min_score)
    min_margin = int(min_margin)
    if not 0 <= min_score <= 100 or not 0 <= min_margin <= 100:
        return {
            "schema": SELECTOR_SCHEMA_VERSION,
            "status": "FAIL",
            "reason": "invalid_rank_threshold",
            "min_score": min_score,
            "min_margin": min_margin,
            "matches": [],
        }

    actual_bundle = payload.get("bundle_id") or ""
    bundle = selector.get("bundle") or ""
    if bundle and actual_bundle != bundle:
        return {
            "schema": SELECTOR_SCHEMA_VERSION,
            "status": "FAIL",
            "reason": "frontmost_bundle_mismatch",
            "expected_bundle": bundle,
            "actual_bundle": actual_bundle,
            "matches": [],
        }

    role = selector.get("role") or ""
    subrole = selector.get("subrole") or ""
    title = selector.get("title") or ""
    description = selector.get("description") or ""
    value = selector.get("value") or ""
    if not any((role, subrole, title, description, value)):
        return {
            "schema": SELECTOR_SCHEMA_VERSION,
            "status": "FAIL",
            "reason": "missing_selector",
            "matches": [],
        }

    matches: list[dict[str, Any]] = []
    for node in iter_nodes(payload.get("windows") or []):
        if role and node.get("role", "") != role:
            continue
        if subrole and node.get("subrole", "") != subrole:
            continue

        field_scores: dict[str, dict[str, Any]] = {}
        rejected = False
        for field, wanted in (
            ("title", title),
            ("description", description),
            ("value", value),
        ):
            if not wanted:
                continue
            score, quality = text_score(node.get(field, ""), wanted)
            if score < 0:
                rejected = True
                break
            field_scores[field] = {"score": score, "quality": quality}
        if rejected:
            continue

        score_values = [x["score"] for x in field_scores.values()]
        score = int(round(sum(score_values) / len(score_values))) if score_values else 100
        if score < min_score:
            continue
        matches.append({
            "ref": node.get("ref", ""),
            "role": node.get("role", ""),
            "subrole": node.get("subrole", ""),
            "title": node.get("title", ""),
            "description": node.get("description", ""),
            "value": node.get("value", ""),
            "value_truncated": bool(node.get("value_truncated", False)),
            "focused": bool(node.get("focused", False)),
            "frame": node.get("frame") or {},
            "actions": node.get("actions") or [],
            "score": score,
            "field_scores": field_scores,
        })

    matches.sort(key=lambda m: (-m["score"], m.get("ref", "")))
    return {
        "schema": SELECTOR_SCHEMA_VERSION,
        "status": "PASS",
        "operation": "semantic_rank",
        "application": payload.get("application", ""),
        "bundle_id": actual_bundle,
        "pid": payload.get("pid"),
        "inventory_node_count": payload.get("node_count"),
        "inventory_max_nodes": payload.get("max_nodes"),
        "inventory_max_depth": payload.get("max_depth"),
        "inventory_truncated": payload.get("truncated", False),
        "match_mode": "ranked",
        "min_score": min_score,
        "min_margin": min_margin,
        "match_count": len(matches),
        "matches": matches[:20],
    }


def choose_ranked_match(
    ranked: dict[str, Any],
    *,
    min_margin: int,
    value_requested: bool = False,
) -> dict[str, Any]:
    """Apply the fail-closed winner contract for a ranked semantic press."""
    matches = list(ranked.get("matches") or [])
    if not matches:
        return {"status": "FAIL", "reason": "no_ranked_match", "exit_code": 1}

    top = matches[0]
    second = matches[1] if len(matches) > 1 else None
    margin = int(top.get("score", 0)) - int(second.get("score", 0)) if second else 100
    if second and margin < int(min_margin):
        return {
            "status": "FAIL",
            "reason": "ambiguous_ranked_selector",
            "exit_code": 65,
            "top_score": top.get("score"),
            "second_score": second.get("score"),
            "score_margin": margin,
        }
    if value_requested and top.get("value_truncated"):
        return {"status": "FAIL", "reason": "ranked_value_truncated", "exit_code": 65}

    return {
        "status": "PASS",
        "exit_code": 0,
        "top": top,
        "second": second,
        "score_margin": margin,
    }
