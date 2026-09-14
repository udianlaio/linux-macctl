#!/usr/bin/env python3
"""Bounded semantic page understanding for R4 browser automation.

Consumes only the already-sanitized extraction contract. It never reads browser
profiles, cookies, credentials, raw HTML or arbitrary JavaScript.
"""
from __future__ import annotations

SEMANTIC_SCHEMA = "macctl-browser-page-analysis/v1"
PAGE_TYPES = {"login", "upload", "search", "form", "article", "listing", "document", "generic"}


def _rows(value):
    return [x for x in (value or []) if isinstance(x, dict)]


def analyze_extracted_page(extract: dict) -> dict:
    if not isinstance(extract, dict) or not extract.get("ok"):
        raise ValueError("invalid_extract_contract")
    interactive = _rows(extract.get("interactive"))
    links = _rows(extract.get("links"))
    forms = _rows(extract.get("forms"))
    text = str(extract.get("text") or "")

    inputs = [x for x in interactive if str(x.get("tag") or "").upper() in {"INPUT", "TEXTAREA", "SELECT"}]
    passwords = [x for x in inputs if str(x.get("type") or "").lower() == "password"]
    files = [x for x in inputs if str(x.get("type") or "").lower() == "file"]
    submits = [x for x in interactive if str(x.get("type") or "").lower() in {"submit", "image"} or (str(x.get("tag") or "").upper()=="BUTTON")]
    searches = []
    for x in inputs:
        kind = str(x.get("type") or "").lower()
        token = " ".join(str(x.get(k) or "").lower() for k in ("id", "name", "role", "autocomplete"))
        if kind == "search" or any(w in token for w in ("search", "query", " q ")) or token.strip() == "q":
            searches.append(x)

    if passwords:
        page_type = "login"
    elif files:
        page_type = "upload"
    elif searches:
        page_type = "search"
    elif forms and inputs:
        page_type = "form"
    elif len(text) >= 1200 and len(links) < 30:
        page_type = "article"
    elif len(links) >= 10:
        page_type = "listing"
    elif text.strip():
        page_type = "document"
    else:
        page_type = "generic"

    risks=[]
    if passwords: risks.append("AUTHENTICATION_SURFACE")
    if files: risks.append("FILE_UPLOAD_SURFACE")
    if forms: risks.append("FORM_SUBMISSION_SURFACE")
    if any(str(x.get("autocomplete") or "").lower().startswith("cc-") for x in inputs):
        risks.append("PAYMENT_FIELD_HINT")

    return {
        "schema": SEMANTIC_SCHEMA,
        "status": "PASS",
        "page_type": page_type,
        "title": str(extract.get("title") or "")[:512],
        "url": extract.get("url"),
        "counts": {
            "links": len(links), "forms": len(forms), "interactive": len(interactive),
            "inputs": len(inputs), "password_fields": len(passwords), "file_inputs": len(files),
            "search_inputs": len(searches), "button_like": len(submits), "text_chars": len(text),
        },
        "risk_hints": risks,
        "credential_values_returned": False,
        "raw_html_used": False,
        "raw_javascript_used": False,
    }
