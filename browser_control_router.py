#!/usr/bin/env python3
"""Fail-closed R4 browser control route planning.

A plan describes capability routing only. It is not authorization for a live action.
"""
from __future__ import annotations

ROUTE_SCHEMA="macctl-browser-control-route/v1"
BROWSERS={"chrome","safari"}
CONTEXTS={"isolated","existing_session"}
READ_ACTIONS={"navigate","query","extract","analyze","wait","pages","history","reload","observe"}
INPUT_ACTIONS={"type","select","search","key","click"}
FILE_ACTIONS={"download","upload"}
ALL_ACTIONS=READ_ACTIONS|INPUT_ACTIONS|FILE_ACTIONS


def plan_control_route(*, browser: str, context: str, action: str, authenticated: bool=False, cdp_available: bool=True, ax_available: bool=True, vision_available: bool=True) -> dict:
    browser=str(browser or "").strip().lower()
    context=str(context or "").strip().lower()
    action=str(action or "").strip().lower().replace("-","_")
    if browser not in BROWSERS: raise ValueError("unsupported_browser")
    if context not in CONTEXTS: raise ValueError("unsupported_browser_context")
    if action not in ALL_ACTIONS: raise ValueError("unsupported_browser_action")

    routes=[]
    reason=None
    if browser=="chrome" and context=="isolated" and cdp_available:
        routes.append("CDP_DOM")
        if ax_available: routes.append("AX_SEMANTIC_FALLBACK")
        if vision_available: routes.append("SCREENCAPTUREKIT_VISION_FALLBACK")
        reason="isolated_chrome_cdp_primary"
    else:
        # Default-profile CDP is intentionally unavailable. Safari has no CDP route here.
        if ax_available: routes.append("AX_SEMANTIC")
        if vision_available: routes.append("SCREENCAPTUREKIT_VISION")
        reason="native_existing_session_or_non_cdp_browser"

    if not routes:
        return {"schema":ROUTE_SCHEMA,"status":"BLOCKED","reason":"no_qualified_browser_control_route","browser":browser,"context":context,"action":action,"routes":[]}

    if action in FILE_ACTIONS and routes[0] != "CDP_DOM":
        # Native file chooser/download paths need independent site-specific qualification.
        status="NOT_QUALIFIED"
        reason="native_file_transfer_requires_site_specific_qualification"
    else:
        status="PASS"

    return {
        "schema": ROUTE_SCHEMA,
        "status": status,
        "browser": browser,
        "context": context,
        "authenticated": bool(authenticated),
        "action": action,
        "routes": routes,
        "reason": reason,
        "default_profile_cdp": "FORBIDDEN",
        "credential_export": "FORBIDDEN",
        "cookie_export": "FORBIDDEN",
        "session_token_export": "FORBIDDEN",
        "requires_site_specific_policy": bool(context=="existing_session" or authenticated),
        "plan_is_authorization": False,
    }
