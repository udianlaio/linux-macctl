#!/usr/bin/env python3
import argparse
import base64
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

from architecture_security_contract import architecture_security_contract
from fleet_control_engine import (
    fleet_control_capabilities,
    fleet_doctor,
    fleet_inventory,
    fleet_operation_plan,
    fleet_resolve,
    fleet_status,
)
from workstation_control_engine import (
    evaluate_workstation_live_evidence,
    evaluate_workstation_observation,
    workstation_profile_contract,
)
from remote_linux_control_engine import (
    evaluate_remote_linux_live_evidence,
    load_remote_linux_registry,
    remote_linux_profile_contract,
    remote_linux_high_impact_reason,
    resolve_remote_linux_target,
    select_remote_linux_targets,
)
from remote_linux_ssh_manager import (
    bounded_batch_parallelism,
    classify_transport_failure,
    evaluate_ssh_transport_config,
    parse_ssh_g_output,
)
from artifact_engine import ArtifactError, ArtifactStore
from attachment_delivery_engine import delivery_probe, runtime_adapters_from_config
from browser_cdp_engine import (
    BrowserCdpError,
    CdpClient,
    dom_click_expression,
    dom_link_expression,
    dom_query_expression,
    dom_type_expression,
    evaluate as cdp_evaluate,
    free_tcp_port,
    http_json as cdp_http_json,
    page_snapshot_expression,
    parse_targets,
    rewrite_ws_url,
    select_page_target,
    wait_http_json as cdp_wait_http_json,
    wait_ready as cdp_wait_ready,
)
from browser_automation_engine import (
    BrowserAutomationError,
    dom_extract_expression,
    dom_file_input_probe_expression,
    dom_focus_expression,
    dom_select_expression,
    dom_search_probe_expression,
    dom_wait_probe_expression,
    dom_value_equals_expression,
    history_target,
    normalize_key_event,
)
from browser_semantic_engine import analyze_extracted_page
from browser_control_router import plan_control_route
from browser_session_engine import (
    BrowserSessionError,
    BrowserSessionStore,
    build_session_record,
    evaluate_session_action_policy,
    evaluate_url_policy,
    sanitize_url_for_output,
    pid_alive,
    pid_matches,
    validate_qualification_config,
    validate_session_id,
)
from messaging_engine import (
    MessagingError,
    MessagingStore,
    build_binding,
    build_draft,
    evaluate_action as evaluate_messaging_action,
    detect_provider_login_state as messaging_detect_login_state,
    exact_text_candidates as messaging_exact_text_candidates,
    load_message_file as messaging_load_message_file,
    public_binding as messaging_public_binding,
    select_header_candidate as messaging_select_header_candidate,
    token_region_evidence as messaging_token_region_evidence,
    visible_region_texts as messaging_visible_region_texts,
    DEFAULT_RATE_LIMIT_COUNT as MESSAGING_DEFAULT_RATE_LIMIT_COUNT,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS as MESSAGING_DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
)
from native_browser_engine import (
    NativeBrowserActionError,
    NativeBrowserActionStore,
    assess_native_action_recovery,
    build_native_action_record,
    complete_native_action_event,
    evaluate_native_address_bar,
    evaluate_native_action_effect,
    finish_native_action_record,
    materialize_interrupted_native_action,
    prepare_native_action_event,
    record_native_action_event,
    validate_native_action_plan,
)
from attachment_gateway import AttachmentGateway
from attachment_session_engine import AttachmentSessionStore, DeliverySessionError
from host_adapter_qualification_engine import (
    HostAdapterQualificationError,
    evaluate_host_adapter_observation,
    qualification_contract_capabilities,
)
from host_native_file_return_conformance import (
    HostNativeConformanceError,
    build_synthetic_conformance_fixture,
    conformance_contract_capabilities,
    evaluate_conformance_evidence,
)
from host_native_runtime_capability_watch import (
    HostNativeRuntimeWatchError,
    current_project_baseline,
    evaluate_runtime_capability_watch,
    runtime_watch_capabilities,
)
from delivery_route_engine import PathProbe, select_path
from execution_backend import (
    remote_command_string,
    remote_rsync_argv,
    remote_scp_argv,
    remote_ssh_argv,
)
from lan_probe_engine import LanProbeError, probe_registered_ssh_lan
from audit_engine import (
    append_audit_record,
    build_audit_record,
    new_correlation_id,
    read_audit_lines,
    resolve_correlation_id,
    summarize_postcondition,
    summarize_precondition,
    verify_audit_chain,
)
from doctor_engine import evaluate_doctor
from hardening_engine import evaluate_hardening, parse_probe_output
from runtime_engine import bounded_run
from selector_engine import choose_ranked_match, rank_ax_inventory
from policy_engine import (
    classify_operation,
    evaluate_break_glass,
    policy_status,
)
from transfer_engine import (
    TransferPlanError,
    effective_remote_file_path,
    local_stage_sibling,
    remote_stage_sibling,
    resolve_remote_user_path,
    sha256_file,
)
from transaction_engine import (
    COMPLETED,
    DISPATCHED,
    FAILED,
    INDETERMINATE,
    POSTCONDITION_FAILED,
    PRECONDITION_FAILED,
    PREPARED,
    TransactionStore,
    build_operation_id,
    parse_expected_sha256_spec,
    validate_remote_path,
    validate_request_id,
)
from target_registry_engine import TargetSpecError, resolve_runtime_target
from target_registry_store import TargetRegistryStoreError, load_registry

BASE_CFG = json.loads(Path("/etc/macctl/config.json").read_text(encoding="utf-8"))
REQUESTED_TARGET = str(os.environ.get("MACCTL_TARGET") or "").strip()
if REQUESTED_TARGET and REQUESTED_TARGET != str(BASE_CFG.get("target") or ""):
    registry_path = Path(BASE_CFG.get("target_registry_file", "/etc/macctl/targets.json"))
    if not registry_path.is_file():
        raise SystemExit("macctl target selection failed: explicit_target_registry_missing")
    try:
        registry_document = load_registry(registry_path, legacy_config=BASE_CFG)
        TARGET_SELECTION = resolve_runtime_target(
            BASE_CFG,
            requested_target=REQUESTED_TARGET,
            registry_document=registry_document,
        )
    except (TargetSpecError, TargetRegistryStoreError) as e:
        raise SystemExit(f"macctl target selection failed: {e}")
else:
    TARGET_SELECTION = resolve_runtime_target(BASE_CFG, requested_target=REQUESTED_TARGET or None)
CFG = TARGET_SELECTION["runtime_config"]
TARGET = CFG.get("target", "macmini")
SSH_CONFIG = CFG["ssh_config_file"]
DEFAULT_TIMEOUT = int(CFG.get("command_timeout_seconds", 60))
DEFAULT_CAP = int(CFG.get("max_output_bytes", 32768))
AUDIT_PATH = Path(CFG.get("audit_path", "/var/log/macctl/audit.jsonl"))
AUDIT_MAX_BYTES = int(CFG.get("audit_max_bytes", 5 * 1024 * 1024))
AUDIT_RETENTION_FILES = int(CFG.get("audit_retention_files", 5))
AUDIT_DIGEST_SEAL = bool(CFG.get("audit_digest_seal", True))
TRANSACTION_DIR = Path(CFG.get("transaction_dir", "/var/lib/macctl/transactions"))
TX_STORE = TransactionStore(TRANSACTION_DIR)
ARTIFACT_STORE = ArtifactStore(
    CFG.get("artifact_root", "/var/lib/macctl/artifacts"),
    import_roots=CFG.get("artifact_import_roots", ["/tmp"]),
    default_ttl_seconds=int(CFG.get("artifact_default_ttl_seconds", 86400)),
    max_artifact_bytes=int(CFG.get("artifact_max_bytes", 512 * 1024 * 1024)),
    default_principal=str(CFG.get("artifact_owner_principal", "local-owner")),
)
ATTACHMENT_ADAPTERS = runtime_adapters_from_config(CFG.get("attachment_host_adapters"))
ATTACHMENT_SESSION_STORE = AttachmentSessionStore(
    CFG.get("attachment_delivery_root", "/var/lib/macctl/attachment-deliveries"),
    artifact_store=ARTIFACT_STORE,
    adapters=ATTACHMENT_ADAPTERS,
)
BROWSER_SESSION_STORE = BrowserSessionStore(
    CFG.get("browser_session_root", "/var/lib/macctl/browser-sessions")
)
NATIVE_BROWSER_ACTION_STORE = NativeBrowserActionStore(
    CFG.get("native_browser_action_root", "/var/lib/macctl/native-browser-actions")
)
MESSAGING_STORE = MessagingStore(
    CFG.get("messaging_root", "/var/lib/macctl/messaging")
)
WORKSTATION_QUALIFICATION_ROOT = Path(
    CFG.get("workstation_qualification_root", "/var/lib/macctl/workstation-qualifications")
)
REMOTE_LINUX_REGISTRY_FILE = Path(
    CFG.get("remote_linux_registry_file", "/etc/macctl/remote-linux-targets.json")
)
REMOTE_LINUX_QUALIFICATION_ROOT = Path(
    CFG.get("remote_linux_qualification_root", "/var/lib/macctl/remote-linux-qualifications")
)

def audit_record(args, rc, duration_ms):
    try:
        rec = build_audit_record(
            args,
            rc,
            duration_ms,
            version=CFG.get("version", "unknown"),
            target=TARGET,
        )
        append_audit_record(
            AUDIT_PATH,
            rec,
            max_bytes=AUDIT_MAX_BYTES,
            retention_files=AUDIT_RETENTION_FILES,
            digest_seal=AUDIT_DIGEST_SEAL,
        )
    except Exception:
        pass

def emit(obj):
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))

def run(argv, timeout=DEFAULT_TIMEOUT, input_bytes=None, cap=DEFAULT_CAP):
    return bounded_run(argv, timeout=timeout, cap=cap, input_bytes=input_bytes)


def ssh_argv(remote=None, fresh=False, op=None):
    return remote_ssh_argv(
        ssh_config=SSH_CONFIG,
        target=TARGET,
        remote=remote,
        fresh=fresh,
        op=op,
    )

def remote_wrap(command, sudo=False, shell=None, remote_timeout=None):
    shell = shell or CFG.get("remote_shell", "/bin/zsh")
    return remote_command_string(
        command,
        sudo=sudo,
        shell=shell,
        remote_timeout=remote_timeout,
    )

def ssh_run(command, sudo=False, timeout=DEFAULT_TIMEOUT, fresh=False, input_bytes=None, cap=DEFAULT_CAP, shell=None):
    remote_timeout = max(1, int(timeout) - 2) if timeout and int(timeout) > 2 else None
    return run(
        ssh_argv(remote_wrap(command, sudo=sudo, shell=shell, remote_timeout=remote_timeout), fresh=fresh),
        timeout=timeout,
        input_bytes=input_bytes,
        cap=cap,
    )

def require_ok(result, operation):
    if result["rc"] != 0:
        emit({"status": "FAIL", "operation": operation, **result})
        raise SystemExit(result["rc"] or 1)
    return result

def key_fingerprint():
    r = run(["ssh-keygen", "-lf", CFG["identity_file"] + ".pub"], timeout=5, cap=4096)
    parts = r["output"].split()
    return parts[1] if len(parts) > 1 else "unknown"

def remember_policy(args, decision):
    args._policy_risk_class = decision.risk_class
    args._policy_allowed = bool(decision.allowed)
    args._policy_reason = decision.reason
    args._policy_source = decision.source
    args._policy_requires_confirmation = bool(decision.requires_confirmation)
    return decision

def enforce_typed_policy(args):
    decision = classify_operation(
        getattr(args, "cmd", None),
        getattr(args, "action", None),
        vars(args),
        CFG,
    )
    remember_policy(args, decision)
    if not decision.allowed:
        emit({
            "status": "BLOCKED",
            "schema": "macctl-policy/v2",
            "risk_class": decision.risk_class,
            "reason": decision.reason,
            "source": decision.source,
            "cmd": getattr(args, "cmd", None),
            "action": getattr(args, "action", None),
        })
        raise SystemExit(77)
    return decision

def enforce_command_policy(command, context="exec", args=None):
    decision = evaluate_break_glass(command, context, CFG)
    if args is not None:
        remember_policy(args, decision)
    if not decision.allowed:
        emit({
            "status": "BLOCKED",
            "schema": "macctl-policy/v2",
            "risk_class": decision.risk_class,
            "reason": decision.reason,
            "source": decision.source,
            "context": context,
        })
        raise SystemExit(77)
    return decision

def cmd_policy(args):
    if args.action == "status":
        emit(policy_status(CFG))
        return
    if args.action == "classify":
        attrs = {
            "label": args.label,
            "confirm": args.confirm,
            "sudo": args.sudo,
            "recursive": args.recursive,
            "delete": args.delete,
            "dry_run": args.dry_run,
            "scope": args.scope,
        }
        family = args.family
        operation_action = args.operation_action
        if args.command is not None and (family in {"exec", "script"} or (family == "job" and operation_action == "start")):
            decision = evaluate_break_glass(args.command, f"policy-classify:{family}", CFG)
        else:
            decision = classify_operation(family, operation_action, attrs, CFG)
        emit({
            "status": "PASS",
            "query": {"family": family, "action": operation_action},
            "decision": decision.as_dict(),
        })
        return
    raise SystemExit(64)

def _transaction_operation_attrs(args):
    attrs = dict(vars(args))
    attrs.pop("fn", None)
    for key in list(attrs):
        if key.startswith("_"):
            attrs.pop(key, None)
    # Preserve historical operation IDs for the legacy production target while
    # binding every isolated registry target into operation identity. This
    # prevents cross-target replay without invalidating old single-target journals.
    if TARGET_SELECTION.get("source") != "LEGACY_PRODUCTION":
        attrs["target_id"] = TARGET
    if getattr(args, "cmd", None) == "script":
        try:
            p = Path(args.file)
            if p.is_file():
                attrs["script_sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
        except Exception:
            pass
    return attrs

def _parse_expected_sha256(spec):
    return parse_expected_sha256_spec(spec)

def _remote_path_probe(path):
    path = validate_remote_path(path)
    q = shlex.quote(path)
    cmd = (
        f"p={q}; "
        'if [ -L "$p" ]; then printf "SYMLINK|"; /usr/bin/readlink "$p" 2>/dev/null || true; '
        'elif [ -f "$p" ]; then s=$(/usr/bin/stat -f %z -- "$p" 2>/dev/null || echo -); '
        'h=$(/usr/bin/shasum -a 256 -- "$p" 2>/dev/null | /usr/bin/awk \'{print $1}\'); printf "FILE|%s|%s" "$s" "$h"; '
        'elif [ -d "$p" ]; then printf "DIR"; '
        'elif [ -e "$p" ]; then printf "OTHER"; '
        'else printf "ABSENT"; fi'
    )
    r = ssh_run(cmd, timeout=12, cap=4096)
    if r["rc"] != 0:
        return {"status": "ERROR", "path": path, "rc": r["rc"]}
    out = r["output"].strip()
    if out.startswith("FILE|"):
        parts = out.split("|", 2)
        return {
            "status": "PRESENT",
            "path": path,
            "kind": "FILE",
            "size": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else (parts[1] if len(parts) > 1 else None),
            "sha256": parts[2].lower() if len(parts) > 2 else None,
        }
    if out.startswith("SYMLINK|"):
        return {"status": "PRESENT", "path": path, "kind": "SYMLINK", "target": out.split("|", 1)[1]}
    if out == "DIR":
        return {"status": "PRESENT", "path": path, "kind": "DIR"}
    if out == "OTHER":
        return {"status": "PRESENT", "path": path, "kind": "OTHER"}
    if out == "ABSENT":
        return {"status": "ABSENT", "path": path, "kind": "ABSENT"}
    return {"status": "ERROR", "path": path, "detail": out[:256]}

def _explicit_transaction_preconditions(args):
    checks = []
    ok = True
    for spec in getattr(args, "expect_sha256", []) or []:
        path, expected = _parse_expected_sha256(spec)
        observed = _remote_path_probe(path)
        passed = observed.get("kind") == "FILE" and observed.get("sha256") == expected
        checks.append({"type": "sha256", "path": path, "expected": expected, "observed": observed, "pass": passed})
        ok = ok and passed
    for path in getattr(args, "expect_present", []) or []:
        observed = _remote_path_probe(path)
        passed = observed.get("status") == "PRESENT"
        checks.append({"type": "present", "path": path, "observed": observed, "pass": passed})
        ok = ok and passed
    for path in getattr(args, "expect_absent", []) or []:
        observed = _remote_path_probe(path)
        passed = observed.get("status") == "ABSENT"
        checks.append({"type": "absent", "path": path, "observed": observed, "pass": passed})
        ok = ok and passed
    return {"status": "PASS" if ok else "FAIL", "checks": checks}

def _automatic_transaction_precondition(args):
    family = getattr(args, "cmd", None)
    action = getattr(args, "action", None)
    evidence = {"mode": "NONE"}
    if family == "file" and action in {"cp", "mv"}:
        evidence = {
            "mode": "FILE_SOURCE_DESTINATION",
            "source": _remote_path_probe(args.src),
            "destination_before": _remote_path_probe(args.dst),
        }
    elif family == "file" and action in {"mkdir", "rm"}:
        evidence = {"mode": "FILE_TARGET", "target_before": _remote_path_probe(args.path)}
    elif family == "clipboard" and action == "set" and getattr(args, "text", None) is not None:
        evidence = {
            "mode": "CLIPBOARD_SHA256",
            "expected_sha256": hashlib.sha256(args.text.encode("utf-8", "surrogatepass")).hexdigest(),
        }
    return evidence

def _verified_file_destination(args, precondition):
    source = (precondition.get("automatic") or {}).get("source") or {}
    before = (precondition.get("automatic") or {}).get("destination_before") or {}
    dst = args.dst
    if before.get("kind") == "DIR":
        dst = dst.rstrip("/") + "/" + Path(args.src.rstrip("/")).name
    observed = _remote_path_probe(dst)
    if source.get("kind") == "FILE":
        passed = observed.get("kind") == "FILE" and observed.get("sha256") == source.get("sha256")
        return {"status": "PASS" if passed else "FAIL", "mode": "SHA256", "path": dst, "expected_sha256": source.get("sha256"), "observed": observed}
    if source.get("kind") == "DIR":
        passed = observed.get("kind") == "DIR"
        return {"status": "PASS" if passed else "FAIL", "mode": "STRUCTURAL", "path": dst, "expected_kind": "DIR", "observed": observed}
    passed = observed.get("status") == "PRESENT"
    return {"status": "PASS" if passed else "FAIL", "mode": "STRUCTURAL", "path": dst, "observed": observed}

def _transaction_postcondition(args, precondition):
    family = getattr(args, "cmd", None)
    action = getattr(args, "action", None)
    if family == "file" and action == "mkdir":
        observed = _remote_path_probe(args.path)
        passed = observed.get("kind") == "DIR"
        return {"status": "PASS" if passed else "FAIL", "mode": "DIRECTORY_EXISTS", "observed": observed, "verified": True}
    if family == "file" and action == "rm":
        observed = _remote_path_probe(args.path)
        passed = observed.get("status") == "ABSENT"
        return {"status": "PASS" if passed else "FAIL", "mode": "PATH_ABSENT", "observed": observed, "verified": True}
    if family == "file" and action in {"cp", "mv"}:
        result = _verified_file_destination(args, precondition)
        if action == "mv":
            source_after = _remote_path_probe(args.src)
            result["source_after"] = source_after
            if source_after.get("status") != "ABSENT":
                result["status"] = "FAIL"
        result["verified"] = True
        return result
    if family == "clipboard" and action == "set" and getattr(args, "text", None) is not None:
        expected = hashlib.sha256(args.text.encode("utf-8", "surrogatepass")).hexdigest()
        r = helper_gui_run("clipboard-get", timeout=10, cap=max(8192, len(args.text.encode("utf-8", "surrogatepass")) * 6 + 4096))
        observed = None
        if r["rc"] == 0:
            try:
                payload = json.loads(r.get("output", ""))
                observed_text = str(payload.get("text", ""))
                observed = hashlib.sha256(observed_text.encode("utf-8", "surrogatepass")).hexdigest()
            except Exception:
                observed = None
        passed = r["rc"] == 0 and observed == expected
        return {"status": "PASS" if passed else "FAIL", "mode": "CLIPBOARD_SHA256", "expected_sha256": expected, "observed_sha256": observed, "verified": True}
    return {"status": "PASS", "mode": "RC_ONLY", "verified": False}

def _transaction_record_summary(record):
    if not record:
        return None
    return {
        "schema": record.get("schema"),
        "request_id": record.get("request_id"),
        "operation_id": record.get("operation_id"),
        "family": record.get("family"),
        "action": record.get("action"),
        "risk_class": record.get("risk_class"),
        "target": record.get("target"),
        "status": record.get("status"),
        "attempts": record.get("attempts"),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "result": record.get("result"),
        "precondition": record.get("precondition"),
        "postcondition": record.get("postcondition"),
    }

def _prepare_transaction(args, decision):
    attrs = _transaction_operation_attrs(args)
    operation_id = build_operation_id(getattr(args, "cmd", None), getattr(args, "action", None), decision.risk_class, attrs)
    args._operation_id = operation_id
    request_id = getattr(args, "request_id", None) or os.environ.get("MACCTL_REQUEST_ID")
    args._request_id = request_id
    has_expectations = bool((getattr(args, "expect_sha256", []) or []) or (getattr(args, "expect_present", []) or []) or (getattr(args, "expect_absent", []) or []))

    if decision.risk_class == "READ_ONLY":
        if has_expectations:
            emit({"status": "BLOCKED", "reason": "transaction_precondition_requires_mutating_operation"})
            raise SystemExit(64)
        return None
    if request_id is None:
        if has_expectations:
            emit({"status": "BLOCKED", "reason": "transaction_precondition_requires_request_id"})
            raise SystemExit(64)
        args._transaction_status = "LEGACY_NO_REQUEST_ID"
        return None

    try:
        request_id = validate_request_id(request_id)
    except ValueError as e:
        emit({"status": "BLOCKED", "reason": "invalid_request_id", "detail": str(e)})
        raise SystemExit(64)
    args._request_id = request_id

    try:
        begin = TX_STORE.begin(
            request_id,
            operation_id,
            family=getattr(args, "cmd", None),
            action=getattr(args, "action", None),
            risk_class=decision.risk_class,
            policy_reason=decision.reason,
            target=TARGET,
        )
    except Exception as e:
        emit({"status": "FAIL", "reason": "transaction_journal_error", "error": type(e).__name__})
        raise SystemExit(73)

    args._transaction_status = begin.record.get("status")
    if begin.disposition == "TARGET_CONFLICT":
        emit({"status": "BLOCKED", "reason": "request_id_target_conflict", "request_id": request_id, "operation_id": operation_id, "target": TARGET, "existing": _transaction_record_summary(begin.record)})
        raise SystemExit(78)
    if begin.disposition == "CONFLICT":
        emit({"status": "BLOCKED", "reason": "request_id_operation_conflict", "request_id": request_id, "operation_id": operation_id, "existing": _transaction_record_summary(begin.record)})
        raise SystemExit(78)
    if begin.disposition == "ALREADY_COMPLETED":
        args._audit_precondition_summary = summarize_precondition(begin.record.get("precondition") or {})
        drift = _transaction_postcondition(args, begin.record.get("precondition") or {})
        args._audit_postcondition_summary = summarize_postcondition(drift)
        if drift.get("verified") and drift.get("status") != "PASS":
            args._transaction_status = "COMPLETED_STATE_DRIFT"
            emit({"status": "INDETERMINATE", "reason": "completed_transaction_postcondition_drift", "transaction": _transaction_record_summary(begin.record), "current_postcondition": drift})
            raise SystemExit(75)
        args._transaction_status = COMPLETED
        emit({"status": "ALREADY_COMPLETED", "transaction": _transaction_record_summary(begin.record), "current_postcondition": drift if drift.get("verified") else None})
        raise SystemExit(0)
    if begin.disposition == "INDETERMINATE":
        args._transaction_status = INDETERMINATE
        emit({"status": "INDETERMINATE", "reason": "previous_dispatch_not_finalized", "transaction": _transaction_record_summary(begin.record)})
        raise SystemExit(75)
    if begin.disposition == "ALREADY_TERMINAL":
        args._transaction_status = begin.record.get("status")
        previous_rc = int(((begin.record.get("result") or {}).get("rc") or 75))
        emit({"status": "ALREADY_TERMINAL", "reason": "request_id_terminal_result_will_not_be_reexecuted", "transaction": _transaction_record_summary(begin.record)})
        raise SystemExit(previous_rc)

    try:
        explicit = _explicit_transaction_preconditions(args)
    except ValueError as e:
        explicit = {"status": "FAIL", "checks": [], "error": str(e)}
    automatic = _automatic_transaction_precondition(args)
    evidence = {"status": explicit.get("status"), "explicit": explicit, "automatic": automatic}
    args._audit_precondition_summary = summarize_precondition(evidence)
    if explicit.get("status") != "PASS":
        record = TX_STORE.mark_precondition_failed(request_id, operation_id, evidence=evidence)
        args._transaction_status = PRECONDITION_FAILED
        emit({"status": "PRECONDITION_FAILED", "transaction": _transaction_record_summary(record)})
        raise SystemExit(76)
    TX_STORE.set_precondition(request_id, operation_id, evidence)
    TX_STORE.mark_dispatched(request_id, operation_id)
    args._transaction_status = DISPATCHED
    return {"request_id": request_id, "operation_id": operation_id, "precondition": evidence}

def _finalize_transaction(args, tx, rc):
    if tx is None:
        return
    request_id = tx["request_id"]
    operation_id = tx["operation_id"]
    family = getattr(args, "cmd", None)
    action = getattr(args, "action", None)

    if family == "power" and action in {"restart", "shutdown"}:
        record = TX_STORE.mark_indeterminate(request_id, operation_id, reason="asynchronous_power_transition_requires_later_recovery_evidence")
        args._transaction_status = INDETERMINATE
        if int(rc) == 0:
            emit({"status": "INDETERMINATE", "reason": "power_transition_dispatched_requires_recovery_validation", "transaction": _transaction_record_summary(record)})
            raise SystemExit(75)
        return

    if int(rc) != 0:
        record = TX_STORE.mark_failed(request_id, operation_id, rc=int(rc))
        args._transaction_status = FAILED
        return record

    postcondition = _transaction_postcondition(args, tx.get("precondition") or {})
    args._audit_postcondition_summary = summarize_postcondition(postcondition)
    if postcondition.get("status") != "PASS":
        record = TX_STORE.mark_postcondition_failed(request_id, operation_id, evidence=postcondition)
        args._transaction_status = POSTCONDITION_FAILED
        emit({"status": "POSTCONDITION_FAILED", "transaction": _transaction_record_summary(record)})
        raise SystemExit(74)
    record = TX_STORE.mark_completed(request_id, operation_id, postcondition=postcondition, rc=0)
    args._transaction_status = COMPLETED
    return record

def cmd_transaction(args):
    if args.action == "status":
        try:
            record = TX_STORE.get(args.request_id_value)
        except ValueError as e:
            emit({"status": "FAIL", "reason": "invalid_request_id", "detail": str(e)})
            raise SystemExit(64)
        if record is None:
            emit({"status": "NOT_FOUND", "request_id": args.request_id_value})
            raise SystemExit(66)
        emit({"status": "PASS", "transaction": _transaction_record_summary(record)})
        return
    if args.action == "list":
        records = TX_STORE.list(args.limit)
        emit({"status": "PASS", "count": len(records), "transactions": [_transaction_record_summary(r) for r in records]})
        return
    raise SystemExit(64)

def _artifact_fail(error):
    reason = getattr(error, "reason", "artifact_error")
    detail = getattr(error, "detail", None)
    emit({"status": "FAIL", "schema": "macctl-artifact-error/v1", "reason": reason, "detail": detail})
    raise SystemExit(77 if reason in {"artifact_delivery_denied"} else 66)


def _delivery_session_fail(error):
    reason = getattr(error, "reason", "delivery_session_error")
    detail = getattr(error, "detail", None)
    emit({"status": "FAIL", "schema": "macctl-attachment-session-error/v1", "reason": reason, "detail": detail})
    raise SystemExit(66)


def cmd_capabilities(args):
    artifact = ARTIFACT_STORE.capabilities()
    delivery = delivery_probe(ATTACHMENT_ADAPTERS)
    delivery_sessions = ATTACHMENT_SESSION_STORE.capabilities()
    emit({
        "status": "PASS",
        "schema": "macctl-capabilities/v1",
        "version": CFG.get("version", "unknown"),
        "architecture_security_contract": architecture_security_contract(),
        "fleet_control_plane": fleet_control_capabilities(),
        "production_workstation_contract": workstation_profile_contract(),
        "remote_linux_contract": remote_linux_profile_contract(),
        "artifact": artifact,
        "attachment_delivery_control_plane": delivery_sessions,
        "host_adapter_qualification_contract": qualification_contract_capabilities(),
        "host_native_file_return_conformance": conformance_contract_capabilities(),
        "host_native_runtime_capability_watch": runtime_watch_capabilities(),
        "ordinary_chat_delivery": delivery,
        "execution_backend": {
            "schema": "macctl-execution-backend/v2",
            "runtime_mode": "REMOTE_SSH",
            "remote_ssh": "LIVE_QUALIFIED",
            "remote_transport_primitives": ["command", "scp", "rsync"],
            "transport_safety": {
                "command_timeout_descendants": "LIVE_QUALIFIED",
                "connect_timeout_seconds": 5,
                "server_alive_interval_seconds": 15,
                "server_alive_count_max": 2,
                "scp_regular_file_finalization": "STAGED_SHA256_ATOMIC_RENAME_LIVE_QUALIFIED",
                "scp_recursive_tree_atomicity": "NOT_CLAIMED",
                "rsync_partial_policy": "HIDDEN_PARTIAL_DIR_PER_FILE_FINAL_ISOLATION_LIVE_QUALIFIED",
                "rsync_tree_atomicity": "NOT_CLAIMED",
            },
            "local_macos": "PAUSED_BY_PROJECT_SCOPE",
            "auto_selection": "PAUSED_BY_PROJECT_SCOPE",
        },
        "attachment_gateway": {
            "implemented": True,
            "bounded_chunk_streaming": True,
            "principal_acl": True,
            "short_lived_grants": True,
            "adaptive_route_selector": True,
            "lan_active_probe_backend": "REGISTERED_SSH_ACTIVE_PROBE",
            "lan_direct_enabled": bool(CFG.get("artifact_lan_direct_enabled", False)),
            "lan_direct_readiness": "RUNTIME_PROBE_REQUIRED",
            "operator_pc_lan_download": "LIVE_QUALIFIED_HUMAN_CONFIRMED_SHA256",
        },
        "browser_engine": {
            "schema": "macctl-browser-automation/v1",
            "phase": "V0.6_R4_BROWSER_PRODUCTION_AUTOMATION_QUALIFIED",
            "inherited_r2_baseline": "CLOSED_PASS_WITH_SITE_SPECIFIC_BOUNDARIES",
            "isolated_chrome_cdp": "LIVE_QUALIFIED_SYNTHETIC_AND_PUBLIC_READ_ONLY",
            "cdp_transport": "MAC_LOOPBACK_OVER_PINNED_SSH_FORWARD",
            "controlled_session_lifecycle": "LIVE_QUALIFIED",
            "url_allowlist_redirect_boundary": "LIVE_QUALIFIED",
            "url_query_fragment_redaction": "DETERMINISTIC_AND_LIVE_QUALIFIED",
            "dom_sensitive_value_redaction": "DETERMINISTIC_AND_LIVE_QUALIFIED",
            "dom_query_unique": "FAIL_CLOSED_EXACTLY_ONE",
            "page_extract": "LIVE_QUALIFIED_SYNTHETIC_AND_PUBLIC",
            "page_semantic_analysis": "LIVE_QUALIFIED_PUBLIC_EXAMPLE_DOT_COM",
            "wait_conditions": "LIVE_QUALIFIED_SYNTHETIC_AND_PUBLIC",
            "search_get_form": "LIVE_QUALIFIED_SYNTHETIC_QUERY_REDACTED_POSTCONDITION",
            "unicode_type": "LIVE_QUALIFIED_SYNTHETIC",
            "select_control": "LIVE_QUALIFIED_SYNTHETIC",
            "bounded_key_control": "LIVE_QUALIFIED_SYNTHETIC",
            "click_postcondition": "LIVE_QUALIFIED_SYNTHETIC",
            "multi_tab_pages_activate_create_close": "LIVE_QUALIFIED_SYNTHETIC",
            "history_back_forward_contract": "LIVE_QUALIFIED_SYNTHETIC_BACK",
            "reload": "LIVE_QUALIFIED_SYNTHETIC",
            "upload_from_artifact_core": "LIVE_QUALIFIED_SYNTHETIC_FILE_INPUT_ONLY_NO_SUBMIT",
            "download_to_artifact_core": "LIVE_QUALIFIED_SYNTHETIC_EXACT_SHA256",
            "screen_ocr_hybrid": "LIVE_QUALIFIED_SCREEN_CAPTURE_KIT_APPLE_VISION",
            "control_router": "DETERMINISTIC_QUALIFIED_CDP_DOM_THEN_AX_VISION_FALLBACK",
            "native_chrome_existing_session": "LIVE_QUALIFIED_SITE_SPECIFIC_GHOST_FROM_R2",
            "native_safari_read_only": "LIVE_QUALIFIED_EXAMPLE_DOT_COM_AX_ADDRESS_BAR_PLUS_VISION",
            "native_safari_stateful_mutation": "SITE_SPECIFIC_NOT_GLOBALLY_QUALIFIED",
            "native_file_transfer_non_cdp": "NOT_QUALIFIED_SITE_SPECIFIC_REQUIRED",
            "native_profile_control_path": "VISIBLE_GUI_ONLY_NO_DEFAULT_PROFILE_CDP",
            "production_exact_host_path_scope": "ENFORCED",
            "production_authenticated_session": "SITE_SPECIFIC_EXPLICIT_OPERATOR_SCOPE",
            "native_write_ahead_recovery": "LIVE_QUALIFIED_GHOST_FROM_R2",
            "native_exact_host_single_flight_and_action_lock": "LIVE_QUALIFIED_FROM_R2",
            "default_profile_cdp": "FORBIDDEN",
            "raw_runtime_evaluate_cli": "NOT_EXPOSED",
            "credential_export": "FORBIDDEN",
            "cookie_export": "FORBIDDEN",
            "session_token_export": "FORBIDDEN",
            "production_publish_send_payment_account_security_delete_existing": "SEPARATELY_GATED_OR_HARD_FORBIDDEN_BY_CURRENT_CONTRACT",
            "arbitrary_authenticated_site_generalization": "NOT_CLAIMED",
            "network_subresource_egress_containment": "NOT_CLAIMED",
        },
        "delegated_messaging": {
            "schema": "macctl-delegated-messaging/v1",
            "phase": "V0.6_R5_WECHAT_CLOSED_PASS_FEISHU_PENDING",
            "providers": ["wechat", "feishu"],
            "wechat_bundle_id": "com.tencent.xinWeChat",
            "contact_allowlist": "IMPLEMENTED_RUNTIME_0600_BINDING_STORE",
            "read_draft_send_separation": "IMPLEMENTED_FAIL_CLOSED",
            "send_binding_confirmation": "REQUIRED",
            "send_action_confirmation": "REQUIRED",
            "exact_selected_contact_revalidation": "LIVE_QUALIFIED_WECHAT_AX_WINDOW_PLUS_VISION_HEADER",
            "visible_history_read": "LIVE_QUALIFIED_SCREEN_CAPTURE_KIT_APPLE_VISION_VISIBLE_ONLY_NO_DB_ACCESS",
            "duplicate_suppression": "LIVE_QUALIFIED_MESSAGE_SHA256_PER_BINDING",
            "rate_limit": "DETERMINISTIC_QUALIFIED_DEFAULT_5_PER_60_SECONDS",
            "message_body_persistence": "FORBIDDEN_HASH_AND_LENGTH_ONLY",
            "secure_text_transport": "LIVE_QUALIFIED_HELPER_PRIVATE_TEMP_FILE_PASTE_CLIPBOARD_RESTORE",
            "helper_secure_text_file": "LIVE_DEPLOYED_STABLE_SIGNING_TCC_RETAINED",
            "draft_region_postcondition": "LIVE_QUALIFIED_COMPOSER_ONLY",
            "send_region_postcondition": "LIVE_QUALIFIED_HISTORY_PRESENT_COMPOSER_EMPTY",
            "indeterminate_send_recovery": "LIVE_QUALIFIED_VISUAL_HISTORY_RECONCILIATION_NO_RECLICK",
            "wechat_live_contact_binding": "LIVE_QUALIFIED_RUNTIME_ONLY_CURRENT_TREE_REDACTED",
            "wechat_live_send": "CLOSED_PASS_SINGLE_SEND_VISUAL_POSTCONDITION_AND_DUPLICATE_BLOCK",
            "wechat_auto_send_without_per_send_confirmation": "NOT_QUALIFIED",
            "feishu_live_adapter": "NOT_YET_QUALIFIED",
        },
        "note": "V0.6-R5 WeChat subphase is CLOSED/PASS for one explicitly bound test conversation: visible-history read, secure draft, exactly-one controlled send, visual postcondition, recovery and duplicate suppression are live-qualified. A draft auto-submit defect in the first Unicode-CGEvent implementation was detected live, reconciled without re-click, and fixed by clipboard-preserving paste plus COMPOSER/HISTORY region postconditions. Feishu remains NOT_YET_QUALIFIED, so combined R5 is not globally CLOSED/PASS.",
    })


def _fleet_registry_snapshot():
    registry_path = Path(BASE_CFG.get("target_registry_file", "/etc/macctl/targets.json"))
    if not registry_path.exists():
        return None, False
    return load_registry(registry_path, legacy_config=BASE_CFG), True


def cmd_fleet(args):
    try:
        registry_document, registry_present = _fleet_registry_snapshot()
        if args.action == "list":
            emit(fleet_inventory(
                BASE_CFG,
                registry_document,
                registry_present=registry_present,
            ))
            return
        if args.action == "status":
            emit(fleet_status(
                BASE_CFG,
                registry_document,
                registry_present=registry_present,
            ))
            return
        if args.action == "doctor":
            emit(fleet_doctor(
                BASE_CFG,
                registry_document,
                registry_present=registry_present,
            ))
            return
        if args.action == "resolve":
            emit(fleet_resolve(BASE_CFG, args.target, registry_document))
            return
        if args.action == "plan":
            emit(fleet_operation_plan(BASE_CFG, args.target, registry_document))
            return
    except (TargetSpecError, TargetRegistryStoreError) as e:
        emit({
            "status": "FAIL",
            "schema": "macctl-fleet-error/v1",
            "reason": str(e),
            "network_contact_performed": False,
            "stateful_mutation_performed": False,
        })
        raise SystemExit(66)
    raise SystemExit(64)


def cmd_artifact(args):
    try:
        if args.action == "import":
            manifest = ARTIFACT_STORE.create_snapshot(
                args.source,
                classification=args.classification,
                filename=args.filename,
                ttl_seconds=args.ttl_seconds,
                producer="artifact.import",
            )
            emit({"status": "PASS", "artifact": manifest})
            return
        if args.action == "list":
            emit({"status": "PASS", "schema": "macctl-artifact-list/v1", "artifacts": ARTIFACT_STORE.list(limit=args.limit)})
            return
        if args.action == "inspect":
            emit({"status": "PASS", "artifact": ARTIFACT_STORE.inspect(args.artifact_id)})
            return
        if args.action == "verify":
            result = ARTIFACT_STORE.verify(args.artifact_id)
            emit(result)
            if result.get("status") != "PASS":
                raise SystemExit(1)
            return
        if args.action == "revoke":
            emit({"status": "PASS", "artifact": ARTIFACT_STORE.revoke(args.artifact_id)})
            return
        if args.action == "gc":
            emit(ARTIFACT_STORE.gc(include_revoked=not args.keep_revoked))
            return
        if args.action == "delivery-probe":
            if args.artifact_id:
                ARTIFACT_STORE.authorize_delivery(args.artifact_id, purpose="download")
            emit(delivery_probe(ATTACHMENT_ADAPTERS))
            return
        if args.action == "host-adapter-evaluate":
            manifest = ARTIFACT_STORE.authorize_delivery(args.artifact_id, purpose="download")
            content = manifest["content"]
            emit(evaluate_host_adapter_observation(
                adapter=args.adapter,
                surface=args.surface,
                expected_sha256=content["sha256"],
                expected_size_bytes=content["size_bytes"],
                inline_visible=args.inline_visible,
                native_attachment=args.native_attachment,
                stable_file_reference=args.stable_file_reference,
                host_reported_sha256=args.host_reported_sha256,
                host_reported_size_bytes=args.host_reported_size_bytes,
                redownload_sha256=args.redownload_sha256,
                resource_link=args.resource_link,
                link_only=args.link_only,
            ))
            return
        if args.action == "host-native-conformance-contract":
            emit({"status": "PASS", "contract": conformance_contract_capabilities()})
            return
        if args.action == "host-native-conformance-fixture":
            manifest = ARTIFACT_STORE.authorize_delivery(args.artifact_id, purpose="download")
            content = manifest["content"]
            evidence = build_synthetic_conformance_fixture(
                adapter=args.adapter,
                surface=args.surface,
                expected_sha256=content["sha256"],
                expected_size_bytes=content["size_bytes"],
                inline_visible=args.inline_visible,
            )
            result = evaluate_conformance_evidence(
                evidence,
                expected_sha256=content["sha256"],
                expected_size_bytes=content["size_bytes"],
            )
            emit({
                "status": "PASS",
                "schema": "macctl-host-native-file-return-fixture/v1",
                "artifact": {
                    "artifact_id": manifest["artifact_id"],
                    "sha256": content["sha256"],
                    "size_bytes": content["size_bytes"],
                },
                "synthetic_evidence": evidence,
                "conformance": result,
                "production_grade_a_ready": False,
                "note": "synthetic_fixture_only_live_runtime_verifier_required",
            })
            return
        if args.action == "host-native-runtime-watch-baseline":
            emit({"status": "PASS", "baseline": current_project_baseline(), "contract": runtime_watch_capabilities()})
            return
        if args.action == "host-native-runtime-watch-evaluate":
            try:
                payload = json.loads(Path(args.observations_file).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as e:
                emit({"status":"FAIL","schema":"macctl-host-native-runtime-capability-watch-error/v1","reason":str(e)})
                raise SystemExit(64)
            observations = payload.get("surfaces") if isinstance(payload, dict) else payload
            emit(evaluate_runtime_capability_watch(observations))
            return
        if args.action == "grant":
            emit(ARTIFACT_STORE.issue_grant(
                args.artifact_id,
                scope=args.scope,
                ttl_seconds=args.ttl_seconds,
                principal=ARTIFACT_STORE.default_principal,
            ))
            return
        if args.action == "revoke-grants":
            emit(ARTIFACT_STORE.revoke_grants(args.artifact_id, principal=ARTIFACT_STORE.default_principal))
            return
        if args.action == "delivery-plan":
            gateway = AttachmentGateway(ARTIFACT_STORE)
            emit(gateway.prepare(
                args.artifact_id,
                principal=ARTIFACT_STORE.default_principal,
                original_required=args.original_required,
                presentation=args.presentation,
                allow_debug_fallback=args.allow_debug_fallback,
                adapters=ATTACHMENT_ADAPTERS,
            ))
            return
        if args.action == "delivery-create":
            record = ATTACHMENT_SESSION_STORE.create(
                args.artifact_id,
                principal=ARTIFACT_STORE.default_principal,
                idempotency_key=args.idempotency_key,
                original_required=args.original_required,
                presentation=args.presentation,
                allow_debug_fallback=args.allow_debug_fallback,
            )
            emit({"status": "PASS", "delivery_session": record})
            return
        if args.action == "delivery-status":
            emit({"status": "PASS", "delivery_session": ATTACHMENT_SESSION_STORE.inspect(args.delivery_session_id)})
            return
        if args.action == "delivery-list":
            rows = ATTACHMENT_SESSION_STORE.list(limit=args.limit)
            emit({"status": "PASS", "schema": "macctl-attachment-session-list/v1", "count": len(rows), "delivery_sessions": rows})
            return
        if args.action == "delivery-host-accept":
            record = ATTACHMENT_SESSION_STORE.record_host_acceptance(
                args.delivery_session_id,
                adapter=args.adapter,
                receipt_id=args.receipt_id,
                sha256=args.sha256,
                size_bytes=args.size_bytes,
            )
            emit({"status": "PASS", "delivery_session": record})
            return
        if args.action == "delivery-render-qualify":
            record = ATTACHMENT_SESSION_STORE.qualify_render(
                args.delivery_session_id,
                surface=args.surface,
                native_attachment=args.native_attachment,
                exact_original=args.exact_original,
                downloaded_sha256=args.downloaded_sha256,
                inline_visible=args.inline_visible,
            )
            emit({"status": "PASS", "delivery_session": record})
            return
        if args.action == "delivery-user-confirm":
            record = ATTACHMENT_SESSION_STORE.confirm_user_visible(
                args.delivery_session_id,
                confirmed_by=args.confirmed_by,
            )
            emit({"status": "PASS", "delivery_session": record})
            return
        if args.action == "delivery-fail":
            record = ATTACHMENT_SESSION_STORE.fail(args.delivery_session_id, reason=args.reason)
            emit({"status": "PASS", "delivery_session": record})
            return
        if args.action in {"relay-stage", "relay-status", "relay-cleanup"}:
            relay_script = Path(__file__).resolve().parent / "scripts" / "attachment-relay.py"
            script_action = {"relay-stage": "stage", "relay-status": "inspect", "relay-cleanup": "cleanup"}[args.action]
            relay_value = args.artifact_id if args.action == "relay-stage" else args.relay_id
            result = run(
                [sys.executable, str(relay_script), script_action, relay_value],
                timeout=240 if args.action == "relay-stage" else 90,
                cap=65536,
            )
            raw = str(result.get("output") or "").strip()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                emit({"status": "FAIL", "schema": "macctl-chatgpt-attachment-relay-error/v1", "reason": "relay_invalid_json"})
                raise SystemExit(75)
            emit(payload)
            if result.get("rc") != 0 or payload.get("status") != "PASS":
                raise SystemExit(75)
            return
        if args.action == "lan-probe":
            try:
                result = probe_registered_ssh_lan(
                    host=str(CFG["host"]),
                    port=int(CFG["port"]),
                    target=TARGET,
                    ssh_config=SSH_CONFIG,
                    sample_bytes=int(args.sample_mib) * 1024 * 1024,
                    tcp_attempts=int(args.tcp_attempts),
                    timeout=float(args.timeout),
                    policy_allowed=bool(CFG.get("artifact_lan_direct_enabled", False)),
                )
            except LanProbeError as e:
                emit({"schema":"macctl-lan-probe/v1","status":"FAIL","reason":e.reason,"detail":e.detail})
                raise SystemExit(75)
            emit(result)
            if result.get("status") != "PASS":
                raise SystemExit(75)
            return
        if args.action == "route-auto":
            manifest = ARTIFACT_STORE.authorize_delivery(args.artifact_id, purpose="download")
            probes = []
            try:
                lan = probe_registered_ssh_lan(
                    host=str(CFG["host"]),
                    port=int(CFG["port"]),
                    target=TARGET,
                    ssh_config=SSH_CONFIG,
                    sample_bytes=int(args.sample_mib) * 1024 * 1024,
                    tcp_attempts=int(args.tcp_attempts),
                    timeout=float(args.timeout),
                    policy_allowed=bool(CFG.get("artifact_lan_direct_enabled", False)),
                )
                probes.append(PathProbe(**lan["path_probe"]))
            except LanProbeError as e:
                lan = {"schema":"macctl-lan-probe/v1","status":"FAIL","reason":e.reason,"detail":e.detail}
                probes.append(PathProbe(
                    name=f"lan:{TARGET}", kind="LAN_DIRECT", ready=False,
                    authenticated=False, policy_allowed=False, reason=e.reason,
                ))
            for raw in args.probe:
                try:
                    item = json.loads(raw)
                    probes.append(PathProbe(**item))
                except Exception as e:
                    emit({"status":"FAIL","reason":"invalid_route_probe","detail":type(e).__name__})
                    raise SystemExit(64)
            route = select_path(probes, size_bytes=int(manifest["content"]["size_bytes"]))
            emit({"schema":"macctl-route-auto/v1","status":route["status"],"lan_probe":lan,"route":route})
            if route.get("status") != "READY":
                raise SystemExit(75)
            return
        if args.action == "route-plan":
            manifest = ARTIFACT_STORE.authorize_delivery(args.artifact_id, purpose="download")
            probes = []
            for raw in args.probe:
                try:
                    item = json.loads(raw)
                    probes.append(PathProbe(**item))
                except Exception as e:
                    emit({"status":"FAIL","reason":"invalid_route_probe","detail":type(e).__name__})
                    raise SystemExit(64)
            emit(select_path(probes, size_bytes=int(manifest["content"]["size_bytes"])))
            return
        raise SystemExit(64)
    except ArtifactError as e:
        _artifact_fail(e)
    except DeliverySessionError as e:
        _delivery_session_fail(e)
    except HostAdapterQualificationError as e:
        emit({"status":"FAIL","schema":"macctl-host-adapter-qualification-error/v1","reason":str(e)})
        raise SystemExit(64)
    except HostNativeConformanceError as e:
        emit({"status":"FAIL","schema":"macctl-host-native-file-return-conformance-error/v1","reason":str(e)})
        raise SystemExit(64)
    except HostNativeRuntimeWatchError as e:
        emit({"status":"FAIL","schema":"macctl-host-native-runtime-capability-watch-error/v1","reason":str(e)})
        raise SystemExit(64)


def cmd_version(args):
    emit({
        "macctl": CFG.get("version", "unknown"),
        "transport": "openssh",
        "auth": "publickey",
        "target": TARGET,
        "host": CFG["host"],
        "port": CFG["port"],
        "privilege": "sudo-nopasswd",
    })

def cmd_ping(args):
    t0 = time.perf_counter()
    try:
        with socket.create_connection(
            (CFG["host"], int(CFG["port"])),
            float(CFG.get("connect_timeout_seconds", 5)),
        ):
            pass
        emit({
            "status": "PASS",
            "tcp": True,
            "host": CFG["host"],
            "port": CFG["port"],
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
        })
    except Exception as e:
        emit({"status": "FAIL", "tcp": False, "error": type(e).__name__})
        raise SystemExit(1)

def cmd_auth(args):
    r = ssh_run("printf __MACCTL_AUTH_OK__", fresh=args.fresh, timeout=10)
    ok = r["rc"] == 0 and r["output"] == "__MACCTL_AUTH_OK__"
    emit({
        "status": "PASS" if ok else "FAIL",
        "auth": "publickey",
        "fresh": args.fresh,
        "fingerprint": key_fingerprint(),
        "duration_ms": r["duration_ms"],
        "detail": None if ok else r["output"],
    })
    if not ok:
        raise SystemExit(r["rc"] or 1)

def cmd_status(args):
    fields = [
        "u=$(whoami)",
        "h=$(hostname)",
        "v=$(sw_vers -productVersion)",
        "b=$(sw_vers -buildVersion)",
        "a=$(uname -m)",
        "m=$(sysctl -n hw.model 2>/dev/null || true)",
        "mem=$(sysctl -n hw.memsize 2>/dev/null || true)",
        "up=$(uptime | sed 's/^[[:space:]]*//')",
        "printf '%s|%s|%s|%s|%s|%s|%s|%s\\n' \"$u\" \"$h\" \"$v\" \"$b\" \"$a\" \"$m\" \"$mem\" \"$up\"",
    ]
    r = require_ok(ssh_run(";".join(fields), timeout=15), "status")
    v = (r["output"].split("|", 7) + [""] * 8)[:8]
    emit({
        "status": "PASS",
        "auth": "publickey",
        "user": v[0],
        "hostname": v[1],
        "macos": v[2],
        "build": v[3],
        "arch": v[4],
        "model": v[5],
        "memory_bytes": int(v[6]) if v[6].isdigit() else v[6],
        "uptime": v[7],
        "duration_ms": r["duration_ms"],
    })

def cmd_health(args):
    out = {"status": "PASS", "target": TARGET}
    t0 = time.perf_counter()
    try:
        with socket.create_connection((CFG["host"], int(CFG["port"])), 5):
            pass
        out["tcp22"] = "PASS"
    except Exception as e:
        out["tcp22"] = "FAIL"
        out["tcp_error"] = type(e).__name__
        out["status"] = "FAIL"

    r = ssh_run("printf AUTH_OK", fresh=True, timeout=10)
    out["fresh_publickey"] = "PASS" if r["rc"] == 0 and r["output"] == "AUTH_OK" else "FAIL"
    if out["fresh_publickey"] == "FAIL":
        out["status"] = "FAIL"

    r = ssh_run("sudo -n true && printf SUDO_OK", timeout=10)
    out["sudo_nopasswd"] = "PASS" if r["rc"] == 0 and r["output"] == "SUDO_OK" else "FAIL"
    if out["sudo_nopasswd"] == "FAIL" and out["status"] == "PASS":
        out["status"] = "DEGRADED"

    r = ssh_run(
        "/usr/sbin/sshd -T | egrep '^(authenticationmethods|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|maxauthtries)'",
        sudo=True,
        timeout=10,
    )
    out["sshd_effective"] = r["output"].splitlines()

    r = ssh_run(
        'for p in "$HOME/Library/Mail" "$HOME/Library/Safari"; do test -r "$p" || exit 1; done; printf FDA_OK',
        timeout=10,
    )
    out["protected_user_data"] = "PASS" if r["rc"] == 0 and r["output"] == "FDA_OK" else "LIMITED"

    r = run(ssh_argv(op="check"), timeout=5, cap=4096)
    out["control_master"] = "UP" if r["rc"] == 0 else "DOWN"
    out["duration_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    emit(out)
    if out["status"] == "FAIL":
        raise SystemExit(1)


def _doctor_json(result):
    try:
        return json.loads(result.get("output") or "{}")
    except Exception:
        return {}


def _doctor_tcc_rows(text):
    out = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        try:
            client_type = int(parts[2])
            auth_value = int(parts[3])
        except ValueError:
            continue
        out.append({
            "service": parts[0],
            "client": parts[1],
            "client_type": client_type,
            "auth_value": auth_value,
            "target": parts[4],
        })
    return out


def cmd_doctor(args):
    """Layered, read-only recovery diagnosis.

    The login-window state is intentionally represented as LOGIN_REQUIRED with
    exit code 0 when headless control remains healthy. Doctor never enables
    auto-login, requests TCC grants, resets TCC, reboots, or changes policy.
    """
    t0 = time.perf_counter()
    root = Path(__file__).resolve().parent
    expected_user = str(CFG.get("user") or "")
    probes = {"expected_user": expected_user}
    details = {}

    required_local = [
        root / "macctl.py",
        root / "policy_engine.py",
        root / "transaction_engine.py",
        root / "doctor_engine.py",
        Path(SSH_CONFIG),
        Path(CFG.get("identity_file", "")),
        Path(CFG.get("known_hosts_file", "")),
    ]
    local_files = {str(x): x.is_file() for x in required_local if str(x)}
    probes["vm_runtime"] = bool(local_files) and all(local_files.values())
    details["vm"] = {"runtime_files": local_files}

    route_r = run(["ip", "route", "get", str(CFG["host"])], timeout=min(args.timeout, 5), cap=4096)
    route_text = route_r.get("output", "").splitlines()[0] if route_r.get("rc") == 0 and route_r.get("output") else ""
    route_tokens = route_text.split()
    route_dev = route_tokens[route_tokens.index("dev") + 1] if "dev" in route_tokens and route_tokens.index("dev") + 1 < len(route_tokens) else None
    route_src = route_tokens[route_tokens.index("src") + 1] if "src" in route_tokens and route_tokens.index("src") + 1 < len(route_tokens) else None
    route_via = route_tokens[route_tokens.index("via") + 1] if "via" in route_tokens and route_tokens.index("via") + 1 < len(route_tokens) else None
    details["network_path"] = {
        "target_host": CFG["host"],
        "route_ok": route_r.get("rc") == 0,
        "device": route_dev,
        "source": route_src,
        "gateway": route_via,
        "direct_route": route_r.get("rc") == 0 and route_dev is not None and route_via is None,
    }

    ssh_g = run(["ssh", "-G", "-F", SSH_CONFIG, TARGET], timeout=min(args.timeout, 5), cap=16000)
    ssh_effective = {}
    if ssh_g.get("rc") == 0:
        wanted = {
            "connecttimeout", "connectionattempts", "serveraliveinterval",
            "serveralivecountmax", "controlmaster", "controlpersist",
            "stricthostkeychecking", "batchmode",
        }
        for line in ssh_g.get("output", "").splitlines():
            key, sep, value = line.partition(" ")
            if sep and key in wanted:
                ssh_effective[key] = value.strip()
    details["ssh_transport"] = {"effective": ssh_effective}

    try:
        with socket.create_connection(
            (CFG["host"], int(CFG["port"])),
            float(CFG.get("connect_timeout_seconds", 5)),
        ):
            pass
        probes["tcp22"] = True
    except Exception as e:
        probes["tcp22"] = False
        details.setdefault("ssh", {})["tcp_error"] = type(e).__name__

    fresh = ssh_run("printf AUTH_OK", fresh=True, timeout=min(args.timeout, 10), cap=4096) if probes["tcp22"] else {"rc": 1, "output": ""}
    probes["fresh_publickey"] = fresh.get("rc") == 0 and fresh.get("output") == "AUTH_OK"

    sudo = ssh_run("sudo -n true && printf SUDO_OK", timeout=min(args.timeout, 10), cap=4096) if probes["fresh_publickey"] else {"rc": 1, "output": ""}
    probes["sudo_nopasswd"] = sudo.get("rc") == 0 and sudo.get("output") == "SUDO_OK"

    remote = {"rc": 1, "output": ""}
    if probes["fresh_publickey"]:
        remote_cmd = (
            "console=$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null || printf unknown); "
            "uid=$(/usr/bin/id -u); "
            "if /bin/launchctl print gui/$uid >/dev/null 2>&1; then gui=YES; else gui=NO; fi; "
            "boot=$(/usr/sbin/sysctl -n kern.boottime 2>/dev/null | /usr/bin/sed -E 's/^\\{ sec = ([0-9]+),.*/\\1/'); "
            "os=$(/usr/bin/sw_vers -productVersion 2>/dev/null || true); "
            "build=$(/usr/bin/sw_vers -buildVersion 2>/dev/null || true); "
            "printf '%s|%s|%s|%s|%s\\n' \"$console\" \"$gui\" \"$boot\" \"$os\" \"$build\""
        )
        remote = ssh_run(remote_cmd, timeout=min(args.timeout, 12), cap=4096)

    console_user = "unknown"
    gui_domain = False
    boot_epoch = 0
    macos = ""
    build = ""
    if remote.get("rc") == 0:
        parts = (remote.get("output", "").split("|", 4) + [""] * 5)[:5]
        console_user, gui_raw, boot_raw, macos, build = parts
        gui_domain = gui_raw == "YES"
        try:
            boot_epoch = int(boot_raw)
        except ValueError:
            boot_epoch = 0
    probes["remote_identity"] = remote.get("rc") == 0 and bool(macos) and bool(build)
    probes["console_user"] = console_user
    probes["gui_domain"] = gui_domain
    details["ssh"] = {
        **details.get("ssh", {}),
        "tcp22": probes["tcp22"],
        "fresh_publickey": probes["fresh_publickey"],
        "sudo_nopasswd": probes["sudo_nopasswd"],
    }
    details["mac"] = {
        "remote_identity": probes["remote_identity"],
        "console_user": console_user,
        "expected_user": expected_user,
        "gui_domain": gui_domain,
        "boot_epoch": boot_epoch or None,
        "macos": macos or None,
        "build": build or None,
    }

    helper_lifecycle = {}
    helper_status = {}
    marker_current = False
    if probes["remote_identity"] and console_user == expected_user and gui_domain:
        lifecycle_r = helper_gui_run("lifecycle-status", timeout=min(args.timeout, 10), cap=8192)
        status_r = helper_gui_run("status", timeout=min(args.timeout, 10), cap=4096)
        helper_lifecycle = _doctor_json(lifecycle_r)
        helper_status = _doctor_json(status_r)
        probes["helper_probe"] = lifecycle_r.get("rc") == 0 and status_r.get("rc") == 0
        probes["helper_service_enabled"] = helper_lifecycle.get("service_status") == "ENABLED"
        marker = helper_lifecycle.get("marker") if isinstance(helper_lifecycle.get("marker"), dict) else {}
        marker_ts = marker.get("timestamp")
        if marker_ts and boot_epoch:
            try:
                marker_epoch = datetime.datetime.fromisoformat(str(marker_ts).replace("Z", "+00:00")).timestamp()
                marker_current = marker_epoch >= (boot_epoch - 5)
            except Exception:
                marker_current = False
        probes["helper_marker_current_boot"] = marker_current
    else:
        probes["helper_probe"] = False
        probes["helper_service_enabled"] = False
        probes["helper_marker_current_boot"] = False

    details["helper"] = {
        "probe": probes["helper_probe"],
        "service_status": helper_lifecycle.get("service_status") if helper_lifecycle else None,
        "marker_present": helper_lifecycle.get("marker_present") if helper_lifecycle else None,
        "marker_current_boot": probes["helper_marker_current_boot"],
        "bundle": helper_status.get("bundle") if helper_status else None,
    }

    for key in (
        "tcc_accessibility_allow", "tcc_screen_capture_allow",
        "tcc_finder_automation_allow", "tcc_systemevents_automation_allow",
        "tcc_runtime_automation_probe", "ax_probe", "screen_capture_probe", "vision_probe",
    ):
        probes[key] = False

    if probes["helper_probe"]:
        user_sql = (
            "select service,client,client_type,auth_value,indirect_object_identifier "
            "from access where service='kTCCServiceAppleEvents' and "
            "client='app.openai.macctl.helper' order by indirect_object_identifier;"
        )
        system_sql = (
            "select service,client,client_type,auth_value,indirect_object_identifier "
            "from access where service in ('kTCCServiceScreenCapture','kTCCServiceAccessibility') and "
            "client='app.openai.macctl.helper' order by service,client;"
        )
        user_cmd = (
            'db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"; ' +
            '/usr/bin/sqlite3 -separator "|" "$db" ' + shlex.quote(user_sql)
        )
        system_cmd = (
            'db="/Library/Application Support/com.apple.TCC/TCC.db"; ' +
            '/usr/bin/sqlite3 -separator "|" "$db" ' + shlex.quote(system_sql)
        )
        ur = ssh_run(user_cmd, timeout=min(args.timeout, 10), cap=8192)
        sr = ssh_run(system_cmd, sudo=True, timeout=min(args.timeout, 10), cap=8192)
        user_rows = _doctor_tcc_rows(ur.get("output", "")) if ur.get("rc") == 0 else []
        system_rows = _doctor_tcc_rows(sr.get("output", "")) if sr.get("rc") == 0 else []

        def allowed(rows, service, target=None):
            for row in rows:
                if row.get("service") != service or row.get("client") != "app.openai.macctl.helper":
                    continue
                if target is not None and row.get("target") != target:
                    continue
                if row.get("auth_value") == 2:
                    return True
            return False

        probes["tcc_accessibility_allow"] = allowed(system_rows, "kTCCServiceAccessibility")
        probes["tcc_screen_capture_allow"] = allowed(system_rows, "kTCCServiceScreenCapture")
        probes["tcc_finder_automation_allow"] = allowed(user_rows, "kTCCServiceAppleEvents", "com.apple.finder")
        probes["tcc_systemevents_automation_allow"] = allowed(user_rows, "kTCCServiceAppleEvents", "com.apple.systemevents")

        persisted_tcc_ready = all((
            probes["tcc_accessibility_allow"], probes["tcc_screen_capture_allow"],
            probes["tcc_finder_automation_allow"], probes["tcc_systemevents_automation_allow"],
        ))
        if persisted_tcc_ready:
            finder = helper_gui_run("automation-finder", timeout=min(args.timeout, 8), cap=4096)
            systemevents = helper_gui_run("automation-systemevents", timeout=min(args.timeout, 8), cap=4096)
            probes["tcc_runtime_automation_probe"] = finder.get("rc") == 0 and systemevents.get("rc") == 0

            ax = helper_gui_run("accessibility-test", timeout=min(args.timeout, 8), cap=4096)
            probes["ax_probe"] = ax.get("rc") == 0 and _doctor_json(ax).get("status") == "PASS"

            capture = helper_gui_run("screen-capture-test", timeout=min(args.timeout, 10), cap=8192)
            probes["screen_capture_probe"] = capture.get("rc") == 0 and _doctor_json(capture).get("status") == "PASS"

            vision = helper_gui_run("screen-ocr", timeout=min(args.timeout, 12), cap=max(24000, args.max_bytes))
            vision_payload = _doctor_json(vision)
            probes["vision_probe"] = (
                vision.get("rc") == 0
                and vision_payload.get("status") == "PASS"
                and isinstance(vision_payload.get("ocr"), dict)
                and vision_payload["ocr"].get("status") == "PASS"
            )

    details["tcc"] = {
        "accessibility_allow": probes["tcc_accessibility_allow"],
        "screen_capture_allow": probes["tcc_screen_capture_allow"],
        "finder_automation_allow": probes["tcc_finder_automation_allow"],
        "systemevents_automation_allow": probes["tcc_systemevents_automation_allow"],
        "runtime_automation_probe": probes["tcc_runtime_automation_probe"],
    }
    details["gui_probes"] = {
        "ax": probes["ax_probe"],
        "screen_capture": probes["screen_capture_probe"],
        "vision": probes["vision_probe"],
    }

    ps = policy_status(CFG)
    probes["policy_fail_closed"] = bool(ps.get("fail_closed_unknown_typed_operation"))
    probes["policy_system_update_blocked"] = not bool(ps.get("allow_macos_system_update"))
    probes["policy_major_upgrade_blocked"] = not bool(ps.get("allow_macos_major_upgrade"))
    details["policy"] = {
        "fail_closed_unknown_typed_operation": probes["policy_fail_closed"],
        "system_update_blocked": probes["policy_system_update_blocked"],
        "major_upgrade_blocked": probes["policy_major_upgrade_blocked"],
    }

    repo_present = (root / ".git").exists()
    probes["github_repo_present"] = repo_present
    branch = run(["git", "-C", str(root), "branch", "--show-current"], timeout=min(args.timeout, 5), cap=4096) if repo_present else {"rc": 1, "output": ""}
    probes["github_branch_main"] = branch.get("rc") == 0 and branch.get("output") == "main"

    def unit_state(unit, mode):
        result = run(["systemctl", mode, "--quiet", unit], timeout=min(args.timeout, 5), cap=4096)
        return result.get("rc") == 0

    probes["github_sync_path_active"] = unit_state("macctl-github-sync.path", "is-active")
    probes["github_sync_path_enabled"] = unit_state("macctl-github-sync.path", "is-enabled")
    probes["github_sync_timer_active"] = unit_state("macctl-github-sync.timer", "is-active")
    probes["github_sync_timer_enabled"] = unit_state("macctl-github-sync.timer", "is-enabled")

    head = run(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=min(args.timeout, 5), cap=4096) if repo_present else {"rc": 1, "output": ""}
    remote_head = run(["git", "-C", str(root), "ls-remote", "origin", "refs/heads/main"], timeout=min(args.timeout, 12), cap=4096) if repo_present else {"rc": 1, "output": ""}
    probes["github_remote_reachable"] = remote_head.get("rc") == 0
    remote_sha = ""
    if probes["github_remote_reachable"] and remote_head.get("output"):
        remote_sha = remote_head["output"].split()[0]
    local_sha = head.get("output", "") if head.get("rc") == 0 else ""
    probes["github_remote_matches_head"] = bool(local_sha) and local_sha == remote_sha
    details["github_sync"] = {
        "repo_present": repo_present,
        "branch": branch.get("output") if branch.get("rc") == 0 else None,
        "path_active": probes["github_sync_path_active"],
        "path_enabled": probes["github_sync_path_enabled"],
        "timer_active": probes["github_sync_timer_active"],
        "timer_enabled": probes["github_sync_timer_enabled"],
        "remote_reachable": probes["github_remote_reachable"],
        "local_head": local_sha or None,
        "remote_main": remote_sha or None,
        "remote_matches_head": probes["github_remote_matches_head"],
    }

    backup_script = root / "scripts" / "backup-health.sh"
    backup_health = (
        run(["bash", str(backup_script)], timeout=min(args.timeout, 20), cap=12000)
        if backup_script.is_file()
        else {"rc": 1, "output": ""}
    )
    backup_lines = [line for line in backup_health.get("output", "").splitlines() if line.strip()]
    probes["backup_health"] = (
        backup_health.get("rc") == 0
        and any(line.startswith("MACCTL_BACKUP_HEALTH_PASS") for line in backup_lines)
    )
    details["backup"] = {
        "script_present": backup_script.is_file(),
        "health": probes["backup_health"],
        "summary": backup_lines[-1] if backup_lines else None,
    }

    evaluated = evaluate_doctor(probes)
    evaluated.update({
        "target": TARGET,
        "details": details,
        "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
    })
    emit(evaluated)
    if evaluated["exit_code"]:
        raise SystemExit(evaluated["exit_code"])


def cmd_exec(args):
    command = " ".join(args.command)
    enforce_command_policy(command, "exec", args)
    r = ssh_run(
        command,
        sudo=args.sudo,
        timeout=args.timeout,
        cap=args.max_bytes,
    )
    if args.json:
        emit({"status": "PASS" if r["rc"] == 0 else "FAIL", **r})
    elif r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_script(args):
    p = Path(args.file)
    if not p.is_file():
        print(f"local script not found: {p}", file=sys.stderr)
        raise SystemExit(66)
    shell = {"zsh": "/bin/zsh", "bash": "/bin/bash", "sh": "/bin/sh"}[args.shell]
    script_bytes = p.read_bytes()
    enforce_command_policy(script_bytes.decode("utf-8", "replace"), "script", args)
    remote_timeout = max(1, int(args.timeout) - 2) if args.timeout and int(args.timeout) > 2 else None
    argv = [shell, "-s"]
    if remote_timeout:
        perl_alarm = "use POSIX qw(setsid); $t=shift; $p=fork(); die qq(fork failed) unless defined $p; if(!$p){setsid(); exec @ARGV; exit 127} $SIG{ALRM}=sub{kill q(TERM), -$p; select undef,undef,undef,0.2; kill q(KILL), -$p; exit 124}; alarm $t; waitpid($p,0); alarm 0; $s=$?; exit(($s & 127) ? 128+($s & 127) : ($s >> 8));"
        argv = ["/usr/bin/perl", "-e", perl_alarm, str(remote_timeout)] + argv
    if args.sudo:
        argv = ["/usr/bin/sudo", "-n"] + argv
    remote = shlex.join(argv)
    r = run(
        ssh_argv(remote),
        timeout=args.timeout,
        input_bytes=script_bytes,
        cap=args.max_bytes,
    )
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_file(args):
    q = shlex.quote
    if args.action == "read":
        r = ssh_run(f"/usr/bin/head -c {int(args.max_bytes)} -- {q(args.path)}", sudo=args.sudo, timeout=args.timeout, cap=args.max_bytes)
    elif args.action == "list":
        r = ssh_run(f"/bin/ls -la -- {q(args.path)} | /usr/bin/head -n {int(args.limit)}", sudo=args.sudo, timeout=args.timeout)
    elif args.action == "stat":
        r = ssh_run(f"/usr/bin/stat -f '%N|%z|%Sp|%Su|%Sg|%m' -- {q(args.path)}", sudo=args.sudo, timeout=args.timeout)
    elif args.action == "sha256":
        r = ssh_run(f"/usr/bin/shasum -a 256 -- {q(args.path)}", sudo=args.sudo, timeout=args.timeout)
    elif args.action == "mkdir":
        flags = "-p " if args.parents else ""
        r = ssh_run(f"/bin/mkdir {flags}{q(args.path)}", sudo=args.sudo, timeout=args.timeout)
    elif args.action == "rm":
        flags = "-rf" if args.recursive else "-f"
        r = ssh_run(f"/bin/rm {flags} -- {q(args.path)}", sudo=args.sudo, timeout=args.timeout)
    elif args.action == "mv":
        r = ssh_run(f"/bin/mv -- {q(args.src)} {q(args.dst)}", sudo=args.sudo, timeout=args.timeout)
    elif args.action == "cp":
        flags = "-R " if args.recursive else ""
        r = ssh_run(f"/bin/cp {flags}-- {q(args.src)} {q(args.dst)}", sudo=args.sudo, timeout=args.timeout)
    else:
        raise SystemExit(64)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def _remote_transfer_home():
    r = ssh_run('printf "%s" "$HOME"', fresh=True, timeout=10, cap=4096)
    if r["rc"] != 0 or not r["output"].strip():
        raise TransferPlanError("unable to resolve remote HOME")
    return r["output"].strip()


def _cleanup_remote_transfer_stage(path):
    # Cleanup is best-effort and never retries the business transfer itself.
    try:
        ssh_run(f"/bin/rm -f -- {shlex.quote(path)}", fresh=True, timeout=10, cap=4096)
    except Exception:
        pass


def _atomic_push_file(src, args):
    home = _remote_transfer_home()
    requested_abs = resolve_remote_user_path(args.remote, home=home)
    requested_probe = _remote_path_probe(requested_abs)
    final_path = effective_remote_file_path(
        args.remote,
        home=home,
        local_name=src.name,
        destination_is_dir=requested_probe.get("kind") == "DIR",
    )
    final_probe = _remote_path_probe(final_path)
    if final_probe.get("kind") in {"SYMLINK", "DIR", "OTHER"}:
        print(f"atomic push refuses unsafe final target kind={final_probe.get('kind')}", file=sys.stderr)
        raise SystemExit(73)

    expected_sha = sha256_file(src)
    stage = remote_stage_sibling(final_path, token=uuid.uuid4().hex)
    argv = remote_scp_argv(
        ssh_config=SSH_CONFIG,
        target=TARGET,
        local_path=str(src),
        remote_path=stage,
        direction="push",
        recursive=False,
    )
    transfer = run(argv, timeout=args.timeout)
    if transfer["rc"] != 0:
        _cleanup_remote_transfer_stage(stage)
        if transfer["output"]:
            print(transfer["output"])
        raise SystemExit(transfer["rc"])

    staged = _remote_path_probe(stage)
    if staged.get("kind") != "FILE" or staged.get("sha256") != expected_sha:
        _cleanup_remote_transfer_stage(stage)
        print("atomic push SHA-256 verification failed before commit", file=sys.stderr)
        raise SystemExit(74)

    commit = ssh_run(
        f"/bin/mv -f -- {shlex.quote(stage)} {shlex.quote(final_path)}",
        fresh=True,
        timeout=15,
        cap=4096,
    )
    final = _remote_path_probe(final_path)
    if final.get("kind") == "FILE" and final.get("sha256") == expected_sha:
        return

    _cleanup_remote_transfer_stage(stage)
    if commit["output"]:
        print(commit["output"], file=sys.stderr)
    print("atomic push final SHA-256 verification failed", file=sys.stderr)
    raise SystemExit(commit["rc"] or 74)


def _atomic_pull_file(args):
    home = _remote_transfer_home()
    remote_source = resolve_remote_user_path(args.remote, home=home)
    before = _remote_path_probe(remote_source)
    if before.get("kind") != "FILE" or not before.get("sha256"):
        print(f"atomic pull requires a regular remote file, got {before.get('kind')}", file=sys.stderr)
        raise SystemExit(66)

    requested_local = Path(args.local)
    if requested_local.exists() and requested_local.is_dir():
        final_local = requested_local / Path(remote_source).name
    else:
        if str(args.local).endswith(os.sep):
            print("local destination ends with / but is not a directory", file=sys.stderr)
            raise SystemExit(73)
        final_local = requested_local
    if final_local.is_symlink() or (final_local.exists() and not final_local.is_file()):
        print("atomic pull refuses non-regular local final target", file=sys.stderr)
        raise SystemExit(73)
    if not final_local.parent.exists() or not final_local.parent.is_dir():
        print("local destination parent does not exist", file=sys.stderr)
        raise SystemExit(73)

    stage = local_stage_sibling(final_local, token=uuid.uuid4().hex)
    try:
        argv = remote_scp_argv(
            ssh_config=SSH_CONFIG,
            target=TARGET,
            local_path=str(stage),
            remote_path=remote_source,
            direction="pull",
            recursive=False,
        )
        transfer = run(argv, timeout=args.timeout)
        if transfer["rc"] != 0:
            if transfer["output"]:
                print(transfer["output"])
            raise SystemExit(transfer["rc"])

        after = _remote_path_probe(remote_source)
        if after.get("kind") != "FILE" or after.get("sha256") != before.get("sha256"):
            print("remote source changed during atomic pull", file=sys.stderr)
            raise SystemExit(74)
        if sha256_file(stage) != before.get("sha256"):
            print("atomic pull SHA-256 verification failed before commit", file=sys.stderr)
            raise SystemExit(74)
        os.replace(stage, final_local)
        if sha256_file(final_local) != before.get("sha256"):
            print("atomic pull final SHA-256 verification failed", file=sys.stderr)
            raise SystemExit(74)
    finally:
        try:
            stage.unlink(missing_ok=True)
        except Exception:
            pass


def cmd_push(args):
    src = Path(args.local)
    if not src.exists():
        print("local path not found", file=sys.stderr)
        raise SystemExit(66)
    if src.is_file():
        try:
            _atomic_push_file(src, args)
        except TransferPlanError as e:
            print(f"atomic push planning error: {e}", file=sys.stderr)
            raise SystemExit(64)
        return

    # Recursive directory SCP remains a legacy compatibility path.  R0 does
    # not claim whole-tree atomicity for it; use rsync for resumable trees.
    argv = remote_scp_argv(
        ssh_config=SSH_CONFIG,
        target=TARGET,
        local_path=str(src),
        remote_path=args.remote,
        direction="push",
        recursive=True,
    )
    r = run(argv, timeout=args.timeout)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])


def cmd_pull(args):
    if not args.recursive:
        try:
            _atomic_pull_file(args)
        except TransferPlanError as e:
            print(f"atomic pull planning error: {e}", file=sys.stderr)
            raise SystemExit(64)
        return

    # Recursive directory SCP remains legacy/non-atomic for compatibility.
    argv = remote_scp_argv(
        ssh_config=SSH_CONFIG,
        target=TARGET,
        local_path=args.local,
        remote_path=args.remote,
        direction="pull",
        recursive=True,
    )
    r = run(argv, timeout=args.timeout)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_process(args):
    q = shlex.quote
    if args.action == "list":
        cmd = "ps aux"
        if args.match:
            cmd += f" | grep -i -- {q(args.match)} | grep -v grep"
        cmd += f" | head -n {int(args.limit)}"
        r = ssh_run(cmd, timeout=15)
    elif args.action == "top":
        r = ssh_run(f"ps -Ao pid,ppid,user,%cpu,%mem,etime,command -r | head -n {int(args.limit)}", timeout=15)
    else:
        sig = args.signal.upper()
        if not sig.startswith("SIG"):
            sig = "SIG" + sig
        r = ssh_run(f"kill -s {q(sig)} {args.pid}", sudo=args.sudo, timeout=10)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def user_domain():
    return "gui/" + ssh_run("id -u", timeout=5)["output"].strip()

def cmd_launchd(args):
    q = shlex.quote
    sudo = getattr(args, "scope", "user") == "system"
    domain = "system" if sudo else user_domain()
    if args.action == "list":
        cmd = "launchctl list | head -n 120"
        sudo = False
    elif args.action == "print":
        cmd = f"launchctl print {q(domain + '/' + args.label)}"
    elif args.action == "kickstart":
        cmd = f"launchctl kickstart {'-k ' if args.kill else ''}{q(domain + '/' + args.label)}"
    else:
        cmd = f"launchctl {args.action} {q(domain + '/' + args.label)}"
    r = ssh_run(cmd, sudo=sudo, timeout=args.timeout)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_logs(args):
    parts = ["/usr/bin/log", "show", "--style", args.style, "--last", args.last]
    if args.predicate:
        parts += ["--predicate", args.predicate]
    if args.level == "info":
        parts += ["--info"]
    elif args.level == "debug":
        parts += ["--info", "--debug"]
    r = ssh_run(shlex.join(parts), sudo=args.sudo, timeout=args.timeout, cap=args.max_bytes)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_system(args):
    if args.action == "network-summary":
        remote = (
            "iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'); "
            "gw=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'); "
            "ip=$(ipconfig getifaddr \"$iface\" 2>/dev/null || true); "
            "dns=$(scutil --dns 2>/dev/null | awk '/nameserver\\[[0-9]+\\]/{print $3}' | awk '!seen[$0]++' | paste -sd, -); "
            "printf '%s|%s|%s|%s\\n' \"$iface\" \"$ip\" \"$gw\" \"$dns\""
        )
        r = require_ok(ssh_run(remote, timeout=args.timeout, cap=8192), "network-summary")
        vals = (r["output"].split("|", 3) + [""] * 4)[:4]
        emit({
            "status":"PASS",
            "interface":vals[0],
            "ip":vals[1],
            "gateway":vals[2],
            "dns":vals[3].split(",") if vals[3] else [],
            "duration_ms":r["duration_ms"]
        })
        return
    if args.action == "dns":
        r = ssh_run("scutil --dns", timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "proxy":
        r = ssh_run("scutil --proxy", timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "reachability":
        r = ssh_run("scutil -r " + shlex.quote(args.host), timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "storage-health":
        remote = (
            "diskutil info / | egrep 'Device Identifier|Volume Name|File System Personality|SMART Status|Disk Size|Volume Used Space|Container Total Space|Container Free Space|Solid State'"
        )
        r = ssh_run(remote, timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "network-quality":
        r = ssh_run("networkQuality -c", timeout=args.timeout, cap=max(args.max_bytes, 262144))
        require_ok(r, "network-quality")
        try:
            data = json.loads(r["output"])
            emit({
                "status":"PASS",
                "interface":data.get("interface_name"),
                "download_mbps":round(float(data.get("dl_throughput",0))/1_000_000,1),
                "upload_mbps":round(float(data.get("ul_throughput",0))/1_000_000,1),
                "base_rtt_ms":data.get("base_rtt"),
                "responsiveness_rpm":round(float(data.get("responsiveness",0)),1),
                "os_version":data.get("os_version"),
                "duration_ms":r["duration_ms"]
            })
        except Exception as e:
            emit({"status":"FAIL","operation":"network-quality-parse","error":type(e).__name__,"detail":str(e)})
            raise SystemExit(65)
        return
    cmds = {
        "info": "sw_vers; echo ARCH=$(uname -m); echo MODEL=$(sysctl -n hw.model); echo CPU=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true); echo MEM=$(sysctl -n hw.memsize); uptime",
        "disk": "df -h; echo ---DISKS---; diskutil list",
        "memory": "vm_stat; echo ---PRESSURE---; memory_pressure 2>/dev/null | head -n 40 || true",
        "network": "echo DEFAULT_ROUTE; route -n get default; echo ---INTERFACES---; ifconfig",
        "power": "pmset -g custom; echo ---ASSERTIONS---; pmset -g assertions",
        "thermal": "pmset -g therm 2>&1 || true",
        "power-schedule": "pmset -g sched",
    }
    r = ssh_run(cmds[args.action], sudo=args.sudo, timeout=args.timeout, cap=args.max_bytes)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_power(args):
    if args.action == "blockers":
        r = ssh_run("pmset -g assertions | egrep 'PreventSystemSleep|PreventUserIdleSystemSleep|PreventUserIdleDisplaySleep|pid [0-9]+'", timeout=10, cap=12000)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action in ("restart", "shutdown") and not getattr(args, "confirm", False):
        emit({"status":"BLOCKED","reason":"explicit_confirmation_required","action":args.action})
        raise SystemExit(77)
    cmd = {"sleep": "pmset sleepnow", "restart": "shutdown -r now", "shutdown": "shutdown -h now"}[args.action]
    r = ssh_run(cmd, sudo=True, timeout=10)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_wake(args):
    mac = bytes.fromhex(CFG["wake_mac"].replace(":", ""))
    packet = b"\xff" * 6 + mac * 16
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    dest = CFG.get("wake_broadcast", "255.255.255.255")
    s.sendto(packet, (dest, 9))
    s.close()
    emit({"status": "SENT", "mac": CFG["wake_mac"], "broadcast": dest, "port": 9})

def cmd_update(args):
    if args.action == "list":
        r = ssh_run("softwareupdate --list", timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])

    if args.action == "settings":
        cmd = (
            "printf 'AutomaticDownload='; defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo UNKNOWN; "
            "printf 'Schedule='; softwareupdate --schedule 2>&1; "
            "printf 'ConfigDataInstall='; defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo DEFAULT_OR_UNKNOWN; "
            "printf 'CriticalUpdateInstall='; defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall 2>/dev/null || echo DEFAULT_OR_UNKNOWN"
        )
        r = ssh_run(cmd, timeout=15, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])

    if args.action == "policy":
        emit({
            "status":"PASS",
            "allow_macos_system_update":bool(CFG.get("allow_macos_system_update", False)),
            "allow_macos_major_upgrade":bool(CFG.get("allow_macos_major_upgrade", False)),
            "install_all":"BLOCKED" if not CFG.get("allow_macos_system_update", False) else "ALLOWED",
            "safe_safari_only":"ALLOWED"
        })
        return

    if args.action == "install-all" and not CFG.get("allow_macos_system_update", False):
        emit({"status":"BLOCKED","reason":"macos_system_update_policy","detail":"install-all may install macOS updates/upgrades and is disabled by policy"})
        raise SystemExit(77)

    if args.action in ("safari-download", "safari-install"):
        verb = "--download" if args.action == "safari-download" else "--install"
        r = ssh_run(f"softwareupdate {verb} --safari-only", sudo=True, timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])

    if args.action == "install":
        label = args.label
        low = label.lower()
        os_markers = ("macos", "tahoe", "sequoia", "sonoma", "ventura", "monterey", "big sur")
        if any(x in low for x in os_markers) and not CFG.get("allow_macos_system_update", False):
            emit({"status":"BLOCKED","reason":"macos_system_update_policy","label":label})
            raise SystemExit(77)
        cmd = "softwareupdate --install " + shlex.quote(label)
        r = ssh_run(cmd, sudo=True, timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])

    raise SystemExit(64)

def cmd_brew(args):
    cmds = {
        "version": "command -v brew >/dev/null 2>&1 && brew --version || { echo BREW_NOT_FOUND; exit 127; }",
        "list": "brew list --versions",
        "doctor": "brew doctor",
        "update": "brew update",
        "upgrade": "brew upgrade",
    }
    r = ssh_run(cmds[args.action], timeout=args.timeout, cap=args.max_bytes)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])


def _workstation_remote_observation():
    prefix = "export PATH=/opt/homebrew/bin:/opt/homebrew/sbin:$HOME/.local/bin:$PATH; "
    checks = {
        "brew": "brew --version",
        "git": "git --version",
        "git_lfs": "git lfs version",
        "gh": "gh --version",
        "clang": "clang --version",
        "swift": "swift --version",
        "python312": "python3.12 --version",
        "node": "node --version",
        "npm": "npm --version",
        "go": "go version",
        "rustc": "rustc --version",
        "cargo": "cargo --version",
        "java": "java -version",
        "javac": "javac -version",
        "maven": "mvn --version",
        "gradle": "gradle --version",
        "pnpm": "pnpm --version",
        "uv": "uv --version",
        "pipx": "pipx --version",
        "cmake": "cmake --version",
        "ninja": "ninja --version",
        "pkg_config": "pkg-config --version",
        "protoc": "protoc --version",
        "shellcheck": "shellcheck --version",
        "shfmt": "shfmt --version",
        "docker": "docker --version",
        "colima": "colima version",
    }
    tools = {}
    for name, command in checks.items():
        r = ssh_run(prefix + command, timeout=20, cap=4096)
        tools[name] = {
            "available": r["rc"] == 0,
            "version": "\n".join((r.get("output") or "").splitlines()[:3]),
        }

    app_paths = {
        "safari": "/Applications/Safari.app",
        "chrome": "/Applications/Google Chrome.app",
        "vscode": "/Applications/Visual Studio Code.app",
    }
    apps = {}
    for name, path in app_paths.items():
        r = ssh_run("test -d " + shlex.quote(path), timeout=10, cap=1024)
        apps[name] = {"available": r["rc"] == 0, "path": path}

    venv = ssh_run("test -x $HOME/.venvs/macctl-production/bin/python", timeout=10, cap=1024)
    full_xcode = ssh_run("command -v xcodebuild >/dev/null 2>&1 && xcodebuild -version", timeout=20, cap=2048)
    developer_id = ssh_run("security find-identity -v -p codesigning 2>/dev/null | grep -q 'Developer ID Application'", timeout=20, cap=1024)
    notarytool = ssh_run("xcrun --find notarytool >/dev/null 2>&1", timeout=20, cap=1024)
    # Binary presence is not notarization readiness.  A production-ready
    # notarization path also needs an explicitly configured Apple credential
    # profile/account and a successful authenticated notarytool probe.  R2 does
    # not configure or infer Apple-account credentials, so fail closed here.
    notarization_ready = False
    return {
        "schema": "macctl-production-workstation-observation/v1",
        "target": TARGET,
        "tools": tools,
        "apps": apps,
        "runtime_assets": {
            "production_python_venv": {"available": venv["rc"] == 0, "path": "$HOME/.venvs/macctl-production"},
        },
        "specialized_optional": {
            "full_xcode": full_xcode["rc"] == 0,
            "developer_id_signing": developer_id["rc"] == 0,
            "notarization": notarization_ready,
        },
        "specialized_optional_details": {
            "notarytool_available": notarytool["rc"] == 0,
            "notarization_ready_semantics": "authenticated Apple credential/profile plus successful notarytool probe required",
            "notarization_readiness_probe_performed": False,
            "notarization_readiness_reason": "APPLE_ACCOUNT_CREDENTIAL_PROFILE_NOT_CONFIGURED_OR_NOT_EXPLICITLY_QUALIFIED",
        },
        "network_contact_performed": True,
        "stateful_mutation_performed": False,
    }


def _workstation_live_evidence_path():
    safe_target = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(TARGET))
    return WORKSTATION_QUALIFICATION_ROOT / f"{safe_target}.json"


def _load_workstation_live_evidence():
    path = _workstation_live_evidence_path()
    if not path.is_file():
        return None, path, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), path, None
    except Exception as e:
        return {"_load_error": str(e)}, path, str(e)


def cmd_workstation(args):
    if args.action == "profile":
        emit(workstation_profile_contract())
        return
    if args.action == "qualification":
        evidence, path, load_error = _load_workstation_live_evidence()
        result = evaluate_workstation_live_evidence(evidence, expected_target=TARGET)
        result["evidence_path"] = str(path)
        if load_error:
            result["evidence_load_error"] = load_error
        emit(result)
        return
    if args.action == "qualification-plan":
        contract = workstation_profile_contract()
        emit({
            "status": "PASS",
            "schema": "macctl-production-workstation-qualification-plan/v1",
            "target": TARGET,
            "live_qualification_required": contract["live_qualification_required"],
            "network_contact_performed": False,
            "stateful_mutation_performed": False,
        })
        return
    observed = _workstation_remote_observation()
    if args.action == "inventory":
        emit({"status": "PASS", **observed})
        return
    if args.action == "doctor":
        evidence, path, load_error = _load_workstation_live_evidence()
        result = evaluate_workstation_observation(observed, live_evidence=evidence, expected_target=TARGET)
        result.update({"target": TARGET, "observation": observed, "live_evidence_path": str(path)})
        if load_error:
            result["live_evidence_load_error"] = load_error
        emit(result)
        return
    raise SystemExit(64)


def _remote_linux_registry():
    return load_remote_linux_registry(REMOTE_LINUX_REGISTRY_FILE)


def _remote_linux_target(target_id):
    target = resolve_remote_linux_target(_remote_linux_registry(), target_id)
    if target["gateway_target"] != TARGET:
        raise ValueError("remote_linux_gateway_target_mismatch")
    return target


def _remote_linux_evidence_path(target_id):
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(target_id))
    return REMOTE_LINUX_QUALIFICATION_ROOT / f"{safe}.json"


def _load_remote_linux_evidence(target_id):
    path = _remote_linux_evidence_path(target_id)
    if not path.is_file():
        return None, path, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), path, None
    except Exception as e:
        return {"_load_error": str(e)}, path, str(e)


def _remote_linux_effective_ssh_config(target, alias=None):
    alias = str(alias or target["ssh_alias"])
    r = ssh_run("ssh -G " + shlex.quote(alias), timeout=12, cap=32768)
    if r["rc"] != 0:
        return {
            "schema": "macctl-remote-linux-ssh-transport/v1",
            "status": "BLOCKED",
            "target": target["id"],
            "ssh_alias": alias,
            "reason": "ssh_effective_config_unavailable",
            "rc": r["rc"],
            "failure_class": classify_transport_failure(r.get("output", ""), r["rc"]),
        }
    effective = parse_ssh_g_output(r.get("output", ""))
    result = evaluate_ssh_transport_config(target, effective, alias=alias)
    control_path = str(effective.get("controlpath") or "").strip()
    if control_path:
        qpath = shlex.quote(control_path)
        socket_probe = ssh_run(f"if [ -S {qpath} ]; then echo ACTIVE; else echo INACTIVE; fi", timeout=8, cap=1024)
        result["control_master_active"] = socket_probe.get("output", "").strip() == "ACTIVE"
    else:
        result["control_master_active"] = False
    fallbacks = []
    for fallback_alias in target["transport"]["fallback_ssh_aliases"]:
        fr = ssh_run("ssh -G " + shlex.quote(fallback_alias), timeout=12, cap=32768)
        fe = parse_ssh_g_output(fr.get("output", "")) if fr["rc"] == 0 else {}
        fallbacks.append({
            "ssh_alias": fallback_alias,
            "status": "PASS" if fr["rc"] == 0 else "BLOCKED",
            "route": "PROXYJUMP" if str(fe.get("proxyjump") or "").strip() else "DIRECT",
            "hostname": fe.get("hostname"),
            "user": fe.get("user"),
            "port": fe.get("port"),
            "proxyjump": fe.get("proxyjump"),
            "strict_host_key": str(fe.get("stricthostkeychecking") or "").casefold() in {"yes", "true"},
            "connection_reuse": str(fe.get("controlmaster") or "").casefold() in {"auto", "yes"} and bool(str(fe.get("controlpath") or "").strip()),
        })
    result["fallbacks"] = fallbacks
    return result


def _remote_linux_local_summary(target):
    evidence, path, load_error = _load_remote_linux_evidence(target["id"])
    live = evaluate_remote_linux_live_evidence(evidence, expected_target=target["id"])
    return {
        "id": target["id"],
        "ssh_alias": target["ssh_alias"],
        "host": target["host"],
        "port": target["port"],
        "user": target["user"],
        "metadata": target["metadata"],
        "transport": target["transport"],
        "protected_services": target["protected_services"],
        "qualification_state": live["qualification_state"],
        "remote_linux_live_qualified": live["remote_linux_live_qualified"],
        "live_evidence_path": str(path),
        "live_evidence_load_error": load_error,
    }


def _remote_linux_doctor_result(target, observation=None, transport=None):
    observation = observation or _remote_linux_live_status(target)
    transport = transport or _remote_linux_effective_ssh_config(target)
    evidence, path, load_error = _load_remote_linux_evidence(target["id"])
    live = evaluate_remote_linux_live_evidence(evidence, expected_target=target["id"])
    ready = bool(
        observation["ssh_publickey_auth"]
        and observation["sudo_nopasswd_root"]
        and live["remote_linux_live_qualified"]
        and transport.get("status") == "PASS"
    )
    result = {
        "schema": "macctl-remote-linux-doctor/v1",
        "status": "PASS" if ready else "BLOCKED",
        "overall_state": "ROOT_OPERATIONS_READY" if ready else "QUALIFICATION_INCOMPLETE",
        "target": target["id"],
        "ssh_publickey_auth": observation["ssh_publickey_auth"],
        "sudo_nopasswd_root": observation["sudo_nopasswd_root"],
        "remote_linux_live_qualified": live["remote_linux_live_qualified"],
        "ssh_transport_ready": transport.get("status") == "PASS",
        "observation": observation,
        "transport": transport,
        "live_qualification": live,
        "live_evidence_path": str(path),
    }
    if load_error:
        result["live_evidence_load_error"] = load_error
    return result


def _remote_linux_fleet_live(mode, requested_parallelism=None, *, provider=None, region=None, role=None, environment=None, tag=None):
    registry = _remote_linux_registry()
    targets = select_remote_linux_targets(
        registry,
        provider=provider,
        region=region,
        role=role,
        environment=environment,
        tag=tag,
    )
    if not targets:
        return {
            "schema": f"macctl-remote-linux-fleet-{mode}/v1",
            "status": "EMPTY",
            "target_count": 0,
            "pass_count": 0,
            "fail_count": 0,
            "parallelism": 0,
            "results": [],
            "filters": {"provider": provider, "region": region, "role": role, "environment": environment, "tag": tag},
            "network_contact_performed": False,
            "stateful_mutation_performed": False,
        }
    workers = bounded_batch_parallelism(requested_parallelism, len(targets))
    results = {}

    def probe(target):
        observation = _remote_linux_live_status(target)
        transport = _remote_linux_effective_ssh_config(target)
        if mode == "status":
            ok = observation["status"] == "PASS" and transport.get("status") == "PASS"
            return {
                "target": target["id"],
                "status": "PASS" if ok else "FAIL",
                "metadata": target["metadata"],
                "observation": observation,
                "transport": transport,
            }
        return _remote_linux_doctor_result(target, observation=observation, transport=transport)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(probe, target): target for target in targets}
        for future in as_completed(future_map):
            target = future_map[future]
            try:
                results[target["id"]] = future.result()
            except Exception as e:
                results[target["id"]] = {
                    "target": target["id"],
                    "status": "FAIL",
                    "reason": "fleet_probe_exception",
                    "error": str(e),
                }
    ordered = [results[t["id"]] for t in targets]
    pass_count = sum(1 for item in ordered if item.get("status") == "PASS")
    return {
        "schema": f"macctl-remote-linux-fleet-{mode}/v1",
        "status": "PASS" if pass_count == len(ordered) else "DEGRADED",
        "target_count": len(ordered),
        "pass_count": pass_count,
        "fail_count": len(ordered) - pass_count,
        "parallelism": workers,
        "results": ordered,
        "filters": {"provider": provider, "region": region, "role": role, "environment": environment, "tag": tag},
        "network_contact_performed": True,
        "stateful_mutation_performed": False,
    }


def _remote_linux_gateway_run(target, command, *, sudo=False, timeout=DEFAULT_TIMEOUT, cap=DEFAULT_CAP):
    alias = target["ssh_alias"]
    remote_command = command
    if sudo:
        remote_command = "sudo -n -- sh -c " + shlex.quote(command)
    mac_command = " ".join([
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=8",
        shlex.quote(alias),
        shlex.quote(remote_command),
    ])
    result = ssh_run(mac_command, timeout=timeout, cap=cap)
    result["transport_alias"] = alias
    result["transport_failure_class"] = classify_transport_failure(result.get("output", ""), result.get("rc", 1))
    result["fallback_used"] = False
    return result


def _remote_linux_live_status(target):
    probe = r'''set -e
. /etc/os-release
printf 'REMOTE_USER=%s\n' "$(id -un)"
printf 'HOSTNAME=%s\n' "$(hostname)"
printf 'OS_ID=%s\n' "${ID:-unknown}"
printf 'OS_VERSION=%s\n' "${VERSION_ID:-unknown}"
printf 'ARCH=%s\n' "$(uname -m)"
printf 'KERNEL=%s\n' "$(uname -r)"
printf 'SYSTEMD_STATE=%s\n' "$(systemctl is-system-running 2>/dev/null || true)"
printf 'SSH_SERVICE=%s\n' "$(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || true)"
printf 'SUDO_NOPASSWD=%s\n' "$(if sudo -n true 2>/dev/null; then echo true; else echo false; fi)"
printf 'ROOT_ID=%s\n' "$(sudo -n id -u 2>/dev/null || echo unavailable)"
'''
    r = _remote_linux_gateway_run(target, probe, timeout=25, cap=8192)
    fields = {}
    for line in (r.get("output") or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    auth_ok = r["rc"] == 0 and fields.get("REMOTE_USER") == target["user"]
    sudo_ok = fields.get("SUDO_NOPASSWD") == "true" and fields.get("ROOT_ID") == "0"
    return {
        "schema": "macctl-remote-linux-observation/v1",
        "target": target["id"],
        "status": "PASS" if auth_ok else "FAIL",
        "ssh_publickey_auth": auth_ok,
        "sudo_nopasswd_root": sudo_ok,
        "identity": {
            "user": fields.get("REMOTE_USER"),
            "hostname": fields.get("HOSTNAME"),
            "os_id": fields.get("OS_ID"),
            "os_version": fields.get("OS_VERSION"),
            "arch": fields.get("ARCH"),
            "kernel": fields.get("KERNEL"),
        },
        "services": {
            "systemd_state": fields.get("SYSTEMD_STATE"),
            "ssh": fields.get("SSH_SERVICE"),
        },
        "metadata": target["metadata"],
        "transport": {
            "gateway_target": target["gateway_target"],
            "ssh_alias": target["ssh_alias"],
            "host": target["host"],
            "port": target["port"],
            "user": target["user"],
            "host_key_pinned": bool(target["host_key_fingerprints"]),
            "credential_reference_configured": bool(target["credential_ref"]),
            "policy": target["transport"],
            "transport_alias_used": r.get("transport_alias"),
            "failure_class": r.get("transport_failure_class"),
            "fallback_used": bool(r.get("fallback_used")),
        },
        "network_contact_performed": True,
        "stateful_mutation_performed": False,
        "rc": r["rc"],
    }


def _remote_linux_emit_command_result(result, operation):
    if result.get("output"):
        print(result["output"])
    if result.get("rc") != 0:
        raise SystemExit(result.get("rc") or 1)


def cmd_linux(args):
    if args.action == "profile":
        emit(remote_linux_profile_contract())
        return
    if args.action in {"list", "overview"}:
        registry = _remote_linux_registry()
        if args.action == "overview":
            selected = select_remote_linux_targets(
                registry,
                provider=args.provider,
                region=args.region,
                role=args.role,
                environment=args.environment,
                tag=args.tag,
            )
            summaries = [_remote_linux_local_summary(t) for t in selected]
            emit({
                "schema": "macctl-remote-linux-overview/v1",
                "status": "PASS" if summaries else "EMPTY",
                "target_count": len(summaries),
                "qualified_count": sum(1 for item in summaries if item["remote_linux_live_qualified"]),
                "targets": summaries,
                "filters": {"provider": args.provider, "region": args.region, "role": args.role, "environment": args.environment, "tag": args.tag},
                "network_contact_performed": False,
                "stateful_mutation_performed": False,
            })
            return
        emit({
            "schema": "macctl-remote-linux-list/v1",
            "status": "PASS",
            "target_count": len(registry["targets"]),
            "targets": [
                {
                    "id": t["id"],
                    "ssh_alias": t["ssh_alias"],
                    "host": t["host"],
                    "port": t["port"],
                    "user": t["user"],
                    "gateway_target": t["gateway_target"],
                    "metadata": t["metadata"],
                    "transport": t["transport"],
                    "protected_services": t["protected_services"],
                    "host_key_pinned": True,
                    "credential_reference_configured": True,
                    "authorized": True,
                }
                for t in registry["targets"]
            ],
            "network_contact_performed": False,
            "stateful_mutation_performed": False,
        })
        return
    if args.action in {"fleet-status", "fleet-doctor"}:
        mode = "status" if args.action == "fleet-status" else "doctor"
        result = _remote_linux_fleet_live(
            mode,
            requested_parallelism=args.parallel,
            provider=args.provider,
            region=args.region,
            role=args.role,
            environment=args.environment,
            tag=args.tag,
        )
        emit(result)
        raise SystemExit(0 if result["status"] == "PASS" else 1)
    try:
        target = _remote_linux_target(args.target)
    except ValueError as e:
        emit({"status": "BLOCKED", "reason": str(e), "target": getattr(args, "target", None)})
        raise SystemExit(77)
    if args.action == "transport":
        result = _remote_linux_effective_ssh_config(target)
        emit(result)
        raise SystemExit(0 if result.get("status") == "PASS" else 1)
    if args.action == "qualification-plan":
        contract = remote_linux_profile_contract()
        emit({
            "schema": "macctl-remote-linux-qualification-plan/v1",
            "status": "PASS",
            "target": target["id"],
            "required_live_checks": contract["required_live_checks"],
            "network_contact_performed": False,
            "stateful_mutation_performed": False,
        })
        return
    if args.action == "qualification":
        evidence, path, load_error = _load_remote_linux_evidence(target["id"])
        result = evaluate_remote_linux_live_evidence(evidence, expected_target=target["id"])
        result["evidence_path"] = str(path)
        if load_error:
            result["evidence_load_error"] = load_error
        emit(result)
        return
    if args.action == "command":
        reason = remote_linux_high_impact_reason(args.command)
        if reason and not args.confirm_high_impact:
            emit({
                "status": "BLOCKED",
                "schema": "macctl-remote-linux-command-gate/v1",
                "target": target["id"],
                "reason": reason,
                "requires": "--confirm-high-impact plus fresh explicit authorization",
            })
            raise SystemExit(77)
        r = _remote_linux_gateway_run(target, args.command, sudo=args.sudo, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-command")
        return
    if args.action == "logs":
        if args.unit and not re.fullmatch(r"[A-Za-z0-9@_.:-]+", args.unit):
            raise SystemExit(64)
        lines = max(1, min(int(args.lines), 500))
        command = f"journalctl -n {lines} --no-pager"
        if args.unit:
            command += " -u " + shlex.quote(args.unit)
        r = _remote_linux_gateway_run(target, command, sudo=True, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-logs")
        return
    if args.action == "package":
        if not re.fullmatch(r"[A-Za-z0-9.+:-]+", args.name):
            raise SystemExit(64)
        name = shlex.quote(args.name)
        command = f"apt-cache policy {name}; dpkg-query -W -f='${{Status}} ${{Version}}\\n' {name} 2>/dev/null || true"
        r = _remote_linux_gateway_run(target, command, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-package")
        return
    if args.action == "network":
        command = "ip -br addr; echo '--- routes ---'; ip route; echo '--- listeners ---'; ss -lntup"
        r = _remote_linux_gateway_run(target, command, sudo=True, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-network")
        return
    if args.action == "process":
        limit = max(1, min(int(args.limit), 200))
        command = f"ps -eo pid,ppid,user,stat,%cpu,%mem,etimes,comm,args --sort=-%cpu | head -n {limit + 1}"
        r = _remote_linux_gateway_run(target, command, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-process")
        return
    if args.action == "systemd":
        if not re.fullmatch(r"[A-Za-z0-9@_.:-]+", args.unit):
            raise SystemExit(64)
        unit = shlex.quote(args.unit)
        command = f"systemctl status {unit} --no-pager -n {max(1, min(int(args.lines), 200))}; systemctl show {unit} -p ActiveState -p SubState -p UnitFileState -p Result --no-pager"
        r = _remote_linux_gateway_run(target, command, sudo=True, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-systemd")
        return
    if args.action == "file":
        path_value = str(args.path)
        if "\x00" in path_value or "\n" in path_value:
            raise SystemExit(64)
        qp = shlex.quote(path_value)
        commands = {
            "read": f"cat -- {qp}",
            "stat": f"stat -- {qp}",
            "sha256": f"sha256sum -- {qp}",
        }
        r = _remote_linux_gateway_run(target, commands[args.file_action], sudo=args.sudo, timeout=args.timeout, cap=args.max_bytes)
        _remote_linux_emit_command_result(r, "linux-file")
        return
    observation = _remote_linux_live_status(target)
    if args.action == "status":
        emit(observation)
        raise SystemExit(0 if observation["status"] == "PASS" else 1)
    if args.action == "doctor":
        result = _remote_linux_doctor_result(target, observation=observation)
        emit(result)
        raise SystemExit(0 if result["status"] == "PASS" else 1)
    raise SystemExit(64)


def cmd_sync(args):
    argv = remote_rsync_argv(
        ssh_config=SSH_CONFIG,
        target=TARGET,
        local_path=args.local,
        remote_path=args.remote,
        direction=args.action,
        delete=args.delete,
        dry_run=args.dry_run,
    )
    r = run(argv, timeout=args.timeout, cap=args.max_bytes)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_backup(args):
    if args.action == "status":
        r = ssh_run("tmutil status", timeout=args.timeout, cap=args.max_bytes)
    elif args.action == "destinations":
        r = ssh_run("tmutil destinationinfo", timeout=args.timeout, cap=args.max_bytes)
    elif args.action == "snapshots":
        r = ssh_run("tmutil listlocalsnapshotdates /", timeout=args.timeout, cap=args.max_bytes)
    elif args.action == "apfs-snapshots":
        r = ssh_run("diskutil apfs listSnapshots /", timeout=args.timeout, cap=args.max_bytes)
    elif args.action == "create-local":
        r = ssh_run("tmutil localsnapshot", sudo=True, timeout=args.timeout, cap=args.max_bytes)
    elif args.action == "delete-local":
        import re
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}-\d{6}", args.date):
            emit({"status":"BLOCKED","reason":"invalid_snapshot_date","date":args.date})
            raise SystemExit(64)
        r = ssh_run("tmutil deletelocalsnapshots " + shlex.quote(args.date), sudo=True, timeout=args.timeout, cap=args.max_bytes)
    else:
        raise SystemExit(64)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_job(args):
    q = shlex.quote
    if args.action == "start":
        jid = args.id or time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        if not jid or any(not (c.isalnum() or c in "._-") for c in jid):
            raise SystemExit("invalid job id")
        cmd_args = list(args.command)
        if cmd_args and cmd_args[0] == "--":
            cmd_args = cmd_args[1:]
        if not cmd_args:
            raise SystemExit("job start requires a command")
        cmd = shlex.join(cmd_args)
        enforce_command_policy(cmd, "job", args)
        runner = '''#!/bin/zsh
set +e
d=${0:A:h}
echo RUNNING > "$d/status"
date +%s > "$d/started_at"
trap 'pkill -TERM -P $$ 2>/dev/null || true; echo KILLED > "$d/status"; date +%s > "$d/ended_at"; exit 143' TERM INT HUP
cmd=$(cat "$d/command.txt")
/bin/zsh -lc "$cmd"
rc=$?
echo "$rc" > "$d/rc"
echo EXITED > "$d/status"
date +%s > "$d/ended_at"
exit "$rc"
'''
        cmd_b64 = base64.b64encode(cmd.encode()).decode()
        runner_b64 = base64.b64encode(runner.encode()).decode()
        remote = (
            f'd=$HOME/.macctl/jobs/{q(jid)}; mkdir -p "$d"; '
            f"printf %s {q(cmd_b64)} | /usr/bin/base64 -D > \"$d/command.txt\"; "
            f"printf %s {q(runner_b64)} | /usr/bin/base64 -D > \"$d/runner.sh\"; "
            'chmod 700 "$d/runner.sh"; echo STARTING > "$d/status"; '
            'nohup /bin/zsh "$d/runner.sh" >"$d/log" 2>&1 </dev/null & '
            'p=$!; echo "$p" >"$d/pid"; printf "%s|%s\\n" "${d##*/}" "$p"'
        )
        r = require_ok(ssh_run(remote, timeout=10), "job-start")
        job, pid = r["output"].split("|", 1)
        emit({"status": "STARTED", "job_id": job, "pid": int(pid) if pid.isdigit() else pid})
        return

    if args.action == "list":
        cmd = (
            'd=$HOME/.macctl/jobs; [ -d "$d" ] || exit 0; '
            'for jdir in "$d"/*; do [ -d "$jdir" ] || continue; j=${jdir##*/}; '
            'p=$(cat "$jdir/pid" 2>/dev/null || echo -); s=$(cat "$jdir/status" 2>/dev/null || echo UNKNOWN); '
            'rc=$(cat "$jdir/rc" 2>/dev/null || echo -); st=$(cat "$jdir/started_at" 2>/dev/null || echo -); et=$(cat "$jdir/ended_at" 2>/dev/null || echo -); '
            'if [ "$s" = RUNNING ] && ! kill -0 "$p" 2>/dev/null; then s=STALE; fi; '
            'printf "%s|%s|%s|%s|%s|%s\\n" "$j" "$p" "$s" "$rc" "$st" "$et"; done'
        )
    elif args.action == "status":
        jid = q(args.id)
        cmd = (
            f'd=$HOME/.macctl/jobs/{jid}; [ -d "$d" ] || {{ echo NOT_FOUND; exit 66; }}; '
            'p=$(cat "$d/pid" 2>/dev/null || echo -); s=$(cat "$d/status" 2>/dev/null || echo UNKNOWN); '
            'rc=$(cat "$d/rc" 2>/dev/null || echo -); st=$(cat "$d/started_at" 2>/dev/null || echo -); et=$(cat "$d/ended_at" 2>/dev/null || echo -); '
            'if [ "$s" = RUNNING ] && ! kill -0 "$p" 2>/dev/null; then s=STALE; fi; '
            'printf "%s|%s|%s|%s|%s\\n" "$p" "$s" "$rc" "$st" "$et"'
        )
    elif args.action == "log":
        cmd = f"tail -n {args.lines} -- $HOME/.macctl/jobs/{q(args.id)}/log"
    elif args.action == "kill":
        jid = q(args.id)
        sig = q(args.signal.upper())
        cmd = (
            f'd=$HOME/.macctl/jobs/{jid}; [ -d "$d" ] || {{ echo NOT_FOUND; exit 66; }}; '
            'p=$(cat "$d/pid" 2>/dev/null) || exit 66; '
            f'kill -s {sig} "$p" 2>/dev/null || true; /bin/sleep 0.3; '
            'if kill -0 "$p" 2>/dev/null; then kill -KILL "$p" 2>/dev/null || true; fi; '
            'echo KILLED > "$d/status"; date +%s > "$d/ended_at"; echo "$p|KILLED"'
        )
    elif args.action == "cleanup":
        days = max(0, int(args.older_than_days))
        cmd = (
            'd=$HOME/.macctl/jobs; [ -d "$d" ] || { echo CLEANED=0; exit 0; }; '
            f'cutoff=$(( $(date +%s) - {days}*86400 )); n=0; '
            'for jdir in "$d"/*; do [ -d "$jdir" ] || continue; '
            's=$(cat "$jdir/status" 2>/dev/null || echo UNKNOWN); et=$(cat "$jdir/ended_at" 2>/dev/null || echo 0); '
            'case "$s" in RUNNING|STARTING) continue;; esac; '
            'if [ "$et" -gt 0 ] 2>/dev/null && [ "$et" -le "$cutoff" ]; then rm -rf -- "$jdir"; n=$((n+1)); fi; done; '
            'echo CLEANED=$n'
        )
    else:
        raise SystemExit(64)

    r = ssh_run(cmd, timeout=15, cap=getattr(args, "max_bytes", DEFAULT_CAP))
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])


def _messaging_decode_helper(result, label):
    if result.get("rc") != 0:
        raise MessagingError(f"{label}_helper_failed")
    try:
        payload=json.loads(result.get("output") or "{}")
    except Exception as exc:
        raise MessagingError(f"{label}_invalid_json") from exc
    if payload.get("status") != "PASS":
        raise MessagingError(f"{label}_not_pass")
    return payload


def _messaging_observe_binding(binding):
    provider=str(binding.get("provider") or "")
    if provider != "wechat":
        raise MessagingError("live_adapter_not_implemented_for_provider")
    front=_messaging_decode_helper(helper_gui_run("frontmost",timeout=10,cap=8000),"frontmost")
    expected_bundle=str(binding.get("bundle_id") or "")
    if front.get("bundle_id") != expected_bundle:
        raise MessagingError("expected_messaging_app_not_frontmost")
    inventory=_messaging_decode_helper(helper_gui_run("accessibility-inventory",timeout=15,cap=40000),"accessibility_inventory")
    if inventory.get("bundle_id") != expected_bundle:
        raise MessagingError("accessibility_bundle_mismatch")
    visual=_messaging_decode_helper(helper_gui_run("screen-ocr",timeout=20,cap=50000),"screen_ocr")
    width=int(visual.get("width") or 0); height=int(visual.get("height") or 0)
    ocr=visual.get("ocr") if isinstance(visual.get("ocr"),dict) else {}
    items=ocr.get("items") if isinstance(ocr.get("items"),list) else []
    login_state=messaging_detect_login_state(provider,items)
    if login_state == "LOGIN_REQUIRED":
        raise MessagingError("messaging_login_required")
    windows=inventory.get("windows") if isinstance(inventory.get("windows"),list) else []
    candidates=[w for w in windows if isinstance(w,dict) and isinstance(w.get("frame"),dict)]
    if not candidates:
        raise MessagingError("messaging_window_missing")
    main=max(candidates,key=lambda w: float(w["frame"].get("width",0))*float(w["frame"].get("height",0)))
    window=main["frame"]
    if float(window.get("width",0)) < 500 or float(window.get("height",0)) < 400:
        raise MessagingError("messaging_main_window_not_ready")
    contact=str(binding.get("contact") or "")
    contact_candidates=messaging_exact_text_candidates(items,contact,screen_width=width,screen_height=height,window=window)
    header=messaging_select_header_candidate(contact_candidates,window)
    send_candidates=messaging_exact_text_candidates(items,"发送",screen_width=width,screen_height=height,window=window)
    return {
        "status":"PASS",
        "provider":provider,
        "bundle_id":expected_bundle,
        "binding_id":binding.get("binding_id"),
        "contact_sha256":binding.get("contact_sha256"),
        "selected_contact":contact,
        "selected_contact_exact":True,
        "login_state":login_state,
        "window":window,
        "header_rect":header["rect"],
        "send_rect":send_candidates[0]["rect"] if len(send_candidates) == 1 else None,
        "send_button_count":len(send_candidates),
        "screen":{"width":width,"height":height},
        "ocr_items":items,
    }


def _messaging_stage_message_file(local_path, sha256_value):
    token=uuid.uuid4().hex
    remote=f"/private/tmp/macctl-message-{token}.txt"
    pushed=run(remote_scp_argv(ssh_config=SSH_CONFIG,target=TARGET,local_path=str(local_path),remote_path=remote,direction="push"),timeout=20,cap=4096)
    if pushed["rc"] != 0:
        raise MessagingError("message_stage_push_failed")
    q=shlex.quote
    check=ssh_run(f"chmod 600 {q(remote)} && test -f {q(remote)} && [ \"$(stat -f %Su {q(remote)})\" = \"$(id -un)\" ] && [ \"$(shasum -a 256 {q(remote)} | awk '{{print $1}}')\" = {q(sha256_value)} ]",timeout=10,cap=2048)
    if check["rc"] != 0:
        try: ssh_run(f"rm -f {q(remote)}",timeout=5,cap=512)
        except Exception: pass
        raise MessagingError("message_stage_integrity_failed")
    return remote


def _messaging_token_regions(observed, token):
    if not token:
        return None
    screen=observed.get("screen") if isinstance(observed.get("screen"),dict) else {}
    return messaging_token_region_evidence(
        observed.get("ocr_items") or [],
        str(token),
        screen_width=int(screen.get("width") or 0),
        screen_height=int(screen.get("height") or 0),
        window=observed.get("window") or {},
    )


def cmd_messaging(args):
    try:
        if args.action == "bind":
            binding=build_binding(args.provider,args.contact,allow_read=True,allow_draft=True,allow_send=bool(args.allow_send))
            MESSAGING_STORE.save_binding(binding)
            emit({"status":"PASS","operation":"messaging_bind","binding":messaging_public_binding(binding),"message_body_persisted":False})
            return
        if args.action == "list":
            MESSAGING_STORE._ensure()
            rows=[]
            for path in sorted(MESSAGING_STORE.bindings.glob("msgb_*.json")):
                try: rows.append(messaging_public_binding(json.loads(path.read_text(encoding="utf-8"))))
                except Exception: continue
            emit({"status":"PASS","operation":"messaging_list","bindings":rows,"count":len(rows)})
            return
        if args.action == "observe":
            binding=MESSAGING_STORE.load_binding(args.binding_id)
            gate=evaluate_messaging_action(binding,"read",selected_contact=binding.get("contact"))
            if not gate.get("allowed"):
                emit({"status":"BLOCKED","operation":"messaging_observe","gate":gate}); raise SystemExit(77)
            observed=_messaging_observe_binding(binding)
            emit({k:v for k,v in observed.items() if k != "ocr_items"})
            return
        if args.action == "read":
            binding=MESSAGING_STORE.load_binding(args.binding_id)
            gate=evaluate_messaging_action(binding,"read",selected_contact=binding.get("contact"))
            if not gate.get("allowed"):
                emit({"status":"BLOCKED","operation":"messaging_read","gate":gate}); raise SystemExit(77)
            observed=_messaging_observe_binding(binding)
            screen=observed.get("screen") or {}
            rows=messaging_visible_region_texts(
                observed.get("ocr_items") or [],
                region="HISTORY",
                screen_width=int(screen.get("width") or 0),
                screen_height=int(screen.get("height") or 0),
                window=observed.get("window") or {},
                limit=int(args.limit),
                exclude_texts={str(binding.get("contact") or ""), "发送"},
            )
            emit({"status":"PASS","operation":"messaging_read","binding_id":binding["binding_id"],"contact_sha256":binding["contact_sha256"],"visible_items":[{"text":r["text"],"confidence":r.get("confidence")} for r in rows],"count":len(rows),"message_body_persisted":False,"source":"ScreenCaptureKit+AppleVision_visible_history_only"})
            return
        if args.action == "draft":
            binding=MESSAGING_STORE.load_binding(args.binding_id)
            observed=_messaging_observe_binding(binding)
            gate=evaluate_messaging_action(binding,"draft",selected_contact=observed["selected_contact"])
            if not gate.get("allowed"):
                emit({"status":"BLOCKED","operation":"messaging_draft","gate":gate}); raise SystemExit(77)
            _data,meta=messaging_load_message_file(args.message_file)
            draft=build_draft(binding,meta)
            if bool(getattr(args,"adopt_existing",False)):
                if not args.expect_token:
                    raise MessagingError("adopt_existing_expect_token_required")
                region_evidence=_messaging_token_regions(observed,args.expect_token)
                counts=region_evidence["counts"]
                if counts.get("HISTORY",0) > 0:
                    raise MessagingError("adopt_existing_token_already_in_history")
                if counts.get("COMPOSER",0) < 1:
                    raise MessagingError("adopt_existing_token_not_in_composer")
                draft["state"]="DRAFTED_UI_VERIFIED_ADOPTED"
                draft["expect_token_sha256"]=region_evidence["token_sha256"]
                MESSAGING_STORE.save_draft(draft)
                emit({"status":"PASS","operation":"messaging_draft_adopted","draft_id":draft["draft_id"],"binding_id":draft["binding_id"],"message_sha256":draft["message_sha256"],"message_bytes":draft["message_bytes"],"message_chars":draft["message_chars"],"message_body_persisted":False,"visual_postcondition":"COMPOSER_PASS","region_counts":counts})
                return
            remote=None
            try:
                remote=_messaging_stage_message_file(args.message_file,meta["sha256"])
                window=observed["window"]
                # Fixed composer band, independent of whether the Send button is
                # currently visible. Exact contact/header binding was already
                # revalidated immediately above.
                x=float(window["x"])+float(window["width"])*0.60
                y=float(window["y"])+float(window["height"])*0.82
                click=helper_gui_run("mouse-click",timeout=10,cap=4096,extra_args=["--x",str(round(x,1)),"--y",str(round(y,1)),"--button","left","--count","1"])
                if click["rc"] != 0: raise MessagingError("composer_focus_failed")
                typed=helper_gui_run("type-text-file",timeout=15,cap=8192,extra_args=["--text-file",remote])
                remote=None
                if typed["rc"] != 0: raise MessagingError("secure_message_typing_failed")
                time.sleep(0.6)
                observed_after=_messaging_observe_binding(binding)
                region_evidence=_messaging_token_regions(observed_after,args.expect_token) if args.expect_token else None
                if region_evidence:
                    counts=region_evidence["counts"]
                    if counts.get("HISTORY",0) > 0:
                        draft["state"]="UNEXPECTED_SENT_DURING_DRAFT"
                        draft["expect_token_sha256"]=region_evidence["token_sha256"]
                        MESSAGING_STORE.save_draft(draft)
                        receipt_path=MESSAGING_STORE.save_receipt(draft,result="UNEXPECTED_SENT_DURING_DRAFT_VISUAL_RECOVERY")
                        emit({"status":"INDETERMINATE_RECOVERED","operation":"messaging_draft","draft_id":draft["draft_id"],"binding_id":draft["binding_id"],"message_sha256":draft["message_sha256"],"receipt":receipt_path.name,"reason":"draft_text_observed_in_history","message_body_persisted":False,"region_counts":counts})
                        raise SystemExit(75)
                    if counts.get("COMPOSER",0) < 1:
                        raise MessagingError("draft_visual_postcondition_not_in_composer")
                draft["state"]="DRAFTED_UI_VERIFIED"
                draft["expect_token_sha256"]=hashlib.sha256(str(args.expect_token or "").encode()).hexdigest() if args.expect_token else None
                MESSAGING_STORE.save_draft(draft)
                emit({"status":"PASS","operation":"messaging_draft","draft_id":draft["draft_id"],"binding_id":draft["binding_id"],"message_sha256":draft["message_sha256"],"message_bytes":draft["message_bytes"],"message_chars":draft["message_chars"],"message_body_persisted":False,"visual_postcondition":"COMPOSER_PASS" if args.expect_token else "NOT_REQUESTED","region_counts":region_evidence["counts"] if region_evidence else None})
                return
            finally:
                if remote:
                    try: ssh_run(f"rm -f {shlex.quote(remote)}",timeout=5,cap=512)
                    except Exception: pass
        if args.action == "send":
            draft=MESSAGING_STORE.load_draft(args.draft_id)
            binding=MESSAGING_STORE.load_binding(draft["binding_id"])
            observed=_messaging_observe_binding(binding)
            prior=MESSAGING_STORE.sent_hashes(binding["binding_id"])
            rate_window=max(1,int(CFG.get("messaging_rate_limit_window_seconds",MESSAGING_DEFAULT_RATE_LIMIT_WINDOW_SECONDS)))
            rate_count=max(1,int(CFG.get("messaging_rate_limit_count",MESSAGING_DEFAULT_RATE_LIMIT_COUNT)))
            recent_count=MESSAGING_STORE.recent_sent_count(binding["binding_id"],window_seconds=rate_window)
            gate=evaluate_messaging_action(binding,"send",selected_contact=observed["selected_contact"],confirm=bool(args.confirm),message_sha256=draft.get("message_sha256"),prior_sent_sha256=prior,recent_send_count=recent_count,rate_limit_count=rate_count)
            if not gate.get("allowed"):
                emit({"status":"BLOCKED","operation":"messaging_send","gate":gate}); raise SystemExit(77)
            before_regions=_messaging_token_regions(observed,args.expect_token) if args.expect_token else None
            if before_regions:
                counts=before_regions["counts"]
                # Recovery path for an indeterminate prior attempt: if the unique
                # token is already in history and absent from the composer, record
                # the send without clicking again.
                if counts.get("HISTORY",0) > 0 and counts.get("COMPOSER",0) == 0:
                    receipt_path=MESSAGING_STORE.save_receipt(draft,result="SENT_VISUAL_RECOVERED_PREEXISTING")
                    emit({"status":"PASS","operation":"messaging_send_recovered","binding_id":binding["binding_id"],"draft_id":draft["draft_id"],"message_sha256":draft["message_sha256"],"receipt":receipt_path.name,"message_body_persisted":False,"duplicate_suppression":True,"postcondition":"HISTORY_PASS","region_counts":counts})
                    return
                if counts.get("COMPOSER",0) < 1:
                    raise MessagingError("send_draft_not_observed_in_composer")
            if observed.get("send_button_count") != 1 or not isinstance(observed.get("send_rect"),dict):
                raise MessagingError("send_button_not_unique")
            send=observed["send_rect"]
            click=helper_gui_run("mouse-click",timeout=10,cap=4096,extra_args=["--x",str(round(float(send["cx"]),1)),"--y",str(round(float(send["cy"]),1)),"--button","left","--count","1"])
            if click["rc"] != 0: raise MessagingError("send_click_failed")
            time.sleep(0.9)
            observed_after=_messaging_observe_binding(binding)
            after_regions=_messaging_token_regions(observed_after,args.expect_token) if args.expect_token else None
            if after_regions:
                counts=after_regions["counts"]
                if counts.get("HISTORY",0) < 1 or counts.get("COMPOSER",0) > 0:
                    raise MessagingError("send_visual_postcondition_failed")
            receipt_path=MESSAGING_STORE.save_receipt(draft,result="SENT_VISUAL_VERIFIED" if args.expect_token else "SENT_DISPATCHED")
            emit({"status":"PASS","operation":"messaging_send","binding_id":binding["binding_id"],"draft_id":draft["draft_id"],"message_sha256":draft["message_sha256"],"receipt":receipt_path.name,"message_body_persisted":False,"duplicate_suppression":True,"postcondition":"HISTORY_PASS" if args.expect_token else "DISPATCH_ONLY","region_counts":after_regions["counts"] if after_regions else None})
            return
        raise MessagingError("unsupported_messaging_action")
    except MessagingError as e:
        reason=str(e)
        if reason == "messaging_login_required":
            emit({"status":"WAITING","schema":"macctl-delegated-messaging/v1","operation":f"messaging_{getattr(args,'action',None)}","reason":reason,"recovery_hint":"login_to_messaging_app_then_retry"})
            raise SystemExit(2)
        emit({"status":"FAIL","schema":"macctl-delegated-messaging/v1","operation":f"messaging_{getattr(args,'action',None)}","reason":reason})
        raise SystemExit(1)


def cmd_clipboard(args):
    if args.action == "get":
        r = helper_gui_run("clipboard-get", timeout=10, cap=max(8192, int(args.max_bytes) * 6 + 4096))
        if r["rc"] != 0:
            if r.get("output"):
                print(r["output"])
            raise SystemExit(r["rc"])
        try:
            payload = json.loads(r.get("output", ""))
            text = str(payload.get("text", ""))
        except Exception:
            print("clipboard helper returned invalid JSON", file=sys.stderr)
            raise SystemExit(70)
        data = text.encode("utf-8", "surrogatepass")
        if len(data) > int(args.max_bytes):
            sys.stdout.buffer.write(data[: int(args.max_bytes)])
            raise SystemExit(75)
        sys.stdout.write(text)
        return
    text = args.text if args.text is not None else sys.stdin.read()
    r = helper_gui_run(
        "clipboard-set",
        timeout=10,
        cap=8192,
        extra_args=["--text", text],
    )
    if r["rc"] != 0 and r.get("output"):
        print(r["output"])
    raise SystemExit(r["rc"])

def helper_gui_run(subcommand, timeout=15, cap=4096, extra_args=None):
    token = uuid.uuid4().hex[:10]
    out = f"/tmp/macctl-helper-{token}.json"
    q = shlex.quote
    arg_text = " ".join(q(str(x)) for x in (extra_args or []))
    remote = (
        f"out={q(out)}; app=\"$HOME/Applications/MacCtl Helper.app\"; rm -f \"$out\"; "
        f"open -n -g \"$app\" --args {q(subcommand)} {arg_text} --output \"$out\" >/dev/null 2>&1 || exit 69; "
        f"i=0; while [ ! -s \"$out\" ] && [ $i -lt {max(5, int(max(1, timeout - 4) * 10))} ]; do sleep 0.1; i=$((i+1)); done; "
        "if [ ! -s \"$out\" ]; then "
        "pids=$(pgrep -f \"MacCtlHelper.*--output $out\" 2>/dev/null || true); "
        "for p in $pids; do kill -TERM \"$p\" 2>/dev/null || true; done; sleep 0.2; "
        "for p in $pids; do kill -KILL \"$p\" 2>/dev/null || true; done; "
        "printf '{\"status\":\"FAIL\",\"error\":\"helper_gui_timeout\"}\\n'; rm -f \"$out\"; exit 124; fi; "
        "cat \"$out\"; rc=$?; rm -f \"$out\"; exit $rc"
    )
    result = ssh_run(remote, timeout=timeout, cap=cap)
    if result["rc"] == 0 and result.get("output"):
        try:
            payload = json.loads(result["output"])
            state = payload.get("status")
            if state == "FAIL":
                result["rc"] = 1
            elif state == "TIMEOUT":
                result["rc"] = 75
            elif state == "NEEDS_USER_APPROVAL":
                result["rc"] = 2
            elif state == "REQUESTED" and not payload.get("accessibility", payload.get("screen_recording", False)):
                result["rc"] = 2
        except Exception:
            pass
    return result


def _rank_ax_inventory(payload, args):
    return rank_ax_inventory(
        payload,
        {
            "bundle": args.bundle,
            "role": args.role,
            "subrole": args.subrole,
            "title": args.title,
            "description": args.description,
            "value": args.value,
        },
        min_score=int(args.min_score),
        min_margin=int(args.min_margin),
    )


def _ranked_semantic_gui(args):
    if not (0 <= int(args.min_score) <= 100) or not (0 <= int(args.min_margin) <= 100):
        emit({"status": "FAIL", "reason": "invalid_rank_threshold", "min_score": args.min_score, "min_margin": args.min_margin})
        raise SystemExit(64)
    cap = max(int(args.max_bytes), 32768)
    inv = helper_gui_run("accessibility-inventory", timeout=args.timeout, cap=cap)
    if inv["rc"] != 0 or not inv.get("output"):
        if inv.get("output"):
            print(inv["output"])
        raise SystemExit(inv["rc"] or 1)
    try:
        payload = json.loads(inv["output"])
    except Exception:
        emit({"status": "FAIL", "reason": "invalid_accessibility_inventory_json"})
        raise SystemExit(1)

    ranked = _rank_ax_inventory(payload, args)
    if ranked.get("status") != "PASS":
        emit(ranked)
        raise SystemExit(1)
    if args.action == "semantic-find":
        emit(ranked)
        return

    selection = choose_ranked_match(
        ranked,
        min_margin=int(args.min_margin),
        value_requested=bool(args.value),
    )
    if selection.get("status") != "PASS":
        ranked["status"] = "FAIL"
        ranked["operation"] = "semantic_press_ranked"
        ranked["reason"] = selection.get("reason")
        for key in ("top_score", "second_score", "score_margin"):
            if key in selection:
                ranked[key] = selection[key]
        emit(ranked)
        raise SystemExit(int(selection.get("exit_code", 1)))

    top = selection["top"]
    second = selection.get("second")
    margin = selection["score_margin"]

    exact_args = ["--bundle", ranked.get("bundle_id", "")]
    if top.get("role"):
        exact_args += ["--role", top["role"]]
    if top.get("subrole"):
        exact_args += ["--subrole", top["subrole"]]
    for flag, field, wanted in (
        ("--title", "title", args.title),
        ("--description", "description", args.description),
        ("--value", "value", args.value),
    ):
        if wanted:
            exact_args += [flag, top.get(field, "")]

    pressed = helper_gui_run(
        "accessibility-semantic-press",
        timeout=args.timeout,
        cap=max(int(args.max_bytes), 12000),
        extra_args=exact_args,
    )
    if pressed.get("output"):
        try:
            result = json.loads(pressed["output"])
            result["ranked_selection"] = {
                "source_ref": top.get("ref", ""),
                "score": top["score"],
                "second_score": second["score"] if second else None,
                "score_margin": margin,
                "min_score": int(args.min_score),
                "min_margin": int(args.min_margin),
                "field_scores": top.get("field_scores") or {},
                "action_time_re_resolved": True,
            }
            emit(result)
        except Exception:
            print(pressed["output"])
    raise SystemExit(pressed["rc"])


def _browser_session_public(record):
    return {
        "schema": record.get("schema", "macctl-browser-session/v1"),
        "session_id": record.get("session_id"),
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "allow_hosts": record.get("allow_hosts") or [],
        "allow_loopback": bool(record.get("allow_loopback")),
        "site_class": record.get("site_class", "synthetic"),
        "qualification_scope": record.get("qualification_scope", "read_only"),
        "authorized_action_id": record.get("authorized_action_id"),
        "credential_entry": record.get("credential_entry", "NOT_EXPOSED_PHASE3"),
        "chrome_product": record.get("chrome_product"),
        "protocol_version": record.get("protocol_version"),
        "profile_isolated": bool(record.get("profile_isolated", True)),
        "default_profile_touched": bool(record.get("default_profile_touched", False)),
        "active_target_id": record.get("active_target_id"),
        "automation_schema": "macctl-browser-automation/v1",
    }


def _browser_session_fail(error, *, status="FAIL", rc=66):
    emit({
        "status": status,
        "schema": "macctl-browser-session/v1",
        "reason": getattr(error, "reason", str(error)),
        "detail": getattr(error, "detail", None),
    })
    raise SystemExit(rc)


def _browser_session_record(session_id, *, allow_expired=False):
    try:
        return BROWSER_SESSION_STORE.load(validate_session_id(session_id), allow_expired=allow_expired)
    except BrowserSessionError as e:
        _browser_session_fail(e, rc=66)


def _browser_session_enforce_action(record, action, args):
    policy = evaluate_session_action_policy(
        record,
        action,
        confirmed=bool(getattr(args, "confirm", False)),
        production_confirmed=bool(getattr(args, "confirm_production", False)),
        input_class=str(getattr(args, "input_class", "plain") or "plain"),
    )
    if not policy.get("allowed"):
        emit({
            "status":"BLOCKED",
            "schema":"macctl-browser-session/v1",
            "reason":"production_session_policy_denied",
            "production_policy":policy,
            "session_id":record.get("session_id"),
        })
        raise SystemExit(77)
    return policy


def _browser_session_target(record):
    local_port = int(record["local_port"])
    items = cdp_http_json(local_port, "/json/list", timeout=3)
    pages = [x for x in parse_targets(items) if x.type == "page"]
    active_id = str(record.get("active_target_id") or "")
    if active_id:
        matches = [x for x in pages if x.id == active_id]
        if len(matches) != 1:
            raise BrowserSessionError("active_page_target_missing")
        return matches[0]
    if len(pages) == 1:
        return pages[0]
    # Prefer the sole non-about:blank page for backwards-compatible single-tab sessions.
    nonblank = [x for x in pages if x.url != "about:blank"]
    if len(nonblank) == 1:
        return nonblank[0]
    raise BrowserSessionError("multiple_page_targets_activate_required", str(len(pages)))


def _browser_session_current(record, *, timeout=5):
    page = _browser_session_target(record)
    with CdpClient(rewrite_ws_url(page.websocket_url, int(record["local_port"])), timeout=timeout) as cdp:
        cdp.call("Page.enable")
        cdp.call("Runtime.enable")
        snapshot = cdp_evaluate(cdp, page_snapshot_expression(), timeout=timeout)
    policy = evaluate_url_policy(
        snapshot.get("url") or "",
        allow_hosts=record.get("allow_hosts") or [],
        allow_loopback=bool(record.get("allow_loopback")),
    )
    if not policy.get("allowed"):
        raise BrowserSessionError("current_page_outside_session_policy", policy.get("reason"))
    return snapshot


def _browser_session_visual(expect_text=None, *, attempts=4, interval=0.25):
    last = {"rc": 1, "output": ""}
    payload = {}
    seen = False
    for idx in range(max(1, int(attempts))):
        last = helper_gui_run("screen-ocr", timeout=20, cap=32000)
        payload = {}
        if last.get("output"):
            try:
                payload = json.loads(last["output"])
            except Exception:
                payload = {}
        items = ((payload.get("ocr") or {}).get("items") or [])
        text = "\n".join(str(x.get("text") or "") for x in items)
        seen = True if not expect_text else str(expect_text) in text
        if last.get("rc") == 0 and seen:
            break
        if idx + 1 < max(1, int(attempts)):
            time.sleep(max(0.0, float(interval)))
    return {
        "status": "PASS" if last.get("rc") == 0 and seen else "FAIL",
        "backend": payload.get("backend"),
        "ocr_count": (payload.get("ocr") or {}).get("count"),
        "expect_text": expect_text,
        "expect_text_seen": seen,
    }


def _browser_session_tunnel_matches(record):
    return pid_matches(
        int(record.get("tunnel_pid") or 0),
        [
            "ssh",
            "-N",
            "-L",
            f"127.0.0.1:{int(record['local_port'])}:127.0.0.1:{int(record['remote_port'])}",
            TARGET,
        ],
    )


def _browser_session_remote_cleanup(record):
    q = shlex.quote
    profile = str(record.get("remote_profile") or "")
    download_dir = str(record.get("remote_download_dir") or "")
    upload_dir = str(record.get("remote_upload_dir") or "")
    session_id = validate_session_id(record.get("session_id"))
    expected_profile = f"/tmp/macctl-r2-session-{session_id}"
    expected_download = f"/tmp/macctl-r2-download-{session_id}"
    expected_upload = f"/tmp/macctl-r4-upload-{session_id}"
    if profile != expected_profile or download_dir != expected_download:
        raise BrowserSessionError("session_cleanup_path_mismatch")
    if upload_dir and upload_dir != expected_upload:
        raise BrowserSessionError("session_upload_cleanup_path_mismatch")
    cleanup = (
        f"pids=$(pgrep -f {q('[G]oogle Chrome.*--user-data-dir=' + profile)} 2>/dev/null || true); "
        "for p in $pids; do kill -TERM \"$p\" 2>/dev/null || true; done; sleep 0.3; "
        "for p in $pids; do kill -KILL \"$p\" 2>/dev/null || true; done; "
        f"rm -rf {q(profile)} {q(download_dir)}" + (f" {q(upload_dir)}" if upload_dir else "")
    )
    return ssh_run(cleanup, timeout=10, cap=4096)


def _browser_session_start(args):
    q = shlex.quote
    session_id = validate_session_id(args.session_id or ("r2-" + uuid.uuid4().hex[:16]))
    try:
        qualification = validate_qualification_config(
            site_class=args.site_class,
            qualification_scope=args.qualification_scope,
            allow_hosts=args.allow_host or [],
            allow_loopback=bool(args.allow_loopback),
            authorized_action_id=args.authorized_action_id,
        )
    except BrowserSessionError as e:
        _browser_session_fail(e, status="BLOCKED", rc=77)
    remote_profile = f"/tmp/macctl-r2-session-{session_id}"
    remote_download_dir = f"/tmp/macctl-r2-download-{session_id}"
    remote_upload_dir = f"/tmp/macctl-r4-upload-{session_id}"
    remote_port = None
    local_port = free_tcp_port()
    tunnel = None
    record = None
    frontmost_bundle = None
    try:
        try:
            BROWSER_SESSION_STORE.load(session_id, allow_expired=True)
        except BrowserSessionError as e:
            if e.reason != "session_not_found":
                raise
        else:
            raise BrowserSessionError("session_already_exists")

        front = helper_gui_run("frontmost", timeout=10, cap=4096)
        if front.get("rc") == 0 and front.get("output"):
            try:
                fp = json.loads(front["output"])
                frontmost_bundle = fp.get("bundle_id") or fp.get("bundle")
            except Exception:
                pass

        for _ in range(16):
            candidate = 42000 + (int(uuid.uuid4().hex[:6], 16) % 18000)
            probe = ssh_run(f"/usr/bin/nc -z 127.0.0.1 {candidate}", timeout=4, cap=1024)
            if probe["rc"] != 0:
                remote_port = candidate
                break
        if remote_port is None:
            raise BrowserSessionError("remote_debug_port_unavailable")

        prefs = json.dumps({
            "download": {
                "default_directory": remote_download_dir,
                "prompt_for_download": False,
                "directory_upgrade": True,
            }
        }, ensure_ascii=False, separators=(",", ":"))
        prefs_path = remote_profile + "/Default/Preferences"
        setup_profile = ssh_run(
            f"mkdir -p {q(remote_download_dir)} {q(remote_upload_dir)} {q(remote_profile + '/Default')} && "
            f"chmod 700 {q(remote_download_dir)} {q(remote_upload_dir)} {q(remote_profile)} && "
            f"printf '%s\\n' {q(prefs)} > {q(prefs_path)}",
            timeout=8, cap=2048,
        )
        if setup_profile["rc"] != 0:
            raise BrowserSessionError("browser_session_profile_setup_failed", setup_profile.get("output", "")[:300])
        launch = (
            f"/usr/bin/open -na {q('Google Chrome')} --args "
            f"--remote-debugging-address=127.0.0.1 --remote-debugging-port={remote_port} "
            f"--user-data-dir={q(remote_profile)} --no-first-run --no-default-browser-check "
            f"--disable-sync --disable-default-apps about:blank"
        )
        started = ssh_run(launch, timeout=12, cap=4096)
        if started["rc"] != 0:
            raise BrowserSessionError("browser_session_chrome_launch_failed", started.get("output", "")[:300])

        tunnel_argv = [
            "ssh", "-F", SSH_CONFIG,
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ExitOnForwardFailure=yes",
            "-N", "-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", TARGET,
        ]
        tunnel = subprocess.Popen(
            tunnel_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.25)
        if tunnel.poll() is not None:
            raise BrowserSessionError("ssh_forward_failed")
        version = cdp_wait_http_json(local_port, "/json/version", timeout=12)
        record = build_session_record(
            session_id=session_id,
            local_port=local_port,
            remote_port=remote_port,
            tunnel_pid=tunnel.pid,
            remote_profile=remote_profile,
            remote_download_dir=remote_download_dir,
            remote_upload_dir=remote_upload_dir,
            allow_hosts=qualification["allow_hosts"],
            allow_loopback=qualification["allow_loopback"],
            ttl_seconds=args.ttl_seconds,
            chrome_product=version.get("Browser"),
            protocol_version=version.get("Protocol-Version"),
            site_class=qualification["site_class"],
            qualification_scope=qualification["qualification_scope"],
            authorized_action_id=qualification["authorized_action_id"],
        )
        record["frontmost_bundle_before"] = frontmost_bundle
        BROWSER_SESSION_STORE.save(record, create_only=True)
        emit({
            "status": "PASS",
            "schema": "macctl-browser-session/v1",
            "operation": "session_start",
            "session": _browser_session_public(record),
            "transport": "MAC_LOOPBACK_OVER_PINNED_SSH_FORWARD",
            "remote_debug_bind": "127.0.0.1",
            "raw_runtime_evaluate_cli": "NOT_EXPOSED",
        })
        return
    except BrowserSessionError as e:
        if tunnel is not None and tunnel.poll() is None:
            try:
                tunnel.terminate()
            except Exception:
                pass
        if record is None:
            cleanup_record = {
                "session_id": session_id,
                "remote_profile": remote_profile,
                "remote_download_dir": remote_download_dir,
                "remote_upload_dir": remote_upload_dir,
            }
            try:
                _browser_session_remote_cleanup(cleanup_record)
            except Exception:
                pass
        _browser_session_fail(e, rc=1)


def _browser_session_stop(args):
    record = _browser_session_record(args.session_id, allow_expired=True)
    browser_close = False
    tunnel_killed = False
    try:
        try:
            version = cdp_http_json(int(record["local_port"]), "/json/version", timeout=2)
            ws = str(version.get("webSocketDebuggerUrl") or "")
            if ws:
                try:
                    with CdpClient(rewrite_ws_url(ws, int(record["local_port"])), timeout=4) as cdp:
                        cdp.call("Browser.close", timeout=3)
                except BrowserCdpError as e:
                    if "closed_by_peer" not in str(e) and "websocket_eof" not in str(e):
                        raise
                browser_close = True
        except Exception:
            browser_close = False

        pid = int(record.get("tunnel_pid") or 0)
        if pid_alive(pid) and _browser_session_tunnel_matches(record):
            try:
                os.kill(pid, 15)
                tunnel_killed = True
            except ProcessLookupError:
                tunnel_killed = True
        elif not pid_alive(pid):
            tunnel_killed = True

        _browser_session_remote_cleanup(record)
        bundle = record.get("frontmost_bundle_before")
        if bundle:
            try:
                ssh_run(f"/usr/bin/open -b {shlex.quote(str(bundle))}", timeout=8, cap=2048)
            except Exception:
                pass
        BROWSER_SESSION_STORE.delete(record["session_id"])
        emit({
            "status": "PASS" if tunnel_killed else "DEGRADED",
            "schema": "macctl-browser-session/v1",
            "operation": "session_stop",
            "session_id": record["session_id"],
            "browser_close_requested": browser_close,
            "tunnel_cleanup": "PASS" if tunnel_killed else "PID_IDENTITY_MISMATCH_NOT_KILLED",
            "remote_profile_cleanup": "PASS",
        })
        raise SystemExit(0 if tunnel_killed else 2)
    except BrowserSessionError as e:
        _browser_session_fail(e, rc=1)


def _browser_session_status(args):
    record = _browser_session_record(args.session_id, allow_expired=True)
    expired = False
    try:
        BROWSER_SESSION_STORE.load(record["session_id"], allow_expired=False)
    except BrowserSessionError as e:
        expired = e.reason == "session_expired"
    pid = int(record.get("tunnel_pid") or 0)
    tunnel_alive = pid_alive(pid)
    tunnel_identity = tunnel_alive and _browser_session_tunnel_matches(record)
    cdp_ready = False
    current = None
    if tunnel_identity and not expired:
        try:
            cdp_http_json(int(record["local_port"]), "/json/version", timeout=2)
            cdp_ready = True
            current = _browser_session_current(record, timeout=3)
        except Exception:
            cdp_ready = False
    emit({
        "status": "PASS" if cdp_ready and not expired else "DEGRADED",
        "schema": "macctl-browser-session/v1",
        "operation": "session_status",
        "session": _browser_session_public(record),
        "expired": expired,
        "tunnel_alive": tunnel_alive,
        "tunnel_identity_verified": tunnel_identity,
        "cdp_ready": cdp_ready,
        "current_page": current,
    })
    raise SystemExit(0 if cdp_ready and not expired else 2)


def _browser_session_navigate(args):
    record = _browser_session_record(args.session_id)
    policy = evaluate_url_policy(
        args.url,
        allow_hosts=record.get("allow_hosts") or [],
        allow_loopback=bool(record.get("allow_loopback")),
    )
    if not policy.get("allowed"):
        emit({"status":"BLOCKED","schema":"macctl-browser-session/v1","reason":"url_policy_denied","policy":policy})
        raise SystemExit(77)
    try:
        page = _browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url, int(record["local_port"])), timeout=6) as cdp:
            cdp.call("Page.enable")
            cdp.call("Runtime.enable")
            cdp.call("Page.navigate", {"url": args.url}, timeout=6)
            cdp_wait_ready(cdp, timeout=args.timeout)
            after = cdp_evaluate(cdp, page_snapshot_expression())
            redirect_policy = evaluate_url_policy(
                after.get("url") or "",
                allow_hosts=record.get("allow_hosts") or [],
                allow_loopback=bool(record.get("allow_loopback")),
            )
            if not redirect_policy.get("allowed"):
                cdp.call("Page.navigate", {"url": "about:blank"}, timeout=4)
                raise BrowserSessionError("redirect_escaped_url_policy", redirect_policy.get("reason"))
        visual = _browser_session_visual(args.visual_expect_text) if args.visual_expect_text else None
        if visual and visual.get("status") != "PASS":
            raise BrowserSessionError("visual_postcondition_failed")
        emit({
            "status":"PASS","schema":"macctl-browser-session/v1","operation":"session_navigate",
            "session_id":record["session_id"],"requested_url":policy.get("url"),"policy":policy,
            "current_page":after,"redirect_policy":redirect_policy,"visual":visual,
        })
    except (BrowserCdpError, BrowserSessionError) as e:
        if isinstance(e, BrowserSessionError):
            _browser_session_fail(e, rc=1)
        _browser_session_fail(BrowserSessionError("cdp_navigation_failed", str(e)), rc=1)


def _browser_session_query(args):
    record = _browser_session_record(args.session_id)
    try:
        current = _browser_session_current(record, timeout=4)
        page = _browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url, int(record["local_port"])), timeout=5) as cdp:
            cdp.call("Runtime.enable")
            result = cdp_evaluate(cdp, dom_query_expression(args.selector))
        if not result.get("ok"):
            raise BrowserSessionError("selector_not_unique", str(result.get("count")))
        emit({"status":"PASS","schema":"macctl-browser-session/v1","operation":"session_query","session_id":record["session_id"],"current_page":current,"selector":args.selector,"result":result,"action_time_re_resolution":False})
    except (BrowserCdpError, BrowserSessionError) as e:
        if isinstance(e, BrowserSessionError):
            _browser_session_fail(e, rc=1)
        _browser_session_fail(BrowserSessionError("cdp_query_failed", str(e)), rc=1)


def _browser_session_input_text(args):
    text_file = getattr(args, "text_file", None)
    if text_file:
        root = Path("/run/macctl/credentials").resolve()
        requested = Path(text_file)
        if not requested.is_absolute():
            raise BrowserSessionError("credential_text_file_must_be_absolute")
        try:
            resolved = requested.resolve(strict=True)
        except FileNotFoundError:
            raise BrowserSessionError("credential_text_file_missing")
        if resolved.parent != root:
            raise BrowserSessionError("credential_text_file_outside_runtime_root")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(resolved), flags)
        except OSError as e:
            raise BrowserSessionError("credential_text_file_open_failed", str(e))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise BrowserSessionError("credential_text_file_not_regular")
            if st.st_uid != os.geteuid():
                raise BrowserSessionError("credential_text_file_owner_mismatch")
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise BrowserSessionError("credential_text_file_permissions_too_open")
            if st.st_size < 1 or st.st_size > 16384:
                raise BrowserSessionError("credential_text_file_size_invalid")
            raw = os.read(fd, st.st_size + 1)
            if len(raw) != st.st_size:
                raise BrowserSessionError("credential_text_file_read_mismatch")
        finally:
            os.close(fd)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise BrowserSessionError("credential_text_file_not_utf8")
        if "\x00" in text:
            raise BrowserSessionError("credential_text_contains_nul")
        if getattr(args, "consume_text_file", False):
            try:
                resolved.unlink()
            except OSError as e:
                raise BrowserSessionError("credential_text_file_consume_failed", str(e))
        return text, "EPHEMERAL_FILE"
    if str(getattr(args, "input_class", "plain") or "plain") == "credential":
        raise BrowserSessionError("credential_text_file_required")
    if getattr(args, "text", None) is None:
        raise BrowserSessionError("input_text_required")
    return str(args.text), "ARGV"


def _browser_session_type(args):
    record = _browser_session_record(args.session_id)
    _browser_session_enforce_action(record, "session-type", args)
    try:
        text, input_channel = _browser_session_input_text(args)
        current = _browser_session_current(record, timeout=4)
        page = _browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url, int(record["local_port"])), timeout=5) as cdp:
            cdp.call("Runtime.enable")
            pre = cdp_evaluate(cdp, dom_query_expression(args.selector))
            if not pre.get("ok"):
                raise BrowserSessionError("selector_not_unique", str(pre.get("count")))
            action = cdp_evaluate(cdp, dom_type_expression(args.selector, text))
            if args.input_class == "credential":
                post = cdp_evaluate(cdp, dom_value_equals_expression(args.selector, text))
                post_ok = bool(post.get("ok") and post.get("matches"))
            else:
                post = cdp_evaluate(cdp, dom_query_expression(args.selector))
                post_ok = bool(post.get("ok") and post.get("value") == text)
        if not action.get("ok") or not post_ok:
            raise BrowserSessionError("type_postcondition_failed")
        visual = _browser_session_visual(args.visual_expect_text) if args.visual_expect_text else None
        if visual and visual.get("status") != "PASS":
            raise BrowserSessionError("visual_postcondition_failed")
        out = {
            "status":"PASS","schema":"macctl-browser-session/v1","operation":"session_type",
            "session_id":record["session_id"],"current_page":current,"selector":args.selector,
            "action_time_re_resolution":True,"postcondition":"VALUE_EXACT_READBACK",
            "input_class":args.input_class,"input_channel":input_channel,
            "credential_value_disclosed":False,"visual":visual,
        }
        if args.input_class == "plain":
            out["typed_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        emit(out)
    except (BrowserCdpError, BrowserSessionError) as e:
        if isinstance(e, BrowserSessionError):
            _browser_session_fail(e, rc=1)
        _browser_session_fail(BrowserSessionError("cdp_type_failed", str(e)), rc=1)


def _browser_session_click(args):
    record = _browser_session_record(args.session_id)
    _browser_session_enforce_action(record, "session-click", args)
    if not args.expect_selector:
        _browser_session_fail(BrowserSessionError("click_postcondition_required"), rc=64)
    try:
        current = _browser_session_current(record, timeout=4)
        page = _browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url, int(record["local_port"])), timeout=5) as cdp:
            cdp.call("Runtime.enable")
            pre = cdp_evaluate(cdp, dom_query_expression(args.selector))
            if not pre.get("ok"):
                raise BrowserSessionError("selector_not_unique", str(pre.get("count")))
            for target_url in (pre.get("href"), pre.get("formAction")):
                if not target_url:
                    continue
                target_policy = evaluate_url_policy(
                    str(target_url),
                    allow_hosts=record.get("allow_hosts") or [],
                    allow_loopback=bool(record.get("allow_loopback")),
                )
                if not target_policy.get("allowed"):
                    raise BrowserSessionError("click_target_url_policy_denied", target_policy.get("reason"))
            action = cdp_evaluate(cdp, dom_click_expression(args.selector))
            if not action.get("ok"):
                raise BrowserSessionError("click_action_failed", str(action.get("reason")))
            time.sleep(max(0.0, min(float(args.settle_seconds), 3.0)))
            post = cdp_evaluate(cdp, dom_query_expression(args.expect_selector))
        if not post.get("ok"):
            raise BrowserSessionError("click_postcondition_selector_failed", str(post.get("count")))
        if args.expect_text and str(args.expect_text) not in str(post.get("text") or ""):
            raise BrowserSessionError("click_postcondition_text_failed")
        visual = _browser_session_visual(args.visual_expect_text) if args.visual_expect_text else None
        if visual and visual.get("status") != "PASS":
            raise BrowserSessionError("visual_postcondition_failed")
        after = _browser_session_current(record, timeout=4)
        emit({
            "status":"PASS","schema":"macctl-browser-session/v1","operation":"session_click",
            "session_id":record["session_id"],"current_page_before":current,"current_page_after":after,
            "selector":args.selector,"action_time_re_resolution":True,
            "postcondition_selector":args.expect_selector,"postcondition_text":args.expect_text,
            "postcondition":"PASS","visual":visual,
        })
    except (BrowserCdpError, BrowserSessionError) as e:
        if isinstance(e, BrowserSessionError):
            _browser_session_fail(e, rc=1)
        _browser_session_fail(BrowserSessionError("cdp_click_failed", str(e)), rc=1)


def _browser_session_pages(args):
    record = _browser_session_record(args.session_id)
    try:
        items = cdp_http_json(int(record["local_port"]), "/json/list", timeout=3)
        rows=[]
        for page in [x for x in parse_targets(items) if x.type == "page"]:
            policy=evaluate_url_policy(page.url or "about:blank", allow_hosts=record.get("allow_hosts") or [], allow_loopback=bool(record.get("allow_loopback")))
            rows.append({"target_id":page.id,"title":page.title,"url":policy.get("url"),"url_query_redacted":bool(policy.get("query_redacted")),"policy_allowed":bool(policy.get("allowed")),"policy_reason":policy.get("reason"),"active":page.id==record.get("active_target_id")})
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_pages","session_id":record["session_id"],"pages":rows,"page_count":len(rows),"websocket_urls_returned":False})
    except (BrowserCdpError, BrowserSessionError) as e:
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("page_list_failed",str(e)),rc=1)


def _browser_session_activate(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-activate",args)
    try:
        pages=[x for x in parse_targets(cdp_http_json(int(record["local_port"]),"/json/list",timeout=3)) if x.type=="page"]
        matches=[x for x in pages if x.id==args.target_id]
        if len(matches)!=1: raise BrowserSessionError("page_target_not_found")
        page=matches[0]
        policy=evaluate_url_policy(page.url or "about:blank",allow_hosts=record.get("allow_hosts") or [],allow_loopback=bool(record.get("allow_loopback")))
        if not policy.get("allowed"): raise BrowserSessionError("page_target_url_policy_denied",policy.get("reason"))
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=4) as cdp:
            cdp.call("Page.bringToFront",timeout=3)
        record["active_target_id"]=page.id
        BROWSER_SESSION_STORE.save(record)
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_activate","session_id":record["session_id"],"target_id":page.id,"url":policy.get("url"),"policy":policy})
    except (BrowserCdpError,BrowserSessionError) as e:
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("page_activate_failed",str(e)),rc=1)


def _browser_session_new_tab(args):
    record=_browser_session_record(args.session_id); _browser_session_enforce_action(record,"session-new-tab",args)
    policy=evaluate_url_policy(args.url,allow_hosts=record.get("allow_hosts") or [],allow_loopback=bool(record.get("allow_loopback")))
    if not policy.get("allowed"):
        _browser_session_fail(BrowserSessionError("new_tab_url_policy_denied",policy.get("reason")),status="BLOCKED",rc=77)
    try:
        version=cdp_http_json(int(record["local_port"]),"/json/version",timeout=3); ws=str(version.get("webSocketDebuggerUrl") or "")
        if not ws: raise BrowserSessionError("browser_websocket_missing")
        with CdpClient(rewrite_ws_url(ws,int(record["local_port"])),timeout=5) as browser:
            res=browser.call("Target.createTarget",{"url":args.url},timeout=5).get("result") or {}; target_id=str(res.get("targetId") or "")
            if not target_id: raise BrowserSessionError("new_tab_target_id_missing")
            browser.call("Target.activateTarget",{"targetId":target_id},timeout=3)
        deadline=time.monotonic()+min(max(float(args.timeout),1.0),30.0); page=None
        while time.monotonic()<deadline:
            pages=[x for x in parse_targets(cdp_http_json(int(record["local_port"]),"/json/list",timeout=3)) if x.type=="page"]
            found=[x for x in pages if x.id==target_id]
            if found: page=found[0]; break
            time.sleep(0.1)
        if page is None: raise BrowserSessionError("new_tab_target_not_discoverable")
        record["active_target_id"]=target_id; BROWSER_SESSION_STORE.save(record)
        nav_deadline=time.monotonic()+min(max(float(args.timeout),1.0),30.0); current=None
        while time.monotonic()<nav_deadline:
            current=_browser_session_current(record,timeout=5)
            if args.url=="about:blank" or str(current.get("url") or "")!="about:blank":
                break
            time.sleep(0.1)
        if current is None or (args.url!="about:blank" and str(current.get("url") or "")=="about:blank"):
            raise BrowserSessionError("new_tab_navigation_timeout")
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_new_tab","session_id":record["session_id"],"target_id":target_id,"policy":policy,"current_page":current})
    except (BrowserCdpError,BrowserSessionError) as e:
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("new_tab_failed",str(e)),rc=1)


def _browser_session_close_tab(args):
    record=_browser_session_record(args.session_id); _browser_session_enforce_action(record,"session-close-tab",args)
    try:
        pages=[x for x in parse_targets(cdp_http_json(int(record["local_port"]),"/json/list",timeout=3)) if x.type=="page"]
        if len(pages)<2: raise BrowserSessionError("refuse_close_last_tab")
        matches=[x for x in pages if x.id==args.target_id]
        if len(matches)!=1: raise BrowserSessionError("page_target_not_found")
        victim=matches[0]; policy=evaluate_url_policy(victim.url or "about:blank",allow_hosts=record.get("allow_hosts") or [],allow_loopback=bool(record.get("allow_loopback")))
        if not policy.get("allowed"): raise BrowserSessionError("close_tab_url_policy_denied",policy.get("reason"))
        version=cdp_http_json(int(record["local_port"]),"/json/version",timeout=3); ws=str(version.get("webSocketDebuggerUrl") or "")
        if not ws: raise BrowserSessionError("browser_websocket_missing")
        with CdpClient(rewrite_ws_url(ws,int(record["local_port"])),timeout=5) as browser:
            browser.call("Target.closeTarget",{"targetId":victim.id},timeout=4)
        survivors=[x for x in pages if x.id!=victim.id]
        if record.get("active_target_id")==victim.id:
            allowed=[]
            for page in survivors:
                pol=evaluate_url_policy(page.url or "about:blank",allow_hosts=record.get("allow_hosts") or [],allow_loopback=bool(record.get("allow_loopback")))
                if pol.get("allowed"): allowed.append(page)
            if not allowed: raise BrowserSessionError("no_allowed_tab_after_close")
            record["active_target_id"]=allowed[0].id
        BROWSER_SESSION_STORE.save(record)
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_close_tab","session_id":record["session_id"],"closed_target_id":victim.id,"remaining_page_count":len(survivors),"active_target_id":record.get("active_target_id")})
    except (BrowserCdpError,BrowserSessionError) as e:
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("close_tab_failed",str(e)),rc=1)


def _browser_session_extract(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-extract",args)
    try:
        current=_browser_session_current(record,timeout=4)
        page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=6) as cdp:
            cdp.call("Runtime.enable")
            result=cdp_evaluate(cdp,dom_extract_expression(mode=args.mode,selector=args.selector,max_chars=args.max_chars,max_items=args.max_items),timeout=6)
        if not result.get("ok"): raise BrowserSessionError("extract_failed",result.get("reason"))
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_extract","session_id":record["session_id"],"current_page":current,"extract":result,"raw_html_exposed":False,"raw_javascript_exposed":False})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_extract_failed",str(e)),rc=1)


def _browser_session_wait(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-wait",args)
    deadline=time.monotonic()+max(0.2,min(float(args.timeout),120.0)); last=None
    try:
        _browser_session_current(record,timeout=4)
        page=_browser_session_target(record)
        expression=dom_wait_probe_expression(selector=args.selector,state=args.state,expect_text=args.expect_text,expect_value=args.expect_value)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=5) as cdp:
            cdp.call("Runtime.enable")
            while time.monotonic()<deadline:
                last=cdp_evaluate(cdp,expression,timeout=min(3.0,max(0.2,deadline-time.monotonic())))
                if last.get("satisfied"):
                    emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_wait","session_id":record["session_id"],"selector":args.selector,"state":args.state,"result":last})
                    return
                time.sleep(max(0.05,min(float(args.interval),1.0)))
        raise BrowserSessionError("wait_condition_timeout",json.dumps(last,ensure_ascii=False)[:1000])
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_wait_failed",str(e)),rc=1)


def _browser_session_analyze(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-analyze",args)
    try:
        current=_browser_session_current(record,timeout=4)
        page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=6) as cdp:
            cdp.call("Runtime.enable")
            extracted=cdp_evaluate(cdp,dom_extract_expression(mode="full",max_chars=args.max_chars,max_items=args.max_items),timeout=6)
        if not extracted.get("ok"):
            raise BrowserSessionError("analyze_extract_failed",extracted.get("reason"))
        analysis=analyze_extracted_page(extracted)
        emit({"status":"PASS","schema":"macctl-browser-page-analysis/v1","operation":"session_analyze","session_id":record["session_id"],"current_page":current,"analysis":analysis,"raw_extract_returned":False})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError,ValueError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        if isinstance(e,ValueError) and not isinstance(e,BrowserSessionError): e=BrowserSessionError("page_analysis_failed",str(e))
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_analyze_failed",str(e)),rc=1)


def _browser_session_search(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-search",args)
    if not args.expect_selector:
        _browser_session_fail(BrowserSessionError("search_postcondition_required"),rc=64)
    try:
        before=_browser_session_current(record,timeout=4); page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=6) as cdp:
            cdp.call("Page.enable"); cdp.call("Runtime.enable")
            probe=cdp_evaluate(cdp,dom_search_probe_expression(args.selector))
            if not probe.get("ok"): raise BrowserSessionError("search_surface_invalid",probe.get("reason"))
            action_url=str(probe.get("action") or "")
            policy=evaluate_url_policy(action_url,allow_hosts=record.get("allow_hosts") or [],allow_loopback=bool(record.get("allow_loopback")))
            if not policy.get("allowed"): raise BrowserSessionError("search_target_url_policy_denied",policy.get("reason"))
            typed=cdp_evaluate(cdp,dom_type_expression(args.selector,args.query))
            if not typed.get("ok"): raise BrowserSessionError("search_type_failed")
            spec=normalize_key_event("Enter",[])
            params=dict(spec["cdp"]); params["modifiers"]=0; params["text"]="\r"
            cdp.call("Input.dispatchKeyEvent",{"type":"keyDown",**params},timeout=3)
            cdp.call("Input.dispatchKeyEvent",{"type":"keyUp",**{k:v for k,v in params.items() if k!="text"}},timeout=3)
            try: cdp_wait_ready(cdp,timeout=args.timeout)
            except BrowserCdpError: pass
        deadline=time.monotonic()+max(0.5,min(float(args.timeout),30.0)); post=None
        while time.monotonic()<deadline:
            page=_browser_session_target(record)
            with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=5) as cdp:
                cdp.call("Runtime.enable"); post=cdp_evaluate(cdp,dom_query_expression(args.expect_selector))
            if post.get("ok") and (not args.expect_text or str(args.expect_text) in str(post.get("text") or "")): break
            time.sleep(0.15)
        if not post or not post.get("ok") or (args.expect_text and str(args.expect_text) not in str(post.get("text") or "")):
            raise BrowserSessionError("search_postcondition_failed")
        after=_browser_session_current(record,timeout=4)
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_search","session_id":record["session_id"],"current_page_before":before,"current_page_after":after,"selector":args.selector,"query_sha256":hashlib.sha256(str(args.query).encode("utf-8")).hexdigest(),"query_disclosed":False,"target_policy":policy,"postcondition_selector":args.expect_selector,"postcondition_text":args.expect_text})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_search_failed",str(e)),rc=1)


def _browser_session_select(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-select",args)
    try:
        current=_browser_session_current(record,timeout=4); page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=5) as cdp:
            cdp.call("Runtime.enable")
            action=cdp_evaluate(cdp,dom_select_expression(args.selector,args.value))
            post=cdp_evaluate(cdp,dom_query_expression(args.selector))
        if not action.get("ok") or not post.get("ok") or str(post.get("value"))!=str(args.value): raise BrowserSessionError("select_postcondition_failed")
        visual=_browser_session_visual(args.visual_expect_text) if args.visual_expect_text else None
        if visual and visual.get("status")!="PASS": raise BrowserSessionError("visual_postcondition_failed")
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_select","session_id":record["session_id"],"current_page":current,"selector":args.selector,"value":args.value,"postcondition":"VALUE_EXACT_READBACK","visual":visual})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_select_failed",str(e)),rc=1)


def _browser_session_key(args):
    record=_browser_session_record(args.session_id)
    _browser_session_enforce_action(record,"session-key",args)
    if not args.expect_selector and not args.visual_expect_text:
        _browser_session_fail(BrowserSessionError("key_postcondition_required"),rc=64)
    try:
        current=_browser_session_current(record,timeout=4); page=_browser_session_target(record); spec=normalize_key_event(args.key,args.modifier or [])
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=5) as cdp:
            cdp.call("Runtime.enable")
            if args.selector:
                focus=cdp_evaluate(cdp,dom_focus_expression(args.selector))
                if not focus.get("ok"): raise BrowserSessionError("key_focus_failed",focus.get("reason"))
            params=dict(spec["cdp"]); params["modifiers"]=spec["modifier_bits"]
            if args.key=="Enter": params["text"]="\r"
            elif args.key=="Space": params["text"]=" "
            cdp.call("Input.dispatchKeyEvent",{"type":"keyDown",**params},timeout=3)
            cdp.call("Input.dispatchKeyEvent",{"type":"keyUp",**{k:v for k,v in params.items() if k!="text"}},timeout=3)
            time.sleep(max(0.0,min(float(args.settle_seconds),3.0)))
            post=None
            if args.expect_selector:
                post=cdp_evaluate(cdp,dom_query_expression(args.expect_selector))
                if not post.get("ok"): raise BrowserSessionError("key_postcondition_selector_failed",str(post.get("count")))
                if args.expect_text and str(args.expect_text) not in str(post.get("text") or ""): raise BrowserSessionError("key_postcondition_text_failed")
        visual=_browser_session_visual(args.visual_expect_text) if args.visual_expect_text else None
        if visual and visual.get("status")!="PASS": raise BrowserSessionError("visual_postcondition_failed")
        after=_browser_session_current(record,timeout=4)
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_key","session_id":record["session_id"],"current_page_before":current,"current_page_after":after,"key":spec["key"],"modifiers":spec["modifiers"],"postcondition":post,"visual":visual})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_key_failed",str(e)),rc=1)


def _browser_session_history(args):
    record=_browser_session_record(args.session_id); _browser_session_enforce_action(record,"session-history",args)
    try:
        _browser_session_current(record,timeout=4); page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=5) as cdp:
            cdp.call("Page.enable")
            h=cdp.call("Page.getNavigationHistory",timeout=3).get("result") or {}
            target=history_target(h,args.direction)
            policy=evaluate_url_policy(target["url"],allow_hosts=record.get("allow_hosts") or [],allow_loopback=bool(record.get("allow_loopback")))
            if not policy.get("allowed"): raise BrowserSessionError("history_target_url_policy_denied",policy.get("reason"))
            cdp.call("Page.navigateToHistoryEntry",{"entryId":target["entry_id"]},timeout=5); cdp_wait_ready(cdp,timeout=args.timeout)
        after=_browser_session_current(record,timeout=4)
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_history","session_id":record["session_id"],"direction":args.direction,"target_policy":policy,"current_page":after})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError) as e:
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_history_failed",str(e)),rc=1)


def _browser_session_reload(args):
    record=_browser_session_record(args.session_id); _browser_session_enforce_action(record,"session-reload",args)
    try:
        before=_browser_session_current(record,timeout=4); page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=5) as cdp:
            cdp.call("Page.enable"); cdp.call("Page.reload",{"ignoreCache":bool(args.ignore_cache)},timeout=5); cdp_wait_ready(cdp,timeout=args.timeout)
        after=_browser_session_current(record,timeout=4)
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_reload","session_id":record["session_id"],"before":before,"after":after,"ignore_cache":bool(args.ignore_cache)})
    except (BrowserCdpError,BrowserSessionError) as e:
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("cdp_reload_failed",str(e)),rc=1)


def _browser_session_upload(args):
    record=_browser_session_record(args.session_id); _browser_session_enforce_action(record,"session-upload",args)
    q=shlex.quote; staged=None
    try:
        current=_browser_session_current(record,timeout=4)
        manifest=ARTIFACT_STORE.authorize_delivery(args.artifact_id,purpose="download")
        verified=ARTIFACT_STORE.verify(args.artifact_id)
        if verified.get("status")!="PASS": raise BrowserSessionError("upload_artifact_integrity_failed")
        local_path=ARTIFACT_STORE.payload_path_for_gateway(args.artifact_id,purpose="download")
        filename=str((manifest.get("content") or {}).get("filename") or "upload.bin")
        safe_name=Path(filename).name
        upload_dir=str(record.get("remote_upload_dir") or "")
        expected=f"/tmp/macctl-r4-upload-{validate_session_id(record['session_id'])}"
        if upload_dir!=expected: raise BrowserSessionError("upload_dir_not_qualified")
        staged=f"{upload_dir}/.stage-{uuid.uuid4().hex}"
        final=f"{upload_dir}/{uuid.uuid4().hex[:12]}-{safe_name}"
        push=run(remote_scp_argv(ssh_config=SSH_CONFIG,target=TARGET,local_path=str(local_path),remote_path=staged,direction="push"),timeout=args.timeout,cap=4096)
        if push["rc"]!=0: raise BrowserSessionError("upload_push_failed",push.get("output","")[:300])
        remote_hash=ssh_run(f"shasum -a 256 {q(staged)} | awk '{{print $1}}'",timeout=8,cap=1024)
        if remote_hash["rc"]!=0 or remote_hash.get("output","").strip()!=verified.get("sha256"): raise BrowserSessionError("upload_remote_sha256_mismatch")
        moved=ssh_run(f"mv {q(staged)} {q(final)} && chmod 600 {q(final)}",timeout=8,cap=1024)
        if moved["rc"]!=0: raise BrowserSessionError("upload_finalize_failed")
        staged=None
        page=_browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url,int(record["local_port"])),timeout=6) as cdp:
            cdp.call("Runtime.enable"); cdp.call("DOM.enable")
            pre=cdp_evaluate(cdp,dom_file_input_probe_expression(args.selector))
            if not pre.get("ok"): raise BrowserSessionError("upload_input_invalid",pre.get("reason"))
            doc=cdp.call("DOM.getDocument",{"depth":0},timeout=3).get("result") or {}; root_id=((doc.get("root") or {}).get("nodeId"))
            if not root_id: raise BrowserSessionError("upload_dom_root_missing")
            qr=cdp.call("DOM.querySelector",{"nodeId":root_id,"selector":args.selector},timeout=3).get("result") or {}; node_id=int(qr.get("nodeId") or 0)
            if not node_id: raise BrowserSessionError("upload_selector_not_found")
            cdp.call("DOM.setFileInputFiles",{"files":[final],"nodeId":node_id},timeout=5)
            post=cdp_evaluate(cdp,dom_file_input_probe_expression(args.selector))
        if not post.get("ok") or int(post.get("fileCount") or 0)!=1: raise BrowserSessionError("upload_postcondition_failed")
        emit({"status":"PASS","schema":"macctl-browser-automation/v1","operation":"session_upload","session_id":record["session_id"],"current_page":current,"selector":args.selector,"artifact_id":args.artifact_id,"sha256":verified.get("sha256"),"size_bytes":verified.get("size_bytes"),"filename":safe_name,"postcondition":"FILE_INPUT_COUNT_1","server_submit_performed":False})
    except (BrowserCdpError,BrowserSessionError,BrowserAutomationError,ArtifactError) as e:
        if isinstance(e,ArtifactError): e=BrowserSessionError("upload_artifact_denied",getattr(e,"reason",str(e)))
        if isinstance(e,BrowserAutomationError): e=BrowserSessionError(e.reason,e.detail)
        _browser_session_fail(e if isinstance(e,BrowserSessionError) else BrowserSessionError("browser_upload_failed",str(e)),rc=1)
    finally:
        if staged:
            try: ssh_run(f"rm -f {q(staged)}",timeout=5,cap=512)
            except Exception: pass


def _browser_session_download(args):
    record = _browser_session_record(args.session_id)
    _browser_session_enforce_action(record, "session-download", args)
    q = shlex.quote
    stage = Path(f"/tmp/macctl-browser-download-{uuid.uuid4().hex}.stage")
    remote_file = None
    export_path = str(record["remote_download_dir"]) + "/artifact.bin"
    try:
        current = _browser_session_current(record, timeout=4)
        clear = ssh_run(f"find {q(record['remote_download_dir'])} -mindepth 1 -maxdepth 1 -type f -delete", timeout=8, cap=2048)
        if clear["rc"] != 0:
            raise BrowserSessionError("browser_download_clear_failed", clear.get("output", "")[:300])
        version = cdp_http_json(int(record["local_port"]), "/json/version", timeout=3)
        browser_ws = str(version.get("webSocketDebuggerUrl") or "")
        if not browser_ws:
            raise BrowserSessionError("browser_websocket_missing")
        with CdpClient(rewrite_ws_url(browser_ws, int(record["local_port"])), timeout=5) as browser_cdp:
            browser_cdp.call("Browser.setDownloadBehavior", {
                "behavior":"allow",
                "downloadPath":record["remote_download_dir"],
                "eventsEnabled":True,
            }, timeout=4)
        page = _browser_session_target(record)
        with CdpClient(rewrite_ws_url(page.websocket_url, int(record["local_port"])), timeout=5) as cdp:
            cdp.call("Page.enable")
            cdp.call("Runtime.enable")
            pre = cdp_evaluate(cdp, dom_link_expression(args.selector))
            if not pre.get("ok"):
                raise BrowserSessionError("download_target_invalid", str(pre.get("reason") or pre.get("count")))
            href = str(pre.get("href") or "")
            href_policy = evaluate_url_policy(
                href,
                allow_hosts=record.get("allow_hosts") or [],
                allow_loopback=bool(record.get("allow_loopback")),
            )
            if not href_policy.get("allowed"):
                raise BrowserSessionError("download_url_policy_denied", href_policy.get("reason"))
            nav = cdp.call("Page.navigate", {"url": href}, timeout=6)
            nav_error = str((nav.get("result") or {}).get("errorText") or "")
            if nav_error and nav_error != "net::ERR_ABORTED":
                raise BrowserSessionError("download_navigation_failed", nav_error)
        deadline = time.monotonic() + float(args.timeout)
        files = []
        while time.monotonic() < deadline:
            listing = ssh_run(
                f"find {q(record['remote_download_dir'])} -mindepth 1 -maxdepth 1 -type f ! -name '*.crdownload' -print",
                timeout=5, cap=8192,
            )
            if listing["rc"] == 0:
                files = [x for x in listing.get("output", "").splitlines() if x.strip()]
                if files:
                    break
            time.sleep(0.2)
        if len(files) != 1:
            raise BrowserSessionError("download_file_count_unexpected", str(len(files)))
        remote_file = files[0]
        original_name = Path(remote_file).name
        moved = ssh_run(f"mv {q(remote_file)} {q(export_path)}", timeout=8, cap=2048)
        if moved["rc"] != 0:
            raise BrowserSessionError("browser_download_stage_rename_failed", moved.get("output", "")[:300])
        remote_file = export_path
        remote_hash_r = ssh_run(f"shasum -a 256 {q(remote_file)} | awk '{{print $1}}'", timeout=8, cap=1024)
        if remote_hash_r["rc"] != 0:
            raise BrowserSessionError("browser_download_remote_sha256_failed", remote_hash_r.get("output", "")[:300])
        remote_hash = remote_hash_r.get("output", "").strip().splitlines()[0]
        pull = run(
            remote_scp_argv(
                ssh_config=SSH_CONFIG,target=TARGET,local_path=str(stage),remote_path=remote_file,direction="pull"
            ),
            timeout=args.timeout,cap=4096,
        )
        if pull["rc"] != 0:
            raise BrowserSessionError("browser_download_pull_failed", pull.get("output", "")[:300])
        local_hash = hashlib.sha256(stage.read_bytes()).hexdigest()
        if local_hash != remote_hash:
            raise BrowserSessionError("download_sha256_mismatch")
        manifest = ARTIFACT_STORE.create_snapshot(
            stage,
            classification="BROWSER_DOWNLOAD",
            filename=args.filename or original_name,
            ttl_seconds=args.ttl_seconds,
            producer="browser.session_download",
            producer_metadata={
                "session_id":record["session_id"],"source_url":current.get("url"),
                "selector":args.selector,"remote_sha256":remote_hash,
            },
        )
        emit({
            "status":"PASS","schema":"macctl-browser-session/v1","operation":"session_download",
            "session_id":record["session_id"],"source_url":current.get("url"),"selector":args.selector,
            "action_time_re_resolution":True,"remote_sha256":remote_hash,"local_sha256":local_hash,
            "exact_byte":"PASS","artifact":manifest,
        })
    except (BrowserCdpError, BrowserSessionError, ArtifactError) as e:
        if isinstance(e, BrowserSessionError):
            _browser_session_fail(e, rc=1)
        if isinstance(e, ArtifactError):
            _artifact_fail(e)
        _browser_session_fail(BrowserSessionError("browser_download_failed", str(e)), rc=1)
    finally:
        stage.unlink(missing_ok=True)
        try:
            ssh_run(f"rm -f {q(export_path)}", timeout=6, cap=1024)
        except Exception:
            pass


def _native_browser_fail(error, *, status="FAIL", rc=66):
    emit({
        "status": status,
        "schema": "macctl-browser-native-action/v1",
        "reason": getattr(error, "reason", str(error)),
        "detail": getattr(error, "detail", None),
    })
    raise SystemExit(rc)


def _native_action_public(record):
    recovery = assess_native_action_recovery(record)
    return {
        "schema": record.get("schema", "macctl-browser-native-action/v1"),
        "authorized_action_id": record.get("authorized_action_id"),
        "browser_family": record.get("browser_family", "chrome"),
        "browser_bundle_id": record.get("browser_bundle_id", "com.google.Chrome"),
        "site_host": record.get("site_host"),
        "site_path_prefix": record.get("site_path_prefix", "/"),
        "intent": record.get("intent"),
        "resource_scope": record.get("resource_scope"),
        "cleanup_required": bool(record.get("cleanup_required")),
        "profile_mode": record.get("profile_mode"),
        "status": record.get("status"),
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "allowed_effects": record.get("allowed_effects") or [],
        "hard_forbidden_effects": record.get("hard_forbidden_effects") or [],
        "event_counts": record.get("event_counts") or {},
        "last_event": record.get("last_event"),
        "result": record.get("result"),
        "cleanup_verified": bool(record.get("cleanup_verified")),
        "recovery": recovery,
        "publish_allowed": False,
        "credential_export": "FORBIDDEN",
        "cookie_export": "FORBIDDEN",
        "session_token_export": "FORBIDDEN",
        "default_profile_cdp": "FORBIDDEN",
        "raw_runtime_evaluate": "FORBIDDEN",
    }


def _native_action_record(action_id, *, allow_expired=False):
    try:
        return NATIVE_BROWSER_ACTION_STORE.load(action_id, allow_expired=allow_expired)
    except NativeBrowserActionError as e:
        _native_browser_fail(e, rc=66)


def _native_action_enforce_effect(record, effect, args):
    policy = evaluate_native_action_effect(
        record,
        effect,
        confirmed=bool(getattr(args, "confirm", False)),
        production_confirmed=bool(getattr(args, "confirm_production", False)),
        native_profile_confirmed=bool(getattr(args, "confirm_native_profile", False)),
    )
    if not policy.get("allowed"):
        emit({
            "status": "BLOCKED",
            "schema": "macctl-browser-native-action/v1",
            "reason": "native_action_policy_denied",
            "native_policy": policy,
            "authorized_action_id": record.get("authorized_action_id"),
        })
        raise SystemExit(77)
    return policy


def _native_action_visual_precondition(record, *, expect_text=None, expect_absent_text=None):
    front = helper_gui_run("frontmost", timeout=10, cap=4096)
    try:
        front_payload = json.loads(front.get("output") or "{}")
    except Exception:
        front_payload = {}
    bundle = front_payload.get("bundle_id") or front_payload.get("bundle")
    expected_bundle = str(record.get("browser_bundle_id") or "com.google.Chrome")
    browser_family = str(record.get("browser_family") or "chrome")
    if front.get("rc") != 0 or bundle != expected_bundle:
        raise NativeBrowserActionError("native_action_requires_expected_frontmost_browser", browser_family)

    ax = helper_gui_run(
        "accessibility-semantic-find",
        timeout=15,
        cap=20000,
        extra_args=["--bundle", expected_bundle, "--role", "AXTextField"],
    )
    try:
        ax_payload = json.loads(ax.get("output") or "{}")
    except Exception:
        ax_payload = {}
    if ax.get("rc") != 0:
        raise NativeBrowserActionError("native_action_address_bar_probe_failed")
    address = evaluate_native_address_bar(
        ax_payload.get("matches") or [],
        expected_host=record.get("site_host"),
        path_prefix=record.get("site_path_prefix", "/"),
    )

    ocr = helper_gui_run("screen-ocr", timeout=20, cap=32000)
    try:
        payload = json.loads(ocr.get("output") or "{}")
    except Exception:
        payload = {}
    items = ((payload.get("ocr") or {}).get("items") or [])
    host = str(record.get("site_host") or "").lower()
    top_host_matches = []
    all_text = []
    for item in items:
        text = str(item.get("text") or "")
        all_text.append(text)
        box = item.get("box") or {}
        try:
            y = float(box.get("y", 0.0))
        except Exception:
            y = 0.0
        if host and host in text.lower() and y >= 0.80:
            top_host_matches.append({"y": round(y, 4), "confidence": item.get("confidence")})
    if ocr.get("rc") != 0 or not top_host_matches:
        raise NativeBrowserActionError("native_action_visible_host_precondition_failed")
    joined_text = "\n".join(all_text)
    text_seen = True if not expect_text else str(expect_text) in joined_text
    absent_ok = True if not expect_absent_text else str(expect_absent_text) not in joined_text
    if not text_seen:
        raise NativeBrowserActionError("native_action_expected_visual_text_missing")
    if not absent_ok:
        raise NativeBrowserActionError("native_action_forbidden_visual_text_still_present")
    return {
        "status": "PASS",
        "frontmost_bundle": bundle,
        "browser_family": browser_family,
        "site_host": host,
        "site_path_prefix": record.get("site_path_prefix", "/"),
        "address_bar": address,
        "top_band_host_match_count": len(top_host_matches),
        "expect_text": expect_text,
        "expect_text_seen": text_seen,
        "expect_absent_text": expect_absent_text,
        "expect_absent_text_ok": absent_ok,
        "capture_backend": payload.get("backend"),
        "ocr_backend": "Apple Vision",
    }


def _native_action_plan_from_args(args):
    try:
        return validate_native_action_plan(
            site_host=args.site_host,
            site_path_prefix=args.site_path_prefix,
            authorized_action_id=args.authorized_action_id,
            browser_family=getattr(args, "browser_family", "chrome"),
            intent=args.intent,
            resource_scope=args.resource_scope,
            cleanup_required=getattr(args, "cleanup_required", None),
            ttl_seconds=args.ttl_seconds,
        )
    except NativeBrowserActionError as e:
        _native_browser_fail(e, status="BLOCKED", rc=77)


def _native_action_begin(args):
    plan = _native_action_plan_from_args(args)
    if not (args.confirm and args.confirm_production and args.confirm_native_profile):
        _native_browser_fail(NativeBrowserActionError("native_action_triple_confirmation_required"), status="BLOCKED", rc=77)
    try:
        with NATIVE_BROWSER_ACTION_STORE.site_lock(plan.get("site_host")):
            blockers = NATIVE_BROWSER_ACTION_STORE.site_single_flight_blockers(plan.get("site_host"))
            if blockers:
                emit({
                    "status": "BLOCKED",
                    "schema": "macctl-browser-native-action/v1",
                    "reason": "native_action_site_single_flight_blocked",
                    "site_host": plan.get("site_host"),
                    "blocking_actions": [
                        {
                            "authorized_action_id": r.get("authorized_action_id"),
                            "recovery_state": (r.get("recovery") or {}).get("recovery_state"),
                        }
                        for r in blockers
                    ],
                })
                raise SystemExit(77)
            record = build_native_action_record(plan)
            NATIVE_BROWSER_ACTION_STORE.save(record, create_only=True)
    except NativeBrowserActionError as e:
        _native_browser_fail(e, status="BLOCKED", rc=77)
    emit({
        "status": "PASS",
        "schema": "macctl-browser-native-action/v1",
        "operation": "native_action_begin",
        "action": _native_action_public(record),
        "single_flight": "EXACT_HOST_FLOCK_GUARDED",
        "note": "local action contract created; this does not itself perform a website mutation",
    })


def _native_action_with_lock(action_id, fn):
    try:
        with NATIVE_BROWSER_ACTION_STORE.action_lock(action_id):
            return fn()
    except NativeBrowserActionError as e:
        _native_browser_fail(e, status="BLOCKED", rc=77)


def _native_action_observe(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id)
        _native_action_enforce_effect(record, "observe", args)
        try:
            precondition = _native_action_visual_precondition(
                record,
                expect_text=args.expect_text,
                expect_absent_text=args.expect_absent_text,
            )
            updated = record_native_action_event(record, "observe", status="PASS")
            NATIVE_BROWSER_ACTION_STORE.save(updated)
        except NativeBrowserActionError as e:
            _native_browser_fail(e, rc=1)
        emit({
            "status": "PASS",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_observe",
            "authorized_action_id": record.get("authorized_action_id"),
            "precondition": precondition,
            "action_lock": "FLOCK_EXCLUSIVE",
        })
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def _native_action_prepare_gui_effect(record, effect):
    try:
        prepared = prepare_native_action_event(record, effect)
        NATIVE_BROWSER_ACTION_STORE.save(prepared)
        return prepared
    except NativeBrowserActionError as e:
        _native_browser_fail(e, status="BLOCKED", rc=77)


def _native_action_complete_gui_effect(prepared, effect, rc):
    try:
        updated = complete_native_action_event(
            prepared,
            effect,
            status="PASS" if rc == 0 else "FAIL",
        )
        NATIVE_BROWSER_ACTION_STORE.save(updated)
        return updated
    except NativeBrowserActionError as e:
        _native_browser_fail(e, rc=66)


def _native_action_type(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id)
        _native_action_enforce_effect(record, "input_plain", args)
        try:
            precondition = _native_action_visual_precondition(record, expect_text=args.visual_expect_text)
        except NativeBrowserActionError as e:
            _native_browser_fail(e, rc=1)
        prepared = _native_action_prepare_gui_effect(record, "input_plain")
        r = helper_gui_run("type-text", timeout=args.timeout, cap=args.max_bytes, extra_args=["--text", args.text])
        _native_action_complete_gui_effect(prepared, "input_plain", r.get("rc") or 0)
        emit({
            "status": "PASS" if r.get("rc") == 0 else "FAIL",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_type",
            "authorized_action_id": record.get("authorized_action_id"),
            "precondition": precondition,
            "text_length": len(args.text or ""),
            "text_value_echoed": False,
            "action_lock": "FLOCK_EXCLUSIVE",
        })
        raise SystemExit(r.get("rc") or 0)
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def _native_action_click(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id)
        _native_action_enforce_effect(record, args.effect, args)
        try:
            precondition = _native_action_visual_precondition(record, expect_text=args.visual_expect_text)
        except NativeBrowserActionError as e:
            _native_browser_fail(e, rc=1)
        prepared = _native_action_prepare_gui_effect(record, args.effect)
        r = helper_gui_run(
            "mouse-click",
            timeout=args.timeout,
            cap=args.max_bytes,
            extra_args=["--x", args.x, "--y", args.y, "--button", args.button, "--count", args.count],
        )
        _native_action_complete_gui_effect(prepared, args.effect, r.get("rc") or 0)
        emit({
            "status": "PASS" if r.get("rc") == 0 else "FAIL",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_click",
            "authorized_action_id": record.get("authorized_action_id"),
            "effect": args.effect,
            "precondition": precondition,
            "coordinates": {"x": float(args.x), "y": float(args.y)},
            "action_lock": "FLOCK_EXCLUSIVE",
        })
        raise SystemExit(r.get("rc") or 0)
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def _native_action_key(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id)
        _native_action_enforce_effect(record, args.effect, args)
        try:
            precondition = _native_action_visual_precondition(record, expect_text=args.visual_expect_text)
        except NativeBrowserActionError as e:
            _native_browser_fail(e, rc=1)
        prepared = _native_action_prepare_gui_effect(record, args.effect)
        r = helper_gui_run(
            "key-press",
            timeout=args.timeout,
            cap=args.max_bytes,
            extra_args=["--keycode", args.keycode, "--modifiers", args.modifiers],
        )
        _native_action_complete_gui_effect(prepared, args.effect, r.get("rc") or 0)
        emit({
            "status": "PASS" if r.get("rc") == 0 else "FAIL",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_key",
            "authorized_action_id": record.get("authorized_action_id"),
            "effect": args.effect,
            "precondition": precondition,
            "keycode": int(args.keycode),
            "modifiers": args.modifiers,
            "action_lock": "FLOCK_EXCLUSIVE",
        })
        raise SystemExit(r.get("rc") or 0)
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def _native_action_finish(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id, allow_expired=True)
        if not (args.confirm and args.confirm_production and args.confirm_native_profile):
            _native_browser_fail(NativeBrowserActionError("native_action_triple_confirmation_required"), status="BLOCKED", rc=77)
        try:
            updated = finish_native_action_record(
                record,
                result=args.result,
                cleanup_verified=bool(args.cleanup_verified),
            )
            NATIVE_BROWSER_ACTION_STORE.save(updated)
        except NativeBrowserActionError as e:
            _native_browser_fail(e, status="BLOCKED", rc=77)
        emit({
            "status": "PASS" if updated.get("status") == "CLOSED" else "HOLD",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_finish",
            "action": _native_action_public(updated),
            "action_lock": "FLOCK_EXCLUSIVE",
        })
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def _native_action_recovery_plan(args):
    if args.authorized_action_id:
        records = [_native_action_record(args.authorized_action_id, allow_expired=True)]
    else:
        records = NATIVE_BROWSER_ACTION_STORE.list()
    actions = [_native_action_public(record) for record in records]
    blockers = [
        action for action in actions
        if (action.get("recovery") or {}).get("new_action_blocked")
    ]
    emit({
        "status": "PASS",
        "schema": "macctl-browser-native-action/v1",
        "operation": "native_action_recovery_plan",
        "recovery_required": bool(blockers),
        "blocking_count": len(blockers),
        "actions": actions,
        "note": "read-only recovery assessment; no browser or record mutation performed",
    })


def _native_action_recovery_observe(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id, allow_expired=True)
        recovery = assess_native_action_recovery(record)
        if recovery.get("recovery_state") in {"NONE", "ACTIVE_VALID"}:
            _native_browser_fail(NativeBrowserActionError("native_action_recovery_not_required"), status="BLOCKED", rc=77)
        try:
            precondition = _native_action_visual_precondition(
                record,
                expect_text=args.expect_text,
                expect_absent_text=args.expect_absent_text,
            )
        except NativeBrowserActionError as e:
            _native_browser_fail(e, rc=1)
        emit({
            "status": "PASS",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_recovery_observe",
            "authorized_action_id": record.get("authorized_action_id"),
            "recovery": recovery,
            "precondition": precondition,
            "record_mutated": False,
            "action_lock": "FLOCK_EXCLUSIVE",
        })
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def _native_action_recover_interrupted(args):
    def run_locked():
        record = _native_action_record(args.authorized_action_id, allow_expired=True)
        if not (args.confirm and args.confirm_production and args.confirm_native_profile):
            _native_browser_fail(
                NativeBrowserActionError("native_action_triple_confirmation_required"),
                status="BLOCKED",
                rc=77,
            )
        try:
            updated = materialize_interrupted_native_action(record)
            NATIVE_BROWSER_ACTION_STORE.save(updated)
        except NativeBrowserActionError as e:
            _native_browser_fail(e, status="BLOCKED", rc=77)
        emit({
            "status": "PASS",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_recover_interrupted",
            "action": _native_action_public(updated),
            "record_mutated": True,
            "website_mutated": False,
            "action_lock": "FLOCK_EXCLUSIVE",
            "note": "materializes durable pending intent as explicit uncertainty after process interruption",
        })
    return _native_action_with_lock(args.authorized_action_id, run_locked)


def cmd_browser(args):
    if args.action == "native-action-plan":
        plan = _native_action_plan_from_args(args)
        emit({
            "status": "PASS",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_plan",
            "plan": plan,
            "note": "plan validation is not authorization and performs no browser mutation",
        })
        return
    if args.action == "native-action-begin":
        return _native_action_begin(args)
    if args.action == "native-action-list":
        emit({
            "status": "PASS",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_list",
            "actions": [_native_action_public(r) | {"expired": bool(r.get("expired"))} for r in NATIVE_BROWSER_ACTION_STORE.list()],
        })
        return
    if args.action == "native-action-status":
        record = _native_action_record(args.authorized_action_id, allow_expired=True)
        emit({
            "status": "PASS",
            "schema": "macctl-browser-native-action/v1",
            "operation": "native_action_status",
            "action": _native_action_public(record),
        })
        return
    if args.action == "native-action-observe":
        return _native_action_observe(args)
    if args.action == "native-action-type":
        return _native_action_type(args)
    if args.action == "native-action-click":
        return _native_action_click(args)
    if args.action == "native-action-key":
        return _native_action_key(args)
    if args.action == "native-action-finish":
        return _native_action_finish(args)
    if args.action == "native-action-recovery-plan":
        return _native_action_recovery_plan(args)
    if args.action == "native-action-recovery-observe":
        return _native_action_recovery_observe(args)
    if args.action == "native-action-recover-interrupted":
        return _native_action_recover_interrupted(args)
    if args.action == "control-plan":
        try:
            plan=plan_control_route(browser=args.browser_family,context=args.context,action=args.operation,authenticated=bool(args.authenticated),cdp_available=bool(args.cdp_available),ax_available=bool(args.ax_available),vision_available=bool(args.vision_available))
        except ValueError as e:
            emit({"status":"BLOCKED","schema":"macctl-browser-control-route/v1","reason":str(e)})
            raise SystemExit(77)
        emit(plan)
        raise SystemExit(0 if plan.get("status")!="BLOCKED" else 77)
    if args.action == "qualification-plan":
        try:
            qualification = validate_qualification_config(
                site_class=args.site_class,
                qualification_scope=args.qualification_scope,
                allow_hosts=args.allow_host or [],
                allow_loopback=bool(args.allow_loopback),
                authorized_action_id=args.authorized_action_id,
            )
        except BrowserSessionError as e:
            _browser_session_fail(e, status="BLOCKED", rc=77)
        probe_record = dict(qualification)
        action_matrix = {}
        for action in ("session-navigate", "session-query", "session-extract", "session-analyze", "session-wait", "session-pages", "session-activate", "session-new-tab", "session-close-tab", "session-type", "session-select", "session-search", "session-key", "session-history", "session-reload", "session-click", "session-download", "session-upload"):
            action_matrix[action] = evaluate_session_action_policy(
                probe_record,
                action,
                confirmed=True,
                production_confirmed=True,
                input_class="plain",
            )
        emit({
            "status":"PASS",
            "schema":"macctl-browser-production-qualification/v1",
            "operation":"qualification_plan",
            "qualification":qualification,
            "action_matrix":action_matrix,
            "default_profile_access":"NOT_EXPOSED_BY_DESIGN",
            "production_credential_entry":"NOT_EXPOSED_PHASE3",
            "captcha_webauthn_passkey_payment":"NOT_EXPOSED_PHASE3",
            "note":"plan validation is not authorization for a live production mutation",
        })
        return
    if args.action == "url-check":
        policy = evaluate_url_policy(args.url, allow_hosts=args.allow_host or [], allow_loopback=bool(args.allow_loopback))
        emit({"status":"PASS","schema":"macctl-browser-session/v1","operation":"url_check","policy":policy})
        raise SystemExit(0 if policy.get("allowed") else 77)
    if args.action == "session-start":
        return _browser_session_start(args)
    if args.action == "session-list":
        emit({
            "status":"PASS","schema":"macctl-browser-session/v1","operation":"session_list",
            "sessions":[_browser_session_public(r) | {"expired": bool(r.get("expired"))} for r in BROWSER_SESSION_STORE.list()],
        })
        return
    if args.action == "session-status":
        return _browser_session_status(args)
    if args.action == "session-stop":
        return _browser_session_stop(args)
    if args.action == "session-navigate":
        return _browser_session_navigate(args)
    if args.action == "session-query":
        return _browser_session_query(args)
    if args.action == "session-extract":
        return _browser_session_extract(args)
    if args.action == "session-wait":
        return _browser_session_wait(args)
    if args.action == "session-analyze":
        return _browser_session_analyze(args)
    if args.action == "session-pages":
        return _browser_session_pages(args)
    if args.action == "session-activate":
        return _browser_session_activate(args)
    if args.action == "session-new-tab":
        return _browser_session_new_tab(args)
    if args.action == "session-close-tab":
        return _browser_session_close_tab(args)
    if args.action == "session-type":
        return _browser_session_type(args)
    if args.action == "session-select":
        return _browser_session_select(args)
    if args.action == "session-search":
        return _browser_session_search(args)
    if args.action == "session-key":
        return _browser_session_key(args)
    if args.action == "session-history":
        return _browser_session_history(args)
    if args.action == "session-reload":
        return _browser_session_reload(args)
    if args.action == "session-click":
        return _browser_session_click(args)
    if args.action == "session-download":
        return _browser_session_download(args)
    if args.action == "session-upload":
        return _browser_session_upload(args)
    if args.action == "cdp-plan":
        emit({
            "status": "PASS",
            "schema": "macctl-browser-cdp/v1",
            "mode": "ISOLATED_PROFILE_OVER_PINNED_SSH_LOOPBACK",
            "chrome_profile": "NON_DEFAULT_EPHEMERAL_ONLY",
            "default_profile_access": "FORBIDDEN_BY_DESIGN",
            "remote_debug_bind": "127.0.0.1_ONLY",
            "transport": "pinned OpenSSH local-forward",
            "dom_selector_contract": "EXACTLY_ONE_OR_FAIL_CLOSED",
            "raw_runtime_evaluate_cli": "NOT_EXPOSED",
            "visual_fallback": ["ScreenCaptureKit", "Apple Vision OCR", "AX"],
        })
        return

    if args.action != "cdp-smoke":
        raise SystemExit(64)

    q = shlex.quote
    token = uuid.uuid4().hex[:12]
    remote_html = f"/tmp/macctl-r2-cdp-{token}.html"
    remote_profile = f"/tmp/macctl-r2-cdp-profile-{token}"
    local_html = Path(f"/tmp/macctl-r2-cdp-{token}.html")
    input_text = "R2-CDP-中文-✓-🙂"
    html = """<!doctype html><meta charset=\"utf-8\"><title>R2 CDP Scratch Ready</title>
<style>body{font-family:-apple-system,sans-serif;padding:80px}h1{font-size:44px}button,input,#status{font-size:30px;margin:18px;padding:14px}</style>
<h1>R2 CDP Scratch Ready</h1><button id=\"go\">R2 Scratch Button</button><input id=\"input\" aria-label=\"R2 Scratch Input\"><div id=\"status\">R2 Waiting</div>
<script>document.querySelector('#go').addEventListener('click',()=>{document.querySelector('#status').textContent='R2 Clicked PASS'});</script>"""
    local_html.write_text(html, encoding="utf-8")

    frontmost_bundle = None
    tunnel = None
    browser_closed = False
    remote_port = None
    local_port = None
    try:
        front = helper_gui_run("frontmost", timeout=10, cap=4096)
        if front.get("rc") == 0 and front.get("output"):
            try:
                fp = json.loads(front["output"])
                frontmost_bundle = fp.get("bundle_id") or fp.get("bundle")
            except Exception:
                pass

        pushed = run(
            remote_scp_argv(
                ssh_config=SSH_CONFIG,
                target=TARGET,
                local_path=str(local_html),
                remote_path=remote_html,
                direction="push",
            ),
            timeout=15,
            cap=4096,
        )
        require_ok(pushed, "browser-cdp-scratch-push")

        for _ in range(12):
            candidate = 42000 + (int(uuid.uuid4().hex[:6], 16) % 18000)
            probe = ssh_run(f"/usr/bin/nc -z 127.0.0.1 {candidate}", timeout=4, cap=1024)
            if probe["rc"] != 0:
                remote_port = candidate
                break
        if remote_port is None:
            raise BrowserCdpError("remote_debug_port_unavailable")

        local_port = free_tcp_port()
        launch = (
            f"/usr/bin/open -na {q('Google Chrome')} --args "
            f"--remote-debugging-address=127.0.0.1 --remote-debugging-port={remote_port} "
            f"--user-data-dir={q(remote_profile)} --no-first-run --no-default-browser-check "
            f"--disable-sync --disable-default-apps about:blank"
        )
        started = ssh_run(launch, timeout=12, cap=4096)
        require_ok(started, "browser-cdp-isolated-chrome-launch")

        tunnel_argv = [
            "ssh", "-F", SSH_CONFIG,
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "ExitOnForwardFailure=yes",
            "-N", "-L", f"127.0.0.1:{local_port}:127.0.0.1:{remote_port}", TARGET,
        ]
        tunnel = subprocess.Popen(
            tunnel_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        time.sleep(0.25)
        if tunnel.poll() is not None:
            detail = (tunnel.stderr.read(4096) if tunnel.stderr else b"").decode("utf-8", "replace")
            raise BrowserCdpError("ssh_forward_failed:" + detail[:300])

        version = cdp_wait_http_json(local_port, "/json/version", timeout=12)
        targets = cdp_wait_http_json(local_port, "/json/list", timeout=8)
        page = select_page_target(targets)
        page_ws = rewrite_ws_url(page.websocket_url, local_port)

        with CdpClient(page_ws, timeout=6) as cdp:
            cdp.call("Page.enable")
            cdp.call("Runtime.enable")
            file_url = "file://" + remote_html
            cdp.call("Page.navigate", {"url": file_url}, timeout=6)
            cdp_wait_ready(cdp, timeout=10)
            before = cdp_evaluate(cdp, page_snapshot_expression())
            button = cdp_evaluate(cdp, dom_query_expression("#go"))
            field = cdp_evaluate(cdp, dom_query_expression("#input"))
            if not button.get("ok") or not field.get("ok"):
                raise BrowserCdpError("synthetic_dom_query_failed")
            clicked = cdp_evaluate(cdp, dom_click_expression("#go"))
            status_after = cdp_evaluate(cdp, dom_query_expression("#status"))
            typed = cdp_evaluate(cdp, dom_type_expression("#input", input_text))
            input_after = cdp_evaluate(cdp, dom_query_expression("#input"))
            after = cdp_evaluate(cdp, page_snapshot_expression())

        dom_ok = (
            before.get("title") == "R2 CDP Scratch Ready"
            and clicked.get("ok") is True
            and status_after.get("ok") is True
            and "R2 Clicked PASS" in str(status_after.get("text") or "")
            and typed.get("ok") is True
            and input_after.get("value") == input_text
        )
        if not dom_ok:
            raise BrowserCdpError("synthetic_dom_postcondition_failed")

        ocr = helper_gui_run("screen-ocr", timeout=20, cap=32000)
        ocr_payload = {}
        if ocr.get("output"):
            try:
                ocr_payload = json.loads(ocr["output"])
            except Exception:
                ocr_payload = {}
        ocr_items = ((ocr_payload.get("ocr") or {}).get("items") or [])
        ocr_text = "\n".join(str(x.get("text") or "") for x in ocr_items)
        visual_heading = "R2 CDP Scratch Ready" in ocr_text
        visual_status = "R2 Clicked PASS" in ocr_text
        visual_ok = ocr.get("rc") == 0 and (visual_heading or visual_status)

        try:
            browser_ws_raw = str(version.get("webSocketDebuggerUrl") or "")
            if browser_ws_raw:
                with CdpClient(rewrite_ws_url(browser_ws_raw, local_port), timeout=4) as browser_cdp:
                    try:
                        browser_cdp.call("Browser.close", timeout=3)
                    except BrowserCdpError as e:
                        if "closed_by_peer" not in str(e) and "websocket_eof" not in str(e):
                            raise
                browser_closed = True
        except Exception:
            browser_closed = False

        emit({
            "status": "PASS" if visual_ok else "DEGRADED",
            "schema": "macctl-browser-cdp/v1",
            "qualification": "R2_PHASE1_ISOLATED_SYNTHETIC",
            "chrome_product": version.get("Browser"),
            "protocol_version": version.get("Protocol-Version"),
            "profile_isolated": True,
            "default_profile_touched": False,
            "remote_debug_bind": "127.0.0.1",
            "ssh_forward": "PASS",
            "dom_query_unique": "PASS",
            "dom_click_postcondition": "PASS",
            "dom_unicode_type_postcondition": "PASS",
            "typed_sha256": hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
            "page_title": after.get("title"),
            "visual_ocr": "PASS" if visual_ok else "DEGRADED",
            "visual_heading_seen": visual_heading,
            "visual_status_seen": visual_status,
            "screen_backend": ocr_payload.get("backend"),
            "ocr_count": (ocr_payload.get("ocr") or {}).get("count"),
            "browser_close_requested": browser_closed,
        })
        raise SystemExit(0 if visual_ok else 2)
    except BrowserCdpError as e:
        emit({"status": "FAIL", "schema": "macctl-browser-cdp/v1", "reason": str(e)})
        raise SystemExit(1)
    finally:
        if tunnel is not None:
            try:
                tunnel.terminate()
                tunnel.wait(timeout=2)
            except Exception:
                try:
                    tunnel.kill()
                except Exception:
                    pass
        cleanup = (
            f"pids=$(pgrep -f {q('[G]oogle Chrome.*--user-data-dir=' + remote_profile)} 2>/dev/null || true); "
            "for p in $pids; do kill -TERM \"$p\" 2>/dev/null || true; done; "
            "sleep 0.3; "
            "for p in $pids; do kill -KILL \"$p\" 2>/dev/null || true; done; "
            f"rm -rf -- {q(remote_profile)} {q(remote_html)}"
        )
        try:
            ssh_run(cleanup, timeout=8, cap=2048)
        except Exception:
            pass
        try:
            local_html.unlink(missing_ok=True)
        except Exception:
            pass
        if frontmost_bundle:
            try:
                ssh_run(f"/usr/bin/open -b {q(frontmost_bundle)}", timeout=8, cap=2048)
            except Exception:
                pass


def cmd_gui(args):
    q = shlex.quote
    helper = '"$HOME/Applications/MacCtl Helper.app/Contents/MacOS/MacCtlHelper"'
    if args.action == "screenshot":
        if not args.local and not args.artifact:
            emit({"status":"FAIL","reason":"local_path_or_artifact_required"})
            raise SystemExit(64)
        remote = f"/tmp/macctl-screenshot-{uuid.uuid4().hex[:8]}.png"
        output_local = Path(args.local) if args.local else None
        stage = Path(f"/tmp/macctl-artifact-stage-{uuid.uuid4().hex}.png") if args.artifact else output_local
        stage.parent.mkdir(parents=True, exist_ok=True)
        if output_local is not None:
            output_local.parent.mkdir(parents=True, exist_ok=True)
        r = helper_gui_run(
            "screen-capture-file",
            timeout=args.timeout,
            cap=8192,
            extra_args=["--image-output", remote],
        )
        require_ok(r, "screenshot-capture")
        metadata = {}
        if r.get("output"):
            try:
                metadata = json.loads(r["output"])
            except Exception:
                metadata = {"helper_output": r["output"]}
        pull = run(
            remote_scp_argv(
                ssh_config=SSH_CONFIG,
                target=TARGET,
                local_path=str(stage),
                remote_path=remote,
                direction="pull",
            ),
            timeout=args.timeout,
            cap=4096,
        )
        ssh_run(f"/bin/rm -f -- {q(remote)}", timeout=10, cap=4096)
        require_ok(pull, "screenshot-pull")
        digest = hashlib.sha256(stage.read_bytes()).hexdigest() if stage.exists() else None
        if args.artifact and output_local is not None:
            shutil.copyfile(stage, output_local)
        payload = {
            "status":"PASS",
            "local":str(output_local) if output_local is not None else None,
            "bytes":stage.stat().st_size if stage.exists() else None,
            "sha256":digest,
            "backend":metadata.get("backend", "ScreenCaptureKit"),
            "display_id":metadata.get("display_id"),
            "width":metadata.get("width"),
            "height":metadata.get("height"),
        }
        if args.artifact:
            try:
                manifest = ARTIFACT_STORE.create_snapshot(
                    stage,
                    classification="SCREEN_CAPTURE",
                    filename=args.filename or "macctl-screen.png",
                    ttl_seconds=args.ttl_seconds,
                    producer="gui.screenshot",
                    producer_metadata={
                        "backend": payload["backend"],
                        "display_id": payload["display_id"],
                        "width": payload["width"],
                        "height": payload["height"],
                    },
                )
                payload["artifact"] = manifest
            except ArtifactError as e:
                _artifact_fail(e)
            finally:
                stage.unlink(missing_ok=True)
        emit(payload)
        return
    if args.action == "compare":
        try:
            from PIL import Image, ImageChops, ImageStat
        except Exception as e:
            emit({"status":"FAIL","reason":"pillow_unavailable","detail":type(e).__name__})
            raise SystemExit(69)
        before = Path(args.before)
        after = Path(args.after)
        if not before.is_file() or not after.is_file():
            emit({"status":"FAIL","reason":"missing_image","before":str(before),"after":str(after)})
            raise SystemExit(66)
        a = Image.open(before).convert("RGB")
        b = Image.open(after).convert("RGB")
        if a.size != b.size:
            emit({"status":"FAIL","reason":"dimension_mismatch","before_size":a.size,"after_size":b.size})
            raise SystemExit(65)
        region = None
        if args.region:
            try:
                x, y, w, h = [int(v) for v in args.region.split(",")]
            except Exception:
                emit({"status":"FAIL","reason":"invalid_region","expected":"x,y,w,h"})
                raise SystemExit(64)
            if w <= 0 or h <= 0:
                emit({"status":"FAIL","reason":"invalid_region_size"})
                raise SystemExit(64)
            box = (x, y, x + w, y + h)
            a = a.crop(box)
            b = b.crop(box)
            region = {"x":x,"y":y,"width":w,"height":h}
        diff = ImageChops.difference(a, b)
        stat = ImageStat.Stat(diff)
        mean_abs = round(sum(stat.mean) / max(1, len(stat.mean)), 4)
        rms = round(sum(stat.rms) / max(1, len(stat.rms)), 4)
        gray = diff.convert("L")
        hist = gray.histogram()
        threshold = max(0, min(255, int(args.threshold)))
        changed_pixels = int(sum(hist[threshold + 1:]))
        total_pixels = int(a.size[0] * a.size[1])
        ratio = changed_pixels / total_pixels if total_pixels else 0.0
        changed = ratio >= float(args.min_ratio)
        status = "PASS" if (not args.expect_change or changed) else "FAIL"
        emit({"status":status,"changed":changed,"threshold":threshold,"min_ratio":args.min_ratio,"changed_pixels":changed_pixels,"total_pixels":total_pixels,"changed_pixel_ratio":round(ratio,8),"mean_abs_diff":mean_abs,"rms_diff":rms,"region":region,"size":{"width":a.size[0],"height":a.size[1]}})
        if status != "PASS":
            raise SystemExit(1)
        return
    if args.action in ("semantic-find", "semantic-press"):
        if args.match_mode == "ranked":
            _ranked_semantic_gui(args)
            return
        extra = []
        for flag, value in (
            ("--bundle", args.bundle),
            ("--role", args.role),
            ("--subrole", args.subrole),
            ("--title", args.title),
            ("--description", args.description),
            ("--value", args.value),
        ):
            if value:
                extra.extend([flag, value])
        helper_action = "accessibility-semantic-find" if args.action == "semantic-find" else "accessibility-semantic-press"
        r = helper_gui_run(helper_action, timeout=args.timeout, cap=args.max_bytes, extra_args=extra)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action in ("event-observe", "event-wait"):
        extra = [
            "--events", args.events,
            "--observe-seconds", args.observe_seconds,
            "--event-limit", args.event_limit,
        ]
        for flag, value in (
            ("--bundle", args.bundle),
            ("--role", args.role),
            ("--subrole", args.subrole),
            ("--title", args.title),
            ("--description", args.description),
            ("--value", args.value),
        ):
            if value:
                extra.extend([flag, value])
        helper_action = "accessibility-event-observe" if args.action == "event-observe" else "accessibility-event-wait"
        minimum_timeout = int(float(args.observe_seconds)) + 6
        r = helper_gui_run(helper_action, timeout=max(args.timeout, minimum_timeout), cap=args.max_bytes, extra_args=extra)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "type-text":
        r = helper_gui_run("type-text", timeout=args.timeout, cap=args.max_bytes, extra_args=["--text", args.text])
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "key-press":
        r = helper_gui_run("key-press", timeout=args.timeout, cap=args.max_bytes, extra_args=["--keycode", args.keycode, "--modifiers", args.modifiers])
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "mouse-move":
        r = helper_gui_run("mouse-move", timeout=args.timeout, cap=args.max_bytes, extra_args=["--x", args.x, "--y", args.y])
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "mouse-click":
        r = helper_gui_run("mouse-click", timeout=args.timeout, cap=args.max_bytes, extra_args=["--x", args.x, "--y", args.y, "--button", args.button, "--count", args.count])
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "inspect":
        ax = helper_gui_run("accessibility-inventory", timeout=args.timeout, cap=max(args.max_bytes, 12000))
        ocr = helper_gui_run("screen-ocr", timeout=args.timeout, cap=max(args.max_bytes, 20000))
        def _decode(result):
            try:
                return json.loads(result.get("output") or "{}")
            except Exception:
                return {"status":"FAIL", "raw":result.get("output", "")}
        ax_payload = _decode(ax)
        ocr_payload = _decode(ocr)
        ok = ax.get("rc") == 0 and ocr.get("rc") == 0
        emit({
            "status":"PASS" if ok else "DEGRADED",
            "semantic":ax_payload,
            "visual_text":ocr_payload,
            "capture_backend":"ScreenCaptureKit",
            "ocr_backend":"Apple Vision",
        })
        raise SystemExit(0 if ok else 1)
    if args.action in ("helper-status", "helper-lifecycle-status", "helper-lifecycle-register", "helper-lifecycle-unregister", "helper-request-accessibility", "helper-request-screen-recording", "helper-screen-capture-test", "helper-screen-ocr", "helper-automation-test", "helper-systemevents-test", "helper-accessibility-test", "helper-accessibility-action-test", "helper-accessibility-inventory", "helper-frontmost", "helper-mouse-position", "helper-mouse-nudge"):
        sub = {
            "helper-status":"status",
            "helper-lifecycle-status":"lifecycle-status",
            "helper-lifecycle-register":"lifecycle-register",
            "helper-lifecycle-unregister":"lifecycle-unregister",
            "helper-request-accessibility":"request-accessibility",
            "helper-request-screen-recording":"request-screen-recording",
            "helper-screen-capture-test":"screen-capture-test",
            "helper-screen-ocr":"screen-ocr",
            "helper-automation-test":"automation-finder",
            "helper-systemevents-test":"automation-systemevents",
            "helper-accessibility-test":"accessibility-test",
            "helper-accessibility-action-test":"accessibility-action-test",
            "helper-accessibility-inventory":"accessibility-inventory",
            "helper-frontmost":"frontmost",
            "helper-mouse-position":"mouse-position",
            "helper-mouse-nudge":"mouse-nudge",
        }[args.action]
        r = helper_gui_run(sub, timeout=args.timeout, cap=args.max_bytes)
        if r["output"]:
            print(r["output"])
        raise SystemExit(r["rc"])
    if args.action == "open":
        if args.app:
            cmd = f"open -a {q(args.app)}" + (f" {q(args.target)}" if args.target else "")
        else:
            cmd = f"open {q(args.target)}"
    else:
        cmd = f"/usr/bin/osascript -e {q(args.code)}"
    r = ssh_run(cmd, timeout=args.timeout, cap=args.max_bytes)
    if r["output"]:
        print(r["output"])
    raise SystemExit(r["rc"])

def cmd_security(args):
    if args.action in {"firewall-enable", "firewall-disable"}:
        requested = "on" if args.action == "firewall-enable" else "off"
        command = (
            f"/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate {requested}; "
            "rc=$?; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1; exit $rc"
        )
        r = ssh_run(command, sudo=True, timeout=20, cap=8192)
        state = "ENABLED" if "State = 1" in r["output"] else ("DISABLED" if "State = 0" in r["output"] else "UNKNOWN")
        expected = "ENABLED" if requested == "on" else "DISABLED"
        ok = r["rc"] == 0 and state == expected
        emit({
            "status": "PASS" if ok else "FAIL",
            "schema": "macctl-host-hardening/v1",
            "operation": args.action,
            "requested_state": expected,
            "observed_state": state,
            "explicit_confirmation": bool(args.confirm),
            "duration_ms": r["duration_ms"],
        })
        if not ok:
            raise SystemExit(r["rc"] or 1)
        return
    if args.action == "hardening-assess":
        remote = (
            "printf '@@MACOS@@\\n'; sw_vers -productVersion 2>&1; "
            "printf '@@BUILD@@\\n'; sw_vers -buildVersion 2>&1; "
            "printf '@@FILEVAULT@@\\n'; fdesetup status 2>&1; "
            "printf '@@FIREWALL_GLOBAL@@\\n'; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1; "
            "printf '@@FIREWALL_BLOCK_ALL@@\\n'; /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>&1; "
            "printf '@@FIREWALL_STEALTH@@\\n'; /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>&1; "
            "printf '@@FIREWALL_ALLOW_SIGNED@@\\n'; /usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned 2>&1; "
            "printf '@@REMOTE_LOGIN@@\\n'; sudo -n /usr/sbin/systemsetup -getremotelogin 2>&1; "
            "printf '@@PMSET_CUSTOM@@\\n'; pmset -g custom 2>&1"
        )
        r = ssh_run(remote, timeout=20, cap=24000)
        require_ok(r, "security-hardening-assess")
        snapshot = parse_probe_output(r["output"])
        payload = evaluate_hardening(snapshot)
        payload["target"] = TARGET
        payload["duration_ms"] = r["duration_ms"]
        emit(payload)
        return
    if args.action == "ssh-state":
        cmd = "/usr/sbin/sshd -T | egrep '^(authenticationmethods|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|maxauthtries|allowagentforwarding|allowtcpforwarding|permittty|usepam)'"
        sudo = True
    elif args.action == "sudo-state":
        cmd = "sudo -n true && echo SUDO_NOPASSWD=YES || echo SUDO_NOPASSWD=NO"
        sudo = False
    elif args.action == "hostkey":
        cmd = "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
        sudo = False
    elif args.action == "posture":
        remote = (
            "printf 'FILEVAULT='; fdesetup status 2>&1; "
            "printf 'GATEKEEPER='; spctl --status 2>&1; "
            "printf 'SIP='; csrutil status 2>&1; "
            "printf 'FIREWALL='; /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>&1; "
            "printf 'FDA_MAIL='; test -r \"$HOME/Library/Mail\" && echo PASS || echo DENIED; "
            "printf 'FDA_SAFARI='; test -r \"$HOME/Library/Safari\" && echo PASS || echo DENIED; "
            "printf 'SSHD='; sudo -n /usr/sbin/sshd -T | egrep '^(authenticationmethods|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|maxauthtries)' | tr '\\n' ';'"
        )
        r = ssh_run(remote, timeout=20, cap=16384)
        require_ok(r, "security-posture")
        out = r["output"]
        emit({
            "status":"PASS",
            "filevault":"ON" if "FILEVAULT=FileVault is On." in out else ("OFF" if "FILEVAULT=FileVault is Off." in out else "UNKNOWN"),
            "gatekeeper":"ENABLED" if "GATEKEEPER=assessments enabled" in out else "UNKNOWN",
            "sip":"ENABLED" if "SIP=System Integrity Protection status: enabled." in out else "UNKNOWN",
            "firewall":"ENABLED" if "State = 1" in out else ("DISABLED" if "State = 0" in out else "UNKNOWN"),
            "full_disk_mail":"PASS" if "FDA_MAIL=PASS" in out else "DENIED",
            "full_disk_safari":"PASS" if "FDA_SAFARI=PASS" in out else "DENIED",
            "ssh_password":"DISABLED" if "passwordauthentication no" in out else "UNKNOWN",
            "ssh_kbdinteractive":"DISABLED" if "kbdinteractiveauthentication no" in out else "UNKNOWN",
            "ssh_publickey":"ENABLED" if "pubkeyauthentication yes" in out else "UNKNOWN",
            "ssh_root_login":"DISABLED" if "permitrootlogin no" in out else "UNKNOWN",
            "duration_ms":r["duration_ms"]
        })
        return
    elif args.action == "tcc-state":
        user_sql = (
            "select service,client,client_type,auth_value,indirect_object_identifier "
            "from access where (service='kTCCServiceAppleEvents' and "
            "(client='app.openai.macctl.helper' or client='/usr/libexec/sshd-keygen-wrapper')) "
            "order by service,client,indirect_object_identifier;"
        )
        system_sql = (
            "select service,client,client_type,auth_value,indirect_object_identifier "
            "from access where service in ('kTCCServiceScreenCapture','kTCCServiceAccessibility') and "
            "client='app.openai.macctl.helper' order by service,client;"
        )
        user_cmd = (
            'db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"; ' +
            '/usr/bin/sqlite3 -separator "|" "$db" ' + shlex.quote(user_sql)
        )
        system_cmd = (
            'db="/Library/Application Support/com.apple.TCC/TCC.db"; ' +
            '/usr/bin/sqlite3 -separator "|" "$db" ' + shlex.quote(system_sql)
        )
        ur = ssh_run(user_cmd, timeout=10, cap=8192)
        sr = ssh_run(system_cmd, sudo=True, timeout=10, cap=8192)
        require_ok(ur, "tcc-user-state")
        require_ok(sr, "tcc-system-state")
        def rows(text):
            out = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                parts = line.split("|", 4)
                if len(parts) == 5:
                    out.append({
                        "service":parts[0], "client":parts[1], "client_type":int(parts[2]),
                        "auth_value":int(parts[3]), "target":parts[4]
                    })
            return out
        system_rows = rows(sr["output"])
        emit({
            "status":"PASS",
            "apple_events":rows(ur["output"]),
            "accessibility":[r for r in system_rows if r["service"] == "kTCCServiceAccessibility"],
            "screen_capture":[r for r in system_rows if r["service"] == "kTCCServiceScreenCapture"],
            "auth_value_note":{"0":"DENY","2":"ALLOW"}
        })
        return
    elif args.action == "tcc-probe":
        screen = ssh_run("tmp=/tmp/macctl-tcc-screen.png; /usr/sbin/screencapture -x $tmp >/dev/null 2>&1; test -s $tmp; rc=$?; /bin/rm -f $tmp; exit $rc", timeout=8, cap=4096)
        helper_status = helper_gui_run("status", timeout=8, cap=4096)
        automation = helper_gui_run("automation-finder", timeout=8, cap=4096)
        accessibility = helper_gui_run("accessibility-test", timeout=8, cap=4096)
        helper_screen = "UNKNOWN"
        if helper_status["rc"] == 0:
            try:
                hs = json.loads(helper_status["output"])
                helper_screen = "PASS" if hs.get("screen_recording") else "NEEDS_USER_APPROVAL"
            except Exception:
                pass
        emit({
            "status":"PASS",
            "ssh_screenshot_transport":"PASS" if screen["rc"] == 0 else "NEEDS_USER_APPROVAL",
            "helper_screen_recording":helper_screen,
            "helper_automation_finder":"PASS" if automation["rc"] == 0 else "NEEDS_USER_APPROVAL",
            "helper_accessibility":"PASS" if accessibility["rc"] == 0 else "NEEDS_USER_APPROVAL",
            "automation_rc":automation["rc"],
            "accessibility_rc":accessibility["rc"]
        })
        return
    elif args.action == "password-probe":
        passfile = Path("/etc/macctl/macmini.pass")
        if not passfile.is_file():
            emit({"status":"SKIP","password_login":"UNKNOWN","reason":"bootstrap_password_removed"})
            return
        argv = ["sshpass","-f",str(passfile),"ssh","-F",SSH_CONFIG,
                "-o","ControlMaster=no","-o","ControlPath=none",
                "-o","BatchMode=no","-o","PubkeyAuthentication=no",
                "-o","PasswordAuthentication=yes","-o","KbdInteractiveAuthentication=yes",
                "-o","PreferredAuthentications=password,keyboard-interactive",
                "-o","NumberOfPasswordPrompts=1",TARGET,"printf PASSWORD_AUTH_UNEXPECTED"]
        r = run(argv, timeout=10, cap=4096)
        denied = r["rc"] != 0
        emit({"status":"PASS" if denied else "FAIL","password_login":"DENIED" if denied else "ACCEPTED","rc":r["rc"],"duration_ms":r["duration_ms"]})
        if not denied:
            raise SystemExit(1)
        return
    else:
        cmd = 'for p in "$HOME/Library/Mail" "$HOME/Library/Safari"; do printf "%s=" "$p"; test -r "$p" && echo PASS || echo DENIED; done'
        sudo = False
    r = ssh_run(cmd, sudo=sudo, timeout=15)
    print(r["output"])
    raise SystemExit(r["rc"])

def cmd_control(args):
    if args.action == "check":
        r = run(ssh_argv(op="check"), timeout=5, cap=4096)
    elif args.action == "stop":
        r = run(ssh_argv(op="exit"), timeout=5, cap=4096)
    else:
        r = ssh_run("printf WARM", timeout=10)
    emit({"status": "PASS" if r["rc"] == 0 else "FAIL", "action": args.action, **r})
    raise SystemExit(r["rc"])

def cmd_audit(args):
    if args.action == "status":
        verify = verify_audit_chain(AUDIT_PATH, retention_files=AUDIT_RETENTION_FILES)
        emit({
            "status": "PASS",
            "schema": "macctl-audit/v2",
            "path": str(AUDIT_PATH),
            "max_bytes": AUDIT_MAX_BYTES,
            "retention_files": AUDIT_RETENTION_FILES,
            "digest_seal": AUDIT_DIGEST_SEAL,
            "verify": verify,
        })
        return
    if args.action == "verify":
        result = verify_audit_chain(AUDIT_PATH, retention_files=AUDIT_RETENTION_FILES)
        emit(result)
        if result.get("status") != "PASS":
            raise SystemExit(1)
        return

    selected = read_audit_lines(
        AUDIT_PATH,
        lines=max(1, int(args.lines)),
        retention_files=AUDIT_RETENTION_FILES,
    )
    if not selected:
        print("AUDIT_EMPTY")
        return
    if args.action == "tail":
        for line in selected:
            print(line)
        return
    counts = {}
    failures = 0
    errors = {}
    for line in selected:
        try:
            rec = json.loads(line)
        except Exception:
            continue
        key = rec.get("cmd") or "unknown"
        counts[key] = counts.get(key, 0) + 1
        error_class = rec.get("error_class") or ("SUCCESS" if int(rec.get("rc", 0) or 0) == 0 else "LEGACY_NONZERO")
        errors[error_class] = errors.get(error_class, 0) + 1
        if int(rec.get("rc", 0) or 0) != 0:
            failures += 1
    emit({"status":"PASS","records":len(selected),"nonzero_rc":failures,"commands":counts,"error_classes":errors})

def build_parser():
    p = argparse.ArgumentParser(prog="macctl", description="Fast high-privilege macOS control plane over pinned OpenSSH")
    p.add_argument("--correlation-id", help="审计 correlation_id；未提供时自动生成，也可用 MACCTL_CORRELATION_ID")
    p.add_argument("--request-id", help="事务/幂等 request_id；修改类操作建议显式提供")
    p.add_argument("--expect-sha256", action="append", default=[], metavar="REMOTE_PATH=SHA256", help="事务前置条件：远端文件 SHA-256 必须匹配；可重复")
    p.add_argument("--expect-present", action="append", default=[], metavar="REMOTE_PATH", help="事务前置条件：远端路径必须存在；可重复")
    p.add_argument("--expect-absent", action="append", default=[], metavar="REMOTE_PATH", help="事务前置条件：远端路径必须不存在；可重复")
    sp = p.add_subparsers(dest="cmd", required=True)

    for name, fn in [("version", cmd_version), ("ping", cmd_ping), ("status", cmd_status), ("health", cmd_health), ("wake", cmd_wake), ("capabilities", cmd_capabilities)]:
        x = sp.add_parser(name)
        x.set_defaults(fn=fn)

    fl = sp.add_parser("fleet")
    fls = fl.add_subparsers(dest="action", required=True)
    y = fls.add_parser("list")
    y.set_defaults(fn=cmd_fleet)
    y = fls.add_parser("status")
    y.set_defaults(fn=cmd_fleet)
    y = fls.add_parser("doctor")
    y.set_defaults(fn=cmd_fleet)
    y = fls.add_parser("resolve")
    y.add_argument("target", nargs="?", help="显式 target_id；省略时只解析当前默认生产目标")
    y.set_defaults(fn=cmd_fleet)
    y = fls.add_parser("plan")
    y.add_argument("target", help="必须显式指定 target_id；仅生成绑定/授权计划，不联系目标")
    y.set_defaults(fn=cmd_fleet)

    x = sp.add_parser("doctor")
    x.add_argument("--timeout", type=int, default=20)
    x.add_argument("--max-bytes", type=int, default=24000)
    x.set_defaults(fn=cmd_doctor)

    x = sp.add_parser("auth")
    x.add_argument("--fresh", action="store_true")
    x.set_defaults(fn=cmd_auth)

    ar = sp.add_parser("artifact")
    ars = ar.add_subparsers(dest="action", required=True)
    y = ars.add_parser("import")
    y.add_argument("source", help="VM-local source path under configured import roots")
    y.add_argument("--filename")
    y.add_argument("--classification", choices=["SCREEN_CAPTURE", "GENERATED_FILE", "USER_SELECTED", "BROWSER_DOWNLOAD", "DIAGNOSTIC", "SENSITIVE", "SECRET", "DENY_EXPORT"], default="USER_SELECTED")
    y.add_argument("--ttl-seconds", type=int)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("list")
    y.add_argument("--limit", type=int, default=50)
    y.set_defaults(fn=cmd_artifact)
    for act in ["inspect", "verify", "revoke"]:
        y = ars.add_parser(act)
        y.add_argument("artifact_id")
        y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("gc")
    y.add_argument("--keep-revoked", action="store_true")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("grant")
    y.add_argument("artifact_id")
    y.add_argument("--scope", choices=["view", "download"], default="download")
    y.add_argument("--ttl-seconds", type=int, default=300)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("revoke-grants")
    y.add_argument("artifact_id")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-probe")
    y.add_argument("artifact_id", nargs="?")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("host-adapter-evaluate")
    y.add_argument("artifact_id")
    y.add_argument("--adapter", required=True)
    y.add_argument("--surface", required=True)
    y.add_argument("--inline-visible", action="store_true")
    y.add_argument("--native-attachment", action="store_true")
    y.add_argument("--stable-file-reference", action="store_true")
    y.add_argument("--host-reported-sha256")
    y.add_argument("--host-reported-size-bytes", type=int)
    y.add_argument("--redownload-sha256")
    y.add_argument("--resource-link", action="store_true")
    y.add_argument("--link-only", action="store_true")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("host-native-conformance-contract")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("host-native-conformance-fixture")
    y.add_argument("artifact_id")
    y.add_argument("--adapter", required=True)
    y.add_argument("--surface", required=True)
    y.add_argument("--inline-visible", action="store_true")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("host-native-runtime-watch-baseline")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("host-native-runtime-watch-evaluate")
    y.add_argument("--observations-file", required=True)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-plan")
    y.add_argument("artifact_id")
    y.add_argument("--presentation", choices=["auto", "inline", "attachment", "both"], default="both")
    y.add_argument("--original-required", action=argparse.BooleanOptionalAction, default=True)
    y.add_argument("--allow-debug-fallback", action="store_true")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-create")
    y.add_argument("artifact_id")
    y.add_argument("--idempotency-key", required=True)
    y.add_argument("--presentation", choices=["auto", "inline", "attachment", "both"], default="both")
    y.add_argument("--original-required", action=argparse.BooleanOptionalAction, default=True)
    y.add_argument("--allow-debug-fallback", action="store_true")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-status")
    y.add_argument("delivery_session_id")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-list")
    y.add_argument("--limit", type=int, default=50)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-host-accept")
    y.add_argument("delivery_session_id")
    y.add_argument("--adapter", required=True)
    y.add_argument("--receipt-id", required=True)
    y.add_argument("--sha256", required=True)
    y.add_argument("--size-bytes", type=int, required=True)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-render-qualify")
    y.add_argument("delivery_session_id")
    y.add_argument("--surface", required=True)
    y.add_argument("--native-attachment", action=argparse.BooleanOptionalAction, default=True)
    y.add_argument("--exact-original", action=argparse.BooleanOptionalAction, default=True)
    y.add_argument("--downloaded-sha256", required=True)
    y.add_argument("--inline-visible", action=argparse.BooleanOptionalAction, default=False)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-user-confirm")
    y.add_argument("delivery_session_id")
    y.add_argument("--confirmed-by", required=True)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("delivery-fail")
    y.add_argument("delivery_session_id")
    y.add_argument("--reason", required=True)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("relay-stage")
    y.add_argument("artifact_id")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("relay-status")
    y.add_argument("relay_id")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("relay-cleanup")
    y.add_argument("relay_id")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("lan-probe")
    y.add_argument("--sample-mib", type=int, default=8)
    y.add_argument("--tcp-attempts", type=int, default=3)
    y.add_argument("--timeout", type=float, default=8.0)
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("route-auto")
    y.add_argument("artifact_id")
    y.add_argument("--sample-mib", type=int, default=8)
    y.add_argument("--tcp-attempts", type=int, default=3)
    y.add_argument("--timeout", type=float, default=8.0)
    y.add_argument("--probe", action="append", default=[], help="optional JSON PathProbe for overlay/relay candidates")
    y.set_defaults(fn=cmd_artifact)
    y = ars.add_parser("route-plan")
    y.add_argument("artifact_id")
    y.add_argument("--probe", action="append", default=[], help="JSON PathProbe object; repeat for LAN/overlay/relay candidates")
    y.set_defaults(fn=cmd_artifact)

    x = sp.add_parser("exec")
    x.add_argument("--sudo", action="store_true")
    x.add_argument("--json", action="store_true")
    x.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    x.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    x.add_argument("command", nargs=argparse.REMAINDER)
    x.set_defaults(fn=cmd_exec)

    x = sp.add_parser("script")
    x.add_argument("file")
    x.add_argument("--shell", choices=["zsh", "bash", "sh"], default="zsh")
    x.add_argument("--sudo", action="store_true")
    x.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    x.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    x.set_defaults(fn=cmd_script)

    f = sp.add_parser("file")
    fs = f.add_subparsers(dest="action", required=True)
    for act in ["read", "list", "stat", "sha256", "mkdir", "rm"]:
        y = fs.add_parser(act)
        y.add_argument("path")
        y.add_argument("--sudo", action="store_true")
        y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
        if act == "read":
            y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
        if act == "list":
            y.add_argument("--limit", type=int, default=100)
        if act == "mkdir":
            y.add_argument("--parents", action="store_true")
        if act == "rm":
            y.add_argument("--recursive", action="store_true")
        y.set_defaults(fn=cmd_file)
    for act in ["mv", "cp"]:
        y = fs.add_parser(act)
        y.add_argument("src")
        y.add_argument("dst")
        y.add_argument("--sudo", action="store_true")
        y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
        if act == "cp":
            y.add_argument("--recursive", action="store_true")
        y.set_defaults(fn=cmd_file)

    x = sp.add_parser("push")
    x.add_argument("local")
    x.add_argument("remote")
    x.add_argument("--timeout", type=int, default=600)
    x.set_defaults(fn=cmd_push)

    x = sp.add_parser("pull")
    x.add_argument("remote")
    x.add_argument("local")
    x.add_argument("--recursive", action="store_true")
    x.add_argument("--timeout", type=int, default=600)
    x.set_defaults(fn=cmd_pull)

    pr = sp.add_parser("process")
    ps = pr.add_subparsers(dest="action", required=True)
    y = ps.add_parser("list")
    y.add_argument("--match")
    y.add_argument("--limit", type=int, default=50)
    y.set_defaults(fn=cmd_process)
    y = ps.add_parser("top")
    y.add_argument("--limit", type=int, default=30)
    y.set_defaults(fn=cmd_process)
    y = ps.add_parser("kill")
    y.add_argument("pid", type=int)
    y.add_argument("--signal", default="TERM")
    y.add_argument("--sudo", action="store_true")
    y.set_defaults(fn=cmd_process)

    la = sp.add_parser("launchd")
    ls = la.add_subparsers(dest="action", required=True)
    y = ls.add_parser("list")
    y.set_defaults(fn=cmd_launchd, scope="user", timeout=15)
    for act in ["print", "kickstart", "enable", "disable"]:
        y = ls.add_parser(act)
        y.add_argument("label")
        y.add_argument("--scope", choices=["user", "system"], default="user")
        y.add_argument("--timeout", type=int, default=30)
        if act == "kickstart":
            y.add_argument("--kill", action="store_true")
        y.set_defaults(fn=cmd_launchd)

    lg = sp.add_parser("logs")
    lg.add_argument("--last", default="10m")
    lg.add_argument("--predicate")
    lg.add_argument("--level", choices=["default", "info", "debug"])
    lg.add_argument("--style", choices=["compact", "syslog", "json"], default="compact")
    lg.add_argument("--sudo", action="store_true")
    lg.add_argument("--timeout", type=int, default=60)
    lg.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    lg.set_defaults(fn=cmd_logs)

    sy = sp.add_parser("system")
    ss = sy.add_subparsers(dest="action", required=True)
    for act in ["info", "disk", "memory", "network", "network-summary", "dns", "proxy", "storage-health", "power", "thermal", "power-schedule", "network-quality"]:
        y = ss.add_parser(act)
        y.add_argument("--sudo", action="store_true")
        y.add_argument("--timeout", type=int, default=30)
        y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
        y.set_defaults(fn=cmd_system)
    y = ss.add_parser("reachability")
    y.add_argument("host")
    y.add_argument("--timeout", type=int, default=10)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_system, sudo=False)

    pw = sp.add_parser("power")
    pws = pw.add_subparsers(dest="action", required=True)
    y = pws.add_parser("sleep")
    y.set_defaults(fn=cmd_power, confirm=False)
    y = pws.add_parser("blockers")
    y.set_defaults(fn=cmd_power, confirm=False)
    for act in ["restart", "shutdown"]:
        y = pws.add_parser(act)
        y.add_argument("--confirm", action="store_true")
        y.set_defaults(fn=cmd_power)

    up = sp.add_parser("update")
    ups = up.add_subparsers(dest="action", required=True)
    y = ups.add_parser("list")
    y.add_argument("--timeout", type=int, default=180)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_update)
    y = ups.add_parser("settings")
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_update)
    y = ups.add_parser("policy")
    y.set_defaults(fn=cmd_update)
    y = ups.add_parser("install")
    y.add_argument("label")
    y.add_argument("--timeout", type=int, default=3600)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_update)
    for act in ["safari-download", "safari-install", "install-all"]:
        y = ups.add_parser(act)
        y.add_argument("--timeout", type=int, default=3600)
        y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
        y.set_defaults(fn=cmd_update)

    br = sp.add_parser("brew")
    bs = br.add_subparsers(dest="action", required=True)
    for act in ["version", "list", "doctor", "update", "upgrade"]:
        y = bs.add_parser(act)
        y.add_argument("--timeout", type=int, default=900)
        y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
        y.set_defaults(fn=cmd_brew)

    ws = sp.add_parser("workstation")
    wss = ws.add_subparsers(dest="action", required=True)
    for act in ["profile", "inventory", "doctor", "qualification-plan", "qualification"]:
        y = wss.add_parser(act)
        y.set_defaults(fn=cmd_workstation)

    ln = sp.add_parser("linux")
    lns = ln.add_subparsers(dest="action", required=True)
    for act in ["profile", "list"]:
        y = lns.add_parser(act)
        y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("overview")
    for opt in ["provider", "region", "role", "environment", "tag"]:
        y.add_argument(f"--{opt}")
    y.set_defaults(fn=cmd_linux)
    for act in ["fleet-status", "fleet-doctor"]:
        y = lns.add_parser(act)
        y.add_argument("--parallel", type=int, default=3)
        for opt in ["provider", "region", "role", "environment", "tag"]:
            y.add_argument(f"--{opt}")
        y.set_defaults(fn=cmd_linux)
    for act in ["status", "doctor", "transport", "qualification-plan", "qualification"]:
        y = lns.add_parser(act)
        y.add_argument("target")
        y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("command")
    y.add_argument("target")
    y.add_argument("--command", required=True)
    y.add_argument("--sudo", action="store_true")
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-high-impact", action="store_true")
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("logs")
    y.add_argument("target")
    y.add_argument("--unit")
    y.add_argument("--lines", type=int, default=50)
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("package")
    y.add_argument("target")
    y.add_argument("name")
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("network")
    y.add_argument("target")
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("process")
    y.add_argument("target")
    y.add_argument("--limit", type=int, default=25)
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("systemd")
    y.add_argument("target")
    y.add_argument("unit")
    y.add_argument("--lines", type=int, default=25)
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)
    y = lns.add_parser("file")
    y.add_argument("target")
    y.add_argument("file_action", choices=["read", "stat", "sha256"])
    y.add_argument("path")
    y.add_argument("--sudo", action="store_true")
    y.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_linux)

    sn = sp.add_parser("sync")
    sns = sn.add_subparsers(dest="action", required=True)
    y = sns.add_parser("push")
    y.add_argument("local")
    y.add_argument("remote")
    y.add_argument("--delete", action="store_true")
    y.add_argument("--dry-run", action="store_true")
    y.add_argument("--timeout", type=int, default=1800)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_sync)
    y = sns.add_parser("pull")
    y.add_argument("remote")
    y.add_argument("local")
    y.add_argument("--delete", action="store_true")
    y.add_argument("--dry-run", action="store_true")
    y.add_argument("--timeout", type=int, default=1800)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_sync)

    bk = sp.add_parser("backup")
    bks = bk.add_subparsers(dest="action", required=True)
    for act in ["status", "destinations", "snapshots", "apfs-snapshots", "create-local"]:
        y = bks.add_parser(act)
        y.add_argument("--timeout", type=int, default=60)
        y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
        y.set_defaults(fn=cmd_backup)
    y = bks.add_parser("delete-local")
    y.add_argument("date")
    y.add_argument("--timeout", type=int, default=60)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_backup)

    jb = sp.add_parser("job")
    js = jb.add_subparsers(dest="action", required=True)
    y = js.add_parser("start")
    y.add_argument("command", nargs=argparse.REMAINDER)
    y.add_argument("--id")
    y.set_defaults(fn=cmd_job)
    y = js.add_parser("list")
    y.set_defaults(fn=cmd_job)
    y = js.add_parser("status")
    y.add_argument("id")
    y.set_defaults(fn=cmd_job)
    y = js.add_parser("log")
    y.add_argument("id")
    y.add_argument("--lines", type=int, default=100)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_job)
    y = js.add_parser("kill")
    y.add_argument("id")
    y.add_argument("--signal", default="TERM")
    y.set_defaults(fn=cmd_job)
    y = js.add_parser("cleanup")
    y.add_argument("--older-than-days", type=int, default=7)
    y.set_defaults(fn=cmd_job)

    ms = sp.add_parser("messaging")
    mss = ms.add_subparsers(dest="action", required=True)
    y = mss.add_parser("bind")
    y.add_argument("--provider", choices=["wechat","feishu"], required=True)
    y.add_argument("--contact", required=True)
    y.add_argument("--allow-send", action="store_true")
    y.add_argument("--confirm", action="store_true")
    y.set_defaults(fn=cmd_messaging)
    y = mss.add_parser("list")
    y.set_defaults(fn=cmd_messaging)
    y = mss.add_parser("observe")
    y.add_argument("binding_id")
    y.set_defaults(fn=cmd_messaging)
    y = mss.add_parser("read")
    y.add_argument("binding_id")
    y.add_argument("--limit", type=int, default=20)
    y.set_defaults(fn=cmd_messaging)
    y = mss.add_parser("draft")
    y.add_argument("binding_id")
    y.add_argument("--message-file", required=True)
    y.add_argument("--expect-token")
    y.add_argument("--adopt-existing", action="store_true", help="verify and register an already-visible composer draft without typing again")
    y.set_defaults(fn=cmd_messaging)
    y = mss.add_parser("send")
    y.add_argument("draft_id")
    y.add_argument("--expect-token")
    y.add_argument("--confirm", action="store_true")
    y.set_defaults(fn=cmd_messaging)

    cb = sp.add_parser("clipboard")
    cs = cb.add_subparsers(dest="action", required=True)
    y = cs.add_parser("get")
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_clipboard)
    y = cs.add_parser("set")
    y.add_argument("text", nargs="?")
    y.set_defaults(fn=cmd_clipboard)

    brw = sp.add_parser("browser")
    brws = brw.add_subparsers(dest="action", required=True)
    y = brws.add_parser("cdp-plan")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("cdp-smoke")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("control-plan")
    y.add_argument("--browser-family", choices=["chrome", "safari"], required=True)
    y.add_argument("--context", choices=["isolated", "existing_session"], required=True)
    y.add_argument("--operation", choices=["navigate", "query", "extract", "analyze", "wait", "pages", "history", "reload", "observe", "type", "select", "search", "key", "click", "download", "upload"], required=True)
    y.add_argument("--authenticated", action="store_true")
    y.add_argument("--cdp-available", action=argparse.BooleanOptionalAction, default=True)
    y.add_argument("--ax-available", action=argparse.BooleanOptionalAction, default=True)
    y.add_argument("--vision-available", action=argparse.BooleanOptionalAction, default=True)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-plan")
    y.add_argument("--site-host", required=True)
    y.add_argument("--browser-family", choices=["chrome", "safari"], default="chrome")
    y.add_argument("--site-path-prefix", default="/")
    y.add_argument("--authorized-action-id", required=True)
    y.add_argument("--intent", choices=["read_only", "reversible_test"], default="reversible_test")
    y.add_argument("--resource-scope")
    y.add_argument("--ttl-seconds", type=int, default=900)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-begin")
    y.add_argument("--site-host", required=True)
    y.add_argument("--browser-family", choices=["chrome", "safari"], default="chrome")
    y.add_argument("--site-path-prefix", default="/")
    y.add_argument("--authorized-action-id", required=True)
    y.add_argument("--intent", choices=["read_only", "reversible_test"], default="reversible_test")
    y.add_argument("--resource-scope")
    y.add_argument("--ttl-seconds", type=int, default=900)
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.add_argument("--confirm-native-profile", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-list")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-status")
    y.add_argument("authorized_action_id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-observe")
    y.add_argument("authorized_action_id")
    y.add_argument("--expect-text")
    y.add_argument("--expect-absent-text")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-type")
    y.add_argument("authorized_action_id")
    y.add_argument("text")
    y.add_argument("--visual-expect-text")
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.add_argument("--confirm-native-profile", action="store_true")
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-click")
    y.add_argument("authorized_action_id")
    y.add_argument("x", type=float)
    y.add_argument("y", type=float)
    y.add_argument("--effect", choices=["reversible_mutation", "cleanup_test_object", "publish", "delete_existing", "send", "payment", "account_security", "credential_export", "cookie_export", "session_token_export"], required=True)
    y.add_argument("--visual-expect-text")
    y.add_argument("--button", choices=["left", "right", "middle"], default="left")
    y.add_argument("--count", type=int, choices=[1, 2, 3], default=1)
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.add_argument("--confirm-native-profile", action="store_true")
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-key")
    y.add_argument("authorized_action_id")
    y.add_argument("keycode", type=int)
    y.add_argument("--modifiers", default="")
    y.add_argument("--effect", choices=["reversible_mutation", "cleanup_test_object"], required=True)
    y.add_argument("--visual-expect-text")
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.add_argument("--confirm-native-profile", action="store_true")
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-finish")
    y.add_argument("authorized_action_id")
    y.add_argument("--result", choices=["verified_cleanup", "aborted_no_mutation", "cleanup_pending"], required=True)
    y.add_argument("--cleanup-verified", action="store_true")
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.add_argument("--confirm-native-profile", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-recovery-plan")
    y.add_argument("authorized_action_id", nargs="?")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-recovery-observe")
    y.add_argument("authorized_action_id")
    y.add_argument("--expect-text")
    y.add_argument("--expect-absent-text")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("native-action-recover-interrupted")
    y.add_argument("authorized_action_id")
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.add_argument("--confirm-native-profile", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("qualification-plan")
    y.add_argument("--site-class", choices=["synthetic", "public", "production"], default="production")
    y.add_argument("--qualification-scope", choices=["read_only", "controlled_input", "stateful_mutation"], default="read_only")
    y.add_argument("--allow-host", action="append", default=[])
    y.add_argument("--allow-loopback", action="store_true")
    y.add_argument("--authorized-action-id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("url-check")
    y.add_argument("url")
    y.add_argument("--allow-host", action="append", default=[])
    y.add_argument("--allow-loopback", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-start")
    y.add_argument("--session-id")
    y.add_argument("--allow-host", action="append", default=[])
    y.add_argument("--allow-loopback", action="store_true")
    y.add_argument("--ttl-seconds", type=int, default=1800)
    y.add_argument("--site-class", choices=["synthetic", "public", "production"], default="synthetic")
    y.add_argument("--qualification-scope", choices=["read_only", "controlled_input", "stateful_mutation"], default="read_only")
    y.add_argument("--authorized-action-id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-list")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-status")
    y.add_argument("session_id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-stop")
    y.add_argument("session_id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-navigate")
    y.add_argument("session_id")
    y.add_argument("url")
    y.add_argument("--visual-expect-text")
    y.add_argument("--timeout", type=int, default=15)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-query")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-extract")
    y.add_argument("session_id")
    y.add_argument("--mode", choices=["summary", "text", "links", "forms", "interactive", "full"], default="summary")
    y.add_argument("--selector")
    y.add_argument("--max-chars", type=int, default=65536)
    y.add_argument("--max-items", type=int, default=100)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-wait")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("--state", choices=["present", "visible", "absent"], default="present")
    y.add_argument("--expect-text")
    y.add_argument("--expect-value")
    y.add_argument("--timeout", type=float, default=15.0)
    y.add_argument("--interval", type=float, default=0.2)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-analyze")
    y.add_argument("session_id")
    y.add_argument("--max-chars", type=int, default=65536)
    y.add_argument("--max-items", type=int, default=100)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-pages")
    y.add_argument("session_id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-activate")
    y.add_argument("session_id")
    y.add_argument("target_id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-new-tab")
    y.add_argument("session_id")
    y.add_argument("url")
    y.add_argument("--timeout", type=float, default=10.0)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-close-tab")
    y.add_argument("session_id")
    y.add_argument("target_id")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-type")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("text", nargs="?")
    y.add_argument("--text-file")
    y.add_argument("--consume-text-file", action="store_true")
    y.add_argument("--visual-expect-text")
    y.add_argument("--input-class", choices=["plain", "credential"], default="plain")
    y.add_argument("--confirm-production", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-select")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("value")
    y.add_argument("--visual-expect-text")
    y.add_argument("--confirm-production", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-search")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("query")
    y.add_argument("--expect-selector", required=True)
    y.add_argument("--expect-text")
    y.add_argument("--timeout", type=float, default=15.0)
    y.add_argument("--confirm-production", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-key")
    y.add_argument("session_id")
    y.add_argument("key")
    y.add_argument("--selector")
    y.add_argument("--modifier", action="append", default=[])
    y.add_argument("--expect-selector")
    y.add_argument("--expect-text")
    y.add_argument("--visual-expect-text")
    y.add_argument("--settle-seconds", type=float, default=0.25)
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-history")
    y.add_argument("session_id")
    y.add_argument("direction", choices=["back", "forward"])
    y.add_argument("--timeout", type=int, default=15)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-reload")
    y.add_argument("session_id")
    y.add_argument("--ignore-cache", action="store_true")
    y.add_argument("--timeout", type=int, default=15)
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-click")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("--expect-selector", required=True)
    y.add_argument("--expect-text")
    y.add_argument("--visual-expect-text")
    y.add_argument("--settle-seconds", type=float, default=0.25)
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-download")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("--filename")
    y.add_argument("--ttl-seconds", type=int)
    y.add_argument("--timeout", type=int, default=30)
    y.add_argument("--confirm", action="store_true")
    y.set_defaults(fn=cmd_browser)
    y = brws.add_parser("session-upload")
    y.add_argument("session_id")
    y.add_argument("selector")
    y.add_argument("artifact_id")
    y.add_argument("--timeout", type=int, default=30)
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--confirm-production", action="store_true")
    y.set_defaults(fn=cmd_browser)

    gu = sp.add_parser("gui")
    gs = gu.add_subparsers(dest="action", required=True)
    y = gs.add_parser("open")
    y.add_argument("target", nargs="?")
    y.add_argument("--app")
    y.add_argument("--timeout", type=int, default=20)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("osascript")
    y.add_argument("code")
    y.add_argument("--timeout", type=int, default=30)
    y.add_argument("--max-bytes", type=int, default=DEFAULT_CAP)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("screenshot")
    y.add_argument("local", nargs="?", help="optional VM-local output path; omit when using --artifact")
    y.add_argument("--artifact", action="store_true", help="snapshot exact PNG into Artifact Core")
    y.add_argument("--filename", help="logical artifact filename (default: macctl-screen.png)")
    y.add_argument("--ttl-seconds", type=int, help="artifact TTL; minimum 60 seconds")
    y.add_argument("--timeout", type=int, default=20)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("inspect")
    y.add_argument("--timeout", type=int, default=25)
    y.add_argument("--max-bytes", type=int, default=20000)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("compare")
    y.add_argument("before")
    y.add_argument("after")
    y.add_argument("--region", help="x,y,w,h in screenshot pixels")
    y.add_argument("--threshold", type=int, default=8)
    y.add_argument("--min-ratio", type=float, default=0.0005)
    y.add_argument("--expect-change", action="store_true")
    y.set_defaults(fn=cmd_gui)
    for semantic_action in ["semantic-find", "semantic-press"]:
        y = gs.add_parser(semantic_action)
        y.add_argument("--bundle")
        y.add_argument("--role")
        y.add_argument("--subrole")
        y.add_argument("--title")
        y.add_argument("--description")
        y.add_argument("--value")
        y.add_argument("--match-mode", choices=["exact", "ranked"], default="exact")
        y.add_argument("--min-score", type=int, default=70)
        y.add_argument("--min-margin", type=int, default=10)
        y.add_argument("--timeout", type=int, default=15)
        y.add_argument("--max-bytes", type=int, default=12000)
        y.set_defaults(fn=cmd_gui)
    event_choices = [
        "window-created", "focused-window-changed", "focused-ui-element-changed", "main-window-changed",
        "application-activated", "application-deactivated", "application-hidden", "application-shown",
        "value-changed", "moved", "resized", "selected-children-changed", "ui-element-destroyed",
    ]
    for event_action in ["event-observe", "event-wait"]:
        y = gs.add_parser(event_action)
        y.add_argument("--bundle")
        y.add_argument("--events", default="window-created,focused-window-changed,focused-ui-element-changed,main-window-changed,application-activated",
                       help="comma-separated AX event names; supported: " + ",".join(event_choices))
        y.add_argument("--role")
        y.add_argument("--subrole")
        y.add_argument("--title")
        y.add_argument("--description")
        y.add_argument("--value")
        y.add_argument("--observe-seconds", type=float, default=3.0)
        y.add_argument("--event-limit", type=int, default=1 if event_action == "event-wait" else 20)
        y.add_argument("--timeout", type=int, default=12)
        y.add_argument("--max-bytes", type=int, default=24000)
        y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("type-text")
    y.add_argument("text")
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("key-press")
    y.add_argument("keycode", type=int)
    y.add_argument("--modifiers", default="")
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("mouse-move")
    y.add_argument("x", type=float)
    y.add_argument("y", type=float)
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_gui)
    y = gs.add_parser("mouse-click")
    y.add_argument("x", type=float)
    y.add_argument("y", type=float)
    y.add_argument("--button", choices=["left", "right", "middle"], default="left")
    y.add_argument("--count", type=int, choices=[1, 2, 3], default=1)
    y.add_argument("--timeout", type=int, default=15)
    y.add_argument("--max-bytes", type=int, default=4096)
    y.set_defaults(fn=cmd_gui)
    for act in ["helper-status", "helper-lifecycle-status", "helper-lifecycle-register", "helper-lifecycle-unregister", "helper-request-accessibility", "helper-request-screen-recording", "helper-screen-capture-test", "helper-screen-ocr", "helper-automation-test", "helper-systemevents-test", "helper-accessibility-test", "helper-accessibility-action-test", "helper-accessibility-inventory", "helper-frontmost", "helper-mouse-position", "helper-mouse-nudge"]:
        y = gs.add_parser(act)
        y.add_argument("--timeout", type=int, default=15)
        y.add_argument("--max-bytes", type=int, default=4096)
        y.set_defaults(fn=cmd_gui)

    po = sp.add_parser("policy")
    pos = po.add_subparsers(dest="action", required=True)
    y = pos.add_parser("status")
    y.set_defaults(fn=cmd_policy)
    y = pos.add_parser("classify")
    y.add_argument("family")
    y.add_argument("operation_action", nargs="?")
    y.add_argument("--command")
    y.add_argument("--label")
    y.add_argument("--confirm", action="store_true")
    y.add_argument("--sudo", action="store_true")
    y.add_argument("--recursive", action="store_true")
    y.add_argument("--delete", action="store_true")
    y.add_argument("--dry-run", action="store_true")
    y.add_argument("--scope", choices=["user", "system"], default="user")
    y.set_defaults(fn=cmd_policy)

    tr = sp.add_parser("transaction")
    trs = tr.add_subparsers(dest="action", required=True)
    y = trs.add_parser("status")
    y.add_argument("request_id_value")
    y.set_defaults(fn=cmd_transaction)
    y = trs.add_parser("list")
    y.add_argument("--limit", type=int, default=20)
    y.set_defaults(fn=cmd_transaction)

    se = sp.add_parser("security")
    ses = se.add_subparsers(dest="action", required=True)
    for act in ["ssh-state", "sudo-state", "hostkey", "posture", "hardening-assess", "tcc-state", "tcc-probe", "password-probe", "full-disk-test"]:
        y = ses.add_parser(act)
        y.set_defaults(fn=cmd_security)
    for act in ["firewall-enable", "firewall-disable"]:
        y = ses.add_parser(act)
        y.add_argument("--confirm", action="store_true")
        y.set_defaults(fn=cmd_security)

    au = sp.add_parser("audit")
    aus = au.add_subparsers(dest="action", required=True)
    for act in ["tail", "stats"]:
        y = aus.add_parser(act)
        y.add_argument("--lines", type=int, default=100)
        y.set_defaults(fn=cmd_audit)
    for act in ["status", "verify"]:
        y = aus.add_parser(act)
        y.set_defaults(fn=cmd_audit)

    co = sp.add_parser("control")
    cos = co.add_subparsers(dest="action", required=True)
    for act in ["check", "warm", "stop"]:
        y = cos.add_parser(act)
        y.set_defaults(fn=cmd_control)
    return p

def main():
    args = build_parser().parse_args()
    t0 = time.perf_counter()
    rc = 0
    tx = None
    try:
        try:
            correlation_id, correlation_source = resolve_correlation_id(
                getattr(args, "correlation_id", None),
                os.environ.get("MACCTL_CORRELATION_ID"),
            )
        except ValueError as e:
            args._correlation_id = new_correlation_id()
            args._correlation_source = "generated_after_invalid_input"
            emit({"status": "BLOCKED", "reason": "invalid_correlation_id", "detail": str(e), "correlation_id": args._correlation_id})
            raise SystemExit(64)
        args._correlation_id = correlation_id
        args._correlation_source = correlation_source

        if args.cmd == "exec" and not args.command:
            print("no remote command", file=sys.stderr)
            raise SystemExit(64)
        if args.cmd == "job" and args.action == "start" and not args.command:
            print("no job command", file=sys.stderr)
            raise SystemExit(64)

        decision = enforce_typed_policy(args)
        tx = _prepare_transaction(args, decision)
        try:
            args.fn(args)
        except SystemExit as inner:
            try:
                action_rc = int(inner.code or 0)
            except Exception:
                action_rc = 1
            rc = action_rc
            if tx is not None:
                _finalize_transaction(args, tx, action_rc)
            raise
        else:
            rc = 0
            if tx is not None:
                _finalize_transaction(args, tx, 0)
    except SystemExit as e:
        try:
            rc = int(e.code or 0)
        except Exception:
            rc = 1
        raise
    except Exception:
        rc = 70
        if tx is not None and getattr(args, "_transaction_status", None) == DISPATCHED:
            try:
                TX_STORE.mark_indeterminate(tx["request_id"], tx["operation_id"], reason="local_exception_after_dispatch")
                args._transaction_status = INDETERMINATE
            except Exception:
                pass
        raise
    finally:
        audit_record(args, rc, (time.perf_counter() - t0) * 1000)

if __name__ == "__main__":
    main()
