#!/usr/bin/env python3
"""Controlled browser-session primitives for Linux-macctl R2 Phase 2/3.

The session layer is intentionally conservative:
- only isolated Chrome profiles are represented;
- navigation is allowlist-based and fails closed;
- raw JavaScript is not part of this API;
- persisted tunnel PIDs are verified against their expected command line before kill;
- state files are atomic and private;
- production-site sessions carry an explicit qualification scope;
- production credential entry/default-profile reuse remain unavailable by design.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import os
import re
import tempfile
import urllib.parse
from pathlib import Path


SESSION_SCHEMA = "macctl-browser-session/v1"
_SESSION_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{7,63}$")
_HOST_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")
_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{3,127}$")
SITE_CLASSES = {"synthetic", "public", "production"}
QUALIFICATION_SCOPES = {"read_only", "controlled_input", "stateful_mutation"}


class BrowserSessionError(RuntimeError):
    def __init__(self, reason: str, detail: str | None = None):
        super().__init__(reason if detail is None else f"{reason}:{detail}")
        self.reason = reason
        self.detail = detail


def utc_now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def iso_z(value: _dt.datetime) -> str:
    return value.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(_dt.timezone.utc)


def validate_session_id(value: str) -> str:
    value = str(value or "").strip().lower()
    if not _SESSION_RE.fullmatch(value):
        raise BrowserSessionError("invalid_session_id")
    return value


def normalize_allow_host(value: str) -> str:
    value = str(value or "").strip().lower().rstrip(".")
    if not value or "/" in value or ":" in value or "@" in value:
        raise BrowserSessionError("invalid_allow_host")
    if not _HOST_RE.fullmatch(value):
        raise BrowserSessionError("invalid_allow_host")
    try:
        if value.startswith("*."):
            suffix = value[2:].encode("idna").decode("ascii")
            return "*." + suffix
        return value.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise BrowserSessionError("invalid_allow_host", type(e).__name__) from e


def normalize_allow_hosts(values) -> list[str]:
    return sorted(set(normalize_allow_host(v) for v in (values or [])))


def normalize_site_class(value: str | None) -> str:
    value = str(value or "synthetic").strip().lower().replace("-", "_")
    if value not in SITE_CLASSES:
        raise BrowserSessionError("invalid_site_class")
    return value


def normalize_qualification_scope(value: str | None) -> str:
    value = str(value or "read_only").strip().lower().replace("-", "_")
    if value not in QUALIFICATION_SCOPES:
        raise BrowserSessionError("invalid_qualification_scope")
    return value


def normalize_authorized_action_id(value: str | None) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    value = str(value).strip()
    if not _ACTION_ID_RE.fullmatch(value):
        raise BrowserSessionError("invalid_authorized_action_id")
    return value


def validate_qualification_config(
    *, site_class: str | None = None, qualification_scope: str | None = None,
    allow_hosts=None, allow_loopback: bool = False, authorized_action_id: str | None = None,
) -> dict:
    """Normalize and fail-close the Phase 3 qualification envelope.

    Production sessions intentionally require exact hosts. Stateful mutation additionally
    requires a bounded operator-defined action id. This metadata is not itself authorization;
    callers still need current human approval before executing a live production mutation.
    """
    site = normalize_site_class(site_class)
    scope = normalize_qualification_scope(qualification_scope)
    hosts = normalize_allow_hosts(allow_hosts)
    action_id = normalize_authorized_action_id(authorized_action_id)

    if site != "production":
        if scope != "read_only" or action_id is not None:
            raise BrowserSessionError("nonproduction_scope_must_be_read_only")
        return {
            "site_class": site,
            "qualification_scope": scope,
            "allow_hosts": hosts,
            "allow_loopback": bool(allow_loopback),
            "authorized_action_id": None,
        }

    if allow_loopback:
        raise BrowserSessionError("production_loopback_forbidden")
    if not hosts:
        raise BrowserSessionError("production_allow_host_required")
    if any(h.startswith("*.") for h in hosts):
        raise BrowserSessionError("production_wildcard_host_forbidden")
    if scope == "stateful_mutation" and action_id is None:
        raise BrowserSessionError("production_authorized_action_id_required")
    if scope != "stateful_mutation" and action_id is not None:
        raise BrowserSessionError("authorized_action_id_requires_stateful_mutation")

    return {
        "site_class": site,
        "qualification_scope": scope,
        "allow_hosts": hosts,
        "allow_loopback": False,
        "authorized_action_id": action_id,
    }


def evaluate_session_action_policy(
    record: dict, action: str, *, confirmed: bool = False,
    production_confirmed: bool = False, input_class: str = "plain",
) -> dict:
    """Secondary policy that can see persisted session qualification metadata.

    The global Policy V2 classifier runs before the session record is loaded. Phase 3 therefore
    adds this record-aware fail-closed layer for production-site sessions.
    """
    site = normalize_site_class(record.get("site_class"))
    scope = normalize_qualification_scope(record.get("qualification_scope"))
    action = str(action or "").strip()
    base = {"site_class": site, "qualification_scope": scope, "action": action}

    if site != "production":
        return {**base, "allowed": True, "reason": "nonproduction_session"}

    if action in {"session-status", "session-stop", "session-navigate", "session-query", "session-extract", "session-analyze", "session-wait", "session-pages", "session-activate", "session-new-tab", "session-close-tab", "session-history", "session-reload"}:
        return {**base, "allowed": True, "reason": "production_read_only_action"}

    if action == "session-download":
        allowed = bool(confirmed)
        return {
            **base,
            "allowed": allowed,
            "reason": "production_download_confirmed" if allowed else "production_download_confirmation_required",
        }

    if action in {"session-type", "session-select", "session-search"}:
        input_class = str(input_class or "plain")
        if input_class == "credential":
            if scope != "stateful_mutation":
                return {**base, "allowed": False, "reason": "production_credential_requires_stateful_mutation_scope"}
            if not record.get("authorized_action_id"):
                return {**base, "allowed": False, "reason": "production_authorized_action_id_missing"}
            allowed = bool(production_confirmed)
            return {
                **base,
                "allowed": allowed,
                "reason": "production_credential_input_confirmed" if allowed else "production_confirmation_required",
            }
        if input_class != "plain":
            return {**base, "allowed": False, "reason": "production_input_class_not_exposed"}
        if scope == "read_only":
            return {**base, "allowed": False, "reason": "production_scope_read_only"}
        allowed = bool(production_confirmed)
        return {
            **base,
            "allowed": allowed,
            "reason": "production_input_confirmed" if allowed else "production_confirmation_required",
        }

    if action in {"session-click", "session-key", "session-upload"}:
        if scope != "stateful_mutation":
            return {**base, "allowed": False, "reason": "production_stateful_action_requires_stateful_mutation_scope"}
        if not record.get("authorized_action_id"):
            return {**base, "allowed": False, "reason": "production_authorized_action_id_missing"}
        allowed = bool(confirmed and production_confirmed)
        return {
            **base,
            "allowed": allowed,
            "reason": "production_stateful_action_confirmed" if allowed else "production_double_confirmation_required",
        }

    return {**base, "allowed": False, "reason": "production_action_not_exposed"}


def _loopback_host(host: str) -> bool:
    low = str(host or "").strip().lower().rstrip(".")
    if low == "localhost":
        return True
    try:
        return ipaddress.ip_address(low).is_loopback
    except ValueError:
        return False


def _host_matches(host: str, rule: str) -> bool:
    host = str(host or "").lower().rstrip(".")
    rule = normalize_allow_host(rule)
    if rule.startswith("*."):
        suffix = rule[2:]
        return host.endswith("." + suffix) and host != suffix
    return host == rule


def sanitize_url_for_output(url: str) -> str | None:
    raw=str(url or "").strip()
    if raw == "about:blank":
        return raw
    try:
        p=urllib.parse.urlsplit(raw)
    except ValueError:
        return None
    if p.scheme.lower() not in {"http","https"} or not p.hostname:
        return None
    host=p.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    try:
        port=p.port
    except ValueError:
        return None
    default=(p.scheme.lower()=="https" and port in {None,443}) or (p.scheme.lower()=="http" and port in {None,80})
    netloc=host if default else f"{host}:{port}"
    return urllib.parse.urlunsplit((p.scheme.lower(),netloc,p.path or "/","",""))


def evaluate_url_policy(url: str, *, allow_hosts=None, allow_loopback: bool = False) -> dict:
    raw = str(url or "").strip()
    public_url = sanitize_url_for_output(raw)
    if raw == "about:blank":
        return {"allowed": True, "reason": "about_blank", "url": "about:blank", "host": None, "scheme": "about", "query_redacted": False}
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError as e:
        return {"allowed": False, "reason": "invalid_url", "detail": type(e).__name__, "url": None, "query_redacted": bool("?" in raw or "#" in raw)}
    scheme = parsed.scheme.lower()
    redacted = bool(parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None)
    if scheme not in {"http", "https"}:
        return {"allowed": False, "reason": "scheme_not_allowed", "url": None, "scheme": scheme, "query_redacted": redacted}
    if parsed.username is not None or parsed.password is not None:
        return {"allowed": False, "reason": "embedded_credentials_denied", "url": public_url, "scheme": scheme, "query_redacted": True}
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return {"allowed": False, "reason": "host_missing", "url": None, "scheme": scheme, "query_redacted": redacted}
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return {"allowed": False, "reason": "invalid_host", "url": None, "scheme": scheme, "query_redacted": redacted}
    if _loopback_host(host):
        allowed = bool(allow_loopback)
        return {
            "allowed": allowed,
            "reason": "loopback_explicitly_allowed" if allowed else "loopback_not_allowed",
            "url": public_url,
            "scheme": scheme,
            "host": host,
            "query_redacted": redacted,
        }
    rules = normalize_allow_hosts(allow_hosts)
    for rule in rules:
        if _host_matches(host, rule):
            return {"allowed": True, "reason": "host_allowlist_match", "url": public_url, "scheme": scheme, "host": host, "rule": rule, "query_redacted": redacted}
    return {"allowed": False, "reason": "host_not_allowlisted", "url": public_url, "scheme": scheme, "host": host, "query_redacted": redacted}

def pid_alive(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError, TypeError):
        return False
    except PermissionError:
        return True


def pid_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{int(pid)}/cmdline").read_bytes()
    except (OSError, ValueError, TypeError):
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def pid_matches(pid: int, required_parts) -> bool:
    cmd = pid_cmdline(pid)
    return bool(cmd) and all(str(part) in cmd for part in required_parts)


class BrowserSessionStore:
    def __init__(self, root: str | os.PathLike, *, now_fn=utc_now):
        self.root = Path(root)
        self.now_fn = now_fn

    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _path(self, session_id: str) -> Path:
        return self.root / (validate_session_id(session_id) + ".json")

    def save(self, record: dict, *, create_only: bool = False) -> dict:
        self._ensure_root()
        record = dict(record)
        session_id = validate_session_id(record.get("session_id"))
        record["session_id"] = session_id
        record["schema"] = SESSION_SCHEMA
        path = self._path(session_id)
        if create_only and path.exists():
            raise BrowserSessionError("session_already_exists")
        fd, tmp_name = tempfile.mkstemp(prefix=".session-", suffix=".tmp", dir=str(self.root))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, path)
            try:
                dfd = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.unlink(tmp_name)
            except OSError:
                pass
        return record

    def load(self, session_id: str, *, allow_expired: bool = False) -> dict:
        path = self._path(session_id)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as e:
            raise BrowserSessionError("session_not_found") from e
        except (OSError, json.JSONDecodeError) as e:
            raise BrowserSessionError("session_state_invalid", type(e).__name__) from e
        if record.get("schema") != SESSION_SCHEMA or record.get("session_id") != validate_session_id(session_id):
            raise BrowserSessionError("session_state_invalid")
        expires_at = record.get("expires_at")
        if expires_at and not allow_expired and self.now_fn() >= parse_iso_z(expires_at):
            raise BrowserSessionError("session_expired")
        return record

    def delete(self, session_id: str) -> None:
        try:
            self._path(session_id).unlink()
        except FileNotFoundError:
            return

    def list(self) -> list[dict]:
        if not self.root.exists():
            return []
        out = []
        for path in sorted(self.root.glob("*.json")):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if record.get("schema") != SESSION_SCHEMA:
                    continue
                expires = record.get("expires_at")
                record = dict(record)
                record["expired"] = bool(expires and self.now_fn() >= parse_iso_z(expires))
                out.append(record)
            except Exception:
                continue
        return out


def build_session_record(
    *, session_id: str, local_port: int, remote_port: int, tunnel_pid: int,
    remote_profile: str, remote_download_dir: str, remote_upload_dir: str | None = None, allow_hosts=None,
    allow_loopback: bool = False, ttl_seconds: int = 1800,
    chrome_product: str | None = None, protocol_version: str | None = None,
    site_class: str = "synthetic", qualification_scope: str = "read_only",
    authorized_action_id: str | None = None,
) -> dict:
    session_id = validate_session_id(session_id)
    ttl = int(ttl_seconds)
    if ttl < 60 or ttl > 14400:
        raise BrowserSessionError("invalid_session_ttl")
    qualification = validate_qualification_config(
        site_class=site_class,
        qualification_scope=qualification_scope,
        allow_hosts=allow_hosts,
        allow_loopback=allow_loopback,
        authorized_action_id=authorized_action_id,
    )
    created = utc_now()
    return {
        "schema": SESSION_SCHEMA,
        "session_id": session_id,
        "created_at": iso_z(created),
        "expires_at": iso_z(created + _dt.timedelta(seconds=ttl)),
        "local_port": int(local_port),
        "remote_port": int(remote_port),
        "tunnel_pid": int(tunnel_pid),
        "remote_profile": str(remote_profile),
        "remote_download_dir": str(remote_download_dir),
        "remote_upload_dir": str(remote_upload_dir) if remote_upload_dir else None,
        "allow_hosts": qualification["allow_hosts"],
        "allow_loopback": qualification["allow_loopback"],
        "site_class": qualification["site_class"],
        "qualification_scope": qualification["qualification_scope"],
        "authorized_action_id": qualification["authorized_action_id"],
        "chrome_product": chrome_product,
        "protocol_version": protocol_version,
        "profile_isolated": True,
        "default_profile_touched": False,
        "credential_entry": (
            "EPHEMERAL_FILE_GATED"
            if qualification["site_class"] == "production" and qualification["qualification_scope"] == "stateful_mutation"
            else "NOT_EXPOSED_FOR_SCOPE"
        ),
    }
