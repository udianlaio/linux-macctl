#!/usr/bin/env python3
"""Pure contracts for bounded delegated messaging control.

No message bodies are persisted by this module. Durable records carry hashes,
lengths, contact bindings and state transitions only.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

SCHEMA = "macctl-delegated-messaging/v1"
SUPPORTED_PROVIDERS = {
    "wechat": {"bundle_id": "com.tencent.xinWeChat", "display_name": "微信"},
    "feishu": {"bundle_id": "com.bytedance.Feishu", "display_name": "飞书"},
}
CONTACT_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BINDING_ID_RE = re.compile(r"^msgb_[0-9a-f]{24}$")
DRAFT_ID_RE = re.compile(r"^msgd_[0-9a-f]{24}$")
MAX_MESSAGE_BYTES = 16384
DEFAULT_RATE_LIMIT_COUNT = 5
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60


class MessagingError(ValueError):
    pass


def normalize_provider(value: str) -> str:
    provider = str(value or "").strip().lower()
    if provider not in SUPPORTED_PROVIDERS:
        raise MessagingError("unsupported_provider")
    return provider


def normalize_contact(value: str) -> str:
    contact = str(value or "").strip()
    if not CONTACT_RE.fullmatch(contact):
        raise MessagingError("invalid_contact")
    return contact


def contact_sha256(provider: str, contact: str) -> str:
    provider = normalize_provider(provider)
    contact = normalize_contact(contact)
    return hashlib.sha256(f"{provider}\0{contact}".encode("utf-8")).hexdigest()


def binding_id(provider: str, contact: str) -> str:
    return "msgb_" + contact_sha256(provider, contact)[:24]


def validate_message_bytes(data: bytes) -> dict:
    if not isinstance(data, (bytes, bytearray)):
        raise MessagingError("message_not_bytes")
    raw = bytes(data)
    if not raw:
        raise MessagingError("message_empty")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise MessagingError("message_too_large")
    if b"\x00" in raw:
        raise MessagingError("message_nul_forbidden")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MessagingError("message_not_utf8") from exc
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "chars": len(text),
    }


def load_message_file(path: str | Path) -> tuple[bytes, dict]:
    p = Path(path)
    st = p.lstat()
    if not p.is_file() or p.is_symlink():
        raise MessagingError("message_file_must_be_regular")
    if st.st_mode & 0o077:
        raise MessagingError("message_file_permissions_too_open")
    data = p.read_bytes()
    return data, validate_message_bytes(data)


def build_binding(provider: str, contact: str, *, allow_read: bool = True, allow_draft: bool = True, allow_send: bool = False, created_at: int | None = None) -> dict:
    provider = normalize_provider(provider)
    contact = normalize_contact(contact)
    return {
        "schema": SCHEMA,
        "record_type": "binding",
        "binding_id": binding_id(provider, contact),
        "provider": provider,
        "bundle_id": SUPPORTED_PROVIDERS[provider]["bundle_id"],
        "contact": contact,
        "contact_sha256": contact_sha256(provider, contact),
        "allow_read": bool(allow_read),
        "allow_draft": bool(allow_draft),
        "allow_send": bool(allow_send),
        "created_at": int(created_at or time.time()),
    }


def public_binding(binding: dict) -> dict:
    return {
        "schema": binding.get("schema", SCHEMA),
        "binding_id": binding.get("binding_id"),
        "provider": binding.get("provider"),
        "bundle_id": binding.get("bundle_id"),
        "contact": binding.get("contact"),
        "contact_sha256": binding.get("contact_sha256"),
        "allow_read": bool(binding.get("allow_read")),
        "allow_draft": bool(binding.get("allow_draft")),
        "allow_send": bool(binding.get("allow_send")),
    }


def build_draft(binding: dict, message_meta: dict, *, created_at: int | None = None) -> dict:
    sha = str(message_meta.get("sha256") or "")
    if not SHA256_RE.fullmatch(sha):
        raise MessagingError("invalid_message_sha256")
    material = f"{binding.get('binding_id')}\0{sha}\0{int(created_at or time.time())}".encode("utf-8")
    did = "msgd_" + hashlib.sha256(material).hexdigest()[:24]
    return {
        "schema": SCHEMA,
        "record_type": "draft",
        "draft_id": did,
        "binding_id": binding.get("binding_id"),
        "provider": binding.get("provider"),
        "contact_sha256": binding.get("contact_sha256"),
        "message_sha256": sha,
        "message_bytes": int(message_meta.get("bytes") or 0),
        "message_chars": int(message_meta.get("chars") or 0),
        "state": "PREPARED",
        "created_at": int(created_at or time.time()),
    }


def validate_selected_contact(binding: dict, observed_contact: str) -> dict:
    observed = normalize_contact(observed_contact)
    expected = str(binding.get("contact") or "")
    ok = observed == expected
    return {
        "status": "PASS" if ok else "BLOCKED",
        "exact_match": ok,
        "expected_contact_sha256": binding.get("contact_sha256"),
        "observed_contact_sha256": contact_sha256(str(binding.get("provider")), observed),
    }


def evaluate_action(binding: dict, action: str, *, selected_contact: str | None = None, confirm: bool = False, message_sha256: str | None = None, prior_sent_sha256: set[str] | None = None, recent_send_count: int = 0, rate_limit_count: int = DEFAULT_RATE_LIMIT_COUNT) -> dict:
    action = str(action or "").strip().lower()
    if action not in {"read", "draft", "send"}:
        raise MessagingError("unsupported_action")
    gate = {
        "schema": SCHEMA,
        "action": action,
        "binding_id": binding.get("binding_id"),
        "allowed": False,
        "reason": None,
    }
    if not bool(binding.get(f"allow_{action}")):
        gate["reason"] = f"binding_{action}_not_allowed"
        return gate
    if selected_contact is not None:
        selected = validate_selected_contact(binding, selected_contact)
        gate["selected_contact"] = selected
        if not selected["exact_match"]:
            gate["reason"] = "selected_contact_mismatch"
            return gate
    if action == "send":
        if not confirm:
            gate["reason"] = "send_explicit_confirmation_required"
            return gate
        sha = str(message_sha256 or "")
        if not SHA256_RE.fullmatch(sha):
            gate["reason"] = "send_message_sha256_required"
            return gate
        if sha in (prior_sent_sha256 or set()):
            gate["reason"] = "duplicate_message_sha256_blocked"
            return gate
        if int(rate_limit_count) < 1:
            raise MessagingError("invalid_rate_limit_count")
        if int(recent_send_count) >= int(rate_limit_count):
            gate["reason"] = "send_rate_limit_blocked"
            gate["recent_send_count"] = int(recent_send_count)
            gate["rate_limit_count"] = int(rate_limit_count)
            return gate
    gate["allowed"] = True
    gate["reason"] = "binding_scope_and_preconditions_satisfied"
    return gate


def vision_box_to_screen(item: dict, *, screen_width: int, screen_height: int) -> dict:
    box = item.get("box") if isinstance(item, dict) else None
    if not isinstance(box, dict):
        raise MessagingError("vision_box_missing")
    x = float(box.get("x", 0.0)) * screen_width
    w = float(box.get("width", 0.0)) * screen_width
    y_bottom = float(box.get("y", 0.0)) * screen_height
    h = float(box.get("height", 0.0)) * screen_height
    y_top = screen_height - (y_bottom + h)
    return {"x": x, "y": y_top, "width": w, "height": h, "cx": x + w / 2, "cy": y_top + h / 2}


def point_in_window(point: dict, window: dict) -> bool:
    return (
        float(window.get("x", 0)) <= float(point.get("cx", -1)) <= float(window.get("x", 0)) + float(window.get("width", 0))
        and float(window.get("y", 0)) <= float(point.get("cy", -1)) <= float(window.get("y", 0)) + float(window.get("height", 0))
    )


def detect_provider_login_state(provider: str, items: list[dict]) -> str:
    provider = normalize_provider(provider)
    texts = {str(item.get("text") or "").strip() for item in (items or [])}
    if provider == "wechat" and ({"你已退出微信", "当前登录用户"} & texts or ("登录" in texts and "切换账号" in texts)):
        return "LOGIN_REQUIRED"
    return "SESSION_PRESENT_OR_UNKNOWN"


def exact_text_candidates(items: list[dict], text: str, *, screen_width: int, screen_height: int, window: dict | None = None) -> list[dict]:
    wanted = normalize_contact(text)
    out = []
    for item in items or []:
        if str(item.get("text") or "").strip() != wanted:
            continue
        rect = vision_box_to_screen(item, screen_width=screen_width, screen_height=screen_height)
        if window is not None and not point_in_window(rect, window):
            continue
        out.append({"text": wanted, "rect": rect, "confidence": item.get("confidence")})
    return out


def select_header_candidate(candidates: list[dict], window: dict) -> dict:
    # WeChat header is the top band of the right conversation pane. This is
    # deliberately geometric only after exact-text matching and window bind.
    x_min = float(window.get("x", 0)) + min(220.0, float(window.get("width", 0)) * 0.30)
    y_max = float(window.get("y", 0)) + min(110.0, float(window.get("height", 0)) * 0.20)
    matches = [c for c in candidates if c["rect"]["cx"] >= x_min and c["rect"]["cy"] <= y_max]
    if len(matches) != 1:
        raise MessagingError("selected_conversation_header_not_unique")
    return matches[0]


def normalize_visual_token(value: str) -> str:
    # OCR commonly confuses O/0 and I/L/1. Normalize only these narrow
    # confusables, then compare a deliberately unique ASCII qualification token.
    raw = re.sub(r"[^A-Z0-9]", "", str(value or "").upper())
    return raw.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))


def visual_token_matches(text: str, token: str) -> bool:
    raw_token = str(token or "").strip()
    raw_text = str(text or "").strip()
    # For CJK qualification markers Vision is substantially more stable than
    # for mixed ASCII tokens. Compare whitespace-normalized literal text.
    if any(ord(ch) > 127 for ch in raw_token):
        wanted_text = re.sub(r"\s+", "", raw_token)
        observed_text = re.sub(r"\s+", "", raw_text)
        return bool(wanted_text) and wanted_text in observed_text
    wanted = normalize_visual_token(raw_token)
    observed = normalize_visual_token(raw_text)
    return bool(wanted) and wanted in observed


def classify_visual_region(rect: dict, window: dict) -> str:
    wx = float(window.get("x", 0)); wy = float(window.get("y", 0))
    ww = float(window.get("width", 0)); wh = float(window.get("height", 0))
    if not point_in_window(rect, window):
        return "OUTSIDE"
    # Left pane is contact/conversation list. Right pane top/middle is history;
    # the lower ~42% is the composer. These are intentionally broad bands and
    # are used only after exact window + exact contact binding succeeds.
    if float(rect.get("cx", -1)) < wx + ww * 0.30:
        return "LEFT_PREVIEW"
    if float(rect.get("cy", -1)) >= wy + wh * 0.58:
        return "COMPOSER"
    return "HISTORY"


def token_region_evidence(items: list[dict], token: str, *, screen_width: int, screen_height: int, window: dict) -> dict:
    counts = {"COMPOSER": 0, "HISTORY": 0, "LEFT_PREVIEW": 0, "OUTSIDE": 0}
    matches = []
    for item in items or []:
        if not visual_token_matches(str(item.get("text") or ""), token):
            continue
        rect = vision_box_to_screen(item, screen_width=screen_width, screen_height=screen_height)
        region = classify_visual_region(rect, window)
        counts[region] += 1
        matches.append({"region": region, "rect": rect, "confidence": item.get("confidence")})
    return {"token_sha256": hashlib.sha256(str(token).encode("utf-8")).hexdigest(), "counts": counts, "matches": matches}


def visible_region_texts(items: list[dict], *, region: str, screen_width: int, screen_height: int, window: dict, limit: int = 20, exclude_texts: set[str] | None = None) -> list[dict]:
    wanted_region = str(region or "").upper()
    if wanted_region not in {"COMPOSER", "HISTORY", "LEFT_PREVIEW"}:
        raise MessagingError("invalid_visual_region")
    cap = max(1, min(int(limit), 50))
    excluded = {str(x).strip() for x in (exclude_texts or set()) if str(x).strip()}
    out = []
    for item in items or []:
        text = str(item.get("text") or "").strip()
        if not text or text in excluded:
            continue
        rect = vision_box_to_screen(item, screen_width=screen_width, screen_height=screen_height)
        if classify_visual_region(rect, window) != wanted_region:
            continue
        out.append({"text": text, "confidence": item.get("confidence"), "rect": rect})
    out.sort(key=lambda x: (round(float(x["rect"]["y"]), 1), round(float(x["rect"]["x"]), 1)))
    return out[:cap]


class MessagingStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.bindings = self.root / "bindings"
        self.drafts = self.root / "drafts"
        self.receipts = self.root / "receipts"

    def _ensure(self):
        for p in (self.root, self.bindings, self.drafts, self.receipts):
            p.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(p, 0o700)

    @staticmethod
    def _atomic_write(path: Path, obj: dict):
        tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
        data = (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with open(tmp, "wb") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def save_binding(self, binding: dict) -> Path:
        self._ensure()
        path = self.bindings / f"{binding['binding_id']}.json"
        self._atomic_write(path, binding)
        return path

    def load_binding(self, bid: str) -> dict:
        if not BINDING_ID_RE.fullmatch(str(bid or "")):
            raise MessagingError("invalid_binding_id")
        path = self.bindings / f"{bid}.json"
        if not path.is_file() or path.is_symlink():
            raise MessagingError("binding_not_found")
        return json.loads(path.read_text(encoding="utf-8"))

    def save_draft(self, draft: dict) -> Path:
        self._ensure()
        path = self.drafts / f"{draft['draft_id']}.json"
        self._atomic_write(path, draft)
        return path

    def load_draft(self, did: str) -> dict:
        if not DRAFT_ID_RE.fullmatch(str(did or "")):
            raise MessagingError("invalid_draft_id")
        path = self.drafts / f"{did}.json"
        if not path.is_file() or path.is_symlink():
            raise MessagingError("draft_not_found")
        return json.loads(path.read_text(encoding="utf-8"))

    def sent_hashes(self, binding_id_value: str) -> set[str]:
        self._ensure()
        out: set[str] = set()
        for path in self.receipts.glob("*.json"):
            try:
                rec = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if rec.get("binding_id") == binding_id_value and SHA256_RE.fullmatch(str(rec.get("message_sha256") or "")):
                out.add(str(rec["message_sha256"]))
        return out

    def recent_sent_count(self, binding_id_value: str, *, window_seconds: int = DEFAULT_RATE_LIMIT_WINDOW_SECONDS, now: int | None = None) -> int:
        self._ensure()
        window = max(1, int(window_seconds))
        cutoff = int(now or time.time()) - window
        count = 0
        for path in self.receipts.glob("*.json"):
            try:
                rec = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if rec.get("binding_id") != binding_id_value:
                continue
            if int(rec.get("sent_at") or 0) >= cutoff:
                count += 1
        return count

    def save_receipt(self, draft: dict, *, result: str, sent_at: int | None = None) -> Path:
        self._ensure()
        ts = int(sent_at or time.time())
        rid = "msgr_" + hashlib.sha256(f"{draft['draft_id']}\0{result}\0{ts}".encode()).hexdigest()[:24]
        rec = {
            "schema": SCHEMA,
            "record_type": "receipt",
            "receipt_id": rid,
            "binding_id": draft.get("binding_id"),
            "draft_id": draft.get("draft_id"),
            "provider": draft.get("provider"),
            "contact_sha256": draft.get("contact_sha256"),
            "message_sha256": draft.get("message_sha256"),
            "message_bytes": draft.get("message_bytes"),
            "message_chars": draft.get("message_chars"),
            "result": str(result),
            "sent_at": ts,
        }
        path = self.receipts / f"{rid}.json"
        self._atomic_write(path, rec)
        return path
