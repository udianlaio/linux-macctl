#!/usr/bin/env python3
"""Pure-stdlib Chrome DevTools Protocol primitives for Linux-macctl.

Security contract:
- intended for an isolated Chrome profile, never the user's default profile;
- CDP port remains bound to Mac loopback and is reached through pinned SSH;
- no arbitrary Runtime.evaluate surface is exposed by the CLI;
- selector helpers fail closed unless exactly one DOM node matches.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass


class BrowserCdpError(RuntimeError):
    pass


@dataclass(frozen=True)
class CdpTarget:
    id: str
    type: str
    title: str
    url: str
    websocket_url: str


def free_tcp_port(host: str = "127.0.0.1") -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def rewrite_ws_url(url: str, local_port: int, host: str = "127.0.0.1") -> str:
    p = urllib.parse.urlsplit(url)
    if p.scheme not in {"ws", "wss"}:
        raise BrowserCdpError("invalid_websocket_url")
    netloc = f"{host}:{int(local_port)}"
    return urllib.parse.urlunsplit(("ws", netloc, p.path, p.query, ""))


def http_json(local_port: int, path: str, timeout: float = 2.0):
    if not path.startswith("/"):
        raise BrowserCdpError("invalid_http_path")
    url = f"http://127.0.0.1:{int(local_port)}{path}"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        raw = r.read(2 * 1024 * 1024)
    return json.loads(raw.decode("utf-8"))


def wait_http_json(local_port: int, path: str, timeout: float = 12.0, interval: float = 0.15):
    deadline = time.monotonic() + float(timeout)
    last = None
    while time.monotonic() < deadline:
        try:
            return http_json(local_port, path, timeout=min(1.5, max(0.2, deadline - time.monotonic())))
        except Exception as e:
            last = e
            time.sleep(interval)
    raise BrowserCdpError(f"cdp_http_not_ready:{type(last).__name__ if last else 'timeout'}")


def parse_targets(items) -> list[CdpTarget]:
    out = []
    for item in items or []:
        ws = str(item.get("webSocketDebuggerUrl") or "")
        if not ws:
            continue
        out.append(CdpTarget(
            id=str(item.get("id") or ""),
            type=str(item.get("type") or ""),
            title=str(item.get("title") or ""),
            url=str(item.get("url") or ""),
            websocket_url=ws,
        ))
    return out


def select_page_target(items, *, url_contains: str | None = None) -> CdpTarget:
    pages = [x for x in parse_targets(items) if x.type == "page"]
    if url_contains is not None:
        pages = [x for x in pages if url_contains in x.url]
    if not pages:
        raise BrowserCdpError("page_target_not_found")
    return pages[0]


def runtime_value(reply):
    try:
        result = reply["result"]["result"]
    except Exception as e:
        raise BrowserCdpError("malformed_runtime_reply") from e
    if "exceptionDetails" in reply.get("result", {}):
        raise BrowserCdpError("runtime_exception")
    if result.get("subtype") == "error":
        raise BrowserCdpError("runtime_error")
    if "value" not in result:
        raise BrowserCdpError("runtime_value_missing")
    return result["value"]


def dom_query_expression(selector: str) -> str:
    sel = json.dumps(str(selector), ensure_ascii=False)
    return f"""(() => {{
 const s={sel}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0], r=e.getBoundingClientRect();
 const type=String(e.getAttribute&&e.getAttribute('type')||'').toLowerCase();
 const ac=String(e.getAttribute&&e.getAttribute('autocomplete')||'').toLowerCase();
 const sensitive=(type==='password'||type==='hidden'||['current-password','new-password','one-time-code','cc-number','cc-csc'].includes(ac));
 const safeUrl=(v)=>{{if(!v)return null;try{{const u=new URL(v,location.href);return u.origin+u.pathname;}}catch(_e){{return null;}}}};
 const f=(e.formAction||((e.closest&&e.closest('form'))?e.closest('form').action:null)||null);
 return {{ok:true,count:1,tag:e.tagName,text:(e.innerText||e.textContent||''),value:('value' in e&&!sensitive?e.value:null),valueRedacted:sensitive,href:safeUrl(e.href||null),formAction:safeUrl(f),disabled:!!e.disabled,rect:{{x:r.x,y:r.y,width:r.width,height:r.height}}}};
}})()"""


def dom_click_expression(selector: str) -> str:
    sel = json.dumps(str(selector), ensure_ascii=False)
    return f"""(() => {{
 const s={sel}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0]; if(e.disabled) return {{ok:false,count:1,reason:'element_disabled'}};
 e.scrollIntoView({{block:'center',inline:'center'}}); e.click();
 return {{ok:true,count:1,tag:e.tagName,text:(e.innerText||e.textContent||'')}};
}})()"""


def dom_link_expression(selector: str) -> str:
    sel = json.dumps(str(selector), ensure_ascii=False)
    return f"""(() => {{
 const s={sel}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0]; if(e.tagName!=='A' || !e.href) return {{ok:false,count:1,reason:'download_target_not_anchor'}};
 return {{ok:true,count:1,tag:e.tagName,text:(e.innerText||e.textContent||''),href:e.href,download:(e.download||null)}};
}})()"""


def dom_type_expression(selector: str, text: str) -> str:
    sel = json.dumps(str(selector), ensure_ascii=False)
    val = json.dumps(str(text), ensure_ascii=False)
    return f"""(() => {{
 const s={sel}, v={val}; const a=Array.from(document.querySelectorAll(s));
 if(a.length!==1) return {{ok:false,count:a.length,reason:'selector_not_unique'}};
 const e=a[0]; if(e.disabled) return {{ok:false,count:1,reason:'element_disabled'}};
 e.focus(); e.value=v;
 e.dispatchEvent(new Event('input',{{bubbles:true}})); e.dispatchEvent(new Event('change',{{bubbles:true}}));
 return {{ok:true,count:1,value:e.value}};
}})()"""


def page_snapshot_expression(max_chars: int = 32768) -> str:
    limit = max(1024, min(int(max_chars), 131072))
    return f"(() => {{const t=(document.body?document.body.innerText:''); const u=new URL(location.href); const safe=u.origin+u.pathname; return {{title:document.title,url:safe,readyState:document.readyState,bodyText:t.slice(0,{limit}),bodyTextTruncated:t.length>{limit},urlQueryRedacted:!!(u.search||u.hash)}};}})()"


class WebSocketClient:
    def __init__(self, url: str, timeout: float = 5.0):
        self.url = url
        self.timeout = float(timeout)
        self.sock = None
        self._connect()

    def _connect(self):
        p = urllib.parse.urlsplit(self.url)
        if p.scheme != "ws":
            raise BrowserCdpError("only_ws_supported")
        host = p.hostname or "127.0.0.1"
        port = int(p.port or 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        s = socket.create_connection((host, port), timeout=self.timeout)
        s.settimeout(self.timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        s.sendall(req)
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                s.close()
                raise BrowserCdpError("websocket_handshake_eof")
            buf.extend(chunk)
            if len(buf) > 65536:
                s.close()
                raise BrowserCdpError("websocket_handshake_too_large")
        head, remain = bytes(buf).split(b"\r\n\r\n", 1)
        lines = head.decode("latin1").split("\r\n")
        if not lines or " 101 " not in (" " + lines[0] + " "):
            s.close()
            raise BrowserCdpError("websocket_handshake_rejected")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            s.close()
            raise BrowserCdpError("websocket_accept_mismatch")
        self.sock = s
        self._remain = bytearray(remain)

    def close(self):
        if self.sock is None:
            return
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _read_exact(self, n: int) -> bytes:
        out = bytearray()
        if self._remain:
            take = min(n, len(self._remain))
            out.extend(self._remain[:take])
            del self._remain[:take]
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise BrowserCdpError("websocket_eof")
            out.extend(chunk)
        return bytes(out)

    def _send_frame(self, opcode: int, payload: bytes):
        if self.sock is None:
            raise BrowserCdpError("websocket_closed")
        payload = bytes(payload)
        first = 0x80 | (opcode & 0x0F)
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            header = bytes([first, 0x80 | n])
        elif n < 65536:
            header = bytes([first, 0x80 | 126]) + struct.pack("!H", n)
        else:
            header = bytes([first, 0x80 | 127]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def send_text(self, text: str):
        self._send_frame(0x1, text.encode("utf-8"))

    def recv_text(self) -> str:
        parts = []
        active_opcode = None
        while True:
            b1, b2 = self._read_exact(2)
            fin = bool(b1 & 0x80)
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._read_exact(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else None
            payload = self._read_exact(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise BrowserCdpError("websocket_closed_by_peer")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in {0x1, 0x2}:
                active_opcode = opcode
                parts = [payload]
            elif opcode == 0x0 and active_opcode is not None:
                parts.append(payload)
            else:
                continue
            if fin:
                data = b"".join(parts)
                if active_opcode != 0x1:
                    raise BrowserCdpError("unexpected_binary_frame")
                return data.decode("utf-8")


class CdpClient:
    def __init__(self, websocket_url: str, timeout: float = 5.0):
        self.ws = WebSocketClient(websocket_url, timeout=timeout)
        self.timeout = float(timeout)
        self._id = 0

    def close(self):
        self.ws.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def call(self, method: str, params: dict | None = None, timeout: float | None = None):
        self._id += 1
        msg_id = self._id
        self.ws.send_text(json.dumps({"id": msg_id, "method": method, "params": params or {}}, separators=(",", ":"), ensure_ascii=False))
        deadline = time.monotonic() + float(timeout if timeout is not None else self.timeout)
        while time.monotonic() < deadline:
            self.ws.sock.settimeout(max(0.1, deadline - time.monotonic()))
            raw = self.ws.recv_text()
            obj = json.loads(raw)
            if obj.get("id") != msg_id:
                continue
            if "error" in obj:
                raise BrowserCdpError(f"cdp_error:{obj['error'].get('message','unknown')}")
            return obj
        raise BrowserCdpError(f"cdp_timeout:{method}")


def evaluate(client: CdpClient, expression: str, *, timeout: float = 5.0):
    reply = client.call("Runtime.evaluate", {
        "expression": expression,
        "returnByValue": True,
        "awaitPromise": True,
    }, timeout=timeout)
    return runtime_value(reply)


def wait_ready(client: CdpClient, timeout: float = 10.0):
    deadline = time.monotonic() + float(timeout)
    while time.monotonic() < deadline:
        try:
            if evaluate(client, "document.readyState", timeout=min(2.0, max(0.2, deadline - time.monotonic()))) == "complete":
                return True
        except Exception:
            pass
        time.sleep(0.1)
    raise BrowserCdpError("page_ready_timeout")
