#!/usr/bin/env python3
import base64
import hashlib
import json
import socket
import struct
import threading
import unittest

from browser_cdp_engine import (
    BrowserCdpError,
    CdpClient,
    dom_click_expression,
    dom_link_expression,
    dom_query_expression,
    dom_type_expression,
    page_snapshot_expression,
    parse_targets,
    rewrite_ws_url,
    runtime_value,
    select_page_target,
)


class BrowserCdpPureTests(unittest.TestCase):
    def test_rewrite_ws_url_keeps_path_and_query(self):
        self.assertEqual(
            rewrite_ws_url("ws://127.0.0.1:9222/devtools/page/abc?x=1", 45678),
            "ws://127.0.0.1:45678/devtools/page/abc?x=1",
        )

    def test_rewrite_rejects_non_websocket(self):
        with self.assertRaisesRegex(BrowserCdpError, "invalid_websocket_url"):
            rewrite_ws_url("http://127.0.0.1:9222/x", 45678)

    def test_target_selection_prefers_page_and_can_filter_url(self):
        items = [
            {"id": "a", "type": "service_worker", "title": "sw", "url": "x", "webSocketDebuggerUrl": "ws://x/a"},
            {"id": "b", "type": "page", "title": "one", "url": "file:///tmp/one.html", "webSocketDebuggerUrl": "ws://x/b"},
            {"id": "c", "type": "page", "title": "two", "url": "file:///tmp/two.html", "webSocketDebuggerUrl": "ws://x/c"},
        ]
        self.assertEqual(select_page_target(items).id, "b")
        self.assertEqual(select_page_target(items, url_contains="two.html").id, "c")
        self.assertEqual(len(parse_targets(items)), 3)

    def test_target_selection_fails_closed(self):
        with self.assertRaisesRegex(BrowserCdpError, "page_target_not_found"):
            select_page_target([])

    def test_runtime_value_contract(self):
        self.assertEqual(runtime_value({"result": {"result": {"type": "string", "value": "ok"}}}), "ok")
        with self.assertRaises(BrowserCdpError):
            runtime_value({"result": {"result": {"type": "undefined"}}})

    def test_selector_expressions_json_escape_untrusted_values(self):
        selector = "#x\\\";globalThis.pwned=true;//"
        text = "中文✓🙂\\\";alert(1);//"
        q = dom_query_expression(selector)
        c = dom_click_expression(selector)
        l = dom_link_expression(selector)
        t = dom_type_expression(selector, text)
        self.assertIn(json.dumps(selector, ensure_ascii=False), q)
        self.assertIn(json.dumps(selector, ensure_ascii=False), c)
        self.assertIn(json.dumps(selector, ensure_ascii=False), l)
        self.assertIn(json.dumps(text, ensure_ascii=False), t)
        self.assertIn("selector_not_unique", q)
        self.assertIn("selector_not_unique", c)
        self.assertIn("selector_not_unique", l)
        self.assertIn("download_target_not_anchor", l)
        self.assertIn("selector_not_unique", t)

    def test_snapshot_expression_is_fixed_contract(self):
        expr = page_snapshot_expression()
        self.assertIn("document.title", expr)
        self.assertIn("document.readyState", expr)
        self.assertIn("bodyTextTruncated", expr)
        self.assertIn("urlQueryRedacted", expr)
        self.assertIn("u.origin+u.pathname", expr)
        self.assertIn("slice(0,32768)", expr)
        self.assertNotIn("eval(", expr)

    def test_query_redacts_sensitive_values_and_url_query_components(self):
        expr = dom_query_expression("#secret")
        self.assertIn("valueRedacted", expr)
        self.assertIn("type==='password'", expr)
        self.assertIn("type==='hidden'", expr)
        self.assertIn("u.origin+u.pathname", expr)
        self.assertNotIn("u.search", expr)


class FakeWsServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.error = None
        self.seen = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    @staticmethod
    def _recv_exact(conn, n):
        out = bytearray()
        while len(out) < n:
            chunk = conn.recv(n - len(out))
            if not chunk:
                raise RuntimeError("eof")
            out.extend(chunk)
        return bytes(out)

    @classmethod
    def _recv_frame(cls, conn):
        b1, b2 = cls._recv_exact(conn, 2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", cls._recv_exact(conn, 2))[0]
        elif n == 127:
            n = struct.unpack("!Q", cls._recv_exact(conn, 8))[0]
        masked = bool(b2 & 0x80)
        mask = cls._recv_exact(conn, 4) if masked else None
        payload = cls._recv_exact(conn, n)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return b1 & 0x0F, payload

    @staticmethod
    def _send_text(conn, text):
        payload = text.encode("utf-8")
        n = len(payload)
        if n < 126:
            header = bytes([0x81, n])
        elif n < 65536:
            header = bytes([0x81, 126]) + struct.pack("!H", n)
        else:
            header = bytes([0x81, 127]) + struct.pack("!Q", n)
        conn.sendall(header + payload)

    def _run(self):
        try:
            conn, _ = self.sock.accept()
            with conn:
                buf = bytearray()
                while b"\r\n\r\n" not in buf:
                    buf.extend(conn.recv(4096))
                head = bytes(buf).split(b"\r\n\r\n", 1)[0].decode("latin1")
                key = None
                for line in head.split("\r\n"):
                    if line.lower().startswith("sec-websocket-key:"):
                        key = line.split(":", 1)[1].strip()
                accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                conn.sendall((
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
                ).encode("ascii"))
                opcode, payload = self._recv_frame(conn)
                self.seen = json.loads(payload.decode("utf-8"))
                self._send_text(conn, json.dumps({"id": self.seen["id"], "result": {"ok": True}}))
        except Exception as e:
            self.error = e
        finally:
            self.sock.close()


class BrowserCdpWebSocketTests(unittest.TestCase):
    def test_cdp_client_stdlib_websocket_roundtrip(self):
        server = FakeWsServer()
        with CdpClient(f"ws://127.0.0.1:{server.port}/devtools/page/test", timeout=2) as client:
            reply = client.call("Page.enable")
        server.thread.join(timeout=2)
        self.assertIsNone(server.error)
        self.assertEqual(server.seen["method"], "Page.enable")
        self.assertTrue(reply["result"]["ok"])


if __name__ == "__main__":
    unittest.main()
