"""The real urllib transport against a loopback server: status, body, and no redirects."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import ModuleType

import pytest

pytestmark = pytest.mark.unit


class _Handler(BaseHTTPRequestHandler):
    seen: list[str] = []  # noqa: RUF012 - shared by the one server in this module

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        _Handler.seen.append(self.path)
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"verdict": "allow", "decision_id": "dec_1"}'
        self.send_response(200 if self.path == "/ok" else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server() -> Iterator[str]:
    _Handler.seen = []
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_transport_returns_status_and_body(hc: ModuleType, server: str) -> None:
    response = hc.UrllibTransport().post(server + "/ok", b"{}", {}, 5.0, None)
    assert response.status == 200
    assert b"dec_1" in response.body


def test_transport_returns_error_status_without_raising(hc: ModuleType, server: str) -> None:
    response = hc.UrllibTransport().post(server + "/fail", b"{}", {}, 5.0, None)
    assert response.status == 500


def test_transport_does_not_follow_redirects(hc: ModuleType, server: str) -> None:
    response = hc.UrllibTransport().post(server + "/redirect", b"{}", {}, 5.0, None)
    assert response.status == 302
    assert _Handler.seen == ["/redirect"]
