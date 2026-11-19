"""Review C1: the client takes nothing security-relevant from the environment. Its one
configuration file sits next to it in the admin-owned install directory; a missing,
malformed or user-writable file refuses; no proxy is ever used; TLS trusts only the
configured bundle."""

from __future__ import annotations

import io
import json
import os
import ssl
import sys
import threading
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from tests.integrations.claude_code.conftest import (
    POST_TOOL_USE,
    PRE_TOOL_USE,
    FakeTransport,
    Runner,
    make_ca_pem,
    write_config,
)

pytestmark = pytest.mark.unit

ALLOW = (200, b'{"verdict": "allow", "decision_id": "dec_1", "reason": "r", "message": "m"}')
#: What the reviewer's proxy sets (variants A and B of C1).
ATTACK_VARIABLES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
                    "SSL_CERT_FILE", "SSL_CERT_DIR", "AIGOV_CA_BUNDLE")  # fmt: skip


def main_with(
    hc: ModuleType,
    mode: str,
    transport: FakeTransport,
    config_path: Path,
    writable: Any,
    environ: dict[str, str],
) -> tuple[int, str]:
    stderr = io.StringIO()
    code = hc.main(
        ["hook_client.py", mode],
        stdin=io.BytesIO(json.dumps(PRE_TOOL_USE if mode == "decide" else POST_TOOL_USE).encode()),
        stdout=io.StringIO(),
        stderr=stderr,
        environ=environ,
        transport=transport,
        hostname=lambda: "WS-0142",
        is_windows=True,
        isolated=True,
        config_path=config_path,
        writable=writable,
    )
    return code, stderr.getvalue()


def test_the_default_configuration_path_is_next_to_the_client(hc: ModuleType) -> None:
    assert Path(hc.__file__).resolve().parent / "aigov-client.json" == hc.DEFAULT_CONFIG_PATH


def test_a_missing_configuration_file_blocks_decide_and_drops_report(
    hc: ModuleType, transport: FakeTransport, tmp_path: Path, environ: dict[str, str]
) -> None:
    transport.results.append(ALLOW)
    missing = tmp_path / "absent.json"
    assert main_with(hc, "decide", transport, missing, lambda p: False, environ)[0] == 2
    assert main_with(hc, "report", transport, missing, lambda p: False, environ)[0] == 0
    assert transport.calls == []


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[]", b"{}", json.dumps({"service_url": "https://x"}).encode()],
)
def test_a_malformed_configuration_file_blocks(
    hc: ModuleType,
    transport: FakeTransport,
    tmp_path: Path,
    environ: dict[str, str],
    content: bytes,
) -> None:
    path = tmp_path / "aigov-client.json"
    path.write_bytes(content)
    assert main_with(hc, "decide", transport, path, lambda p: False, environ)[0] == 2
    assert transport.calls == []


def test_an_unknown_key_blocks(
    run: Runner, transport: FakeTransport, config: dict[str, Any]
) -> None:
    transport.results.append(ALLOW)
    assert run("decide", PRE_TOOL_USE, conf={**config, "proxy": "http://x"})[0] == 2
    assert transport.calls == []


def test_a_user_writable_configuration_file_blocks(
    hc: ModuleType,
    transport: FakeTransport,
    tmp_path: Path,
    config: dict[str, Any],
    environ: dict[str, str],
) -> None:
    path = write_config(tmp_path, config)
    transport.results.append(ALLOW)
    writable = lambda p: p == path  # noqa: E731
    assert main_with(hc, "decide", transport, path, writable, environ)[0] == 2
    assert transport.calls == []


def test_the_real_writability_check_refuses_a_file_the_user_owns(
    hc: ModuleType,
    transport: FakeTransport,
    tmp_path: Path,
    config: dict[str, Any],
    environ: dict[str, str],
) -> None:
    """The test runs as an ordinary user: a file under its temp directory is writable."""
    path = write_config(tmp_path, config)
    assert hc.user_can_write(path) is True
    transport.results.append(ALLOW)
    assert main_with(hc, "decide", transport, path, hc.user_can_write, environ)[0] == 2
    assert transport.calls == []


@pytest.mark.skipif(sys.platform != "win32", reason="Windows probe")
def test_the_windows_probe_accepts_a_system_file(hc: ModuleType) -> None:
    system = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "kernel32.dll"
    if not system.is_file():
        pytest.skip("no system file to probe")
    assert hc.user_can_write(system) is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows attribute")
def test_a_read_only_attribute_counts_as_writable(hc: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "ro.json"
    path.write_text("{}", encoding="utf-8")
    os.chmod(path, 0o444)  # sets FILE_ATTRIBUTE_READONLY on Windows
    try:
        assert hc.user_can_write(path) is True
    finally:
        os.chmod(path, 0o600)


def test_a_user_writable_ca_bundle_blocks(
    hc: ModuleType,
    transport: FakeTransport,
    tmp_path: Path,
    config: dict[str, Any],
    environ: dict[str, str],
) -> None:
    path = write_config(tmp_path, config)
    transport.results.append(ALLOW)
    writable = lambda p: str(p) == config["ca_bundle"]  # noqa: E731
    assert main_with(hc, "decide", transport, path, writable, environ)[0] == 2
    assert transport.calls == []


# --- the reviewer's sequence: proxy and trust anchors from the environment ------------


@pytest.fixture
def attacker_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """HTTPS_PROXY, SSL_CERT_FILE, SSL_CERT_DIR and AIGOV_CA_BUNDLE as the engineer could
    set them (C1 variants A and B), pointing at a CA the attacker made."""
    attacker = tmp_path / "attacker-ca.pem"
    attacker.write_bytes(make_ca_pem())
    for name in ATTACK_VARIABLES:
        monkeypatch.setenv(name, str(attacker) if "SSL" in name or "AIGOV" in name
                           else "http://127.0.0.1:9")  # fmt: skip
    return attacker


def test_the_context_trusts_only_the_configured_bundle(
    hc: ModuleType, attacker_environment: Path, ca_bundle: Path, ca_pem: bytes
) -> None:
    context = hc.tls_context("https://gov.example.test", str(ca_bundle), lambda p: False)
    certs = context.get_ca_certs()
    assert len(certs) == 1
    assert certs[0]["subject"] == ((("commonName", "aigov test ca"),),)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    attacker_der = ssl.PEM_cert_to_DER_cert(attacker_environment.read_text(encoding="ascii"))
    assert attacker_der not in context.get_ca_certs(binary_form=True)


def test_the_opener_never_uses_a_proxy(hc: ModuleType, attacker_environment: Path) -> None:
    opener = hc.make_opener(None)
    # An empty ProxyHandler installs no proxy method, and it stops build_opener from
    # adding the default one that reads *_PROXY (or the Windows registry).
    proxies = [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    assert all(h.proxies == {} for h in proxies)
    assert urllib.request.getproxies()  # the environment does name a proxy


def test_a_configured_bundle_that_is_missing_blocks_whatever_the_environment_says(
    run: Runner,
    transport: FakeTransport,
    config: dict[str, Any],
    attacker_environment: Path,
    environ: dict[str, str],
    tmp_path: Path,
) -> None:
    transport.results.append(ALLOW)
    env = {**environ, "AIGOV_CA_BUNDLE": str(attacker_environment),
           "SSL_CERT_FILE": str(attacker_environment)}  # fmt: skip
    conf = {**config, "ca_bundle": str(tmp_path / "gone.pem")}
    assert run("decide", PRE_TOOL_USE, env=env, conf=conf)[0] == 2
    assert transport.calls == []


class _Recorder(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.seen.append(self.path)  # type: ignore[attr-defined]
        body = b'{"verdict": "allow", "decision_id": "dec_forged", "message": ""}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_CONNECT = do_POST


def _serve() -> tuple[HTTPServer, threading.Thread]:
    httpd = HTTPServer(("127.0.0.1", 0), _Recorder)
    httpd.seen = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


@pytest.fixture
def servers() -> Iterator[tuple[HTTPServer, HTTPServer]]:
    service, t1 = _serve()
    proxy, t2 = _serve()
    try:
        yield service, proxy
    finally:
        for httpd, thread in ((service, t1), (proxy, t2)):
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)


def test_a_proxy_in_the_environment_never_sees_the_request(
    hc: ModuleType, monkeypatch: pytest.MonkeyPatch, servers: tuple[HTTPServer, HTTPServer]
) -> None:
    """Measured shape of C1: a local proxy that answers "allow" itself. Here the real
    transport talks to the service directly; the proxy receives nothing."""
    service, proxy = servers
    proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, proxy_url)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    url = f"http://127.0.0.1:{service.server_address[1]}/v1/governance/decide"
    response = hc.UrllibTransport().post(url, b"{}", {"Authorization": "Bearer t"}, 5.0, None)
    assert response.status == 200
    assert service.seen == ["/v1/governance/decide"]  # type: ignore[attr-defined]
    assert proxy.seen == []  # type: ignore[attr-defined]
