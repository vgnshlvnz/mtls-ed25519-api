"""test_server_plain.py — SP1-SP8 plain-FastAPI tests + LA1 log discipline.

Exercises server.py directly on plain HTTP, with no nginx in front.
This module is intentionally unaware of TLS: it proves what the Python
upstream DOES (and doesn't do) in isolation, so the v1.2 contract
("nginx does the auth; FastAPI serves the endpoints") can be validated
layer by layer.

    SP1   GET /health returns 200 {"status": "ok"}
    SP2   GET /data returns two readings with the expected shape
    SP3   POST /data echoes the JSON body and stamps echoed_at
    SP4   Server header does not leak "uvicorn/<version>"
    SP5   X-Request-ID supplied by the caller is honoured
    SP6   X-Request-ID is minted (uuid4 hex) when absent
    SP7   TLS handshake fails on the plain-HTTP port (no secret TLS)
    SP8   Spoofed X-Client-CN header is IGNORED (v1.2 invariant)

Plus:

    LA1   FastAPI log never emits cert material or X-Client-* values,
          even when the client spoofs those headers at us.
"""
# ruff: noqa: F811

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

import pytest
import requests


# ============================================================================
# SP1-SP8 — plain-FastAPI behaviour
# ============================================================================


@pytest.mark.integration
class TestPlainFastAPI:
    def test_sp1_health_returns_200(self, plain_server):
        r = requests.get(f"{plain_server['base_url']}/health", timeout=5.0)
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_sp2_data_get_shape(self, plain_server):
        r = requests.get(f"{plain_server['base_url']}/data", timeout=5.0)
        assert r.status_code == 200
        body = r.json()
        assert set(body.keys()) == {"readings", "generated_at"}
        assert len(body["readings"]) == 2
        for reading in body["readings"]:
            assert {
                "sensor_id",
                "temperature_c",
                "humidity_pct",
                "recorded_at",
            } <= set(reading.keys())

    def test_sp3_data_post_echoes_body(self, plain_server):
        payload = {"alpha": 1, "beta": ["x", "y"], "nested": {"n": 42}}
        r = requests.post(
            f"{plain_server['base_url']}/data",
            json=payload,
            timeout=5.0,
        )
        assert r.status_code == 200
        body = r.json()
        assert body["received"] == payload
        assert "echoed_at" in body

    def test_sp4_server_header_does_not_leak_uvicorn(self, plain_server):
        """``server_header=False`` on uvicorn must strip the banner.

        We accept either an absent Server header or one that doesn't
        mention uvicorn — both patterns are sometimes seen depending
        on upstream versions. What we reject is ``uvicorn/0.34.1``.
        """
        r = requests.get(f"{plain_server['base_url']}/health", timeout=5.0)
        server = r.headers.get("Server", "")
        assert "uvicorn" not in server.lower(), f"uvicorn banner leaked: {server!r}"

    def test_sp5_x_request_id_honoured_when_supplied(self, plain_server):
        caller_id = "test-rid-client-supplied-12345"
        r = requests.get(
            f"{plain_server['base_url']}/health",
            headers={"X-Request-ID": caller_id},
            timeout=5.0,
        )
        assert r.status_code == 200
        assert r.headers.get("X-Request-ID") == caller_id

    def test_sp6_x_request_id_minted_when_absent(self, plain_server):
        """The middleware mints a uuid4 hex when no request id is supplied."""
        r = requests.get(f"{plain_server['base_url']}/health", timeout=5.0)
        assert r.status_code == 200
        minted = r.headers.get("X-Request-ID", "")
        assert len(minted) == 32, f"expected 32-char uuid hex, got {minted!r}"
        assert all(c in "0123456789abcdef" for c in minted), minted

    def test_sp7_tls_does_not_answer_on_plain_port(self, plain_server):
        """FastAPI serves plain HTTP only. A TLS ClientHello on this port
        MUST NOT succeed — proof that there is no secret TLS listener
        co-bound to the same port, answering a parallel handshake.

        If this ever starts passing, someone re-enabled ``ssl_keyfile``
        in server.py. ST3 will usually catch that first; this test is
        the live-port insurance."""
        parsed = urlparse(plain_server["base_url"])
        host, port = parsed.hostname, parsed.port
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # we're testing handshake failure, not trust

        sock = socket.create_connection((host, port), timeout=3.0)
        with pytest.raises((ssl.SSLError, OSError, ConnectionResetError)):
            try:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    # If the wrap_socket somehow succeeded, force a byte
                    # over the "TLS" session — also must raise.
                    ss.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
                    ss.recv(64)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    def test_sp8_spoofed_x_client_cn_is_ignored(self, plain_server):
        """The v1.2 invariant, positively tested: if FastAPI ever starts
        trusting X-Client-CN, an attacker hitting 127.0.0.1:8443
        directly could forge any identity.

        We fire the same request twice — once clean, once with spoofed
        headers claiming the caller is an admin client — and assert
        both responses are identical. FastAPI must not even read,
        let alone act on, these headers."""
        baseline = requests.get(
            f"{plain_server['base_url']}/health",
            timeout=5.0,
        )
        spoofed = requests.get(
            f"{plain_server['base_url']}/health",
            headers={
                "X-Client-CN": "evil-admin",
                "X-Client-Verify": "SUCCESS",
                "X-Client-DN": "CN=evil-admin,O=Malicious,C=XX",
                "X-Client-Serial": "DEADBEEF",
            },
            timeout=5.0,
        )
        assert spoofed.status_code == baseline.status_code == 200
        assert spoofed.json() == baseline.json()


# ============================================================================
# LA1 — FastAPI log discipline
# ============================================================================


@pytest.mark.integration
@pytest.mark.security
def test_la1_log_does_not_leak_cert_or_client_identity(plain_server):
    """Hit the server with clean + spoofed requests, then read the
    subprocess's log file. Assert it contains NONE of the cert-material
    tokens (``peer_cert``, ``X509``, …) or the spoofed header values.

    This complements ST3: ST3 proves the source has no knowledge of
    those tokens; LA1 proves the running binary doesn't leak them
    even when provoked by a malicious caller."""
    base = plain_server["base_url"]
    # Fire clean + spoofed traffic.
    for _ in range(3):
        requests.get(f"{base}/health", timeout=5.0)
    requests.get(
        f"{base}/health",
        headers={
            "X-Client-CN": "evil-admin-99",
            "X-Client-Verify": "SUCCESS",
            "X-Client-DN": "CN=evil-admin-99,O=Evil,C=XX",
        },
        timeout=5.0,
    )
    # Give the log writer a beat to flush.
    import time

    time.sleep(0.25)

    log_text = plain_server["log_path"].read_text(encoding="utf-8", errors="replace")
    # Sanity: the log should contain request-id middleware output; if
    # it's empty, something else is wrong with the fixture.
    assert (
        "req_start" in log_text
    ), f"expected req_start in log, got: {log_text[:400]!r}"

    banned = [
        "peer_cert",
        "getpeercert",
        "X509",
        "SSLContext",
        "X-Client-CN",
        "X-Client-Verify",
        "X-Client-DN",
        "evil-admin-99",  # if this leaks, the middleware trusted the header value
    ]
    leaks = [token for token in banned if token in log_text]
    assert not leaks, (
        f"FastAPI log leaks forbidden tokens: {leaks}. "
        "The request-id middleware must log only method/path/reqid/status "
        "— nothing about the peer, cert chain, or X-Client-* headers."
    )
