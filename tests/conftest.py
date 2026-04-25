"""Shared pytest fixtures for the mTLS ED25519 API test suite (v1.2).

v1.2 architecture: nginx terminates mTLS on :8444, FastAPI listens on
plain HTTP on :8443. This file exposes fixtures that mirror that split
so individual test modules can target either layer:

* ``pki_paths`` — resolves on-disk CA/server/nginx/client cert paths.
  Skips cleanly if ./pki_setup.sh has not been run yet.
* ``plain_server`` — starts FastAPI (server.py) as a subprocess on a
  free loopback port, plain HTTP only. For tests that want to exercise
  the upstream directly, bypassing nginx.
* ``client_ssl_context`` — a ready-to-use stdlib SSLContext configured
  with our CA + client cert identity. For tests that want to talk
  mTLS to nginx themselves.

The actual nginx fixture lives in the N2v2 auth-test module because
it owns its own port, config, and lifecycle — keeping it module-local
avoids sprinkling test state through this shared conftest.
"""

from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests


REPO_ROOT = Path(__file__).resolve().parent.parent
PKI_DIR = REPO_ROOT / "pki"

_DEFAULT_PORT = 8443
_SERVER_READY_TIMEOUT_S = 15.0
_SERVER_READY_POLL_S = 0.25


# --- PKI discovery ----------------------------------------------------------


@pytest.fixture(scope="session")
def pki_paths() -> dict[str, Path]:
    """Resolve PKI material produced by ``./pki_setup.sh``.

    Returns a dict keyed by role. Skips the suite cleanly with a
    readable message if anything is missing — so CI failures stay
    attributable to "PKI missing" rather than opaque TLS errors.
    """
    paths = {
        "ca_cert": PKI_DIR / "ca" / "ca.crt",
        "ca_crl": PKI_DIR / "ca" / "ca.crl",
        "server_cert": PKI_DIR / "server" / "server.crt",
        "server_key": PKI_DIR / "server" / "server.key",
        "nginx_cert": PKI_DIR / "nginx" / "nginx.crt",
        "nginx_key": PKI_DIR / "nginx" / "nginx.key",
        "client_cert": PKI_DIR / "client" / "client.crt",
        "client_key": PKI_DIR / "client" / "client.key",
    }
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        pytest.skip(
            f"PKI material missing ({', '.join(missing)}); run ./pki_setup.sh first"
        )
    return paths


# --- Client SSLContext ------------------------------------------------------


@pytest.fixture(scope="session")
def client_ssl_context(pki_paths: dict[str, Path]) -> ssl.SSLContext:
    """Client-side SSLContext that trusts our CA + presents client-01.

    SECURITY: ``CERT_REQUIRED`` and ``check_hostname=True`` are the
    stdlib defaults for ``create_default_context`` — we never flip
    them off. Tests that need to exercise a misconfigured client
    must build their own context, not mutate this one.
    """
    ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(pki_paths["ca_cert"]),
    )
    ctx.load_cert_chain(
        certfile=str(pki_paths["client_cert"]),
        keyfile=str(pki_paths["client_key"]),
    )
    return ctx


# --- Plain-HTTP FastAPI subprocess fixture ----------------------------------


def _pick_free_port() -> int:
    """Bind port 0, read the OS-chosen port, and release it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _wait_for_plain_health(base_url: str, deadline: float) -> None:
    """Poll /health over plain HTTP until 200 or deadline."""
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=2.0)
        except requests.exceptions.RequestException as exc:
            last_exc = exc
        else:
            if r.status_code == 200:
                return
        time.sleep(_SERVER_READY_POLL_S)
    raise RuntimeError(
        f"plain-HTTP server at {base_url} did not become ready in "
        f"{_SERVER_READY_TIMEOUT_S}s (last error: {last_exc!r})"
    )


@pytest.fixture(scope="session")
def plain_server() -> Iterator[dict[str, object]]:
    """Start server.py on a free loopback port, plain HTTP.

    Tests that want to verify FastAPI's auth-blind contract (e.g. the
    v1.2 structural suite and the SP1-SP8 plain-FastAPI tests) use
    this fixture to hit the upstream directly, bypassing nginx.
    """
    port = (
        _DEFAULT_PORT
        if not _port_in_use("127.0.0.1", _DEFAULT_PORT)
        else _pick_free_port()
    )

    env = os.environ.copy()
    env["MTLS_API_PORT"] = str(port)
    # Subprocess coverage: if we're running under pytest-cov, forward
    # the .coveragerc so sitecustomize.py can start recording.
    if "coverage" in sys.modules and (REPO_ROOT / ".coveragerc").is_file():
        env["COVERAGE_PROCESS_START"] = str(REPO_ROOT / ".coveragerc")

    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + _SERVER_READY_TIMEOUT_S
    try:
        _wait_for_plain_health(base_url, deadline)
    except Exception:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        sys.stderr.write(
            f"\n[plain_server] startup failed, child stdout:\n"
            f"{out.decode(errors='replace')}\n"
        )
        raise

    try:
        yield {"base_url": base_url, "port": port, "process": proc}
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
