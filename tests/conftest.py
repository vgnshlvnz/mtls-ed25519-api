"""Shared pytest fixtures for the mTLS ED25519 API test suite.

Three layers of fixtures live here:

* ``pki_paths`` — resolves the on-disk CA/server/client cert/key paths
  that ``./pki_setup.sh`` produces. Skips integration tests cleanly if
  the PKI hasn't been generated yet.
* ``client_ssl_context`` — a ready-to-use ``ssl.SSLContext`` for the
  client side (our CA as trust anchor, client cert as identity).
* ``server_process`` — session-scoped fixture that starts the real
  FastAPI server as a subprocess bound to a free loopback port, waits
  until ``/health`` answers over mTLS, yields a base URL, then
  terminates the child. If port 8443 is occupied we pick a random free
  port and pass it via the ``MTLS_API_PORT`` env var that ``server.py``
  honours.
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
    """Resolve the PKI material produced by ``./pki_setup.sh``.

    Returns a dict keyed by role (``ca_cert``, ``server_cert``,
    ``server_key``, ``client_cert``, ``client_key``, ``ca_crl``).
    Skips the suite with a clear message if anything is missing —
    this keeps CI failures attributable to "ran before pki_setup.sh"
    rather than opaque TLS errors.
    """
    paths = {
        "ca_cert": PKI_DIR / "ca" / "ca.crt",
        "ca_crl": PKI_DIR / "ca" / "ca.crl",
        "server_cert": PKI_DIR / "server" / "server.crt",
        "server_key": PKI_DIR / "server" / "server.key",
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
    """Build a client-side SSLContext that mirrors the async client's posture.

    SECURITY: ``CERT_REQUIRED`` and ``check_hostname=True`` are the
    stdlib defaults for ``create_default_context`` — we never flip
    them off. ``verify=False`` and ``CERT_NONE`` would defeat the
    server-identity half of mTLS.
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


# --- Server subprocess fixture ----------------------------------------------


def _pick_free_port() -> int:
    """Bind port 0, read the OS-chosen port, and release it.

    There is an inherent race between releasing the socket and the
    child process re-binding it, but for a single-process test run on
    loopback the window is ~ms and we accept it.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _wait_for_health(
    base_url: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    deadline: float,
) -> None:
    """Poll /health over mTLS until it returns 200 or we hit the deadline."""
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = requests.get(
                f"{base_url}/health",
                verify=str(ca_cert),
                cert=(str(client_cert), str(client_key)),
                timeout=2.0,
            )
        except requests.exceptions.RequestException as exc:
            last_exc = exc
        else:
            if r.status_code == 200:
                return
        time.sleep(_SERVER_READY_POLL_S)
    raise RuntimeError(
        f"server at {base_url} did not become ready in "
        f"{_SERVER_READY_TIMEOUT_S}s (last error: {last_exc!r})"
    )


@pytest.fixture(scope="session")
def server_process(
    pki_paths: dict[str, Path],
) -> Iterator[dict[str, object]]:
    """Start ``server.py`` as a subprocess; yield connection info; terminate.

    If port 8443 is already bound (e.g. ``make server`` is running), the
    fixture falls back to a random free port selected by the kernel.
    This keeps the test run hermetic without requiring the dev to stop
    their background server.
    """
    port = (
        _DEFAULT_PORT
        if not _port_in_use("127.0.0.1", _DEFAULT_PORT)
        else _pick_free_port()
    )

    env = os.environ.copy()
    env["MTLS_API_PORT"] = str(port)
    # SECURITY: never disable TLS/cert checks for the child process; the
    # server logic is unchanged — we only override the bind port here.

    # Subprocess coverage: if we are running under pytest-cov (``coverage``
    # is imported in the parent process) and a .coveragerc is on disk,
    # point the child at it so ``sitecustomize.py`` can start recording.
    # Data files land with a parallel suffix and pytest-cov combines them
    # automatically at end-of-run.
    if "coverage" in sys.modules and (REPO_ROOT / ".coveragerc").is_file():
        env["COVERAGE_PROCESS_START"] = str(REPO_ROOT / ".coveragerc")

    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    base_url = f"https://localhost:{port}"
    deadline = time.monotonic() + _SERVER_READY_TIMEOUT_S
    try:
        _wait_for_health(
            base_url=base_url,
            ca_cert=pki_paths["ca_cert"],
            client_cert=pki_paths["client_cert"],
            client_key=pki_paths["client_key"],
            deadline=deadline,
        )
    except Exception:
        # Drain whatever the child wrote so the failure is attributable.
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
        sys.stderr.write(
            f"\n[server_process] startup failed, child stdout:\n{out.decode(errors='replace')}\n"
        )
        raise

    try:
        yield {
            "base_url": base_url,
            "port": port,
            "process": proc,
        }
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
