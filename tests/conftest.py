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
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests

from hypothesis import HealthCheck, settings

from tests._pki_factory import RogueCA, make_self_signed_client, mirror_existing_ca


# --- Hypothesis profiles (T3 fuzzing) ---------------------------------------
#
# Property-based tests in tests/test_api_fuzzing.py hit a live mTLS
# server, so hypothesis's default per-example deadline (200ms) is
# occasionally tripped by the ~100-example run. Register explicit
# profiles here:
#
#   default   — 100 examples, 60s per-example deadline, allows function-scoped
#               fixtures. Picked unless HYPOTHESIS_PROFILE says otherwise.
#   ci        — same as default but with print_blob=True for reproducibility.
#   dev       — 25 examples, no deadline; for fast iteration.
#
# Select a profile via HYPOTHESIS_PROFILE=<name> or pytest --hypothesis-profile.

_HYPOTHESIS_COMMON_SUPPRESS = (HealthCheck.function_scoped_fixture,)

settings.register_profile(
    "default",
    max_examples=100,
    deadline=60_000,  # 60s per example — plenty for real-network fuzzing
    suppress_health_check=_HYPOTHESIS_COMMON_SUPPRESS,
)
settings.register_profile(
    "ci",
    max_examples=100,
    deadline=60_000,
    print_blob=True,
    suppress_health_check=_HYPOTHESIS_COMMON_SUPPRESS,
)
settings.register_profile(
    "dev",
    max_examples=25,
    deadline=None,
    suppress_health_check=_HYPOTHESIS_COMMON_SUPPRESS,
)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


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
    # Always propagate when a .coveragerc is present; sitecustomize.py
    # turns into a no-op if coverage itself isn't installed, so the
    # env var is harmless in a non-coverage run. Previously we gated
    # on ``"coverage" in sys.modules`` in the pytest process, but
    # pytest-cov can delay its ``coverage`` import past the first
    # session-scoped fixture — leaving subprocess coverage inert.
    if (REPO_ROOT / ".coveragerc").is_file():
        env["COVERAGE_PROCESS_START"] = str(REPO_ROOT / ".coveragerc")

    # Route the child's stdout + stderr to a per-session log file on disk.
    # An in-memory PIPE would fill after ~50-100 requests under fuzzing
    # (no one on the pytest side drains it) and the server would block
    # on logging.emit() — a 64KiB pipe-buffer starvation. The log file
    # is preserved under the tls_attack_tmpdir parent so a failing run
    # leaves diagnostics on disk.
    log_path = REPO_ROOT / f".server-test-{port}.log"
    log_fh = log_path.open("wb")

    # Launch via a tiny inline bootstrap so subprocess coverage fires
    # regardless of site-packages .pth discovery (pytest-cov launch
    # conditions have surprised us there). The bootstrap is a no-op
    # when COVERAGE_PROCESS_START is unset, which is the operational
    # default.
    # Uvicorn registers its own SIGTERM handler at startup that wins
    # a race against coverage.py's sigterm-save hook — and when the
    # fixture later sends SIGTERM for teardown, uvicorn begins a
    # graceful shutdown that blocks on open keep-alive connections
    # and never completes, so coverage data for the child never lands.
    #
    # We fix this by monkey-patching ``signal.signal`` in the child
    # BEFORE uvicorn starts: any SIGTERM handler uvicorn installs is
    # wrapped so that coverage is flushed FIRST, then uvicorn's
    # original handler runs. By the time the process is killed the
    # ``.coverage.<pid>.*`` file is already on disk.
    bootstrap = (
        "import os, runpy, signal\n"
        "_cov = None\n"
        'if os.environ.get("COVERAGE_PROCESS_START"):\n'
        "    try:\n"
        "        import coverage\n"
        "        coverage.process_startup(force=True)\n"
        "        _cov = coverage.Coverage.current()\n"
        "    except ImportError:\n"
        "        pass\n"
        "_orig_signal = signal.signal\n"
        "def _guarded_signal(sig, handler):\n"
        "    if sig in (signal.SIGTERM, signal.SIGINT) and _cov is not None:\n"
        "        _user_handler = handler\n"
        "        def _combined(s, f):\n"
        "            try:\n"
        "                _cov.stop()\n"
        "                _cov.save()\n"
        "            except Exception:\n"
        "                pass\n"
        "            if callable(_user_handler):\n"
        "                return _user_handler(s, f)\n"
        "        return _orig_signal(sig, _combined)\n"
        "    return _orig_signal(sig, handler)\n"
        "signal.signal = _guarded_signal\n"
        'runpy.run_path("server.py", run_name="__main__")\n'
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", bootstrap],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=log_fh,
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
        # Dump the child's log to stderr so the failure is attributable.
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log_fh.close()
        try:
            sys.stderr.write(
                f"\n[server_process] startup failed, child log:\n"
                f"{log_path.read_text(errors='replace')}\n"
            )
        except OSError:
            pass
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
        log_fh.close()
        # Leave log_path on disk for post-mortem; `make clean` removes it.


# --- TLS-attack fixtures (T2) -----------------------------------------------


@pytest.fixture(scope="session")
def tls_attack_tmpdir() -> Iterator[Path]:
    """Single throwaway directory for all T2 attack-cert material.

    Session-scoped so the slow ``openssl`` calls run once. Cleaned up
    after the session even if individual tests raise.
    """
    tmp = Path(tempfile.mkdtemp(prefix="mtls-attack-"))
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="session")
def rogue_ca(tls_attack_tmpdir: Path) -> RogueCA:
    """An ED25519 throwaway CA that the server does NOT trust.

    Any leaf signed by this CA should be rejected at the TLS handshake
    because the server's SSLContext only loads ``pki/ca/ca.crt``.
    """
    return RogueCA(tls_attack_tmpdir / "rogue-ca", cn="rogue-ca")


@pytest.fixture(scope="session")
def untrusted_intermediate_chain(
    tls_attack_tmpdir: Path,
) -> dict[str, Path]:
    """A 3-level chain: rogue-root → rogue-intermediate → leaf.

    Neither the root nor the intermediate are trusted by the server.
    Used to assert that the server refuses handshakes that present a
    plausible-looking chain without a path to a trusted anchor.
    """
    root = RogueCA(tls_attack_tmpdir / "untrusted-root", cn="untrusted-root")
    # We can't easily produce a *real* intermediate cert without
    # reworking the factory (openssl ca can sign with its own CA but
    # the resulting cert has CA:FALSE in our v3_client section). For
    # the attack test the leaf's chain-to-root is what matters — the
    # server still rejects because neither root nor intermediate
    # appears in its trust store. We emit a second rogue root ("the
    # intermediate from the server's point of view") and sign the
    # leaf against that inner root.
    inner = RogueCA(tls_attack_tmpdir / "untrusted-inter", cn="untrusted-intermediate")
    leaf = inner.sign_client("client-01")
    return {
        "root_cert": root.ca_cert,
        "inter_cert": inner.ca_cert,
        "leaf_cert": leaf.cert,
        "leaf_key": leaf.key,
    }


@pytest.fixture(scope="session")
def self_signed_client(tls_attack_tmpdir: Path) -> dict[str, Path]:
    """A self-signed client cert that chains to nothing."""
    leaf = make_self_signed_client(tls_attack_tmpdir / "self-signed", "client-01")
    return {"cert": leaf.cert, "key": leaf.key}


@pytest.fixture(scope="session")
def project_ca_mirror(
    tls_attack_tmpdir: Path,
    pki_paths: dict[str, Path],
) -> RogueCA:
    """A tempdir-scoped mirror of the project CA.

    Same key material and self-signed cert as ``pki/ca/``, but with
    a fresh ``index.txt``/``serial``/``crlnumber`` so tests can
    ``openssl ca``-sign attack leaves without polluting the real
    CA's database. Leaves signed here chain to the project's trust
    anchor — the server will perform a full chain verification on
    them and reject purely on leaf-level defects (expired, not yet
    valid, wrong key usage).
    """
    return mirror_existing_ca(
        src_cert=pki_paths["ca_cert"],
        src_key=PKI_DIR / "ca" / "ca.key",
        dir=tls_attack_tmpdir / "project-ca-mirror",
    )


@pytest.fixture(scope="session")
def attack_leaves(project_ca_mirror: RogueCA) -> dict[str, dict[str, Path]]:
    """Batch-produce leaf certs that chain to the project CA but carry
    exactly one leaf-level defect each.

    Centralising these keeps the slow ``openssl`` calls off the
    per-test hot path — each leaf is generated exactly once per
    session.
    """
    expired = project_ca_mirror.sign_client(
        "client-01",
        start="200101010000Z",
        end="200102010000Z",
    )
    future = project_ca_mirror.sign_client(
        "client-01",
        start="400101010000Z",
        end="400201010000Z",
    )
    # dataEncipherment is semantically wrong for a client identity
    # cert — the server's ssl.CERT_REQUIRED verification trusts the
    # chain but the ClientCertificateVerify step relies on the leaf's
    # digitalSignature usage.
    wrong_ku = project_ca_mirror.sign_client(
        "client-01",
        key_usage="dataEncipherment",
        eku="clientAuth",
    )
    return {
        "expired": {"cert": expired.cert, "key": expired.key},
        "future": {"cert": future.cert, "key": future.key},
        "wrong_ku": {"cert": wrong_ku.cert, "key": wrong_ku.key},
    }
