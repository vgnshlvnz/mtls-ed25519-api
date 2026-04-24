"""Shared pytest fixtures for the mTLS ED25519 API test suite (v1.2).

v1.2 architecture: nginx terminates mTLS on :8444, FastAPI listens on
plain HTTP on :8443. This file exposes fixtures that mirror that split
so individual test modules can target either layer:

* ``pki_paths`` — resolves on-disk CA/server/nginx/client cert paths.
  Skips cleanly if ./pki_setup.sh has not been run yet.
* ``client_ssl_context`` — a ready-to-use stdlib SSLContext configured
  with our CA + client cert identity.
* ``plain_server`` — starts FastAPI (server.py) as a subprocess on a
  free loopback port, plain HTTP only. For tests that want to exercise
  the upstream directly, bypassing nginx.
* ``cert_kit`` — session-scoped helper-cert factory (client-02 /
  client-99 / revoked / expired / self-signed).
* ``nginx_stack`` — session-scoped FastAPI + nginx subprocess pair.
  The only fixture in this file that mutates on-disk state
  (regenerates ca.crl after revoking a cert inside cert_kit).

Helpers ``_client_auth``, ``_count_fastapi_reqstart``, etc. are plain
functions that individual test modules import; they aren't fixtures
because they take arguments the fixture system can't supply.
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

# v1.2 stack ports. The nginx template hardcodes upstream on
# 127.0.0.1:8443 and nginx on :8444; we reuse those ports rather
# than re-render the template per-test. Port collisions are handled
# by pkill-ing prior processes in the nginx_stack fixture.
UPSTREAM_PORT = 8443
NGINX_PORT = 8444


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


# --- Port helpers ----------------------------------------------------------


def _pick_free_port() -> int:
    """Bind port 0, read the OS-chosen port, and release it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


# --- Readiness polling -----------------------------------------------------


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


def _wait_for_mtls_health(
    nginx_url: str,
    ca_cert: Path,
    client_cert: Path,
    client_key: Path,
    timeout: float = 10.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(
                f"{nginx_url}/health",
                verify=str(ca_cert),
                cert=(str(client_cert), str(client_key)),
                timeout=1.5,
            )
            if r.status_code == 200:
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.15)
    raise RuntimeError(f"{nginx_url}/health never returned 200 via mTLS")


# --- Plain-HTTP FastAPI subprocess fixture ---------------------------------


@pytest.fixture(scope="session")
def plain_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, object]]:
    """Start server.py on a free loopback port, plain HTTP.

    Tests that want to verify FastAPI's auth-blind contract (e.g. the
    v1.2 structural suite and the SP1-SP8 plain-FastAPI tests) use
    this fixture to hit the upstream directly, bypassing nginx.

    ``log_path`` in the yielded dict points at a regular file holding
    the subprocess's stdout+stderr. Tests that want to inspect the
    FastAPI log (e.g. LA1) can read it freely — we no longer buffer
    through subprocess.PIPE.
    """
    port = (
        _DEFAULT_PORT
        if not _port_in_use("127.0.0.1", _DEFAULT_PORT)
        else _pick_free_port()
    )

    env = os.environ.copy()
    env["MTLS_API_PORT"] = str(port)
    if "coverage" in sys.modules and (REPO_ROOT / ".coveragerc").is_file():
        env["COVERAGE_PROCESS_START"] = str(REPO_ROOT / ".coveragerc")

    log_path = tmp_path_factory.mktemp("plain-server") / "server.log"
    log_fh = log_path.open("w")

    proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
    )

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + _SERVER_READY_TIMEOUT_S
    try:
        _wait_for_plain_health(base_url, deadline)
    except Exception:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        log_fh.close()
        sys.stderr.write(
            f"\n[plain_server] startup failed, log:\n"
            f"{log_path.read_text(errors='replace')}\n"
        )
        raise

    try:
        yield {
            "base_url": base_url,
            "port": port,
            "process": proc,
            "log_path": log_path,
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


# --- openssl helpers (used by cert_kit) ------------------------------------


def _openssl(*args: str, cwd: Path = REPO_ROOT) -> subprocess.CompletedProcess:
    """Run openssl with stderr captured; raise on non-zero."""
    proc = subprocess.run(
        ["openssl", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"openssl {' '.join(args)} failed ({proc.returncode}):\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )
    return proc


def _sign_client(
    cn: str,
    out_dir: Path,
    *,
    startdate: str | None = None,
    enddate: str | None = None,
    days: int = 365,
) -> tuple[Path, Path]:
    """Issue a new client cert signed by our CA.

    Returns ``(key, crt)`` — the same convention as the rest of the
    test helpers. _client_auth() destructures this tuple accordingly.
    """
    key = out_dir / f"{cn}.key"
    csr = out_dir / f"{cn}.csr"
    crt = out_dir / f"{cn}.crt"

    _openssl("genpkey", "-algorithm", "ed25519", "-out", str(key))
    _openssl(
        "req",
        "-new",
        "-key",
        str(key),
        "-out",
        str(csr),
        "-subj",
        f"/CN={cn}/O=Lab/C=MY",
        "-config",
        str(REPO_ROOT / "pki" / "openssl.cnf"),
    )

    ca_args = [
        "ca",
        "-config",
        "pki/openssl.cnf",
        "-batch",
        "-notext",
        "-in",
        str(csr),
        "-out",
        str(crt),
        "-extensions",
        "v3_client",
        "-cert",
        "pki/ca/ca.crt",
        "-keyfile",
        "pki/ca/ca.key",
    ]
    if startdate and enddate:
        # `openssl ca` accepts explicit -startdate / -enddate in
        # YYMMDDHHMMSSZ format. Backdating lets us mint an already-
        # expired cert.
        ca_args.extend(["-startdate", startdate, "-enddate", enddate])
    else:
        ca_args.extend(["-days", str(days)])
    _openssl(*ca_args)
    return key, crt


def _self_signed_client(cn: str, out_dir: Path) -> tuple[Path, Path]:
    """Mint a self-signed Ed25519 cert NOT chained to our CA."""
    key = out_dir / f"ss_{cn}.key"
    crt = out_dir / f"ss_{cn}.crt"
    _openssl("genpkey", "-algorithm", "ed25519", "-out", str(key))
    _openssl(
        "req",
        "-new",
        "-x509",
        "-key",
        str(key),
        "-out",
        str(crt),
        "-days",
        "365",
        "-subj",
        f"/CN={cn}/O=Rogue/C=MY",
        "-config",
        str(REPO_ROOT / "pki" / "openssl.cnf"),
        "-extensions",
        "v3_ca",
    )
    return key, crt


def _revoke_cert(crt_path: Path) -> None:
    """Run openssl ca -revoke + -gencrl; idempotent on re-run."""
    try:
        _openssl(
            "ca",
            "-config",
            "pki/openssl.cnf",
            "-revoke",
            str(crt_path),
        )
    except RuntimeError as exc:
        if "Already revoked" not in str(exc):
            raise
    _openssl(
        "ca",
        "-config",
        "pki/openssl.cnf",
        "-gencrl",
        "-out",
        "pki/ca/ca.crl",
    )


# --- Log helpers used across nginx-aware tests -----------------------------


def _tail_lines(path: Path, n: int) -> list[str]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()[-n:]


def _count_fastapi_reqstart(log_path: Path, path_hint: str | None = None) -> int:
    """Count ``req_start`` lines in the FastAPI log, optionally filtered by path."""
    import re

    if not log_path.is_file():
        return 0
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if path_hint is None:
        return text.count("req_start ")
    pattern = re.compile(r"req_start\s+\S*\s+path=" + re.escape(path_hint))
    return len(pattern.findall(text))


def _client_auth(
    pki_paths: dict[str, Path],
    pair: tuple[Path, Path] | None = None,
) -> dict[str, object]:
    """Build a requests.get(**kwargs) style dict with mTLS material attached.

    ``pair`` is a ``(key, crt)`` tuple as returned by ``_sign_client``.
    When absent, the default uses the baseline client-01 from pki_paths.
    """
    if pair is None:
        crt, key = pki_paths["client_cert"], pki_paths["client_key"]
    else:
        key, crt = pair
    return {
        "cert": (str(crt), str(key)),
        "verify": str(pki_paths["ca_cert"]),
        "timeout": 5.0,
    }


# --- Stray-process cleanup (used by nginx_stack) ---------------------------


def _kill_pids_by_name(pattern: str, *, exact: bool = True) -> None:
    """Kill processes whose executable-name (not full cmdline) matches.

    DO NOT swap to ``pkill -f <pattern>`` without extreme care:
    ``pkill -f nginx`` happily kills the pytest process itself because
    pytest's command line contains ``tests/test_nginx_auth.py`` — i.e.
    the string ``nginx``. Always match on short name or exact cmdline.
    """
    flag = "-x" if exact else "-f"
    proc = subprocess.run(
        ["pgrep", flag, pattern],
        capture_output=True,
        text=True,
    )
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
            os.kill(pid, 15)  # SIGTERM
        except (ValueError, ProcessLookupError, PermissionError):
            pass


def _kill_stray_nginx() -> None:
    """Stop any stale nginx master/worker owning :8444. Best-effort."""
    _kill_pids_by_name("nginx", exact=True)
    time.sleep(0.3)


def _kill_stray_uvicorn() -> None:
    """Stop a prior `python server.py` bound to UPSTREAM_PORT.

    pgrep -f'd against our exact invocation so we don't kill unrelated
    python processes (pytest, editor LSPs, ipython, …).
    """
    _kill_pids_by_name(
        f"{sys.executable} server.py",
        exact=False,
    )
    time.sleep(0.2)


def _has_nginx() -> bool:
    return subprocess.run(["which", "nginx"], capture_output=True).returncode == 0


# --- Session-scoped helper-cert kit ---------------------------------------


@pytest.fixture(scope="session")
def cert_kit(
    pki_paths: dict[str, Path],
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, tuple[Path, Path]]:
    """Generate every helper cert the suite needs, once per session.

    Also performs the revocation (and CRL regeneration) here — the
    nginx_stack fixture depends on this one, so by the time nginx
    starts, the CRL on disk already contains our revoked serial.
    This ordering is load-bearing; don't invert it.

    Tests that don't need helper certs shouldn't request this fixture
    — cert_kit mutates the CA database (pki/ca/index.txt, pki/ca/ca.crl)
    and triggering it has side-effects visible outside the test run.
    """
    out = tmp_path_factory.mktemp("certkit")

    client_02 = _sign_client("client-02", out)
    client_99 = _sign_client("client-99", out)

    # Revoked: issued normally, then `openssl ca -revoke`.
    revoked = _sign_client("client-to-be-revoked", out)
    _revoke_cert(revoked[1])

    # Expired: backdated with -startdate/-enddate both in 2024.
    expired = _sign_client(
        "client-expired",
        out,
        startdate="240101000000Z",
        enddate="240102000000Z",
    )

    # Self-signed: NOT our CA's issuer, so the TLS handshake will fail
    # at ``ssl_verify_client on`` before HTTP bytes fly.
    self_signed = _self_signed_client("self-signed-client", out)

    return {
        "client_02": client_02,
        "client_99": client_99,
        "revoked": revoked,
        "expired": expired,
        "self_signed": self_signed,
    }


# --- Session-scoped FastAPI + nginx stack ---------------------------------


@pytest.fixture(scope="session")
def nginx_stack(
    pki_paths: dict[str, Path],
    cert_kit: dict[str, tuple[Path, Path]],
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, object]]:
    """Bring up FastAPI (plain) + nginx (mTLS + allowlist) on fixed ports."""
    if not _has_nginx():
        pytest.skip("nginx binary not on PATH — skipping v1.2 nginx-aware tests")

    _kill_stray_uvicorn()
    _kill_stray_nginx()

    # Regenerate nginx-test.conf so paths reflect the current
    # PROJECT_ROOT. The CRL on disk already reflects cert_kit's
    # revocation (that fixture is our dependency).
    gen_sh = REPO_ROOT / "nginx" / "nginx-test-gen.sh"
    subprocess.run([str(gen_sh)], check=True, capture_output=True)
    nginx_conf = REPO_ROOT / "nginx" / "nginx-test.conf"
    nginx_access_log = REPO_ROOT / "nginx" / "logs" / "access.log"

    # Scrub the access log between sessions so per-test tail assertions
    # aren't polluted by earlier runs.
    if nginx_access_log.exists():
        nginx_access_log.write_text("")

    # --- FastAPI upstream ---------------------------------------------------
    log_dir = tmp_path_factory.mktemp("logs")
    fastapi_log = log_dir / "fastapi.log"
    env = os.environ.copy()
    env["MTLS_API_PORT"] = str(UPSTREAM_PORT)
    if "coverage" in sys.modules and (REPO_ROOT / ".coveragerc").is_file():
        env["COVERAGE_PROCESS_START"] = str(REPO_ROOT / ".coveragerc")

    fastapi_proc = subprocess.Popen(
        [sys.executable, "server.py"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=fastapi_log.open("w"),
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_plain_health(
            f"http://127.0.0.1:{UPSTREAM_PORT}",
            time.monotonic() + _SERVER_READY_TIMEOUT_S,
        )
    except Exception:
        fastapi_proc.terminate()
        fastapi_proc.wait(timeout=5)
        pytest.fail(
            f"FastAPI did not start on :{UPSTREAM_PORT}\n"
            f"log: {fastapi_log.read_text(errors='replace')}"
        )

    # --- nginx --------------------------------------------------------------
    nginx_log = log_dir / "nginx-stderr.log"
    nginx_proc = subprocess.Popen(
        ["nginx", "-c", str(nginx_conf), "-g", "daemon off;"],
        cwd=str(REPO_ROOT),
        stdout=nginx_log.open("w"),
        stderr=subprocess.STDOUT,
    )
    try:
        _wait_for_mtls_health(
            f"https://localhost:{NGINX_PORT}",
            pki_paths["ca_cert"],
            pki_paths["client_cert"],
            pki_paths["client_key"],
        )
    except Exception:
        nginx_proc.terminate()
        fastapi_proc.terminate()
        fastapi_proc.wait(timeout=5)
        nginx_proc.wait(timeout=5)
        pytest.fail(
            "nginx did not become ready\n"
            f"nginx stderr:\n{nginx_log.read_text(errors='replace')}\n"
            f"FastAPI log:\n{fastapi_log.read_text(errors='replace')}"
        )

    yield {
        "nginx_url": f"https://localhost:{NGINX_PORT}",
        "upstream_url": f"http://127.0.0.1:{UPSTREAM_PORT}",
        "fastapi_log": fastapi_log,
        "nginx_access_log": nginx_access_log,
        "nginx_conf": nginx_conf,
        "nginx_proc": nginx_proc,
        "fastapi_proc": fastapi_proc,
    }

    # --- teardown: SIGTERM, then SIGKILL fallback ---------------------------
    for proc in (nginx_proc, fastapi_proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
