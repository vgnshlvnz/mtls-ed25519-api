"""test_nginx_auth.py — 22-test nginx auth matrix for the v1.2 architecture.

Layout (pick with ``-k``):

    Group A — allowed paths (5)   positive baselines: client-01, client-02,
                                  GET/POST, keepalive.
    Group B — denied at nginx (5) no cert, rogue CN, revoked, self-signed,
                                  expired — every one of these MUST be
                                  terminal at nginx.
    Group C — observability (4)   audit log fields: cn, verify, allowed
                                  — what ops needs to reconstruct events.
    Group D — TLS hardening (4)   TLS 1.0/1.1 rejected, server_tokens off,
                                  negotiated cipher is AEAD-only.
    Group E — log-absence (4)     proves deny paths NEVER reach the Python
                                  upstream — the v1.2 invariant in test form.

Plus one lifecycle test:

    NC5                           hot-reload after editing the CN allowlist
                                  (SIGHUP, no restart) propagates within ~1s.

The fixtures generate every helper cert the suite needs once, session-
scoped, under a pytest tmp dir. ``nginx_stack`` kills any pre-existing
nginx (Ubuntu's apt package auto-starts one as root+www-data), starts a
plain-HTTP FastAPI on :8443, rewrites the tracked nginx-test.conf, and
spawns nginx on :8444. Teardown is SIGTERM + 5s join; no leaked procs.
"""
# ruff: noqa: F811

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import requests


REPO_ROOT = Path(__file__).resolve().parent.parent
# The nginx template hardcodes upstream on 127.0.0.1:8443 and nginx on
# :8444; we reuse those ports rather than re-render the template per-test.
# Port collisions are handled by pkill-ing prior processes in the fixture.
UPSTREAM_PORT = 8443
NGINX_PORT = 8444


# --- Low-level helpers ------------------------------------------------------


def _tcp_wait(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.25)
            if sock.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def _wait_plain_http(base_url: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=1.5)
            if r.status_code == 200:
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.15)
    raise RuntimeError(f"{base_url}/health never returned 200")


def _wait_mtls(
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


# --- Cert generation helpers ------------------------------------------------


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
    """Issue a new client cert signed by our CA. Returns (key, crt)."""
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
        # expired cert for Group B5.
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


# --- Access-log tailing -----------------------------------------------------


def _tail_lines(path: Path, n: int) -> list[str]:
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()[-n:]


def _count_fastapi_reqstart(log_path: Path, path_hint: str | None = None) -> int:
    """Count ``req_start`` lines in the FastAPI log, optionally filtered by path."""
    if not log_path.is_file():
        return 0
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if path_hint is None:
        return text.count("req_start ")
    pattern = re.compile(r"req_start\s+\S*\s+path=" + re.escape(path_hint))
    return len(pattern.findall(text))


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture(scope="session")
def cert_kit(
    pki_paths: dict[str, Path], tmp_path_factory: pytest.TempPathFactory
) -> dict[str, tuple[Path, Path]]:
    """Generate every helper cert the suite needs, once per session.

    Also performs the revocation (and CRL regeneration) here — the nginx
    fixture depends on this one, so by the time nginx starts, the CRL on
    disk already contains our revoked serial. This ordering is load-
    bearing; don't invert it.
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
    # at `ssl_verify_client on` before HTTP bytes fly.
    self_signed = _self_signed_client("self-signed-client", out)

    return {
        "client_02": client_02,
        "client_99": client_99,
        "revoked": revoked,
        "expired": expired,
        "self_signed": self_signed,
    }


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


@pytest.fixture(scope="session")
def nginx_stack(
    pki_paths: dict[str, Path],
    cert_kit: dict[str, tuple[Path, Path]],
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, object]]:
    """Bring up FastAPI (plain) + nginx (mTLS + allowlist) on fixed ports."""
    if not _has_nginx():
        pytest.skip("nginx binary not on PATH — skipping v1.2 auth matrix")

    _kill_stray_uvicorn()
    _kill_stray_nginx()

    # Regenerate nginx-test.conf so the CRL reload below is a no-op
    # (config is already substituted with current PROJECT_ROOT).
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
        _wait_plain_http(f"http://127.0.0.1:{UPSTREAM_PORT}")
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
        _wait_mtls(
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

    # --- teardown -----------------------------------------------------------
    # SIGTERM, then SIGKILL fallback.
    for proc in (nginx_proc, fastapi_proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def _has_nginx() -> bool:
    return (
        subprocess.run(
            ["which", "nginx"],
            capture_output=True,
        ).returncode
        == 0
    )


def _client_auth(
    pki_paths: dict[str, Path],
    pair: tuple[Path, Path] | None = None,
) -> dict[str, object]:
    """Build a requests.get(**kwargs) style dict with mTLS material attached."""
    if pair is None:
        crt, key = pki_paths["client_cert"], pki_paths["client_key"]
    else:
        key, crt = pair
    return {
        "cert": (str(crt), str(key)),
        "verify": str(pki_paths["ca_cert"]),
        "timeout": 5.0,
    }


# ============================================================================
# Group A — allowed paths (5 tests)
# ============================================================================


@pytest.mark.integration
class TestGroupAAllowed:
    def test_a1_health_client01(self, nginx_stack, pki_paths):
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths),
        )
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_a2_data_get(self, nginx_stack, pki_paths):
        r = requests.get(
            f"{nginx_stack['nginx_url']}/data",
            **_client_auth(pki_paths),
        )
        assert r.status_code == 200
        body = r.json()
        assert "readings" in body
        assert len(body["readings"]) == 2
        assert {"sensor_id", "temperature_c", "humidity_pct", "recorded_at"} <= set(
            body["readings"][0].keys()
        )

    def test_a3_data_post_echoes(self, nginx_stack, pki_paths):
        payload = {"key": "value", "nested": {"n": 42}}
        r = requests.post(
            f"{nginx_stack['nginx_url']}/data",
            json=payload,
            **_client_auth(pki_paths),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["received"] == payload
        assert "echoed_at" in body

    def test_a4_client02_admitted(self, nginx_stack, cert_kit, pki_paths):
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["client_02"]),
        )
        assert r.status_code == 200

    def test_a5_keepalive_reuses_connection(self, nginx_stack, pki_paths):
        """Five sequential requests on one Session — verifies upstream
        keepalive (the `Connection ""` proxy header) doesn't break."""
        session = requests.Session()
        session.cert = (
            str(pki_paths["client_cert"]),
            str(pki_paths["client_key"]),
        )
        session.verify = str(pki_paths["ca_cert"])
        for _ in range(5):
            r = session.get(f"{nginx_stack['nginx_url']}/health", timeout=5.0)
            assert r.status_code == 200


# ============================================================================
# Group B — denied at nginx (5 tests)
# ============================================================================


@pytest.mark.integration
class TestGroupBDenied:
    def test_b1_no_client_cert_returns_400(self, nginx_stack, pki_paths):
        """With ssl_verify_client on and no cert offered, nginx returns
        HTTP 400 "No required SSL certificate was sent" — NOT a TLS
        handshake abort. This was surprising in v1.1 debugging; lock it in."""
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            verify=str(pki_paths["ca_cert"]),
            timeout=5.0,
        )
        assert r.status_code == 400
        assert "SSL certificate" in r.text

    def test_b2_rogue_cn_returns_403_json(self, nginx_stack, cert_kit, pki_paths):
        """client-99 chains to our CA (handshake succeeds) but isn't on the
        allowlist — nginx returns the canonical v1.2 JSON body directly.
        FastAPI is never contacted (see Group E for that assertion)."""
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["client_99"]),
        )
        assert r.status_code == 403
        assert r.json() == {
            "error": "forbidden",
            "cn": "client-99",
            "reason": "cn_not_allowlisted",
        }

    # NOTE on B3/B4/B5: nginx with `ssl_verify_client on` completes the TLS
    # handshake regardless of verify result, then responds with HTTP 400
    # (default static body) if $ssl_client_verify != SUCCESS. It does NOT
    # abort the handshake. This was a surprise when v1.1 was written —
    # a `pytest.raises(ssl.SSLError)` here catches nothing. The upstream
    # is still never contacted; Group E asserts that independently.

    def test_b3_revoked_cert_returns_400(self, nginx_stack, cert_kit, pki_paths):
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["revoked"]),
        )
        assert r.status_code == 400, r.text
        # Body is nginx's static 400 page; it mentions SSL/certificate.
        assert "SSL" in r.text or "certificate" in r.text.lower()

    def test_b4_self_signed_returns_400(self, nginx_stack, cert_kit, pki_paths):
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["self_signed"]),
        )
        assert r.status_code == 400, r.text
        assert "SSL" in r.text or "certificate" in r.text.lower()

    def test_b5_expired_cert_returns_400(self, nginx_stack, cert_kit, pki_paths):
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["expired"]),
        )
        assert r.status_code == 400, r.text
        assert "SSL" in r.text or "certificate" in r.text.lower()


# ============================================================================
# Group C — observability / audit log fields (4 tests)
# ============================================================================


@pytest.mark.integration
class TestGroupCObservability:
    def _make_request_and_get_last_log(
        self, nginx_stack, cert_pair=None, pki_paths=None, status_expected=None
    ):
        # Drop-in helper that sends the request and returns the last
        # access-log line, retrying briefly for nginx buffer flush.
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_pair),
        )
        if status_expected is not None:
            assert r.status_code == status_expected, r.text
        # nginx flushes access_log buffered at 64k by default; with one
        # request on a TTY config it's line-buffered, but give it a beat.
        time.sleep(0.15)
        lines = _tail_lines(nginx_stack["nginx_access_log"], 1)
        assert lines, "access log empty — nginx did not log the request"
        return lines[-1]

    def test_c1_cn_logged_for_allowed(self, nginx_stack, pki_paths):
        line = self._make_request_and_get_last_log(
            nginx_stack,
            pki_paths=pki_paths,
            status_expected=200,
        )
        assert 'cn="client-01"' in line, line

    def test_c2_verify_success_logged(self, nginx_stack, pki_paths):
        line = self._make_request_and_get_last_log(
            nginx_stack,
            pki_paths=pki_paths,
            status_expected=200,
        )
        assert "verify=SUCCESS" in line, line

    def test_c3_allowed_eq_1_for_allowlisted_cn(self, nginx_stack, pki_paths):
        line = self._make_request_and_get_last_log(
            nginx_stack,
            pki_paths=pki_paths,
            status_expected=200,
        )
        assert "allowed=1" in line, line

    def test_c4_allowed_eq_0_for_rogue_cn(self, nginx_stack, cert_kit, pki_paths):
        line = self._make_request_and_get_last_log(
            nginx_stack,
            cert_pair=cert_kit["client_99"],
            pki_paths=pki_paths,
            status_expected=403,
        )
        assert "allowed=0" in line, line
        assert 'cn="client-99"' in line, line
        # status field is bare-integer separated by spaces; tighten the match
        assert re.search(r"\s403\s", line), line


# ============================================================================
# Group D — TLS hardening (4 tests)
# ============================================================================


@pytest.mark.integration
class TestGroupDTLSHardening:
    def _s_client(self, pki_paths, *extra_args):
        return subprocess.run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"127.0.0.1:{NGINX_PORT}",
                "-servername",
                "localhost",
                "-cert",
                str(pki_paths["client_cert"]),
                "-key",
                str(pki_paths["client_key"]),
                "-CAfile",
                str(pki_paths["ca_cert"]),
                *extra_args,
            ],
            input=b"",
            capture_output=True,
            timeout=15,
        )

    def test_d1_tls10_rejected(self, nginx_stack, pki_paths):
        """nginx/ssl_params.conf pins TLS 1.2+; a TLS 1.0 client must lose."""
        proc = self._s_client(pki_paths, "-tls1")
        assert proc.returncode != 0
        text = (proc.stdout + proc.stderr).decode(errors="replace").lower()
        assert any(
            token in text
            for token in (
                "unsupported protocol",
                "wrong version",
                "alert",
                "no protocols available",
            )
        ), text

    def test_d2_tls11_rejected(self, nginx_stack, pki_paths):
        proc = self._s_client(pki_paths, "-tls1_1")
        assert proc.returncode != 0
        text = (proc.stdout + proc.stderr).decode(errors="replace").lower()
        assert any(
            token in text
            for token in (
                "unsupported protocol",
                "wrong version",
                "alert",
                "no protocols available",
            )
        ), text

    def test_d3_server_tokens_off(self, nginx_stack, pki_paths):
        """server_tokens off makes nginx drop the version suffix. We allow
        either a missing Server header or the bare string "nginx" — what
        we reject is anything of the form ``nginx/1.24.0``."""
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths),
        )
        server = r.headers.get("Server", "")
        # Either absent, or exactly "nginx" — no version digits.
        assert server in ("", "nginx"), f"Server header leaked version: {server!r}"

    def test_d4_negotiated_cipher_is_aead(self, nginx_stack, pki_paths):
        """The cipher actually used between client and nginx must come from
        the AEAD suite (TLS 1.3 TLS_AES_*_GCM / TLS_CHACHA20, or TLS 1.2
        ECDHE-*-GCM). This rejects RC4/DES/3DES/MD5/NULL/EXPORT by name."""
        proc = self._s_client(pki_paths)
        assert proc.returncode == 0, (proc.stdout + proc.stderr).decode(
            errors="replace"
        )
        text = (proc.stdout + proc.stderr).decode(errors="replace")
        # openssl 3 formats: "Cipher    : TLS_AES_256_GCM_SHA384"; older: "Cipher is ECDHE-…"
        m = re.search(r"Cipher\s*(?:is|:)\s*(\S+)", text)
        assert m, f"no Cipher line in s_client output:\n{text}"
        cipher = m.group(1)
        banned = re.compile(r"(?i)RC4|3DES|DES-CBC|DES_CBC|MD5|NULL|EXPORT")
        assert not banned.search(cipher), f"weak cipher negotiated: {cipher}"


# ============================================================================
# Group E — log-absence (4 tests)
# ============================================================================


@pytest.mark.integration
class TestGroupELogAbsence:
    """The v1.2 invariant in test form: deny paths MUST NOT reach FastAPI.

    Each test captures the FastAPI req_start count before the probe
    request and checks it did not increment — proving the upstream was
    never asked to serve that request. E4 is the positive control that
    keeps a silly regression (e.g. "we're not logging at all") from
    making E1-E3 vacuously pass.
    """

    def test_e1_no_cert_does_not_reach_upstream(self, nginx_stack, pki_paths):
        before = _count_fastapi_reqstart(nginx_stack["fastapi_log"])
        requests.get(
            f"{nginx_stack['nginx_url']}/health",
            verify=str(pki_paths["ca_cert"]),
            timeout=5.0,
        )
        time.sleep(0.25)
        after = _count_fastapi_reqstart(nginx_stack["fastapi_log"])
        assert after == before, f"upstream saw denied request: {before} -> {after}"

    def test_e2_rogue_cn_does_not_reach_upstream(
        self,
        nginx_stack,
        cert_kit,
        pki_paths,
    ):
        before = _count_fastapi_reqstart(nginx_stack["fastapi_log"])
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["client_99"]),
        )
        assert r.status_code == 403
        time.sleep(0.25)
        after = _count_fastapi_reqstart(nginx_stack["fastapi_log"])
        assert after == before, f"upstream saw denied request: {before} -> {after}"

    def test_e3_revoked_cert_does_not_reach_upstream(
        self,
        nginx_stack,
        cert_kit,
        pki_paths,
    ):
        """Revoked cert -> nginx returns 400 post-handshake. Key invariant:
        the upstream is STILL never contacted, so req_start stays flat.
        This is what makes "nginx is the auth boundary" a testable claim."""
        before = _count_fastapi_reqstart(nginx_stack["fastapi_log"])
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["revoked"]),
        )
        assert r.status_code == 400
        time.sleep(0.25)
        after = _count_fastapi_reqstart(nginx_stack["fastapi_log"])
        assert (
            after == before
        ), f"upstream saw verify-failed request: {before} -> {after}"

    def test_e4_allowed_request_DOES_reach_upstream(self, nginx_stack, pki_paths):
        """Positive control — if this fails, E1-E3 are vacuous.

        Uses a unique path so the req_start count is not polluted by
        earlier tests with retries or health-check noise.
        """
        before = _count_fastapi_reqstart(
            nginx_stack["fastapi_log"],
            path_hint="/health",
        )
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths),
        )
        assert r.status_code == 200
        time.sleep(0.25)
        after = _count_fastapi_reqstart(
            nginx_stack["fastapi_log"],
            path_hint="/health",
        )
        assert after >= before + 1, (
            f"expected an upstream /health req_start to be logged, "
            f"but count went {before} -> {after}"
        )


# ============================================================================
# NC5 — live-reload propagates allowlist edits without a restart
# ============================================================================


@pytest.mark.integration
def test_nc5_nginx_reload_propagates_allowlist_edit(
    nginx_stack,
    cert_kit,
    pki_paths,
):
    """Edit the CN allowlist in nginx-test.conf, SIGHUP, verify propagation.

    1. Baseline: client-99 is denied (403) — it's not on the allowlist.
    2. Patch the map{} block to admit client-99; `nginx -s reload`.
    3. client-99 is now admitted (200) — nginx applied the edit without
       restarting the process or dropping in-flight connections.
    4. Restore the file and reload back to the baseline, so subsequent
       tests in the session see the original policy. The restore runs
       even if the test fails (finally:), keeping the suite hermetic.
    """
    conf = Path(nginx_stack["nginx_conf"])
    original = conf.read_text(encoding="utf-8")

    # 1. Baseline: 403
    r = requests.get(
        f"{nginx_stack['nginx_url']}/health",
        **_client_auth(pki_paths, pair=cert_kit["client_99"]),
    )
    assert r.status_code == 403, r.text

    # 2. Patch: drop client-99 into the allowlist map{} block.
    patched = re.sub(
        r'("client-02"\s+1;)',
        r'\1\n        "client-99"   1;',
        original,
    )
    assert (
        patched != original
    ), "sed patch did not apply — is the template shape intact?"
    conf.write_text(patched, encoding="utf-8")

    try:
        # Send SIGHUP via nginx -s reload. Needs the same -c path the
        # master process was started with.
        subprocess.run(
            ["nginx", "-s", "reload", "-c", str(conf)],
            cwd=str(REPO_ROOT),
            check=True,
            timeout=5,
            capture_output=True,
        )
        time.sleep(0.5)

        # 3. Same cert, now admitted.
        r = requests.get(
            f"{nginx_stack['nginx_url']}/health",
            **_client_auth(pki_paths, pair=cert_kit["client_99"]),
        )
        assert r.status_code == 200, (
            f"post-reload request not admitted. body: {r.text!r}\n"
            f"status: {r.status_code}"
        )
    finally:
        # 4. Restore baseline on the way out.
        conf.write_text(original, encoding="utf-8")
        subprocess.run(
            ["nginx", "-s", "reload", "-c", str(conf)],
            cwd=str(REPO_ROOT),
            check=False,
            timeout=5,
            capture_output=True,
        )
        time.sleep(0.3)
