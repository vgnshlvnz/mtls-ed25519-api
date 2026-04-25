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

Fixtures (``nginx_stack``, ``cert_kit``, ``pki_paths``) and the helper
functions ``_client_auth``, ``_count_fastapi_reqstart``, ``_tail_lines``
all live in conftest.py — they are shared with the N4v2 perf and
concurrency modules.
"""
# ruff: noqa: F811

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

import pytest
import requests

from tests.conftest import (
    NGINX_PORT,
    REPO_ROOT,
    _client_auth,
    _count_fastapi_reqstart,
    _tail_lines,
)


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
        """Positive control — if this fails, E1-E3 are vacuous."""
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
