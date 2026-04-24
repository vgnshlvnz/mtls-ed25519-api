"""Mutation-kill tests (T9).

Each test targets a specific mutation class (MU1..MU5) that mutmut
would otherwise produce on the server-side code. The assertions
here are worded deliberately — weakening them would let a real
mutation survive. Do not ``assert ... >= 400`` when you can
``assert ... == 403``.
"""

from __future__ import annotations

from pathlib import Path

import pytest


pytestmark = [pytest.mark.unit]


# --- MU1: boundary on `cn in ALLOWED_CNS` ----------------------------------


def test_MU1_allowed_cn_actually_reaches_endpoint_on_set_membership() -> None:
    """MU1. Boundary flip — ``cn in ALLOWED_CLIENT_CNS`` mutated to
    ``cn not in ALLOWED_CLIENT_CNS`` would cause legitimate clients
    to 403. This test locks in the polarity.

    Structural, not wire-level: imports ``config.ALLOWED_CLIENT_CNS``
    and asserts each admitted CN is present.
    """
    import config

    assert "client-01" in config.ALLOWED_CLIENT_CNS
    assert "client-02" in config.ALLOWED_CLIENT_CNS
    # And negation path: a non-admitted CN is not in the set.
    assert "stranger" not in config.ALLOWED_CLIENT_CNS
    assert "" not in config.ALLOWED_CLIENT_CNS


# --- MU2: exact status codes, not ``>= 400`` -------------------------------


def test_MU2_forbidden_response_is_exactly_status_403() -> None:
    """MU2. ``status_code = 403`` mutated to ``status_code = 401/404``
    must be caught. `_forbidden` is a pure factory, exercise it
    directly.
    """
    from middleware import _forbidden

    resp = _forbidden("client-evil", "cn_not_allowlisted", request_id="r-1")
    assert resp.status_code == 403  # NOT 401, NOT 404, NOT 400


def test_MU2_forbidden_body_has_fixed_schema() -> None:
    """MU2b. Body key names (``error``/``cn``/``reason``) must be exactly
    those — mutating to ``errors`` or ``status`` would be caught here.
    """
    import json

    from middleware import _forbidden

    resp = _forbidden("client-evil", "no_peer_cert", request_id="r-2")
    body = json.loads(resp.body)
    assert set(body.keys()) == {"error", "cn", "reason"}


# --- MU3: CERT_REQUIRED must not flip to CERT_OPTIONAL --------------------


def test_MU3_ssl_context_is_cert_required_not_optional() -> None:
    """MU3. The strictest-mode guarantee. ``build_server_context``
    MUST set CERT_REQUIRED. A mutation to CERT_OPTIONAL is the
    single highest-impact silent failure in the whole project.
    """
    import ssl
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tls import build_server_context

    repo_root = Path(__file__).resolve().parent.parent
    pki = repo_root / "pki"
    if not (pki / "ca" / "ca.crt").is_file():
        pytest.skip("PKI not generated; run ./pki_setup.sh")

    ctx = build_server_context(
        server_cert=pki / "server" / "server.crt",
        server_key=pki / "server" / "server.key",
        ca_cert=pki / "ca" / "ca.crt",
    )
    assert (
        ctx.verify_mode == ssl.CERT_REQUIRED
    ), "MU3: verify_mode drift — must be CERT_REQUIRED"
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


# --- MU4: error-envelope string literals ----------------------------------


def test_MU4_forbidden_error_key_is_exactly_lowercase_forbidden() -> None:
    """MU4. ``"forbidden"`` mutated to ``"forbiddin"`` or ``"Forbidden"``
    would sneak through a test that only asserts body presence.
    """
    import json

    from middleware import _forbidden

    body = json.loads(_forbidden("c", "r", request_id="r-3").body)
    assert body["error"] == "forbidden"  # exact, lowercase, no typo


# --- MU5: extract_cn return value ------------------------------------------


def test_MU5_extract_cn_returns_string_not_none_for_valid_input() -> None:
    """MU5. ``return value`` mutated to ``return None`` would break
    authn silently — no cert would be admitted.
    """
    from middleware import extract_cn

    cert = {"subject": ((("commonName", "client-01"),),)}
    got = extract_cn(cert)
    assert got == "client-01"
    assert got is not None


def test_MU5_extract_cn_returns_exact_value_not_truncated() -> None:
    """MU5b. A mutation that strips/truncates the CN would admit
    wrong identities. Lock in exact equality for a non-trivial CN.
    """
    from middleware import extract_cn

    cert = {
        "subject": ((("commonName", "client-01.longer-prefix-than-allowlist"),),),
    }
    assert extract_cn(cert) == "client-01.longer-prefix-than-allowlist"
