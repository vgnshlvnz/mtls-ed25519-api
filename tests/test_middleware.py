"""Unit tests for the identity middleware helpers.

Exercises ``extract_cn_from_cert`` and ``subject_fingerprint`` by feeding in dicts
shaped exactly like the output of ``ssl.SSLSocket.getpeercert()`` — a
nested tuple of RDNs. That shape is the full mock surface; nothing in
the middleware's pure path looks past it.

The ``dispatch()`` coroutine is covered end-to-end by the Phase-3
integration matrix and by ``test_client_sync.py`` / ``test_client_async.py``
at the integration layer, so it is deliberately not retested here.

Run:
    pytest -m unit
"""

from __future__ import annotations

import pytest

from middleware import extract_cn_from_cert, subject_fingerprint


# --- Test helpers -----------------------------------------------------------


def _mock_peer_cert(cn: str, *, extra_rdns: tuple = ()) -> dict:
    """Build a peer-cert dict shaped the way stdlib ssl returns one."""
    subject = (
        (("commonName", cn),),
        (("organizationName", "Lab"),),
        (("countryName", "MY"),),
    ) + extra_rdns
    return {
        "subject": subject,
        "issuer": ((("commonName", "mTLS-CA"),),),
        "version": 3,
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Jan  1 00:00:00 2027 GMT",
    }


# --- extract_cn_from_cert -------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    ("peer_cert", "expected"),
    [
        pytest.param(_mock_peer_cert("client-01"), "client-01", id="valid_cn"),
        pytest.param(None, None, id="none_input"),
        pytest.param({}, None, id="empty_dict"),
        pytest.param(
            {"subject": ((("organizationName", "Lab"),),)},
            None,
            id="missing_cn",
        ),
        pytest.param(
            {
                "subject": (
                    (("commonName", "first"),),
                    (("commonName", "second"),),
                )
            },
            "first",
            id="duplicate_cn_first_wins",
        ),
    ],
)
def test_extract_cn_table(peer_cert: dict | None, expected: str | None) -> None:
    """Table-driven coverage of the five canonical input shapes."""
    assert extract_cn_from_cert(peer_cert) == expected


@pytest.mark.unit
def test_extract_cn_unicode_cn_preserved() -> None:
    """Non-ASCII CNs must be returned verbatim — no encoding coercion.

    The stdlib hands us the already-decoded Python str, so the helper
    should be transparent about encoding. We still exercise this to
    lock in the invariant: an attacker cannot smuggle a "valid" CN
    through a unicode-normalisation gap.
    """
    cn = "клиент-01"
    assert extract_cn_from_cert(_mock_peer_cert(cn)) == cn


@pytest.mark.unit
def test_extract_cn_malformed_subject_is_rejected() -> None:
    """A Subject tuple with the wrong nesting depth must yield None.

    Real getpeercert() produces a tuple-of-(tuple-of-(key,value))-tuples.
    If something one level flatter shows up (a hand-rolled mock, a
    future stdlib change, or a corrupted input), the helper must
    NOT raise — it must simply report "no CN found" so the caller
    fails closed at the allowlist check above.
    """
    cert_wrong_depth: dict = {
        "subject": (("commonName", "client-01"),),  # missing the outer tuple
    }
    # The helper tolerates unexpected shapes by iterating what it has;
    # a shape that doesn't yield a ("commonName", value) pair simply
    # results in None, never an exception.
    assert extract_cn_from_cert(cert_wrong_depth) is None


@pytest.mark.unit
def test_extract_cn_empty_string_value() -> None:
    """An explicit empty-string CN is returned as-is, NOT coerced to None.

    The middleware uses ``client_cn is None`` to distinguish "no cert
    context" from "cert present, CN is empty". Both still fail the
    allowlist check with reason=cn_not_allowlisted, but the distinction
    matters for log correlation. This test locks the invariant in.
    """
    assert extract_cn_from_cert(_mock_peer_cert("")) == ""


# --- subject_fingerprint ----------------------------------------------------


@pytest.mark.unit
def test_subject_fingerprint_deterministic_for_same_subject() -> None:
    fp_a = subject_fingerprint(_mock_peer_cert("client-01"))
    fp_b = subject_fingerprint(_mock_peer_cert("client-01"))
    assert fp_a == fp_b
    assert len(fp_a) == 16


@pytest.mark.unit
def test_subject_fingerprint_differs_for_different_cn() -> None:
    fp_a = subject_fingerprint(_mock_peer_cert("client-01"))
    fp_b = subject_fingerprint(_mock_peer_cert("rogue-99"))
    assert fp_a != fp_b


@pytest.mark.unit
@pytest.mark.parametrize("peer_cert", [None, {}], ids=["none", "empty"])
def test_subject_fingerprint_placeholder_for_missing_cert(
    peer_cert: dict | None,
) -> None:
    assert subject_fingerprint(peer_cert) == "-"


@pytest.mark.unit
def test_subject_fingerprint_ou_only_no_cn() -> None:
    """A cert with OU but no CN still produces a stable fingerprint.

    subject_fingerprint doesn't depend on commonName presence — it
    hashes the flattened RDN string. This guards against an accidental
    regression where the helper starts to require CN.
    """
    ou_only_cert = {
        "subject": (
            (("organizationalUnitName", "TestLab"),),
            (("organizationName", "Lab"),),
        )
    }
    fp_a = subject_fingerprint(ou_only_cert)
    fp_b = subject_fingerprint(ou_only_cert)
    assert fp_a == fp_b
    assert len(fp_a) == 16
    # And it must NOT collide with the fingerprint of a CN-bearing cert
    # that happens to contain the same organization.
    assert fp_a != subject_fingerprint(_mock_peer_cert("client-01"))


@pytest.mark.unit
def test_subject_fingerprint_1000_iterations_are_invariant() -> None:
    """1000 repeated calls on the same input must all return identical output.

    Pure hashing of a deterministic string should never introduce
    variance. This test is cheap insurance against anyone sneaking
    a uuid4 or time.time() into the helper under the guise of
    "salting" the fingerprint, which would break log correlation.
    """
    cert = _mock_peer_cert("client-01")
    first = subject_fingerprint(cert)
    # Use a set: if every call is identical, the set has exactly one element.
    seen = {subject_fingerprint(cert) for _ in range(1000)}
    assert seen == {first}


# --- N2: extract_cn_from_headers (NH1–NH6) ---------------------------------
#
# The extract_cn_from_headers function is the NGINX_MODE=true path — it
# trusts the X-Client-CN HTTP header only when the request source IP is
# in TRUSTED_PROXY_IPS AND nginx stamped X-Client-Verify=SUCCESS AND the
# CN passes sanitisation. These tests stub the request object with a
# minimal duck-typed placeholder to exercise each branch without pulling
# in a whole FastAPI app.


class _FakeClient:
    """Stand-in for ``request.client`` — only needs a ``.host`` attribute."""

    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    """Minimal stub that exposes .client and .headers dict-like access."""

    def __init__(self, host: str, headers: dict[str, str]) -> None:
        self.client = _FakeClient(host)
        # Starlette's request.headers is case-insensitive; a plain dict
        # passes for our tests because we match on the exact case
        # nginx forwards.
        self.headers = headers


@pytest.mark.unit
def test_NH1_trusted_ip_success_verify_returns_cn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NH1. Trusted source IP + X-Client-Verify=SUCCESS + valid CN → CN."""
    import middleware

    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="127.0.0.1",
        headers={"X-Client-Verify": "SUCCESS", "X-Client-CN": "client-01"},
    )
    assert middleware.extract_cn_from_headers(req) == "client-01"


@pytest.mark.unit
def test_NH2_untrusted_ip_returns_none_and_logs_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """NH2. Source IP not in TRUSTED_PROXY_IPS → None, WARNING logged."""
    import logging as _logging

    import middleware

    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="203.0.113.1",
        headers={"X-Client-Verify": "SUCCESS", "X-Client-CN": "client-01"},
    )
    with caplog.at_level(_logging.WARNING, logger="middleware"):
        assert middleware.extract_cn_from_headers(req) is None
    assert any(
        "untrusted_proxy_cn_header_blocked" in r.getMessage() for r in caplog.records
    )


@pytest.mark.unit
def test_NH3_verify_not_success_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """NH3. X-Client-Verify != SUCCESS → None."""
    import middleware

    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="127.0.0.1",
        headers={
            "X-Client-Verify": "FAILED:self signed certificate",
            "X-Client-CN": "client-01",
        },
    )
    assert middleware.extract_cn_from_headers(req) is None


@pytest.mark.unit
def test_NH4_cn_with_embedded_newline_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NH4. CN containing \\n is rejected by sanitisation."""
    import middleware

    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="127.0.0.1",
        headers={
            "X-Client-Verify": "SUCCESS",
            "X-Client-CN": "client-01\n[CRITICAL] forged",
        },
    )
    assert middleware.extract_cn_from_headers(req) is None


@pytest.mark.unit
def test_NH5_cn_with_null_byte_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """NH5. CN containing \\x00 is rejected by sanitisation."""
    import middleware

    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="127.0.0.1",
        headers={
            "X-Client-Verify": "SUCCESS",
            "X-Client-CN": "client-01" + chr(0) + "admin",
        },
    )
    assert middleware.extract_cn_from_headers(req) is None


@pytest.mark.unit
def test_NH6_missing_cn_header_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """NH6. X-Client-CN header absent → None (empty string would also be
    rejected by the sanitisation branch, but we exercise the absence
    path explicitly here)."""
    import middleware

    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="127.0.0.1",
        headers={"X-Client-Verify": "SUCCESS"},  # no X-Client-CN
    )
    assert middleware.extract_cn_from_headers(req) is None


# --- N2: resolve_client_cn dispatcher (NH7–NH8) ----------------------------


@pytest.mark.unit
def test_NH7_resolve_uses_cert_path_when_nginx_mode_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NH7. NGINX_MODE=False → resolve_client_cn goes via extract_cn_from_cert."""
    import middleware

    monkeypatch.setattr(middleware, "NGINX_MODE", False)
    req = _FakeRequest(host="127.0.0.1", headers={})
    cert = {"subject": ((("commonName", "client-01"),),)}
    assert middleware.resolve_client_cn(req, cert) == "client-01"


@pytest.mark.unit
def test_NH8_resolve_uses_header_path_when_nginx_mode_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NH8. NGINX_MODE=True → resolve_client_cn goes via extract_cn_from_headers.

    Proves the dispatcher ignores the peer_cert dict entirely when
    running behind nginx — the CN comes from the proxy-forwarded
    header, not the (non-existent) TLS peer cert.
    """
    import middleware

    monkeypatch.setattr(middleware, "NGINX_MODE", True)
    monkeypatch.setattr(middleware, "TRUSTED_PROXY_IPS", frozenset({"127.0.0.1"}))
    req = _FakeRequest(
        host="127.0.0.1",
        headers={"X-Client-Verify": "SUCCESS", "X-Client-CN": "client-01"},
    )
    # Pass a "wrong" peer_cert — the dispatcher must NOT read it in
    # NGINX_MODE. If it did, we'd see "should-not-be-read" in the output.
    cert = {"subject": ((("commonName", "should-not-be-read"),),)}
    assert middleware.resolve_client_cn(req, cert) == "client-01"
