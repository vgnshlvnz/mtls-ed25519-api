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
