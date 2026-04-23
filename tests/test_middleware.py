"""Unit-test stubs for the identity middleware.

Run:
    python -m unittest tests.test_middleware

These tests never touch a real TLS socket. They exercise the pure helpers
(``extract_cn`` and ``subject_fingerprint``) by feeding in dicts shaped
exactly like the output of ``ssl.SSLSocket.getpeercert()`` — a nested
tuple of RDNs. That mock shape is the only thing the middleware cares
about, so reproducing it in a dict is sufficient isolation.

The dispatch() coroutine itself is not unit-tested here — it's exercised
end-to-end against a live server in the Phase-3 test matrix (see handoff
notes). Splitting the pure helpers out makes this test tight and fast.
"""

from __future__ import annotations

import unittest

from middleware import extract_cn, subject_fingerprint


def _mock_peer_cert(cn: str, *, extra_rdns: tuple = ()) -> dict:
    """Build a peer-cert dict shaped the way stdlib ssl returns one.

    This is the sole "mock SSL socket" surface — the real getpeercert()
    returns exactly this shape. Anything shaped like this is a valid
    drop-in for tests.
    """
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


class ExtractCNTests(unittest.TestCase):
    def test_valid_cert_yields_cn(self) -> None:
        self.assertEqual(extract_cn(_mock_peer_cert("client-01")), "client-01")

    def test_none_input_returns_none(self) -> None:
        self.assertIsNone(extract_cn(None))

    def test_empty_dict_returns_none(self) -> None:
        self.assertIsNone(extract_cn({}))

    def test_missing_cn_returns_none(self) -> None:
        cert = {"subject": ((("organizationName", "Lab"),),)}
        self.assertIsNone(extract_cn(cert))

    def test_first_cn_wins_if_multiple(self) -> None:
        # The stdlib structure does not forbid duplicate CNs. We expect the
        # first one to be returned — documenting the invariant via a test.
        cert = {
            "subject": (
                (("commonName", "first"),),
                (("commonName", "second"),),
            )
        }
        self.assertEqual(extract_cn(cert), "first")


class SubjectFingerprintTests(unittest.TestCase):
    def test_deterministic_for_same_subject(self) -> None:
        fp_a = subject_fingerprint(_mock_peer_cert("client-01"))
        fp_b = subject_fingerprint(_mock_peer_cert("client-01"))
        self.assertEqual(fp_a, fp_b)
        self.assertEqual(len(fp_a), 16)

    def test_differs_for_different_cn(self) -> None:
        fp_a = subject_fingerprint(_mock_peer_cert("client-01"))
        fp_b = subject_fingerprint(_mock_peer_cert("rogue-99"))
        self.assertNotEqual(fp_a, fp_b)

    def test_placeholder_for_missing_cert(self) -> None:
        self.assertEqual(subject_fingerprint(None), "-")
        self.assertEqual(subject_fingerprint({}), "-")


if __name__ == "__main__":
    unittest.main()
