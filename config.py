"""Runtime configuration for the mTLS REST API.

Values here drive security decisions. Keep this file deliberately small,
readable, and reviewable in a single glance — every entry is a promise
that a specific identity is trusted.
"""

from __future__ import annotations

# Subject CommonNames that are admitted to the API once their certificate
# chain has already been validated by the TLS layer.
#
# A client that passes the TLS handshake (i.e. holds a key whose cert
# chains to pki/ca/ca.crt) but whose CN does NOT appear here is rejected
# with HTTP 403. This is an application-layer authorization check *on top
# of* TLS verification — "the CA says you are X, and we only talk to
# specific Xs".
#
# frozenset chosen for O(1) membership checks and immutability at import
# time, so a runtime bug cannot silently widen the allowlist.
ALLOWED_CLIENT_CNS: frozenset[str] = frozenset({"client-01", "client-02"})
