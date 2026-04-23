"""TLS context and cert-aware uvicorn protocol for the mTLS REST API.

This module owns every line of code that touches the TLS stack. Splitting it
out from ``server.py`` keeps the security-sensitive surface small and
auditable. It contributes two things:

* :func:`build_server_context` constructs an :class:`ssl.SSLContext` with the
  strict invariants demanded by the project (CERT_REQUIRED, TLSv1.2+,
  explicit CA for client-cert verification).
* :class:`CertAwareH11Protocol` is a thin uvicorn subclass that exposes the
  verified peer certificate on the ASGI scope so downstream middleware can
  read the authenticated client identity without reaching into private
  protocol internals. Uvicorn does not implement the draft ASGI TLS
  extension, so we bridge that gap here.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path
from typing import Any

from uvicorn.protocols.http.h11_impl import H11Protocol

logger = logging.getLogger(__name__)


def build_server_context(
    server_cert: Path,
    server_key: Path,
    ca_cert: Path,
    crl: Path | None = None,
) -> ssl.SSLContext:
    """Build the server-side SSLContext used to terminate mTLS connections.

    Any peer that fails verification against ``ca_cert`` is rejected during
    the TLS handshake, before the HTTP layer ever sees the request.

    If ``crl`` is a real file, the CRL PEM is loaded into the context and
    ``VERIFY_CRL_CHECK_LEAF`` is set. A revoked client cert is then
    rejected at the same handshake stage as an untrusted one.
    """
    # SECURITY: fail fast if any cert/key file is missing — the server must
    # never start with a half-broken TLS stack. A misconfigured path that
    # silently falls back to plaintext would be catastrophic.
    for path in (server_cert, server_key, ca_cert):
        if not path.is_file():
            raise FileNotFoundError(f"TLS material not found: {path}")

    # SECURITY: PROTOCOL_TLS_SERVER advertises server-role only. Never use
    # plain PROTOCOL_TLS (bidirectional) — it loosens role enforcement.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # SECURITY: CERT_REQUIRED — every client MUST present a cert and that
    # cert MUST chain to the loaded CA. CERT_NONE/CERT_OPTIONAL are banned
    # by project rules because they let anonymous peers in.
    ctx.verify_mode = ssl.CERT_REQUIRED

    # SECURITY: raise the protocol floor. OpenSSL negotiates the highest
    # mutually-supported version, so setting the minimum to 1.2 lets TLS 1.3
    # clients still use 1.3 while blocking SSLv3/TLS1.0/TLS1.1.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Load the identity we present during the handshake.
    ctx.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))

    # Trust anchor against which incoming client certs are verified.
    ctx.load_verify_locations(cafile=str(ca_cert))

    # SECURITY: if a CRL is available, load it and enable CRL checking.
    # VERIFY_CRL_CHECK_LEAF is the narrow form — OpenSSL checks the client
    # (leaf) cert against the loaded CRL. Project rules require either
    # CHECK_LEAF or CHECK_CHAIN; we pick LEAF because we only have one
    # issuing CA and no intermediate certs to worry about.
    #
    # NOTE: SSLContext caches the CRL at load time. If you revoke a cert
    # while the server is running you must restart the process (or
    # arrange a reload hook) for the new CRL to take effect.
    if crl is not None and crl.is_file():
        # OpenSSL's X509_STORE_load_locations accepts a PEM file that
        # contains CERTIFICATE or X509 CRL blocks (or both). Loading the
        # CRL via cafile= adds the CRL to the same store the CA cert
        # lives in. cadata= is stricter and rejects CRL-only PEM
        # payloads ("cadata does not contain a certificate"), so we
        # use cafile here.
        ctx.load_verify_locations(cafile=str(crl))
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        logger.info("crl_loaded path=%s mode=VERIFY_CRL_CHECK_LEAF", crl)
    else:
        logger.warning(
            "crl_not_loaded path=%s — revoked certs will NOT be rejected",
            crl if crl else "(disabled)",
        )

    # Server-side SSLContexts don't validate the peer's hostname — clients do
    # that on the other side of the connection. We identify authenticated
    # clients by Subject CN at the app layer (Phase 3), not by DNS.
    ctx.check_hostname = False

    return ctx


class CertAwareH11Protocol(H11Protocol):
    """H11Protocol that surfaces the peer cert on ``scope["extensions"]["tls"]``.

    Uvicorn does not populate the draft ASGI TLS extension. We cache the
    parsed peer cert once at connection time, then re-attach it to each
    request's scope (scope is rebuilt per HTTP request on keep-alive
    connections). Downstream middleware reads it via a plain dict lookup.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # SECURITY: we store only the parsed subject/issuer dict from
        # getpeercert(); we never cache the raw DER bytes or any material
        # derived from the private key.
        self._peer_cert: dict[str, Any] | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        super().connection_made(transport)
        ssl_obj = transport.get_extra_info("ssl_object")
        if ssl_obj is not None:
            self._peer_cert = ssl_obj.getpeercert()

    def handle_events(self) -> None:
        # ``super().handle_events()`` builds ``self.scope`` for the current
        # request and schedules ``cycle.run_asgi`` as an asyncio task. That
        # task cannot run until the current sync callback unwinds, so it is
        # safe to mutate ``self.scope`` here — the middleware will see the
        # injected extension on its first read.
        super().handle_events()

        if self._peer_cert is None or self.scope is None:
            return

        extensions = self.scope.setdefault("extensions", {})
        extensions.setdefault("tls", {})["peer_cert"] = self._peer_cert


__all__ = ["build_server_context", "CertAwareH11Protocol"]
