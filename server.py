"""mTLS REST API server — Phase 3 entrypoint.

Binds to 127.0.0.1:8443 behind strict mutual-TLS. Security is enforced at
two distinct layers, intentionally:

* **TLS layer** (``tls.build_server_context``): the ssl module rejects any
  peer that does not present a cert chaining to ``pki/ca/ca.crt``.
  "No cert" and "cert signed by unknown CA" die here, before any HTTP
  bytes are exchanged. Failures are surfaced via an asyncio exception
  handler installed in :func:`main`.
* **Application layer** (:class:`middleware.ClientIdentityMiddleware`):
  a second check enforces an allowlist of Subject CommonNames from
  ``config.ALLOWED_CLIENT_CNS``. "Valid cert, wrong CN" returns a 403.

Endpoints:
    GET  /health   liveness probe, reports TLS status
    GET  /data     mock sensor-data response
    POST /data     echoes the JSON body back with a server timestamp

Run:
    ./pki_setup.sh           # once — generate certs
    python server.py         # bind 127.0.0.1:8443, wait for mTLS clients
"""

from __future__ import annotations

import asyncio
import asyncio.sslproto as _sslproto
import datetime as dt
import logging
import ssl
import sys
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, FastAPI
from pydantic import BaseModel

from middleware import ClientIdentityMiddleware
from tls import CertAwareH11Protocol, build_server_context


# --- Paths & binding ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
PKI_DIR = PROJECT_ROOT / "pki"

SERVER_CERT = PKI_DIR / "server" / "server.crt"
SERVER_KEY = PKI_DIR / "server" / "server.key"
CA_CERT = PKI_DIR / "ca" / "ca.crt"
CA_CRL = PKI_DIR / "ca" / "ca.crl"

BIND_HOST = "127.0.0.1"
BIND_PORT = 8443


# --- Logging ----------------------------------------------------------------


def _configure_logging() -> logging.Logger:
    """Install the project's single stdout-only log config."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stdout,
        force=True,
    )
    # The middleware emits richer lines (CN, request-id), so uvicorn's
    # per-request access log is redundant noise.
    logging.getLogger("uvicorn.access").disabled = True
    return logging.getLogger("mtls_api")


logger = _configure_logging()


# --- Pydantic models --------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    tls: bool


class SensorReading(BaseModel):
    sensor_id: str
    temperature_c: float
    humidity_pct: float
    recorded_at: str


class DataResponse(BaseModel):
    readings: list[SensorReading]
    generated_at: str


class EchoResponse(BaseModel):
    received: dict[str, Any]
    echoed_at: str


# --- Helpers ----------------------------------------------------------------


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


# --- TLS-layer failure logging ----------------------------------------------
#
# stdlib's ``asyncio.sslproto.SSLProtocol._fatal_error`` silently swallows
# SSL handshake failures because ``ssl.SSLError`` inherits from ``OSError``
# and the stdlib only forwards OSErrors to the loop's exception handler
# when debug mode is on. See cpython ``Lib/asyncio/sslproto.py`` — the
# ``if isinstance(exc, OSError):`` branch writes at DEBUG (if debug) and
# otherwise drops the event on the floor.
#
# For an mTLS service that is unacceptable: "peer didn't present a cert"
# and "cert signed by unknown CA" MUST be visible in ops logs. We wrap
# the stdlib method with a tiny shim that emits a WARNING before
# delegating to the original for the normal close sequence. This is a
# deliberate, documented hook — not a silent override.


_orig_sslproto_fatal_error = _sslproto.SSLProtocol._fatal_error


def _logging_fatal_error(
    self: _sslproto.SSLProtocol,
    exc: BaseException,
    message: str = "Fatal error on transport",
) -> None:
    # SECURITY: log a coarse reason code only. Never include exc.strerror,
    # exc.args, or cert-chain detail — a misbehaving peer must not be
    # able to probe our trust store through verbose error messages.
    if isinstance(exc, ssl.SSLError):
        logger.warning(
            "tls_handshake_failed reason=%s library=%s",
            getattr(exc, "reason", "unknown"),
            getattr(exc, "library", "unknown"),
        )
    return _orig_sslproto_fatal_error(self, exc, message)


_sslproto.SSLProtocol._fatal_error = _logging_fatal_error


# --- FastAPI app ------------------------------------------------------------

app = FastAPI(title="mTLS ED25519 REST API", version="0.3.0")
app.add_middleware(ClientIdentityMiddleware)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", tls=True)


@app.get("/data", response_model=DataResponse)
async def get_data() -> DataResponse:
    now = _utcnow_iso()
    readings = [
        SensorReading(
            sensor_id="temp-01",
            temperature_c=22.5,
            humidity_pct=41.0,
            recorded_at=now,
        ),
        SensorReading(
            sensor_id="temp-02",
            temperature_c=19.8,
            humidity_pct=47.3,
            recorded_at=now,
        ),
    ]
    return DataResponse(readings=readings, generated_at=now)


@app.post("/data", response_model=EchoResponse)
async def post_data(payload: dict[str, Any] = Body(...)) -> EchoResponse:
    return EchoResponse(received=payload, echoed_at=_utcnow_iso())


# --- Entrypoint -------------------------------------------------------------


def main() -> None:
    # SECURITY: build the SSLContext up front. A bad path/permission problem
    # must crash the process before we bind the port, not mid-handshake.
    tls_ctx = build_server_context(
        server_cert=SERVER_CERT,
        server_key=SERVER_KEY,
        ca_cert=CA_CERT,
        crl=CA_CRL,
    )
    logger.info(
        "tls_context mode=CERT_REQUIRED min_version=%s ciphers=%d",
        tls_ctx.minimum_version.name,
        len(tls_ctx.get_ciphers()),
    )
    logger.info("binding https://%s:%d (mTLS: required)", BIND_HOST, BIND_PORT)

    config = uvicorn.Config(
        app=app,
        host=BIND_HOST,
        port=BIND_PORT,
        # Force h11 and our cert-aware subclass so scope gets the peer cert.
        http=CertAwareH11Protocol,
        # SECURITY: force stdlib asyncio. uvloop (shipped by uvicorn[standard])
        # has its own C-level SSL implementation and bypasses
        # asyncio.sslproto, so our ``_logging_fatal_error`` hook — the
        # thing that surfaces TLS handshake failures to ops — is inert
        # under uvloop. Perf is not a concern at this scale; visibility is.
        loop="asyncio",
        # The ssl_* params just flip uvicorn into TLS mode; we override the
        # context below with our audited one.
        ssl_keyfile=str(SERVER_KEY),
        ssl_certfile=str(SERVER_CERT),
        log_config=None,
        access_log=False,
        lifespan="off",
    )
    config.load()
    # SECURITY: replace uvicorn's implicitly-built SSLContext with the one
    # from build_server_context() — the single auditable source of truth.
    config.ssl = tls_ctx

    server = uvicorn.Server(config)

    # TLS handshake failures are surfaced via the
    # ``_logging_fatal_error`` hook installed at module import — no
    # loop-level exception handler is needed. See the SECURITY note
    # near ``_sslproto.SSLProtocol._fatal_error`` above.

    # asyncio.Runner + uvicorn's loop_factory preserves uvloop selection
    # when available; falls back to stdlib asyncio otherwise.
    with asyncio.Runner(loop_factory=config.get_loop_factory()) as runner:
        runner.run(server.serve())


if __name__ == "__main__":
    main()
