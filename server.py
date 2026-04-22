"""mTLS REST API server — Phase 2 entrypoint.

Binds to 127.0.0.1:8443 behind strict mutual-TLS (client cert required,
ED25519-only chain back to pki/ca/ca.crt). The authenticated client identity
is extracted from the peer cert's Subject CN in middleware and attached to
``request.state.client_cn``; Phase 3 will plug an allowlist check into the
same middleware.

Endpoints:
    GET  /health   liveness probe, reports TLS status
    GET  /data     mock sensor-data response
    POST /data     echoes the JSON body back with a server timestamp

Run:
    ./pki_setup.sh           # once — generate certs
    python server.py         # bind 127.0.0.1:8443, wait for mTLS clients
"""

from __future__ import annotations

import datetime as dt
import logging
import sys
import uuid
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from tls import CertAwareH11Protocol, build_server_context


# --- Paths & binding ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
PKI_DIR = PROJECT_ROOT / "pki"

SERVER_CERT = PKI_DIR / "server" / "server.crt"
SERVER_KEY = PKI_DIR / "server" / "server.key"
CA_CERT = PKI_DIR / "ca" / "ca.crt"

BIND_HOST = "127.0.0.1"
BIND_PORT = 8443


# --- Logging ----------------------------------------------------------------


def _configure_logging() -> logging.Logger:
    """Install the project's single stdout-only log config.

    We set ``force=True`` so this call wins over any handler that uvicorn or
    a transitive import may have attached earlier. ``uvicorn.access`` is
    disabled because the per-request middleware below logs richer lines
    (request-id, CN) that supersede it.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stdout,
        force=True,
    )
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


def _extract_cn(peer_cert: dict[str, Any] | None) -> str | None:
    """Pull the Subject commonName out of a stdlib-format peer cert dict."""
    if not peer_cert:
        return None
    for rdn in peer_cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


# --- Middleware -------------------------------------------------------------


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Tags every request with an id + CN and logs start/end lines.

    Phase 3 will extend this with the client-CN allowlist check. Phase 2
    only observes and annotates — all verified clients are admitted.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        peer_cert = request.scope.get("extensions", {}).get("tls", {}).get("peer_cert")
        client_cn = _extract_cn(peer_cert)
        peer_addr = request.client.host if request.client else "-"

        request.state.request_id = request_id
        request.state.client_cn = client_cn

        logger.info(
            "req_start method=%s path=%s cn=%s reqid=%s peer=%s",
            request.method,
            request.url.path,
            client_cn or "-",
            request_id,
            peer_addr,
        )

        try:
            response = await call_next(request)
        except Exception as exc:
            # SECURITY: log internally, respond generically — never leak
            # stack traces or internal detail across the TLS boundary.
            logger.exception("req_error reqid=%s :: %s", request_id, exc)
            response = JSONResponse(
                status_code=500,
                content={"error": "internal_error", "request_id": request_id},
            )

        response.headers["X-Request-ID"] = request_id
        logger.info(
            "req_end   method=%s path=%s cn=%s reqid=%s status=%d",
            request.method,
            request.url.path,
            client_cn or "-",
            request_id,
            response.status_code,
        )
        return response


# --- FastAPI app ------------------------------------------------------------

app = FastAPI(title="mTLS ED25519 REST API", version="0.2.0")
app.add_middleware(RequestContextMiddleware)


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
        # The ssl_* params just make uvicorn flip to TLS mode; we override
        # the context below with our audited one.
        ssl_keyfile=str(SERVER_KEY),
        ssl_certfile=str(SERVER_CERT),
        log_config=None,
        access_log=False,
        lifespan="off",
    )
    config.load()
    # SECURITY: replace uvicorn's implicitly-built SSLContext with the one
    # from build_server_context() — that is the single auditable source of
    # truth for our TLS settings, and it guarantees CERT_REQUIRED.
    config.ssl = tls_ctx

    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
