"""mTLS REST API — v1.2 plain-FastAPI entrypoint.

Binds ``127.0.0.1:8443`` as **plain HTTP**. All authentication and
authorization happens upstream at nginx (see ``nginx/nginx.conf`` —
mTLS handshake, CRL check, and CN allowlist all live there). By the
time a request reaches this process, nginx has already decided the
caller is allowed to talk to us.

Architectural invariant (v1.2): FastAPI is auth-blind. Do NOT
reintroduce ``ssl.SSLContext``, ``CERT_REQUIRED``, cert parsing, or an
application-layer CN check here — those belonged to the v1.0/v1.1
architectures and have been deliberately ripped out. The structural
test suite (``tests/test_v12_structural.py``) enforces this at CI time.

Endpoints (no auth logic — nginx already decided):
    GET  /health   liveness probe
    GET  /data     mock sensor-data response
    POST /data     echoes the JSON body back with a server timestamp

Run:
    python server.py         # bind 127.0.0.1:8443 plain HTTP
"""

from __future__ import annotations

import datetime as dt
import logging
import os
import sys
import uuid
from typing import Any

import uvicorn
from fastapi import Body, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


# --- Binding ---------------------------------------------------------------

BIND_HOST = "127.0.0.1"
# MTLS_API_PORT lets the pytest fixture pick a free port when 8443
# is already bound; operational default stays 8443.
BIND_PORT = int(os.environ.get("MTLS_API_PORT", "8443"))


# --- Logging ---------------------------------------------------------------


def _configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s :: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        stream=sys.stdout,
        force=True,
    )
    # The request-id middleware emits richer lines (method/path/reqid),
    # so uvicorn's default per-request access log is redundant noise.
    logging.getLogger("uvicorn.access").disabled = True
    return logging.getLogger("mtls_api")


logger = _configure_logging()


# --- Pydantic models -------------------------------------------------------


class HealthResponse(BaseModel):
    status: str


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


def _utcnow_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


# --- FastAPI app -----------------------------------------------------------

app = FastAPI(title="mTLS ED25519 REST API", version="1.2.0")


@app.middleware("http")
async def request_id_logger(request: Request, call_next: Any) -> Any:
    # v1.2: context propagation only. NO auth, NO cert parsing, NO
    # allowlist check — that work is done by nginx before the request
    # ever reaches us. Honour the caller's X-Request-ID (nginx can set
    # it) or mint a fresh one.
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    logger.info(
        "req_start method=%s path=%s reqid=%s",
        request.method,
        request.url.path,
        request_id,
    )
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception("req_error reqid=%s :: %s", request_id, exc)
        response = JSONResponse(
            status_code=500,
            content={"error": "internal_error", "request_id": request_id},
        )
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "req_end method=%s path=%s reqid=%s status=%d",
        request.method,
        request.url.path,
        request_id,
        response.status_code,
    )
    return response


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


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


# --- Entrypoint ------------------------------------------------------------


def main() -> None:
    logger.info(
        'event="server_started" mode="plain_http" host=%s port=%d',
        BIND_HOST,
        BIND_PORT,
    )
    config = uvicorn.Config(
        app=app,
        host=BIND_HOST,
        port=BIND_PORT,
        log_config=None,
        access_log=False,
        lifespan="off",
        # Don't leak uvicorn/Python version in the Server header —
        # nginx has server_tokens off on the edge; parity here.
        server_header=False,
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()
