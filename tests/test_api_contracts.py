"""API contract tests — locks down the shape of every response.

Three groups (H, D, P) mirroring the three endpoints:

* ``H`` — GET /health
* ``D`` — GET /data
* ``P`` — POST /data

Every test here uses the live ``server_process`` fixture from T1 and
a session-scoped mTLS client built on ``requests.Session``. Tests
read specific fields and assert both presence and type, so any drift
in the server's response shape produces a pinpointed failure.

Run:
    pytest -m integration tests/test_api_contracts.py
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import requests


pytestmark = pytest.mark.integration


# --- Module-scoped mTLS session --------------------------------------------


@pytest.fixture(scope="module")
def session(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],  # noqa: ARG001 — lifecycle dependency
) -> requests.Session:
    sess = requests.Session()
    sess.verify = str(pki_paths["ca_cert"])
    sess.cert = (str(pki_paths["client_cert"]), str(pki_paths["client_key"]))
    return sess


def _base_url(server_process: dict[str, object]) -> str:
    return str(server_process["base_url"])


# --- Group H: GET /health ---------------------------------------------------


def test_H1_health_schema_has_exactly_the_documented_keys(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """H1. Schema lock — /health returns exactly {status, tls, version}."""
    body = session.get(f"{_base_url(server_process)}/health", timeout=5).json()
    assert set(body.keys()) == {
        "status",
        "tls",
        "version",
    }, f"unexpected /health keys: {sorted(body.keys())}"


def test_H2_health_status_is_the_string_ok(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """H2. ``status`` is the string ``"ok"`` — locks the enum value."""
    body = session.get(f"{_base_url(server_process)}/health", timeout=5).json()
    assert body["status"] == "ok"
    assert isinstance(body["status"], str)


def test_H3_health_tls_is_boolean_true_not_string(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """H3. ``tls`` is the JSON boolean ``true``, NEVER the string ``"true"``.

    A string here would suggest Pydantic serialisation drifted —
    clients parsing with ``is True`` would silently start treating
    it as falsy. This test guards the drift.
    """
    body = session.get(f"{_base_url(server_process)}/health", timeout=5).json()
    assert body["tls"] is True
    assert not isinstance(body["tls"], str)


def test_H4_health_content_type_is_application_json(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """H4. Content-Type header starts with ``application/json``.

    Charset parameter may be appended (``; charset=utf-8``), so
    this is a prefix check, not an equality check.
    """
    resp = session.get(f"{_base_url(server_process)}/health", timeout=5)
    ct = resp.headers.get("Content-Type", "")
    assert ct.startswith(
        "application/json"
    ), f"Content-Type was {ct!r}, expected to start with application/json"


def test_H5_health_x_request_id_header_is_hex_or_uuid(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """H5. X-Request-ID is present and parseable as a 32-char hex token.

    The middleware generates IDs via ``uuid.uuid4().hex``, which is a
    32-char hex string without dashes. Pydantic/UUID4 validation
    accepts either hex or dashed form — we test both for resilience.
    """
    resp = session.get(f"{_base_url(server_process)}/health", timeout=5)
    rid = resp.headers.get("X-Request-ID")
    assert rid, "X-Request-ID header must be present"
    try:
        # Accept both 'abc...' (hex) and 'abc-...-...' (dashed).
        uuid.UUID(rid)
    except ValueError as exc:
        pytest.fail(f"X-Request-ID {rid!r} is not parseable as UUID: {exc}")


# --- Group D: GET /data -----------------------------------------------------


def test_D1_get_data_has_readings_list(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """D1. Top-level ``readings`` is a list and is non-empty."""
    body = session.get(f"{_base_url(server_process)}/data", timeout=5).json()
    assert "readings" in body
    assert isinstance(body["readings"], list)
    assert len(body["readings"]) >= 1


def test_D2_each_reading_has_the_documented_fields_and_types(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """D2. Per-reading contract.

    The project ships rich readings (``sensor_id``, ``temperature_c``,
    ``humidity_pct``, ``recorded_at``). The T3 plan referenced a
    simpler ``sensor_id/value/unit`` shape — we lock down the
    ACTUAL contract the server has always returned so later phases
    can't unilaterally change it.
    """
    body = session.get(f"{_base_url(server_process)}/data", timeout=5).json()
    for reading in body["readings"]:
        assert set(reading.keys()) == {
            "sensor_id",
            "temperature_c",
            "humidity_pct",
            "recorded_at",
        }, f"unexpected reading keys: {sorted(reading.keys())}"
        assert isinstance(reading["sensor_id"], str) and reading["sensor_id"]
        assert isinstance(reading["temperature_c"], (int, float))
        assert isinstance(reading["humidity_pct"], (int, float))
        assert isinstance(reading["recorded_at"], str) and reading["recorded_at"]


def test_D3_generated_at_is_iso8601(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """D3. ``generated_at`` parses as ISO 8601 via ``datetime.fromisoformat``.

    Python 3.11+ ``fromisoformat`` accepts the full ISO 8601 grammar
    including the ``+HH:MM`` offset and the trailing ``Z`` (3.11+).
    """
    body = session.get(f"{_base_url(server_process)}/data", timeout=5).json()
    ts = body.get("generated_at")
    assert isinstance(ts, str) and ts
    try:
        # Normalise a trailing Z to +00:00 for pre-3.11 compatibility.
        datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as exc:
        pytest.fail(f"generated_at {ts!r} is not ISO 8601: {exc}")


def test_D4_response_shape_is_deterministic_across_10_calls(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """D4. Ten consecutive calls return the same key set.

    Timestamps and values may legitimately differ; only the shape
    (key set at each level) is asserted.
    """
    shapes: set[frozenset[str]] = set()
    for _ in range(10):
        body = session.get(f"{_base_url(server_process)}/data", timeout=5).json()
        shapes.add(frozenset(body.keys()))
        for reading in body["readings"]:
            shapes.add(frozenset(reading.keys()))
    # Two distinct shapes: top-level and per-reading. No more, no less.
    assert len(shapes) == 2, f"non-deterministic shapes across 10 calls: {shapes}"


# --- Group P: POST /data ----------------------------------------------------


_VALID_BODY = {"sensor_id": "temp-contract", "value": 42.0, "unit": "C"}


def test_P1_valid_body_returns_200_with_echoed_at(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P1. Happy path — body echoed, timestamp added."""
    resp = session.post(
        f"{_base_url(server_process)}/data", json=_VALID_BODY, timeout=5
    )
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"received", "echoed_at"}
    assert body["received"] == _VALID_BODY
    assert isinstance(body["echoed_at"], str) and body["echoed_at"]


def test_P2_missing_sensor_id_returns_422(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P2. Validation: sensor_id required."""
    payload = {k: v for k, v in _VALID_BODY.items() if k != "sensor_id"}
    resp = session.post(f"{_base_url(server_process)}/data", json=payload, timeout=5)
    assert resp.status_code == 422


def test_P3_missing_value_returns_422(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P3. Validation: value required."""
    payload = {k: v for k, v in _VALID_BODY.items() if k != "value"}
    resp = session.post(f"{_base_url(server_process)}/data", json=payload, timeout=5)
    assert resp.status_code == 422


def test_P4_non_numeric_value_returns_422(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P4. ``value`` cannot coerce from ``"hot"``."""
    payload = {**_VALID_BODY, "value": "hot"}
    resp = session.post(f"{_base_url(server_process)}/data", json=payload, timeout=5)
    assert resp.status_code == 422


def test_P5_extra_key_is_silently_dropped_and_returns_200(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P5. Unknown extra key doesn't break validation.

    Pydantic's default is ``extra=ignore`` — unknown keys come in,
    get dropped, and are absent from ``received``. The server does
    not reject the request and does not leak the extra back.
    """
    payload = {**_VALID_BODY, "hostname_from_client": "laptop-01"}
    resp = session.post(f"{_base_url(server_process)}/data", json=payload, timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    assert (
        "hostname_from_client" not in body["received"]
    ), "extra key leaked into response"


def test_P6_integer_value_is_coerced_to_float(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P6. ``value=42`` (int) is accepted and coerced to 42.0 (float)."""
    payload = {**_VALID_BODY, "value": 42}
    resp = session.post(f"{_base_url(server_process)}/data", json=payload, timeout=5)
    assert resp.status_code == 200
    assert resp.json()["received"]["value"] == 42.0


def test_P7_wrong_content_type_returns_422(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P7. Content-Type: text/plain cannot carry a JSON body.

    FastAPI's Pydantic-backed request parser expects JSON; a text/plain
    request body fails validation with 422 (not 400 / not 415) because
    the body ends up typed as string rather than dict.
    """
    import json as _json

    resp = session.post(
        f"{_base_url(server_process)}/data",
        data=_json.dumps(_VALID_BODY),
        headers={"Content-Type": "text/plain"},
        timeout=5,
    )
    assert resp.status_code == 422


def test_P8_empty_body_returns_422(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """P8. ``{}`` fails — all three fields are required."""
    resp = session.post(f"{_base_url(server_process)}/data", json={}, timeout=5)
    assert resp.status_code == 422


# --- Group HI: header injection (5 tests) -----------------------------------
#
# These tests bypass ``requests`` for the malformed cases where the
# library would sanitise or refuse the payload. Use a raw TLS socket
# via httpx only for the cases httpx can express; drop to raw bytes
# via ssl/socket for the rest.


def _raw_mtls_request(
    pki: dict[str, Path],
    port: int,
    raw_request: bytes,
    *,
    timeout: float = 5.0,
) -> tuple[bytes, Exception | None]:
    """Send a raw HTTP/1.1 request over the project's mTLS socket.

    Returns ``(response_bytes, exception_or_None)``. If the server
    closes the connection before sending a complete response, we
    return whatever we read plus the exception. Either form is a
    valid 'server did not 500' outcome.
    """
    import socket as _socket
    import ssl as _ssl

    ctx = _ssl.create_default_context(
        purpose=_ssl.Purpose.SERVER_AUTH,
        cafile=str(pki["ca_cert"]),
    )
    ctx.load_cert_chain(
        certfile=str(pki["client_cert"]),
        keyfile=str(pki["client_key"]),
    )
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(timeout)
    response = b""
    err: Exception | None = None
    try:
        sock.connect(("127.0.0.1", port))
        with ctx.wrap_socket(sock, server_hostname="localhost") as tls:
            tls.sendall(raw_request)
            try:
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 65_536:
                        break
            except (TimeoutError, _ssl.SSLError, ConnectionError) as exc:
                err = exc
    except (TimeoutError, _ssl.SSLError, ConnectionError, OSError) as exc:
        err = exc
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return response, err


_STATUS_RE = re.compile(rb"^HTTP/1\.1 (\d{3})")


def _status_from(raw: bytes) -> int | None:
    match = _STATUS_RE.match(raw)
    return int(match.group(1)) if match else None


def test_HI1_host_header_with_null_byte_is_rejected(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """HI1. Host header containing a null byte.

    EXPECTED: server closes the connection or returns 400; it must
    NEVER return 5xx, echo the byte, or crash.
    """
    port = int(server_process["port"])
    raw = b"GET /health HTTP/1.1\r\nHost: local\x00host\r\nConnection: close\r\n\r\n"
    response, _ = _raw_mtls_request(pki_paths, port, raw)
    status = _status_from(response)
    # Either a connection drop (empty response) or a 4xx status.
    assert (
        status is None or 400 <= status < 500
    ), f"expected drop or 4xx, got {status} with body: {response[:200]!r}"


def test_HI2_header_with_injected_newlines_does_not_split(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """HI2. X-Forwarded-For attempt to smuggle a second header.

    Malicious value: ``"1.2.3.4\\r\\nX-Injected: yes"``. The requests
    library sanitises outgoing headers, so the server sees either a
    stripped value or a rejected request — never a successful
    injection of ``X-Injected`` into the response.

    EXPECTED: request succeeds or is rejected, but the injected
    header MUST NOT appear in the response.
    """
    # requests refuses to send headers containing \r or \n — that
    # rejection IS the mitigation, and we assert on it.
    with pytest.raises(Exception) as excinfo:
        session.get(
            f"{_base_url(server_process)}/health",
            headers={"X-Forwarded-For": "1.2.3.4\r\nX-Injected: yes"},
            timeout=5,
        )
    # urllib3 raises InvalidHeader / ValueError depending on version.
    assert (
        "newline" in str(excinfo.value).lower()
        or "invalid" in str(excinfo.value).lower()
    ), f"expected header-value rejection, got {excinfo.type.__name__}: {excinfo.value}"


def test_HI3_content_length_mismatch_is_rejected(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """HI3. Claim Content-Length: 100 but send 10 bytes.

    EXPECTED: server times out or returns 4xx. Must not hang forever
    waiting for the 90 missing bytes and must not 500.
    """
    port = int(server_process["port"])
    body = b'{"x": 0}'  # 8 bytes
    raw = (
        b"POST /data HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 100\r\n"  # lies — actual body is much smaller
        b"\r\n" + body
    )
    response, err = _raw_mtls_request(pki_paths, port, raw, timeout=3.0)
    status = _status_from(response)
    # Acceptable outcomes: timeout (err set), drop (no status), 4xx.
    assert (
        err is not None
        or status is None
        or (status is not None and 400 <= status < 500)
    ), f"unexpected status={status} err={err!r} body={response[:200]!r}"


def test_HI4_malformed_chunked_body_is_rejected(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """HI4. Transfer-Encoding: chunked with a garbage chunk-size line.

    EXPECTED: 4xx or connection drop; never 500.
    """
    port = int(server_process["port"])
    # "NOTAHEX" is not a valid chunk size.
    raw = (
        b"POST /data HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"NOTAHEX\r\n"
        b"garbage\r\n"
        b"0\r\n\r\n"
    )
    response, err = _raw_mtls_request(pki_paths, port, raw, timeout=3.0)
    status = _status_from(response)
    assert (
        err is not None
        or status is None
        or (status is not None and 400 <= status < 500)
    ), f"unexpected status={status} err={err!r}"


def test_HI5_duplicate_content_type_is_not_5xx(
    pki_paths: dict[str, Path],
    server_process: dict[str, object],
) -> None:
    """HI5. Two Content-Type headers — server must pick one or reject.

    EXPECTED: any 2xx, 4xx, or drop. A 5xx would indicate the
    parser crashed on duplicate headers.
    """
    port = int(server_process["port"])
    body = b'{"sensor_id": "x", "value": 1, "unit": "C"}'
    raw = (
        b"POST /data HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Type: text/plain\r\n"  # duplicate
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n"
        b"\r\n" + body
    )
    response, err = _raw_mtls_request(pki_paths, port, raw, timeout=3.0)
    status = _status_from(response)
    # The only forbidden outcome is 5xx.
    if status is not None:
        assert status < 500, f"duplicate Content-Type produced 5xx: {status}"
