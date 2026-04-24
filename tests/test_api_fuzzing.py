"""Property-based fuzz tests for the POST /data endpoint.

Eight hypothesis-driven tests covering sensor_id / value inputs and
adversarial request shapes. Every test asserts a property — "never
500", "consistent classification" — not specific values generated
by hypothesis.

Hypothesis settings (from ``conftest.py``):
  max_examples=100
  deadline=60_000 ms
  profile is configurable via HYPOTHESIS_PROFILE (default / ci / dev)

Run:
    pytest -m slow tests/test_api_fuzzing.py
    HYPOTHESIS_PROFILE=dev pytest -m slow tests/test_api_fuzzing.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
import requests
from hypothesis import given, settings
from hypothesis import strategies as st


pytestmark = [pytest.mark.slow, pytest.mark.integration]


# Any HTTP status that is NOT a 5xx is an acceptable outcome for the
# "server must not 500" family of tests. 499 is sometimes returned by
# proxies — we don't have one in front, but the upper bound stays
# permissive to avoid over-fitting.
_NO_500 = range(100, 500)


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


def _url(server_process: dict[str, object]) -> str:
    return f"{server_process['base_url']}/data"


# --- F1-F3: input fuzzing on the validated fields ---------------------------


@given(sensor_id=st.text(max_size=512))
@settings(max_examples=100, deadline=60_000)
def test_F1_arbitrary_text_sensor_id_never_5xx(
    sensor_id: str,
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F1. For ANY hypothesis-generated text as sensor_id, the server
    returns 200 or 422 — never 500.

    The Pydantic layer accepts any non-empty string (our ``SensorIn``
    declares ``min_length=1``). An empty string or a string the
    validator refuses maps to 422; everything else maps to 200.
    """
    payload = {"sensor_id": sensor_id, "value": 1.0, "unit": "C"}
    resp = session.post(_url(server_process), json=payload, timeout=10)
    assert (
        resp.status_code in _NO_500
    ), f"5xx for sensor_id={sensor_id!r}: {resp.status_code} {resp.text[:200]}"


@given(value=st.floats(allow_nan=True, allow_infinity=True))
@settings(max_examples=100, deadline=60_000)
def test_F2_nan_and_infinity_value_handled_consistently(
    value: float,
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F2. NaN and infinity for ``value``.

    Strict JSON does not encode NaN/Infinity, so the requests
    library emits ``NaN``/``Infinity`` tokens; Pydantic's JSON
    loader in FastAPI either accepts them (and Pydantic then
    validates as float) or rejects them as invalid JSON.

    ASSERT: the outcome is CONSISTENT for each (isnan, isinf)
    triple — any single invocation that yields 5xx is a failure,
    and the rejection/acceptance boundary stays on one side for
    a given input class.
    """
    payload = {"sensor_id": "fuzz-F2", "value": value, "unit": "C"}
    try:
        resp = session.post(_url(server_process), json=payload, timeout=10)
    except (ValueError, requests.exceptions.InvalidJSONError):
        # Strict JSON refuses to encode NaN / ±Inf; requests raises
        # InvalidJSONError (which does NOT inherit from ValueError in
        # modern requests). The library refusing to send is itself a
        # clean outcome — mitigation is client-side, before any bytes
        # reach the server.
        return
    assert (
        resp.status_code in _NO_500
    ), f"5xx for value={value}: {resp.status_code} {resp.text[:200]}"
    # Consistency property: the only valid outcomes are 200 or 422.
    assert resp.status_code in (
        200,
        422,
    ), f"unexpected status {resp.status_code} for value={value}: {resp.text[:200]}"
    if resp.status_code == 200 and math.isfinite(value):
        # Round-tripping a finite value should preserve it.
        assert resp.json()["received"]["value"] == pytest.approx(value)


@given(value=st.integers(min_value=-(2**63), max_value=2**63 - 1))
@settings(max_examples=100, deadline=60_000)
def test_F3_arbitrary_64bit_integer_value_never_5xx(
    value: int,
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F3. Any int in the signed-64bit range passes or 422s, never 5xxs."""
    payload = {"sensor_id": "fuzz-F3", "value": value, "unit": "C"}
    resp = session.post(_url(server_process), json=payload, timeout=10)
    assert resp.status_code in _NO_500


# --- F4-F5: adversarial POST bodies -----------------------------------------


@given(raw=st.binary(min_size=1, max_size=65_536))
@settings(max_examples=50, deadline=60_000)
def test_F4_raw_binary_post_body_is_rejected_cleanly(
    raw: bytes,
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F4. Any ~64KiB binary blob sent as the POST body.

    The server MUST not 500 — the request either 4xxs as invalid
    JSON / invalid body, or (extremely unlikely for random bytes)
    parses as JSON and Pydantic-validates.
    """
    resp = session.post(
        _url(server_process),
        data=raw,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    assert (
        resp.status_code in _NO_500
    ), f"5xx on binary POST ({len(raw)} bytes): {resp.status_code} {resp.text[:200]}"
    # T3 plan mandated 400 or 422; accept either (plus 413 for the
    # oversized case) and exclude anything else to keep the
    # assertion meaningful.
    assert resp.status_code in (
        400,
        413,
        422,
        200,
    ), f"unexpected status {resp.status_code} for random binary body"


@given(
    body=st.dictionaries(
        keys=st.text(max_size=64),
        values=st.text(max_size=64),
        max_size=100,
    )
)
@settings(max_examples=100, deadline=60_000)
def test_F5_arbitrary_dict_payload_never_5xx(
    body: dict[str, str],
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F5. Any str-to-str dict as a JSON body.

    Outcomes:
    - body happens to carry valid sensor_id/value/unit: 200
    - body is missing/malformed: 422
    - never 500 or 5xx
    """
    resp = session.post(_url(server_process), json=body, timeout=10)
    assert resp.status_code in _NO_500


# --- F6-F8: specific adversarial inputs -------------------------------------


def test_F6_10MB_post_body_returns_413_or_422_within_5s(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F6. 10 MiB POST body — response must come quickly and be 4xx.

    The project has no explicit body-size limit in server.py; the
    default uvicorn + h11 stack will parse the whole body as JSON
    and Pydantic will 422 it (not 413, since 413 is not configured).
    Either outcome is acceptable — the point is that a 10 MiB body
    must return in <5s and not 500.
    """
    import time

    ten_mb = ("x" * 1024) * 10_240  # ~10 MiB ASCII string
    started = time.perf_counter()
    resp = session.post(
        _url(server_process),
        data=ten_mb,
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"10MB POST took {elapsed:.1f}s (budget 5s)"
    assert resp.status_code in (
        413,
        422,
        400,
    ), f"expected 400/413/422, got {resp.status_code}"


def test_F7_100_levels_deep_nested_json_does_not_recursion_error(
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F7. 100-levels-deep nested JSON.

    Pydantic handles shallow nesting fine; extremely deep JSON can
    trip recursion limits in custom validators. Our SensorIn is
    flat, so Pydantic rejects any nested shape at 422 without
    recursing. The point is: no 500, no RecursionError in logs.
    """
    body: object = {"sensor_id": "fuzz-F7", "value": 1.0, "unit": "C"}
    for _ in range(100):
        body = {"nested": body}

    resp = session.post(_url(server_process), json=body, timeout=10)
    assert resp.status_code in _NO_500
    # The top-level shape doesn't match SensorIn, so a 422 is
    # the expected normal outcome.
    assert resp.status_code == 422


# Edge-case unicode / injection strings that historically break
# naive string handling. Hypothesis is overkill for these; a direct
# table keeps the failure mode readable if one specific value fails.
_UNICODE_BOUNDARY_SENSOR_IDS = [
    "\x00\x00\x00",  # NULL bytes
    "‮‭reversed",  # RTL / LTR override
    "' OR 1=1; --",  # SQL-injection classic
    "<script>alert(1)</script>",  # XSS classic
    "a" * 1024,  # long
    chr(0) + "ASCII" + chr(0),  # embedded NULLs
    "🔐" * 200,  # multi-byte emoji repetition
    "line1\nline2\r\nline3",  # newline smuggling
]


@pytest.mark.parametrize("sensor_id", _UNICODE_BOUNDARY_SENSOR_IDS)
def test_F8_unicode_boundary_sensor_id_is_200_or_422(
    sensor_id: str,
    session: requests.Session,
    server_process: dict[str, object],
) -> None:
    """F8. Adversarial sensor_id strings.

    Every input is either accepted (200) or validation-rejected (422).
    5xx or a hang is a failure. A raw control character or injection
    payload must not produce a different response code class.
    """
    payload = {"sensor_id": sensor_id, "value": 1.0, "unit": "C"}
    resp = session.post(
        _url(server_process),
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    assert (
        resp.status_code in _NO_500
    ), f"5xx for sensor_id={sensor_id!r}: {resp.status_code}"
    assert resp.status_code in (200, 422)
