"""test_nginx_concurrency.py — NC1-NC3 concurrency tests for the v1.2 stack.

Three tests, each drives the nginx + FastAPI stack with parallel
requests to prove the auth boundary is thread-safe in practice:

    NC1   50 concurrent allowed requests → all 200. Exercises TLS
          handshake re-entrancy, upstream keepalive, and nginx's
          worker-internal connection pool.
    NC2   50 concurrent rogue-CN requests → all 403. The 403 body
          must carry the cn/reason fields intact; a race in the
          map{} lookup would surface as mis-attributed CNs.
    NC3   Interleaved allow + deny traffic → each request gets the
          correct status. No status cross-contamination even when
          the two lanes share a worker.

All tests use ``concurrent.futures.ThreadPoolExecutor`` — we're
measuring nginx concurrency, not Python's GIL behaviour. 20 workers
is enough to push multiple connections through nginx's single worker
while staying well below OS fd limits.
"""
# ruff: noqa: F811

from __future__ import annotations

import random
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import requests

from tests.conftest import _client_auth


_CONCURRENT_WORKERS = 20
_TOTAL_REQUESTS = 50


def _drive(
    call: Callable[[], requests.Response],
    n: int = _TOTAL_REQUESTS,
    workers: int = _CONCURRENT_WORKERS,
) -> list[requests.Response]:
    """Run ``call`` ``n`` times across ``workers`` threads; return every response."""
    results: list[requests.Response] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(call) for _ in range(n)]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results


@pytest.mark.integration
@pytest.mark.performance
class TestNginxConcurrency:
    # -------- NC1 ---------------------------------------------------------
    def test_nc1_concurrent_allowed_requests_all_200(
        self,
        nginx_stack,
        pki_paths,
    ):
        url = f"{nginx_stack['nginx_url']}/health"
        auth = _client_auth(pki_paths)

        def _call() -> requests.Response:
            return requests.get(url, **auth)

        results = _drive(_call)
        statuses = [r.status_code for r in results]
        assert statuses.count(200) == _TOTAL_REQUESTS, (
            f"{_TOTAL_REQUESTS} allowed concurrent requests should all return "
            f"200; got status distribution: {dict((s, statuses.count(s)) for s in set(statuses))}"
        )
        # Every body must parse as the canonical health payload — no
        # partial writes / corruption from concurrent upstream re-use.
        assert all(r.json() == {"status": "ok"} for r in results)

    # -------- NC2 ---------------------------------------------------------
    def test_nc2_concurrent_rogue_cn_all_403(
        self,
        nginx_stack,
        cert_kit,
        pki_paths,
    ):
        url = f"{nginx_stack['nginx_url']}/health"
        auth = _client_auth(pki_paths, pair=cert_kit["client_99"])

        def _call() -> requests.Response:
            return requests.get(url, **auth)

        results = _drive(_call)
        statuses = [r.status_code for r in results]
        assert statuses.count(403) == _TOTAL_REQUESTS, (
            f"all rogue-CN concurrent requests should return 403; "
            f"got: {dict((s, statuses.count(s)) for s in set(statuses))}"
        )
        # Every 403 body must correctly attribute the CN — a race in
        # nginx's map{} evaluation would show up as mis-labelled bodies.
        for r in results:
            body = r.json()
            assert body == {
                "error": "forbidden",
                "cn": "client-99",
                "reason": "cn_not_allowlisted",
            }, body

    # -------- NC3 ---------------------------------------------------------
    def test_nc3_mixed_traffic_gets_correct_status_per_cert(
        self,
        nginx_stack,
        cert_kit,
        pki_paths,
    ):
        """25 allowed + 25 rogue, shuffled, in parallel. Each request
        should get exactly the status its own cert earns — no cross-
        contamination between the two lanes."""
        url = f"{nginx_stack['nginx_url']}/health"
        allowed_auth = _client_auth(pki_paths)
        denied_auth = _client_auth(pki_paths, pair=cert_kit["client_99"])

        # Task marker: label -> (auth_kwargs, expected_status)
        allowed_task: tuple[str, dict[str, object], int] = (
            "allowed",
            allowed_auth,
            200,
        )
        denied_task: tuple[str, dict[str, object], int] = (
            "denied",
            denied_auth,
            403,
        )
        tasks: list[tuple[str, dict[str, object], int]] = [allowed_task] * 25 + [
            denied_task
        ] * 25
        random.Random(42).shuffle(tasks)

        def _call(task: tuple[str, dict[str, object], int]) -> tuple[str, int, int]:
            label, auth, expected = task
            r = requests.get(url, **auth)
            return label, r.status_code, expected

        with ThreadPoolExecutor(max_workers=_CONCURRENT_WORKERS) as ex:
            results = list(ex.map(_call, tasks))

        mismatches = [
            (label, actual, expected)
            for (label, actual, expected) in results
            if actual != expected
        ]
        assert (
            not mismatches
        ), f"status mis-attributions under concurrent load: {mismatches[:5]}"
