# Performance Baselines

Documents the performance invariants the test suite enforces and the
SLO thresholds the project commits to under mTLS. Each row cross-
references the test that guards it.

## Attacker / workload model

These baselines are lab numbers — a single-node FastAPI server
bound to loopback with mTLS. They are upper bounds, not targets.

A client's per-connection latency is dominated by the TLS handshake
(3 round trips + Ed25519 signature verification + CertificateVerify);
after the first request the connection is reused via HTTP keep-alive,
so subsequent calls are much faster.

## Micro-benchmarks (pytest-benchmark)

Driven by `tests/test_performance.py`, marker `performance`, 100
rounds + 5 warmup per test. Run via `make bench` or `pytest -m
performance`.

| ID  | What                                           | Median ceiling | Typical (dev box) |
|-----|------------------------------------------------|----------------|------------------|
| PB1 | Fresh mTLS handshake + GET /health              | 50 ms          | ~4.5 ms          |
| PB2 | GET /data, session reuse (no handshake)         | 10 ms          | ~1.3 ms          |
| PB3 | POST /data with ~1 KB body                      | 15 ms          | ~1.6 ms          |
| PB4 | 10 000 × `extract_cn()`                         | 100 ms         | ~1.1 ms          |
| PB5 | 10 000 × `subject_fingerprint()`                | 100 ms         | ~12 ms           |

Results are written to `.benchmarks/latest.json` and autosaved
under `.benchmarks/<python>-<CPU>/0001_<name>.json`. Future phases
can compare against a baseline with:

```bash
pytest -m performance --benchmark-compare=0001_baseline --benchmark-compare-fail=median:20%
```

A 20% median regression fails the run — the default ceiling set by
the T4 plan.

## Concurrency correctness (`pytest -m slow`)

`tests/test_concurrency.py` — correctness under load, not raw
throughput. See Locust (below) for throughput/latency SLOs.

| ID  | Scenario                                                               | Invariant               |
|-----|------------------------------------------------------------------------|-------------------------|
| CS1 | 100 fresh `requests.Session` workers, each with a full handshake       | all 200, wall-clock < 15s |
| CS2 | 50 threads on one shared session (50-slot pool)                        | all 200, wall-clock < 5s |
| CS3 | Mixed fleet: 20 valid + 10 no-cert + 10 wrong-CN simultaneously         | exactly 20=200, 10=TLS-reject, 10=403 |
| CS4 | Burst of 200 concurrent connections, then one probe                    | probe returns < 2s |
| CS5 | Thundering herd — 50 clients synced by `asyncio.Barrier`               | all 200, wall-clock < 10s |

CS3 is the **critical race-condition test**: a middleware bug that
leaked `request.state` across concurrent requests would corrupt the
200/403 counts. Do not simplify it.

## Stability (`pytest -m slow`)

`tests/test_stability.py::test_ST1_...` — 1000 sequential GET /health
calls with a 60 ms delay (~60 s total). Asserts:

| Check                                                         | Budget       |
|---------------------------------------------------------------|--------------|
| Zero 5xx responses                                            | exact        |
| Zero connection errors                                        | exact        |
| Server process RSS growth                                     | < 50 MiB     |
| Steady-state latency (p99 of last 100 vs first 100)           | ≤ 3× factor |

RSS is via `psutil.Process(server_pid).memory_info().rss`. The 50 MiB
ceiling is a guardrail against unbounded caches / fd leaks, not a
micro-regression gate — kernel paging and glibc arena noise easily
reach ±5 MiB between runs.

## Load test (Locust)

`tests/locustfile.py` via `make load-test`:

```
locust -f tests/locustfile.py --headless \
       -u 20 --spawn-rate 5 --run-time 30s \
       --host https://127.0.0.1:8443 --exit-code-on-error 1
```

Workload mix (weighted tasks):

| Task           | Weight | Assertion                    |
|----------------|:------:|------------------------------|
| GET /health    | 3      | 200, body.status == "ok"     |
| GET /data      | 2      | 200, body has "readings"     |
| POST /data     | 1      | 200, body has "echoed_at"    |

`wait_time = between(0.1, 0.5)` per user — roughly 2–5 requests per
user per second, or ~40–100 req/s aggregate at 20 users.

### SLO thresholds

Locust quits with exit code 1 if any of these is breached:

| Metric        | Budget  |
|---------------|---------|
| Failure rate  | 0%      |
| p95 latency   | < 200 ms |
| p99 latency   | < 500 ms |

Typical numbers on a dev box: p95 ~ 9 ms, p99 ~ 13 ms at 20 users.
The budgets are ~20x the dev numbers, leaving room for slower CI
infrastructure without being permissive.

## How to bump a baseline

Bumping a baseline is a commit you should stop and think about.

1. Establish that the regression is real and not infra noise — run
   `make bench` three times; medians should be stable (< 5% spread).
2. If it is a real regression, root-cause it before changing the
   ceiling. Typical causes: new feature with extra work per request,
   unintended re-handshaking, synchronous I/O added to middleware.
3. If the new cost is justified, update both the ceiling constant in
   the test AND the table above, in the same commit. Include the
   explanation in the commit message.
4. Do NOT silently loosen the factor in `test_ST1_...` — that test
   is designed to catch creeping regressions; loosening it defeats
   its purpose.
