"""Vulture whitelist — items that look unused but serve a purpose.

Each entry carries a one-line justification. Anything genuinely
unused should be deleted, not whitelisted.
"""

# Used only for introspection via pytest-benchmark, but imported
# at call site.
from server import SensorReading  # noqa: F401

# Placeholder — tests/test_concurrency.py::client_id is used as a
# label in the async Barrier coroutine; vulture misses that the
# name is read through kwargs binding.
client_id = None  # type: ignore[assignment]

# tests/test_security_pentest.py::tmpdir is kept in the function
# signature for symmetry with other PP helpers even when unused
# in a specific branch — re-using the same signature keeps the
# runner API uniform.
tmpdir = None  # type: ignore[assignment]
