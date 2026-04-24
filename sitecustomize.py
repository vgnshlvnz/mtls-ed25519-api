"""Python site customization for this repository.

Sole purpose today: enable ``coverage.py`` inside subprocesses that the
pytest integration fixture spawns (``server.py`` is launched via
``subprocess.Popen``). Without this hook, any line of code that only
runs in the child process shows as uncovered even though the test
suite exercises it end-to-end.

Mechanism is the standard coverage.py pattern — ``process_startup()``
is a no-op unless ``COVERAGE_PROCESS_START`` points at a config file,
so this file is safe to load in every Python invocation (CLI scripts,
``make pki``, direct ``python server.py``). Coverage is never enabled
outside the pytest-cov run.
"""

from __future__ import annotations

try:
    import coverage
except ImportError:  # coverage isn't a runtime dependency
    pass
else:
    coverage.process_startup()
