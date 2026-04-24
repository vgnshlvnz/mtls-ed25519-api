"""Structured JSON logging for the mTLS REST API (T7).

All server log lines are single-line JSON objects. Operators can
``jq`` / ``grep`` / ship-to-logstash the output without regex
gymnastics, and the audit trail is machine-parseable end-to-end.

Every record carries at minimum::

    {"timestamp": "...", "level": "INFO", "logger": "mtls_api",
     "event": "<slug>", "message": "<human form>"}

Additional fields come from the ``extra={...}`` kwarg on the
logging call sites (see middleware.py). See
``docs/log_schema.md`` for the full schema.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys

# Keys we want at the start of every record, in a stable order.
_STANDARD_KEYS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "message",
    "module",
    "msecs",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
    "taskName",
}


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        payload: dict[str, object] = {
            "timestamp": dt.datetime.fromtimestamp(record.created, dt.UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }
        # Any extra=... dict fields added by the caller land on the
        # record as non-standard attributes. Copy them verbatim.
        for key, value in record.__dict__.items():
            if key in _STANDARD_KEYS or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"), default=str)


def configure_json_logging(level: int = logging.INFO) -> logging.Logger:
    """Replace any existing root-logger handlers with a JSON stdout handler.

    ``force=True`` semantics so this can be called from server.py's
    module-load path without worrying about whether a prior handler
    was already attached.
    """
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level)
    # Uvicorn's per-request access log duplicates the middleware's
    # structured record — keep it off under JSON mode too.
    logging.getLogger("uvicorn.access").disabled = True
    return logging.getLogger("mtls_api")
