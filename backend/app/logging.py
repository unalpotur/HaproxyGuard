"""Structured JSON logging for HAProxy Guard.

Uses Python's built-in `logging` with a custom JSON formatter. Controlled by
the ``LOG_LEVEL`` environment variable (default: ``INFO``).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            payload["exc"] = repr(record.exc_info[1])
        return json.dumps(payload, default=str)


def setup_logging() -> None:
    """Configure the root logger with structured JSON output to stderr."""
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))
    # Remove any pre-existing handlers (uvicorn adds its own).
    root.handlers.clear()
    root.addHandler(handler)

    # Keep noisy libs quiet unless DEBUG.
    if level != "DEBUG":
        for name in ("sqlalchemy.engine", "aiosqlite", "alembic", "uvicorn.access"):
            logging.getLogger(name).setLevel(logging.WARNING)

    root.info("logging_initialised level=%s", level.lower())
