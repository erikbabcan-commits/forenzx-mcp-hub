"""
Štruktúrované JSON logovanie s auditom.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Formatter that outputs JSON logs with audit trail support."""

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            log_data["exc_text"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        # Add module, function, line for traceability
        log_data["module"] = record.module
        log_data["function"] = record.funcName
        log_data["line"] = record.lineno

        # For audit logs, ensure we have user context
        if hasattr(record, "user_id"):
            log_data["user_id"] = record.user_id
        if hasattr(record, "case_id"):
            log_data["case_id"] = record.case_id
        if hasattr(record, "job_id"):
            log_data["job_id"] = record.job_id

        return json.dumps(log_data, ensure_ascii=False, default=str)


def setup_logger(name: str) -> logging.Logger:
    """Setup a structured JSON logger for forensic auditing."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers
    if logger.hasHandlers():
        return logger

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get or create a structured logger."""
    return setup_logger(name)
