"""
Structured JSON & Console Logging Subsystem
Standardizes machine-readable logging for SOC SIEM ingestion and operational auditing.
"""

import json
import logging
import sys
import datetime
from typing import Optional, Dict, Any

from ulpf.packages.config.settings import get_settings


class JSONFormatter(logging.Formatter):
    """
    Formats log records into standard JSON objects.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "process_id": record.process,
            "thread_name": record.threadName
        }

        # Include custom extra fields if attached
        if hasattr(record, "event_id"):
            log_obj["event_id"] = record.event_id
        if hasattr(record, "client_ip"):
            log_obj["client_ip"] = record.client_ip
        if hasattr(record, "parser_id"):
            log_obj["parser_id"] = record.parser_id
        if hasattr(record, "error_stage"):
            log_obj["error_stage"] = record.error_stage

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def configure_logging(level: Optional[str] = None, log_format: Optional[str] = None):
    """Configures global logging system based on settings."""
    settings = get_settings()
    log_lvl_str = level or settings.ULPF_LOG_LEVEL
    log_fmt_str = log_format or settings.ULPF_LOG_FORMAT

    log_level = getattr(logging, log_lvl_str.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)

    if log_fmt_str.lower() == "json":
        stream_handler.setFormatter(JSONFormatter())
    else:
        text_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ"
        )
        stream_handler.setFormatter(text_formatter)

    root_logger.addHandler(stream_handler)


def get_logger(name: str) -> logging.Logger:
    """Retrieves named logger."""
    return logging.getLogger(name)
