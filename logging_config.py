"""Centralized logging configuration for the project."""

import logging
import os

_DEFAULT_FORMAT = "%(asctime)s [%(name)s] %(levelname)s: %(message)s"


def setup_logging() -> None:
    """Configure root logger once for the whole application."""
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root_logger = logging.getLogger()
    if root_logger.handlers:
        root_logger.setLevel(level)
    else:
        logging.basicConfig(level=level, format=_DEFAULT_FORMAT)

    # Avoid per-request HTTP noise when LOG_LEVEL=DEBUG
    if level <= logging.DEBUG:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a module logger under centralized configuration."""
    return logging.getLogger(name)
