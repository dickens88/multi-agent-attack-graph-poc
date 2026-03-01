"""Event bus for streaming real-time progress events from agents to the SSE layer.

Uses thread-ID keyed callbacks so multiple concurrent investigations don't conflict.
"""

from __future__ import annotations
import threading
from typing import Callable, Any

_callbacks: dict[int, Callable] = {}
_lock = threading.Lock()


def register_callback(callback: Callable[[str, dict], None]) -> None:
    """Register a progress callback for the current thread."""
    tid = threading.get_ident()
    with _lock:
        _callbacks[tid] = callback


def unregister_callback() -> None:
    """Remove the callback for the current thread."""
    tid = threading.get_ident()
    with _lock:
        _callbacks.pop(tid, None)


def emit(event_type: str, payload: dict) -> None:
    """Emit a progress event via the registered callback for the current thread."""
    tid = threading.get_ident()
    with _lock:
        cb = _callbacks.get(tid)
    if cb:
        cb(event_type, payload)


def get_callback() -> Callable | None:
    """Get the callback for the current thread (for passing to child threads)."""
    tid = threading.get_ident()
    with _lock:
        return _callbacks.get(tid)
