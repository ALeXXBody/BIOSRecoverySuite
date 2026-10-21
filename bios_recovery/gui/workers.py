"""Registry of background QThreads.

A QThread destroyed while it is still running aborts the process. Every thread the
GUI starts is registered here; windows wait for them on close, and the interpreter
waits for them at exit, before Qt objects are torn down.
"""

from __future__ import annotations

import atexit

_ACTIVE: set = set()


def track(thread) -> None:
    _ACTIVE.add(thread)


def wait_for_workers(timeout_ms: int = 30000) -> None:
    for thread in list(_ACTIVE):
        thread.wait(timeout_ms)
        _ACTIVE.discard(thread)


atexit.register(wait_for_workers)
