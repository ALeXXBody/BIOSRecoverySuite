"""Registry of background QThreads.

A QThread destroyed while it is still running aborts the process. Every thread the
GUI starts is registered here; windows wait for them on close, and the interpreter
waits for them at exit, before Qt objects are torn down.
"""

from __future__ import annotations

import atexit

from PySide6.QtCore import QThread, Signal

_ACTIVE: set = set()


def track(thread) -> None:
    for old in [t for t in _ACTIVE if t.isFinished()]:
        _ACTIVE.discard(old)
    _ACTIVE.add(thread)


def hardware_job_running() -> bool:
    """True while a job that drives a programmer or chip is still running."""
    return any(getattr(t, "hardware", False) and t.isRunning() for t in _ACTIVE)


class Job(QThread):
    """Runs one callable off the UI thread.

    Results carry a token. The owning widget keeps the callback under that token and
    connects these signals to its own methods, so a result that arrives after the
    widget is destroyed is dropped by Qt instead of reaching a deleted object.
    A job with hardware=True drives a chip or programmer; the window will not close
    while one runs.
    """

    done = Signal(object, object)   # (token, result)
    failed = Signal(object, str)    # (token, message)

    def __init__(self, token, task, *args, hardware=False):
        super().__init__()
        self._token = token
        self._task = task
        self._args = args
        self.hardware = hardware
        track(self)

    def run(self):
        try:
            self.done.emit(self._token, self._task(*self._args))
        except Exception as exc:
            self.failed.emit(self._token, str(exc))


def wait_for_workers(timeout_ms: int = 30000) -> bool:
    """Wait for every tracked thread. A thread is forgotten only once it has finished.

    Returns False when some thread is still running after the wait; that thread stays
    tracked, so it cannot be destroyed while running.
    """
    all_done = True
    for thread in list(_ACTIVE):
        if thread.wait(timeout_ms):
            _ACTIVE.discard(thread)
        else:
            all_done = False
    return all_done


atexit.register(wait_for_workers)
