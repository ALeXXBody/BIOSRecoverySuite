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
    _ACTIVE.add(thread)


class Job(QThread):
    """Runs one callable off the UI thread and reports its result or its error."""

    done = Signal(object)
    failed = Signal(str)

    def __init__(self, task, *args):
        super().__init__()
        self._task = task
        self._args = args
        track(self)

    def run(self):
        try:
            self.done.emit(self._task(*self._args))
        except Exception as exc:
            self.failed.emit(str(exc))


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
