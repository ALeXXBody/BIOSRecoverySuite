"""The window must not close while a chip operation is still running (audit F-04)."""

import threading
import time

from tests.test_gui_exercise import qapp  # noqa: F401


def test_window_refuses_to_close_during_a_chip_operation(qapp, monkeypatch):  # noqa: F811
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QMessageBox

    from bios_recovery.gui.main_window import MainWindow
    from bios_recovery.gui.workers import Job

    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a[2]))
    win = MainWindow()

    gate = threading.Event()
    threading.Timer(0.3, gate.set).start()
    job = Job(1, lambda: gate.wait(10), hardware=True)
    job.start()
    try:
        event = QCloseEvent()
        win.closeEvent(event)
        assert not event.isAccepted()
        assert warned
    finally:
        gate.set()
        job.wait(10000)

    event = QCloseEvent()
    win.closeEvent(event)
    assert event.isAccepted()


def test_background_jobs_are_pruned_once_finished(qapp):  # noqa: F811
    from bios_recovery.gui import workers

    done = workers.Job(3, lambda: None)
    done.start()
    done.wait(5000)
    workers.track(done)
    running = workers.Job(2, lambda: time.sleep(0.2))
    running.start()
    try:
        workers.track(running)
        assert done not in workers._ACTIVE
        assert running in workers._ACTIVE
    finally:
        running.wait(5000)

