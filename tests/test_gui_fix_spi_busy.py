"""A chip operation must not overlap another, and every flash control waits (audit F-03)."""

import threading

import pytest

from bios_recovery.apps.spi_flasher import FlasherResult, SPIStatus
from tests.test_gui_exercise import qapp  # noqa: F401


class _Flasher:
    def __init__(self, gate):
        self.gate = gate
        self.calls = []

    def read_chip(self, output_path, programmer="ch341a_spi"):
        self.calls.append("read")
        self.gate.wait(10)
        return FlasherResult(status=SPIStatus.SUCCESS, message="read ok")

    def erase_chip(self, programmer="ch341a_spi", consent=False):
        self.calls.append("erase")
        return FlasherResult(status=SPIStatus.SUCCESS, message="erased")


def _settle(tab, app):
    import time

    deadline = time.time() + 10
    while tab._jobs and time.time() < deadline:
        app.processEvents()
        time.sleep(0.02)
    for _ in range(10):
        app.processEvents()


@pytest.fixture
def tab(qapp, tmp_path, monkeypatch):  # noqa: F811
    from PySide6.QtWidgets import QFileDialog, QMessageBox

    from bios_recovery.gui.spi_tab import SPITab

    monkeypatch.setattr(
        QFileDialog,
        "getSaveFileName",
        lambda *a, **k: (str(tmp_path / "chip.bin"), ""),
    )
    monkeypatch.setattr(
        QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes
    )
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    tab = SPITab()
    gate = threading.Event()
    tab.flasher = _Flasher(gate)
    tab._gate = gate
    yield tab
    gate.set()


def test_erase_is_disabled_and_refused_while_a_read_runs(tab, qapp):  # noqa: F811
    tab.read_chip()
    assert not tab.erase_btn.isEnabled()
    assert not tab.read_btn.isEnabled()

    tab.erase_consent.setChecked(True)
    tab.erase_chip()
    tab._gate.set()
    _settle(tab, qapp)

    assert tab.flasher.calls == ["read"]
    assert "still running" in tab.log_text.toPlainText()


def test_every_flash_control_is_enabled_again_after_the_job(tab, qapp):  # noqa: F811
    tab.read_chip()
    tab._gate.set()
    _settle(tab, qapp)
    for button in (tab.refresh_btn, tab.identify_btn, tab.read_btn, tab.write_btn, tab.erase_btn):
        assert button.isEnabled()
