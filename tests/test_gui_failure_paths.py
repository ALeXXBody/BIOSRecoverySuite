"""A failed background job must leave its control enabled (audit F-01)."""

import pytest

from tests.test_gui_exercise import _wait_threads, qapp  # noqa: F401


@pytest.fixture
def window(qapp, monkeypatch, tmp_path):  # noqa: F811
    from PySide6.QtWidgets import QMessageBox

    from bios_recovery.gui.main_window import MainWindow

    monkeypatch.setattr(QMessageBox, "critical", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    win = MainWindow()
    sample = tmp_path / "dump.bin"
    sample.write_bytes(b"\xff" * 0x20000)
    win.current_file = str(sample)
    return win


def _boom(*_a, **_k):
    raise RuntimeError("injected failure")


def test_repair_button_recovers_after_failure(window, monkeypatch):
    monkeypatch.setattr(window.repair_engine, "auto_repair", _boom)
    window.run_repair()
    _wait_threads(window)
    assert window.repair_btn.isEnabled()


def test_scan_button_recovers_after_failure(window, monkeypatch):
    monkeypatch.setattr(window.password_remover, "find_password_in_dump", _boom)
    window.scan_passwords()
    _wait_threads(window)
    assert window.scan_btn.isEnabled()


def test_remove_button_recovers_after_failure(window, monkeypatch):
    monkeypatch.setattr(window.password_remover, "remove_passwords", _boom)
    window.remove_passwords()
    _wait_threads(window)
    assert window.remove_btn.isEnabled()


def test_extract_button_recovers_after_failure(window, monkeypatch, tmp_path):
    from PySide6.QtWidgets import QFileDialog

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: str(tmp_path))
    monkeypatch.setattr(window.bios_extractor, "extract", _boom)
    window.extract_bios()
    _wait_threads(window)
    assert window.extract_btn.isEnabled()


def test_dmi_extract_button_recovers_after_failure(window, monkeypatch):
    import bios_recovery.gui.main_window as mw

    monkeypatch.setattr(mw, "read_identity_file", _boom)
    window.extract_dmi()
    _wait_threads(window)
    assert window.dmi_extract_btn.isEnabled()


def test_capsule_merge_reads_the_file_it_was_started_on(window, monkeypatch, tmp_path):
    """The worker must use the path captured when the job starts (audit F-13)."""
    import bios_recovery.gui.main_window as mw

    seen = []

    class Done:
        success = False
        messages = ["stop"]
        output_path = ""

    def fake_extract(path, output_path=None, **_k):
        seen.append(path)
        return Done()

    import bios_recovery.manufacturers.common.bios_capsule as capsule

    monkeypatch.setattr(capsule, "extract_flashable_image", fake_extract)
    dump = tmp_path / "other.bin"
    dump.write_bytes(b"\xff" * 0x100)
    monkeypatch.setattr(
        mw.QFileDialog, "getOpenFileName", lambda *a, **k: (str(dump), "BIOS Files (*.bin)")
    )
    first = window.current_file
    window.build_flashable_merged()
    window.current_file = str(tmp_path / "changed_later.bin")
    _wait_threads(window)
    assert seen and seen[0] == first


def test_extract_cancel_writes_nothing_next_to_input(window, monkeypatch, tmp_path):
    """Cancelling the picker starts no extraction and creates no folder beside the input (M7)."""
    from PySide6.QtWidgets import QFileDialog

    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: "")
    called = []
    monkeypatch.setattr(window.bios_extractor, "extract", lambda *a, **k: called.append(a))
    window.extract_bios()
    _wait_threads(window)
    assert called == []
    assert not any(p.name.endswith("_extracted") for p in tmp_path.iterdir())
