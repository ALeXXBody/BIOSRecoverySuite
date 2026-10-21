"""Settings page: folders, imports and scanning through the GUI."""

import os
import stat

import pytest

from tests.fixture_builder import build_intel_ifd_image


@pytest.fixture
def qapp():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("BIOS_RECOVERY_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("BIOS_RECOVERY_DATA_DIR", str(tmp_path / "data"))
    yield


def _page(qapp):
    from bios_recovery.gui.settings_page import SettingsPage
    return SettingsPage()


def test_settings_tab_is_in_main_window(qapp):
    from bios_recovery.gui.main_window import MainWindow
    w = MainWindow()
    assert "Settings" in [w.tabs.tabText(i) for i in range(w.tabs.count())]


def test_add_and_remove_folders_by_kind(qapp, tmp_path):
    page = _page(qapp)
    folder = tmp_path / "fw"
    folder.mkdir()
    page.add_folder("firmware", str(folder))
    assert page.firmware_list.count() == 1 and page.tools_list.item(0).text() == "(none added)"
    page.remove_folder("firmware", str(folder))
    assert page.firmware_list.item(0).text() == "(none added)"


def test_scan_fills_tables_through_run_task(qapp, tmp_path):
    folder = tmp_path / "fw" / "sub"
    folder.mkdir(parents=True)
    (folder / "me.bin").write_bytes(build_intel_ifd_image())
    page = _page(qapp)
    page.add_folder("firmware", str(tmp_path / "fw"))
    page.start_scan()
    assert page.firmware_table.rowCount() == 1
    assert page.firmware_table.item(0, 0).text().startswith("12.")
    assert "1 firmware image" in page.scan_status.text()


def test_import_through_page_copies_into_app_folder(qapp, tmp_path):
    page = _page(qapp)
    full = tmp_path / "me.bin"
    full.write_bytes(build_intel_ifd_image())
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\xff" * 0x1000)
    results = page.import_files("firmware", [str(full), str(junk)])
    assert [bool(r.copied_to) for r in results] == [True, False]
    assert os.path.exists(results[0].copied_to)
    assert page.firmware_list.item(0).text() == "(none added)"  # import does not add a folder
