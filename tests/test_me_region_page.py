"""ME Region page: inspect, clean, repair and verify the loaded image on one page."""

import pytest

from tests.fixture_builder import build_intel_ifd_image


@pytest.fixture
def qapp():
    from PySide6.QtWidgets import QApplication

    yield QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("BIOS_RECOVERY_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("BIOS_RECOVERY_DATA_DIR", str(tmp_path / "data"))
    yield


def test_me_and_flash_pages_are_single_tabs(qapp):
    from bios_recovery.gui.main_window import MainWindow

    w = MainWindow()
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert "ME Region" in titles and "Flash & Hex" in titles
    assert "Rebuild Check" not in titles
    assert w.tabs.widget(w.tabs.indexOf(w.me_page)) is w.me_page
    assert w.tabs.widget(w.tabs.indexOf(w.spi_tab)) is w.spi_tab


def test_check_tools_reports_release_and_empty_library(qapp, tmp_path):
    from bios_recovery.gui.me_region_page import MERegionPage

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = MERegionPage(image_provider=lambda: str(img))
    page.check_tools()
    text = page.output.toPlainText()
    assert "== Tools for this image ==" in text
    assert "ME version:   12." in text and "Tool release: v12 r38" in text
    assert "no Intel tools in your library match" in text


def test_verify_refuses_identical_image(qapp, tmp_path):
    from bios_recovery.gui.me_region_page import MERegionPage

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = MERegionPage(image_provider=lambda: str(img))
    page.verify(str(img))
    assert "REFUSE" in page.output.toPlainText()


def test_verify_needs_a_rebuilt_image(qapp, tmp_path):
    from bios_recovery.gui.me_region_page import MERegionPage

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = MERegionPage(image_provider=lambda: str(img))
    page.verify("")
    assert "Choose the rebuilt image first." in page.output.toPlainText()


def test_actions_need_a_loaded_image(qapp):
    from bios_recovery.gui.me_region_page import MERegionPage

    page = MERegionPage(image_provider=lambda: None)
    page.show_info()
    page.clean()
    page.check_tools()
    assert page.output.toPlainText().count("Open a BIOS file first") == 3


def test_refresh_shows_the_loaded_image(qapp, tmp_path):
    from bios_recovery.gui.me_region_page import MERegionPage

    current = {"path": None}
    page = MERegionPage(image_provider=lambda: current["path"])
    assert page.image_label.text() == ""
    current["path"] = str(tmp_path / "x.bin")
    page.refresh()
    assert page.image_label.text() == str(tmp_path / "x.bin")


def test_spi_page_hex_view_reads_the_shared_image(qapp, tmp_path):
    from bios_recovery.gui.spi_tab import SPITab

    img = tmp_path / "img.bin"
    img.write_bytes(bytes(range(64)))
    tab = SPITab()
    tab.set_image(str(img))
    tab.hex_offset.setText("0")
    tab.hex_length.setText("16")
    tab.view_hex()
    assert "00 01 02 03" in tab.log_text.toPlainText()
