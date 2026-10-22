"""Rebuild Check page: tool fit for an image and region-gated verification."""

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


def test_page_is_in_main_window(qapp):
    from bios_recovery.gui.main_window import MainWindow

    w = MainWindow()
    assert "Rebuild Check" in [w.tabs.tabText(i) for i in range(w.tabs.count())]


def test_check_reports_release_and_empty_library(qapp, tmp_path):
    from bios_recovery.gui.rebuild_check_page import RebuildCheckPage

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = RebuildCheckPage()
    page.check_image(str(img))
    text = page.check_output.toPlainText()
    assert "ME version:   12." in text and "Tool release: v12 r38" in text
    assert "no Intel tools in your library match" in text


def test_verify_refuses_identical_image(qapp, tmp_path):
    from bios_recovery.gui.rebuild_check_page import RebuildCheckPage

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = RebuildCheckPage()
    page.verify(str(img), str(img))
    assert page.verify_output.toPlainText().startswith("REFUSE")


def test_verify_requires_both_paths(qapp):
    from bios_recovery.gui.rebuild_check_page import RebuildCheckPage

    page = RebuildCheckPage()
    page.verify("", "")
    assert "Choose both" in page.verify_output.toPlainText()
