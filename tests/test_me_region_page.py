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
    assert "ME:    12." in text and "needs FIT 12" in text
    assert "Matching tool: none" in text
    assert "No Intel tools found" in text
    # Short: the check must not dump versions, paths or confidence notes.
    assert len(text.strip().splitlines()) <= 7


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


def test_me_info_shows_the_analyzer_field_set(qapp, tmp_path, monkeypatch):
    from bios_recovery.gui import me_region_page

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    entry = {
        "Family": "CSE ME",
        "Version": "12.0.92.2145",
        "Release": "Production",
        "Type": "Extracted",
        "SKU": "Consumer LP",
        "Chipset": "Unknown",
        "File System State": "Initialized",
        "Flash Image Tool": "N/A",
        "MEA Database Name": "12.0.92.2145_CON_LP_X_PRD_EXTR",
    }
    monkeypatch.setattr(
        me_region_page,
        "engine_details",
        lambda path: {"found": True, "engines": [("Management Engine", entry)]},
    )

    page = me_region_page.MERegionPage(image_provider=lambda: str(img))
    page.show_info()
    text = page.output.toPlainText()

    assert "== ME info ==" in text
    assert "Family: CSE ME" in text
    assert "MEA Database Name: 12.0.92.2145_CON_LP_X_PRD_EXTR" in text
    # The loaded image still gets its region line and partition list.
    assert "Generation: " in text and "Partitions:" in text


def test_me_info_falls_back_to_the_built_in_lines(qapp, tmp_path, monkeypatch):
    from bios_recovery.gui import me_region_page

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    reason = "This image has no engine data ME Analyzer could read."
    monkeypatch.setattr(
        me_region_page, "engine_details", lambda path: {"found": False, "reason": reason}
    )

    page = me_region_page.MERegionPage(image_provider=lambda: str(img))
    page.show_info()
    text = page.output.toPlainText()

    assert "ME Version: 12." in text
    assert f"Detail: {reason}" in text
    assert "Partitions:" in text


def test_me_info_says_it_simply_when_no_engine_is_found(qapp, tmp_path, monkeypatch):
    from bios_recovery.gui import me_region_page

    img = tmp_path / "bios.bin"
    img.write_bytes(build_intel_ifd_image())
    monkeypatch.setattr(me_region_page, "engine_details", lambda path: pytest.fail("not asked"))

    page = me_region_page.MERegionPage(image_provider=lambda: str(img))
    monkeypatch.setattr(page.cleaner, "get_me_info", lambda path: {"found": False})
    page.show_info()

    assert page.output.toPlainText().count("No Intel ME region found in this image.") == 1


def test_spi_page_hex_view_reads_the_shared_image(qapp, tmp_path):
    from bios_recovery.gui.spi_tab import SPITab

    img = tmp_path / "img.bin"
    img.write_bytes(bytes(range(64)))
    tab = SPITab(image_provider=lambda: str(img))
    tab.hex_offset.setText("0")
    tab.hex_length.setText("16")
    tab.view_hex()
    assert "00 01 02 03" in tab.log_text.toPlainText()


def test_one_open_serves_every_page(qapp, tmp_path, monkeypatch):
    """Opening a file once must make it the image for every page; no page keeps a copy."""
    from PySide6.QtWidgets import QFileDialog

    from bios_recovery.gui.main_window import MainWindow

    img = tmp_path / "dump.bin"
    img.write_bytes(build_intel_ifd_image())
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(img), ""))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: ("", ""))

    w = MainWindow()
    w.open_file()

    assert w.current_file == str(img)
    assert w.me_page._image() == str(img)
    assert w.spi_tab._image() == str(img)
    assert w.ec_tab.current_dump == str(img)
    assert w.lenovo_tab.current_dump == str(img)
    for name in ("repair_file", "dmi_file", "password_file", "extract_file", "ec_file",
                 "file_edit", "clone_old_edit", "image_edit", "write_path"):
        for owner in (w, w.ec_tab, w.lenovo_tab):
            assert not hasattr(owner, name)
    assert w.file_label.toolTip() == str(img)


def test_audit_removed_duplicates(qapp):
    """The audit's removals stay removed: one place for each action."""
    from PySide6.QtWidgets import QPushButton

    from bios_recovery.gui.main_window import MainWindow

    w = MainWindow()
    labels = [b.text() for b in w.findChildren(QPushButton)]
    assert "Analyze" not in labels
    assert not hasattr(w, "repair_password_ck")
    assert not hasattr(w.me_page, "image_label") and not hasattr(w.spi_tab, "image_label")
    tool_menu = [a for a in w.menuBar().actions() if a.text() == "&Tools"][0].menu()
    assert [a.text() for a in tool_menu.actions()] == ["Run &Analysis", "&ME Analyzer"]
    overview_buttons = [b.text() for b in w.main_tab.findChildren(QPushButton)]
    assert "Capsule → Flashable Image" not in overview_buttons
    repair_buttons = [b.text() for b in w.repair_tab.findChildren(QPushButton)]
    assert "Capsule → Flashable Image" in repair_buttons


def _clean_me_blob(version: str, size: int = 0x3FF000) -> bytes:
    """A minimal ME image: a partition table and one manifest carrying `version`."""
    import struct

    blob = bytearray(b"\xff" * size)
    blob[0x10:0x14] = b"$FPT"
    struct.pack_into("<I", blob, 0x14, 1)
    tag = 0x5000
    blob[tag : tag + 4] = b"$MN2"
    major, minor, hotfix, build = (int(p) for p in version.split("."))
    struct.pack_into("<HHHH", blob, tag + 8, major, minor, hotfix, build)
    return bytes(blob)


def _loaded_image_and_version(tmp_path):
    from bios_recovery.core.user_library import dominant_me_version

    img = tmp_path / "loaded.bin"
    img.write_bytes(build_intel_ifd_image())
    version = dominant_me_version(img.read_bytes())
    assert version, "fixture image must carry an ME version"
    return img, version


def _page(img):
    from bios_recovery.gui.me_region_page import MERegionPage

    return MERegionPage(image_provider=lambda: str(img))


def test_inject_uses_the_library_image_for_this_version(qapp, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QMessageBox

    from bios_recovery.core import user_library as lib

    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)

    img, version = _loaded_image_and_version(tmp_path)
    clean = tmp_path / "clean.bin"
    clean.write_bytes(_clean_me_blob(version))
    lib.import_files([str(clean)], "firmware")

    page = _page(img)
    page.inject()

    assert (tmp_path / "loaded_mefixed.bin").exists()
    assert "from the library:" in page.output.toPlainText()


def test_inject_asks_for_a_file_and_adds_it_to_the_library(qapp, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    from bios_recovery.core import user_library as lib

    img, version = _loaded_image_and_version(tmp_path)
    clean = tmp_path / "clean.bin"
    clean.write_bytes(_clean_me_blob(version))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(clean), ""))

    page = _page(img)
    page.inject()

    assert (tmp_path / "loaded_mefixed.bin").exists()
    assert any(e.me_version == version for e in lib.scan().firmware)
    assert "added to the library and used" in page.output.toPlainText()


def test_inject_keeps_a_wrong_version_in_the_library_but_does_not_use_it(
    qapp, tmp_path, monkeypatch
):
    from PySide6.QtWidgets import QFileDialog

    from bios_recovery.core import user_library as lib

    img, version = _loaded_image_and_version(tmp_path)
    other = "9.0.0.1000" if not version.startswith("9.") else "10.0.0.1000"
    clean = tmp_path / "other.bin"
    clean.write_bytes(_clean_me_blob(other))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(clean), ""))

    page = _page(img)
    page.inject()

    assert not (tmp_path / "loaded_mefixed.bin").exists()
    assert any(e.me_version == other for e in lib.scan().firmware)
    assert "Nothing was injected" in page.output.toPlainText()


def test_inject_refuses_a_file_that_is_not_me_firmware(qapp, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    img, _version = _loaded_image_and_version(tmp_path)
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x00" * 0x1000)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(junk), ""))

    page = _page(img)
    page.inject()

    assert not (tmp_path / "loaded_mefixed.bin").exists()
    assert "Not added to the library" in page.output.toPlainText()


def test_check_tools_names_the_one_matching_tool_plainly(qapp, tmp_path):
    """One short line for the tool to use: no paths, no confidence notes."""
    from bios_recovery.core import user_library as lib
    from bios_recovery.gui.me_region_page import MERegionPage
    from tests.test_fit_tools import _fake_windows_tool

    tool = tmp_path / "fit.exe"
    tool.write_bytes(_fake_windows_tool("", "12.0.45.1509"))
    lib.import_files([str(tool)], "tools")

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = MERegionPage(image_provider=lambda: str(img))
    page.check_tools()
    text = page.output.toPlainText()

    assert "ME:    12." in text and "needs FIT 12" in text
    assert "Matching tool: FIT 12.0.45.1509 (Windows)" in text
    assert str(tmp_path) not in text  # no paths
    assert "confidence" not in text and "release table" not in text
    assert len(text.strip().splitlines()) <= 5


def test_check_tools_lists_an_unidentified_tool_instead_of_hiding_it(qapp, tmp_path):
    from bios_recovery.core import user_library as lib
    from bios_recovery.gui.me_region_page import MERegionPage

    folder = tmp_path / "tools"
    folder.mkdir()
    tool = folder / "fit"
    tool.write_text("Intel (R) Flash Image Tool\n")  # banner, but no version anywhere
    tool.chmod(0o644)  # cannot be run, so no version can be added
    lib.add_folder(str(folder), "tools")

    img = tmp_path / "me.bin"
    img.write_bytes(build_intel_ifd_image())
    page = MERegionPage(image_provider=lambda: str(img))
    page.check_tools()
    text = page.output.toPlainText()
    assert "Matching tool: none" in text
    assert "FIT (not identified)" in text
