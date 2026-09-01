"""GUI smoke test: the whole main window must construct offscreen without errors.

Catches attribute-ordering and wiring bugs that only appear at runtime.
Requires PySide6 (installed via requirements.txt in CI). Skipped if Qt can't
be used in the environment.
"""

import os

import pytest

pyside = pytest.importorskip("PySide6.QtWidgets", reason="PySide6 not installed")


@pytest.fixture(scope="module")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_constructs(qapp):
    from bios_recovery.gui.main_window import MainWindow

    w = MainWindow()
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    for expected in ["Overview", "Repair", "ME Cleaner", "DMI", "Security",
                     "Extract", "Hex Viewer", "Passwords", "SPI Flasher", "EC Patching"]:
        assert expected in titles, f"missing tab: {expected}"


def test_ec_tab_registry_loaded(qapp):
    from bios_recovery.gui.ec_tab import ECTab

    tab = ECTab()
    # The patch registry table must be populated from ec_patches.json at build time
    assert tab.patch_combo.count() >= 1
    assert tab.patches_table.rowCount() >= 1


def test_spi_tab_constructs(qapp):
    from bios_recovery.gui.spi_tab import SPITab

    tab = SPITab()
    assert tab.prog_combo.count() >= 1


def test_analysis_runs_through_gui(qapp, intel_ifd):
    """Drive the Overview tab's real analysis-done handler synchronously."""
    from bios_recovery.gui.main_window import MainWindow

    w = MainWindow()
    result = w.bios_analyzer.analyze(intel_ifd)
    w._analysis_done(result)
    assert w.current_bios_info is result
    assert w.regions_table.rowCount() >= 1
    assert "BIOS Type" in w.info_text.toPlainText()
