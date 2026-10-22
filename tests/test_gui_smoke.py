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
    for expected in [
        "Overview",
        "Repair",
        "ME Region",
        "DMI",
        "Security",
        "Extract",
        "Flash & Hex",
        "EC Patching",
        "Lenovo Unlock",
    ]:
        assert expected in titles, f"missing tab: {expected}"
    assert "Passwords" not in titles, "password generator must live on the Security page"
    assert hasattr(w, "gen_input") and hasattr(w, "password_text")
    assert not hasattr(w, "repair_me_ck"), "ME cleaning must not be duplicated in Repair"


def test_lenovo_tab_scan_and_apply(qapp, uefi_patch_image, tmp_path, monkeypatch):
    """Full Lenovo tab flow against the synthetic patched-driver fixture."""
    from PySide6.QtWidgets import QMessageBox

    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)

    from bios_recovery.gui.lenovo_tab import LenovoTab

    tab = LenovoTab()
    tab.current_dump = uefi_patch_image
    tab.run_scan()
    assert tab.groups_table.rowCount() >= 4
    total_matches = sum(
        int(tab.groups_table.item(i, 2).text()) for i in range(tab.groups_table.rowCount())
    )
    assert total_matches >= 3

    tab.run_detect()
    assert "Lenovo firmware detected: YES" in tab.detect_text.toPlainText()

    # select every group and apply
    from PySide6.QtCore import Qt

    for i in range(tab.groups_table.rowCount()):
        tab.groups_table.item(i, 0).setCheckState(Qt.Checked)
    tab.apply_patches()
    out = uefi_patch_image.rsplit(".", 1)[0] + "_patched.bin"
    assert os.path.exists(out)


def test_lenovo_tab_dxe_registry_populates(qapp):
    from bios_recovery.gui.lenovo_tab import LenovoTab

    tab = LenovoTab()
    assert tab.dxe_table.columnCount() == 5
    assert isinstance(tab._dxe_entries, list)


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
