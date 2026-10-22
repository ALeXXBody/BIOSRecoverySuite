"""Deep GUI exercise: call every tab handler headlessly with a fixture loaded.

Stubs all modal dialogs so nothing blocks, and flushes runtime attribute /
wiring bugs that construction-only smoke tests cannot see.
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


@pytest.fixture
def dialogs(monkeypatch):
    """Stub every modal dialog used across the app."""
    from PySide6.QtWidgets import QFileDialog, QInputDialog, QMessageBox

    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "critical", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "about", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: ("", ""))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: ("", ""))
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *a, **k: "")
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: ("I understand", True))


@pytest.fixture
def window(qapp, dialogs):
    from bios_recovery.gui.main_window import MainWindow

    return MainWindow()


def open_via_dialog(monkeypatch, window, path):
    """Route open_file()'s dialog to a concrete fixture path."""
    from PySide6.QtWidgets import QFileDialog

    monkeypatch.setattr(
        QFileDialog, "getOpenFileName", lambda *a, **k: (path, "BIOS Files (*.bin)")
    )
    window.open_file()


def _wait_threads(window, max_ms=30000):
    """Let WorkerThreads finish AND spin the event loop so their queued
    result signals actually reach the UI handlers."""
    import time

    from PySide6.QtCore import QThread
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()

    def running():
        pool = list(window.__dict__.values())
        pool.extend(getattr(window, "_threads", []))
        return [t for t in pool if isinstance(t, QThread) and t.isRunning()]

    deadline = time.time() + max_ms / 1000
    while time.time() < deadline:
        app.processEvents()
        if not running():
            break
        time.sleep(0.02)
    for _ in range(20):
        app.processEvents()
        time.sleep(0.02)


def test_open_fixture_and_run_analysis(window, intel_ifd, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.run_analysis()
    _wait_threads(window)
    assert window.regions_table.rowCount() >= 1


def test_repair_flow(window, intel_ifd, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.run_repair()
    _wait_threads(window)
    out = intel_ifd.rsplit(".", 1)[0] + "_repaired.bin"
    assert os.path.exists(out), "repair engine produced no output"
    assert (
        "Success" in window.repair_text.toPlainText()
        or "Failed" in window.repair_text.toPlainText()
    )


def test_me_info_and_clean(window, intel_ifd, tmp_path, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.show_me_info()
    _wait_threads(window)
    window.clean_me()
    _wait_threads(window)
    out = intel_ifd.rsplit(".", 1)[0] + "_cleaned.bin"
    assert os.path.exists(out), "ME cleaner produced no output"
    assert "Status:" in window.me_text.toPlainText()


def test_me_inject_with_valid_clean_image(window, intel_ifd, tmp_path, monkeypatch):
    import struct

    open_via_dialog(monkeypatch, window, intel_ifd)
    clean = tmp_path / "clean_me.bin"
    blob = bytearray(bytes((i * 13 + 7) & 0xFF for i in range(0x3FF000)))
    blob[0x10:0x14] = b"$FPT"
    blob[0x5000:0x5004] = b"$MN2"
    struct.pack_into("<HH", blob, 0x5004, 9, 5)
    clean.write_bytes(bytes(blob))
    window.me_clean_file.setText(str(clean))
    window.inject_me()
    _wait_threads(window)
    assert os.path.exists(str(intel_ifd).rsplit(".", 1)[0] + "_mefixed.bin")


def test_dmi_extract_and_clone(window, intel_ifd, tmp_path, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.extract_dmi()
    _wait_threads(window)
    other = tmp_path / "new.bin"
    other.write_bytes(open(intel_ifd, "rb").read())
    window.clone_new_edit.setText(str(other))
    window.clone_dmi()
    _wait_threads(window)
    assert os.path.exists(str(other).rsplit(".", 1)[0] + "_dmiclone.bin")


def test_password_scan_remove_and_hp(window, intel_ifd, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.scan_passwords()
    _wait_threads(window)
    window.remove_passwords()
    _wait_threads(window)
    window.hp_unlock()
    _wait_threads(window)
    assert "Output" in window.password_text.toPlainText()


def test_extract_bios_flow(window, intel_ifd, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.extract_bios()
    _wait_threads(window)


def test_hex_view(window, intel_ifd, monkeypatch):
    open_via_dialog(monkeypatch, window, intel_ifd)
    window.hex_offset.setText("0")
    window.hex_length.setText("64")
    window.view_hex()
    assert window.hex_text.toPlainText().strip() != ""


def test_generate_passwords_every_generator(window):
    from bios_recovery.utils import master_passwords as mp

    samples = {
        "phoenix_5dec": "12345",
        "fsi_hex": "DEADBEEF",
        "fsi_6x4dec": "1234-4321-1234-4321-1234",
        "insyde_8dec": "03133610",
        "samsung": "07088120410C0000",
        "sony_4x4": "73KR-3FP9-PVKH-K29R",
        "hp_mini": "CNU1234ABC",
        "asus_date": "2013-12-31",
    }
    for key in mp.GENERATORS:
        idx = window._gen_keys.index(key)
        window.gen_generator.setCurrentIndex(idx)
        window.gen_input.setText(samples[key])
        window.generate_passwords()
        text = window.gen_text.toPlainText()
        assert "Could not generate" not in text, key
        assert ":" in text, f"no results rendered for {key}"


def test_ec_tab_full_flow(window, ec_dump, tmp_path, monkeypatch):
    tab = window.ec_tab
    tab.current_dump = ec_dump
    tab.ec_file.setText(ec_dump)
    tab.analyze()
    assert "EC firmware found" in tab.analysis_text.toPlainText()

    tab.extract_path.setText(str(tmp_path / "ec_out.bin"))
    tab.extract_ec()
    assert os.path.exists(str(tmp_path / "ec_out.bin"))

    # every registry patch can be force-applied or safely refused
    for i in range(tab.patch_combo.count()):
        tab.patch_combo.setCurrentIndex(i)
        tab.apply_patch()


def test_lenovo_tab_full_flow(window, uefi_patch_image, tmp_path):
    tab = window.lenovo_tab
    tab.set_file(uefi_patch_image)
    tab.run_detect()
    tab.run_scan()
    from PySide6.QtCore import Qt

    for i in range(tab.groups_table.rowCount()):
        tab.groups_table.item(i, 0).setCheckState(Qt.Checked)
    tab.apply_patches()
    assert os.path.exists(uefi_patch_image.rsplit(".", 1)[0] + "_patched.bin")

    # DXE apply with empty registry must not crash
    tab.dxe_consent.setChecked(True)
    tab.apply_dxe()
    tab.run_full_autopatch()


def test_spi_tab_paths(window, tmp_path):
    tab = window.spi_tab
    # missing paths -> warnings, no crash
    tab.read_chip()
    tab.write_chip()
    tab.erase_chip()


def test_menu_and_about(window, monkeypatch):
    from bios_recovery.gui.update_dialog import UpdateDialog

    monkeypatch.setattr(UpdateDialog, "exec", lambda self: None)
    window.show_about()
    window.check_for_updates()


# ---------------------------------------------------------------------------
# EC tab: manual region override (the safety net for a wrong auto-detect)
# ---------------------------------------------------------------------------


def _ec_dump_with_hidden_region(path):
    """A dump where auto-detection finds nothing (all 0xFF), so the ONLY way
    to extract is the manual override. Mirrors boards that store EC firmware
    in a way the heuristics cannot recognise."""
    with open(path, "wb") as f:
        f.write(b"\xff" * 0x10000 + bytes(range(256)) * 1024)
    return path


def test_ec_tab_manual_override_extracts(qapp, dialogs, tmp_path, monkeypatch):
    """Checking the override box + filling offset/size must drive extraction."""
    from bios_recovery.gui.ec_tab import ECTab

    dump = _ec_dump_with_hidden_region(str(tmp_path / "ec_hidden.bin"))
    out = str(tmp_path / "ec_out.bin")

    tab = ECTab()
    tab.current_dump = dump
    tab.extract_path.setText(out)

    # auto-detect alone must find nothing in this dump
    tab.analyze()
    assert "No EC firmware" in tab.analysis_text.toPlainText()

    # now pin the region by hand
    tab.override_check.setChecked(True)
    tab.override_offset.setText("10000")
    tab.override_size.setCurrentText("0x40000 (256 KB)")

    tab.extract_ec()
    assert os.path.exists(out), "override extract produced no file"
    with open(out, "rb") as f:
        got = f.read()
    assert len(got) == 0x40000, f"wrote {len(got)} bytes, expected 0x40000"
    assert got == bytes(range(256)) * 1024


def test_ec_tab_override_analyze_reports_manual(qapp, dialogs, tmp_path):
    """Analysis under override must succeed and flag that it was manual."""
    from bios_recovery.gui.ec_tab import ECTab

    dump = _ec_dump_with_hidden_region(str(tmp_path / "ec_hidden2.bin"))
    tab = ECTab()
    tab.current_dump = dump
    tab.override_check.setChecked(True)
    tab.override_offset.setText("10000")
    tab.override_size.setCurrentText("0x40000 (256 KB)")

    tab.analyze()
    text = tab.analysis_text.toPlainText()
    assert "Offset: 0x10000" in text, text
    assert "0x40000" in text, text
    assert "manual chip size active" in text, text


def test_ec_tab_blank_offset_anchors_at_region_end(qapp, dialogs, tmp_path):
    """The regression fix: chip capacity is known, the exact offset is not.

    The reported failure was a 256KB IT8218VG being detected as 128KB, so a
    truncated 128KB image got written. The user must be able to state the
    capacity and have the region placed at its detected end -- that yields the
    full 256KB without needing to know the offset by heart.
    """
    import random

    from bios_recovery.gui.ec_tab import ECTab

    random.seed(99)
    total = 0x2000000
    ec_size = 0x40000
    ec_off = total - ec_size
    data = bytearray(random.getrandbits(8) for _ in range(total))
    data[ec_off - 0x100000 : ec_off] = b"\xff" * 0x100000
    ec = bytearray(random.getrandbits(8) for _ in range(ec_size))
    ec[0x0000:0x0004] = b"\xaa\x55\xaa\x55"
    ec[0x20000:0x20009] = b"IT8218VG "  # markers in the SECOND HALF
    ec[0x20100:0x20106] = b"ITE8\x02\x00"
    data[ec_off:] = ec
    dump = str(tmp_path / "ec_256k.bin")
    with open(dump, "wb") as f:
        f.write(bytes(data))
    out = str(tmp_path / "ec_256k_out.bin")

    tab = ECTab()
    tab.current_dump = dump
    tab.extract_path.setText(out)

    tab.override_check.setChecked(True)
    tab.override_offset.setText("")  # blank -> anchor at region end
    tab.override_size.setCurrentText("0x40000 (256 KB)")

    assert tab._override_region() == (None, 0x40000)

    tab.extract_ec()
    with open(out, "rb") as f:
        got = f.read()
    assert len(got) == 262144, f"wrote {len(got)} bytes, expected 262144"
    assert got == bytes(data)[ec_off : ec_off + ec_size]
    assert b"IT8218VG" in got


def test_ec_tab_unchecked_override_uses_auto(qapp, dialogs, tmp_path):
    """Unticking the box must fall back to auto-detection, not keep the size."""
    from bios_recovery.gui.ec_tab import ECTab

    tab = ECTab()
    tab.override_check.setChecked(False)
    tab.override_offset.setText("10000")
    tab.override_size.setCurrentText("0x80000 (512 KB)")
    assert tab._override_region() == (None, None)


def test_ec_tab_bad_hex_offset_is_rejected_safely(qapp, dialogs, tmp_path):
    """A typo in the offset box must not crash the tab or extract garbage."""
    from bios_recovery.gui.ec_tab import ECTab

    dump = _ec_dump_with_hidden_region(str(tmp_path / "ec_hidden3.bin"))
    out = str(tmp_path / "ec_bad.bin")

    tab = ECTab()
    tab.current_dump = dump
    tab.extract_path.setText(out)
    tab.override_check.setChecked(True)
    tab.override_offset.setText("ZZZZ")  # invalid hex

    tab.extract_ec()  # must not raise
    assert not os.path.exists(out), "invalid offset must not produce a file"
