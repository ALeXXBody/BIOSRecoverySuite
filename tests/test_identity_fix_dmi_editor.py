"""Identity audit fixes for the DMI editor: strict field lengths, fixed size, no no-op success."""

import os
import struct

from bios_recovery.core.dmi_editor import DMIEditor
from bios_recovery.core.smbios import find_table
from tests.fixture_builder import build_intel_ifd_image
from tests.test_dmi_editor import _smbios_fixture


def _write(tmp_path, blob: bytes, name="dump.bin"):
    p = tmp_path / name
    p.write_bytes(blob)
    return str(p)


def test_uuid_with_trailing_whitespace_is_refused(tmp_path):
    blob, _ = _smbios_fixture()
    src = _write(tmp_path, blob)
    out = str(tmp_path / "out.bin")
    rep = DMIEditor().set_identity(src, out, uuid="00112233-4455-6677-8899-aabbccddee  ")
    assert not rep.success
    assert not os.path.exists(out)


def test_mac_with_wrong_length_is_refused_and_size_is_kept(tmp_path):
    blob = build_intel_ifd_image()
    src = _write(tmp_path, blob)
    for bad in ("AA:BB:CC", "AA:BB:CC:DD:EE:FF:00"):
        out = str(tmp_path / "out.bin")
        rep = DMIEditor().set_identity(src, out, mac=bad)
        assert not rep.success, bad
        assert not os.path.exists(out), bad


def test_nul_in_serial_is_refused_and_table_is_intact(tmp_path):
    blob, tlen = _smbios_fixture()
    src = _write(tmp_path, blob)
    out = str(tmp_path / "out.bin")
    rep = DMIEditor().set_identity(src, out, serial="AS3\x00YGD3jB")
    assert not rep.success
    assert not os.path.exists(out)
    assert find_table(blob)[2] == tlen


def test_non_ascii_serial_is_refused_without_exception(tmp_path):
    blob, _ = _smbios_fixture()
    src = _write(tmp_path, blob)
    rep = DMIEditor().set_identity(src, str(tmp_path / "out.bin"), serial="AS3éYGD3jB")
    assert not rep.success
    assert not os.path.exists(tmp_path / "out.bin")


def test_refused_serial_is_not_reported_as_success(tmp_path):
    blob, _ = _smbios_fixture()
    src = _write(tmp_path, blob)
    out = str(tmp_path / "out.bin")
    rep = DMIEditor().set_identity(src, out, serial="SHORT")
    assert not rep.success
    assert not rep.operations
    assert not os.path.exists(out)


def test_mac_edit_works_without_an_smbios_table(tmp_path):
    blob = bytearray(build_intel_ifd_image())
    anchor, _start, _length = find_table(bytes(blob))
    blob[anchor : anchor + 0x1F] = b"\xff" * 0x1F  # remove the entry point: no table is found
    assert find_table(bytes(blob)) is None
    src = _write(tmp_path, bytes(blob))
    out = str(tmp_path / "out.bin")
    rep = DMIEditor().set_identity(src, out, mac="02:11:22:33:44:55")
    assert rep.success, rep.message
    fixed = open(out, "rb").read()
    assert len(fixed) == len(blob)
    assert fixed[0x400000:0x400006] == bytes.fromhex("021122334455")


def test_mac_write_warns_that_gbe_checksum_is_not_recomputed(tmp_path):
    src = _write(tmp_path, build_intel_ifd_image())
    rep = DMIEditor().set_identity(src, str(tmp_path / "out.bin"), mac="02:11:22:33:44:55")
    assert rep.success
    assert any("checksum" in w for w in rep.warnings)


def test_output_equal_to_input_is_refused(tmp_path):
    blob, _ = _smbios_fixture()
    src = _write(tmp_path, blob)
    rep = DMIEditor().set_identity(src, src, serial="AS3ZZZD9kB")
    assert not rep.success
    assert open(src, "rb").read() == blob


def test_size_is_unchanged_after_valid_uuid_and_mac_edit(tmp_path):
    blob = build_intel_ifd_image()
    src = _write(tmp_path, blob)
    out = str(tmp_path / "out.bin")
    rep = DMIEditor().set_identity(
        src, out, uuid="00000000-1111-2222-3333-444455556666", mac="02:11:22:33:44:55"
    )
    assert rep.success, rep.message
    assert len(open(out, "rb").read()) == len(blob)
    assert DMIEditor().info(out)["uuid"] == "00000000111122223333444455556666"


def test_gbe_region_is_found_through_flmap0_frba(tmp_path):
    blob = bytearray(build_intel_ifd_image())
    frba_old, frba_new = 0x40, 0x80
    blob[frba_new : frba_new + 0x10] = blob[frba_old : frba_old + 0x10]
    struct.pack_into("<I", blob, 0x04, 0x00080001)  # FLMAP0: FRBA = 0x80, two regions
    src = _write(tmp_path, bytes(blob))
    out = str(tmp_path / "out.bin")

    rep = DMIEditor().set_identity(src, out, mac="02:11:22:33:44:55")

    assert rep.success, rep.message
    fixed = open(out, "rb").read()
    assert fixed[0x400000:0x400006] == bytes.fromhex("021122334455")
