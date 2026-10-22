"""Tests for the UEFIPatch-compatible pattern engine and DXE replacement."""

import lzma

from bios_recovery.platforms.intel.uefi_patcher import UEFIPatcher
from tests.fixture_builder import (
    ADV_PATTERN,
    ADV_REPLACEMENT,
    TAMPER_MARKER,
    UEFI_PATCH_OTHER_GUID,
    UEFI_PATCH_TARGET_GUID,
    WW_PATTERN,
)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def test_registry_loaded(patcher):
    keys = [g["key"] for g in patcher.groups]
    assert "xx30_wlan_whitelist" in keys
    assert "xx60_xx80_advanced_menu" in keys
    assert "xx60_xx80_wwan_whitelist" in keys
    assert "xx40_plus_tamper_fix" in keys
    for g in patcher.groups:
        assert g["lines"], f"group {g['key']} has no parsed lines"


def test_scan_finds_all_patterns(patcher, uefi_patch_image):
    scan = patcher.scan(uefi_patch_image)
    assert scan["xx60_xx80_advanced_menu"]["matches"] >= 1  # inside LZMA
    assert scan["xx60_xx80_wwan_whitelist"]["matches"] >= 1  # raw PE32
    assert scan["xx40_plus_tamper_fix"]["matches"] >= 1  # global scope
    assert scan["xx30_wlan_whitelist"]["matches"] == 0  # not in fixture


def test_parse_finds_files_in_lzma(patcher, uefi_patch_image):
    files = {f.guid: f for f in patcher.iter_files(_read(uefi_patch_image))}
    assert UEFI_PATCH_TARGET_GUID in files
    assert UEFI_PATCH_OTHER_GUID in files


def test_apply_patches_lzma_and_raw(patcher, uefi_patch_image, tmp_path):
    out = str(tmp_path / "patched.bin")
    report = patcher.apply(uefi_patch_image, out)
    assert report["matches_total"] >= 3

    patched = _read(out)

    # 1) advanced-menu pattern patched INSIDE the LZMA container
    p = UEFIPatcher(patcher.patches_path)
    files = {f.guid: f for f in p.iter_files(patched)}
    target = files[UEFI_PATCH_TARGET_GUID]
    lzma_sec = next(s for s in target.sections if s.comp == "lzma")
    inner = bytes(
        lzma.decompress(
            patched[lzma_sec.off + 0x18 : lzma_sec.off + lzma_sec.hdr_size + lzma_sec.body_size],
            format=lzma.FORMAT_ALONE,
        )
    )
    assert ADV_REPLACEMENT in inner
    assert ADV_PATTERN not in inner

    # 2) whitelist pattern patched in the raw file
    other = files[UEFI_PATCH_OTHER_GUID]
    body = patched[other.off + other.hdr_size : other.off + other.size]
    assert WW_PATTERN not in body
    assert bytes.fromhex("C8390B7400") in body

    # 3) tamper marker flipped globally
    assert TAMPER_MARKER not in patched
    assert bytes.fromhex("4C4E564242534543FF") in patched

    # 4) sibling file C survived the splice with identical bytes
    assert patched[:0x48] == _read(uefi_patch_image)[:0x48]  # FV header intact
    c_guid = "6F6D2D0C-C56A-4C4F-9E5A-2B3A0F97C2B1"
    c = {f.guid: f for f in p.iter_files(patched)}[c_guid]
    orig_c = {f.guid: f for f in p.iter_files(_read(uefi_patch_image))}[c_guid]
    assert (
        patched[c.off : c.off + c.size]
        == _read(uefi_patch_image)[orig_c.off : orig_c.off + orig_c.size]
    )


def test_file_checksums_valid_after_patch(patcher, uefi_patch_image, tmp_path):
    out = str(tmp_path / "patched.bin")
    patcher.apply(uefi_patch_image, out)
    patched = _read(out)
    for f in UEFIPatcher(patcher.patches_path).iter_files(patched):
        hdr = patched[f.off : f.off + 0x18]
        probe = bytearray(hdr)
        probe[0x10] = 0
        probe[0x11] = 0
        probe[0x17] = 0
        assert (sum(probe) + hdr[0x10]) & 0xFF == 0, f"header checksum broken at {hex(f.off)}"
        if f.attrs & 0x40:
            body = patched[f.off + 0x18 : f.off + f.size]
            assert (sum(body) + hdr[0x11]) & 0xFF == 0, f"file checksum broken at {hex(f.off)}"


def test_apply_is_noop_for_nonmatching_groups(patcher, uefi_patch_image, tmp_path):
    out = str(tmp_path / "patched.bin")
    report = patcher.apply(uefi_patch_image, out, group_keys=["xx30_wlan_whitelist"])
    assert report["matches_total"] == 0
    assert _read(out) == _read(uefi_patch_image)


def test_dxe_replacement_roundtrip(patcher, uefi_patch_image, tmp_path):
    """Replace the DRIVER file with a different-size PE blob; FV must stay valid."""
    out = str(tmp_path / "replaced.bin")
    driver = b"MZ" + bytes(range(256)) * 3  # ~770 bytes vs ~400 byte original
    driver_path = str(tmp_path / "patched_driver.efi")
    with open(driver_path, "wb") as f:
        f.write(driver)
    res = patcher.replace_ffs_file(uefi_patch_image, out, UEFI_PATCH_TARGET_GUID, driver_path)
    assert res["success"], res["message"]

    replaced = _read(out)
    p = UEFIPatcher(patcher.patches_path)
    files = {f.guid: f for f in p.iter_files(replaced)}
    # all three files still present
    assert UEFI_PATCH_TARGET_GUID in files
    assert UEFI_PATCH_OTHER_GUID in files
    assert "6F6D2D0C-C56A-4C4F-9E5A-2B3A0F97C2B1" in files

    # replacement content is exactly wrapped driver
    target = files[UEFI_PATCH_TARGET_GUID]
    body = replaced[target.off + 0x18 : target.off + target.size]
    assert driver in body

    # sibling C byte-identical
    orig_c = {f.guid: f for f in p.iter_files(_read(uefi_patch_image))}[
        "6F6D2D0C-C56A-4C4F-9E5A-2B3A0F97C2B1"
    ]
    new_c = files["6F6D2D0C-C56A-4C4F-9E5A-2B3A0F97C2B1"]
    assert (
        replaced[new_c.off : new_c.off + new_c.size]
        == _read(uefi_patch_image)[orig_c.off : orig_c.off + orig_c.size]
    )


def test_replace_missing_guid_fails(patcher, uefi_patch_image, tmp_path):
    driver = tmp_path / "drv.bin"
    driver.write_bytes(b"MZdata")
    res = patcher.replace_ffs_file(
        uefi_patch_image,
        str(tmp_path / "x.bin"),
        "00000000-0000-0000-0000-000000000000",
        str(driver),
    )
    assert not res["success"]


def test_derive_replacements_from_pair(patcher, uefi_patch_image, tmp_path):
    """Simulate the badcaps flow: original + autopatched dump -> derived entry."""
    patched_path = str(tmp_path / "autopatched.bin")
    patcher.apply(uefi_patch_image, patched_path)

    derived = patcher.derive_replacements(uefi_patch_image, patched_path, str(tmp_path / "drv"))
    guids = {d["target_guid"] for d in derived}
    assert UEFI_PATCH_TARGET_GUID in guids
    assert UEFI_PATCH_OTHER_GUID in guids

    # re-applying every derived .ffs onto the original must reproduce the
    # patched image exactly (that is the whole point of the autopatch flow)
    work = uefi_patch_image
    for d in derived:
        out = str(tmp_path / f"reapplied_{d['key']}.bin")
        res = patcher.replace_ffs_file(
            work, out, d["target_guid"], str(tmp_path / "drv" / d["file"])
        )
        assert res["success"], res["message"]
        work = out
    assert _read(work) == _read(patched_path)


def test_detect_lenovo(patcher, uefi_patch_image):
    det = patcher.detect_lenovo(uefi_patch_image)
    assert det["is_lenovo"]
    assert det["tamper_marker"] is not None
    assert not det["tamper_already_patched"]
    names = {d["name"] for d in det["drivers"]}
    assert "LenovoWmaPolicyDxe" not in names  # driver has no name strings in fixture


def test_list_files_reports_names(patcher, uefi_patch_image):
    files = patcher.list_files(uefi_patch_image)
    guids = {f["guid"] for f in files}
    assert UEFI_PATCH_TARGET_GUID in guids


def test_global_scope_patch(patcher, uefi_patch_image, tmp_path):
    out = str(tmp_path / "tamper.bin")
    patcher.apply(uefi_patch_image, out, group_keys=["xx40_plus_tamper_fix"])
    data = _read(out)
    assert bytes.fromhex("4C4E564242534543FF") in data
    assert TAMPER_MARKER not in data
    # nothing else changed
    original = bytearray(_read(uefi_patch_image))
    idx = original.find(TAMPER_MARKER)
    original[idx : idx + 9] = bytes.fromhex("4C4E564242534543FF")
    assert bytes(original) == data
