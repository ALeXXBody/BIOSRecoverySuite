"""Tests for the badcaps-style autopatch flow (real driver binaries)."""

import os

from bios_recovery.engines.uefi_patcher import UEFIPatcher
from tests.fixture_builder import AUTOpatch_BOOTOPTION_GUID, AUTOpatch_TRANSLATE_GUID

DXE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bios_recovery", "patches", "dxe"
)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def test_real_binaries_present():
    for name in [
        "E0746C42-D3F9-4F8B-B211-1410957B9FF5.ffs",
        "826BCF56-BAC4-43F4-8EA1-8CDF0A121ABD.ffs",
        "NVRAM_EfiSystemNvDataFvGuid.vol",
    ]:
        path = os.path.join(DXE_DIR, name)
        assert os.path.exists(path), name
        assert os.path.getsize(path) > 0


def test_registry_has_autopatch_entries(patcher):
    entries = patcher.load_dxe_replacements()
    guids = {e["target_guid"] for e in entries}
    assert AUTOpatch_BOOTOPTION_GUID in guids
    assert AUTOpatch_TRANSLATE_GUID in guids


def test_replace_with_real_bootoption_driver(patcher, autopatch_image, tmp_path):
    out = str(tmp_path / "replaced.bin")
    driver = os.path.join(DXE_DIR, f"{AUTOpatch_BOOTOPTION_GUID}.ffs")
    res = patcher.replace_ffs_file(autopatch_image, out, AUTOpatch_BOOTOPTION_GUID, driver)
    assert res["success"], res["message"]

    p = UEFIPatcher(patcher.patches_path)
    files = {f.guid: f for f in p.iter_files(_read(out))}
    assert AUTOpatch_BOOTOPTION_GUID in files
    assert AUTOpatch_TRANSLATE_GUID in files
    # replacement body is the real patched driver verbatim
    target = files[AUTOpatch_BOOTOPTION_GUID]
    blob = _read(out)[target.off + 0x18 : target.off + target.size]
    assert blob == _read(driver)[0x18:]


def test_nvram_volume_replaced(patcher, autopatch_image, tmp_path):
    out = str(tmp_path / "nvram.bin")
    vol = os.path.join(DXE_DIR, "NVRAM_EfiSystemNvDataFvGuid.vol")
    res = patcher.replace_nvram_volume(autopatch_image, out, vol)
    assert res["success"], res["message"]
    before = _read(autopatch_image)
    after = _read(out)
    assert before != after
    # header must be untouched, body must now match the clean image
    off = res["offset"]
    assert before[off : off + 0x48] == after[off : off + 0x48]
    assert after[off + 0x48 : off + 0x148] == _read(vol)[0x48:0x148]
    assert before[off + 0x48 : off + 0x148] != after[off + 0x48 : off + 0x148]


def test_nvram_skips_on_checksum_mismatch(patcher, autopatch_image, tmp_path):
    # tamper one checksum byte inside the fixture's NVRAM header
    tampered = bytearray(_read(autopatch_image))
    pos = tampered.find(_read(os.path.join(DXE_DIR, "NVRAM_EfiSystemNvDataFvGuid.vol"))[:48])
    tampered[pos + 0x32] ^= 0xFF
    tpath = str(tmp_path / "tampered.bin")
    with open(tpath, "wb") as f:
        f.write(bytes(tampered))

    out = str(tmp_path / "nvram.bin")
    vol = os.path.join(DXE_DIR, "NVRAM_EfiSystemNvDataFvGuid.vol")
    res = patcher.replace_nvram_volume(tpath, out, vol)
    assert not res["success"]
    assert res.get("skipped")
    assert "checksum" in res["message"]
    assert _read(out) == bytes(tampered)  # untouched


def test_full_autopatch_flow(patcher, autopatch_image, tmp_path):
    out = str(tmp_path / "PATCHED.bin")
    report = patcher.run_autopatch(autopatch_image, out)
    assert report["success"]
    ok_steps = {s["step"] for s in report["steps"] if s["ok"]}
    assert "autopatch_bootoption" in ok_steps
    assert "autopatch_translate_service" in ok_steps

    p = UEFIPatcher(patcher.patches_path)
    patched = _read(out)
    files = {f.guid: f for f in p.iter_files(patched)}
    assert AUTOpatch_BOOTOPTION_GUID in files
    assert AUTOpatch_TRANSLATE_GUID in files
    # the NVRAM body was replaced with the clean store (marker bytes gone)
    vol = _read(os.path.join(DXE_DIR, "NVRAM_EfiSystemNvDataFvGuid.vol"))
    nv_off = patched.find(vol[:48])
    assert nv_off > 0
    assert patched[nv_off + 0x48 : nv_off + 0x148] == vol[0x48:0x148]
    assert b"\x5a" * 0x100 not in patched


def test_autopatch_idempotent(patcher, autopatch_image, tmp_path):
    once = str(tmp_path / "once.bin")
    patcher.run_autopatch(autopatch_image, once)
    twice = str(tmp_path / "twice.bin")
    patcher.run_autopatch(once, twice)
    assert _read(once) == _read(twice)
