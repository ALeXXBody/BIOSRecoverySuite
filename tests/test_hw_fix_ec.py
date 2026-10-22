"""Regression tests for the EC patcher audit fixes (EC-1 to EC-13)."""

import json
import random
import time
from pathlib import Path

import pytest

from bios_recovery.platforms.ec.ec_patcher import ECController, ECPatch, ECPatcher, ECStatus

EC_OFF = 0x100000
EC_SIZE = 0x40000


def _dump(start: bytes, total: int = 0x400000) -> bytes:
    """0xFF-padded dump with one 256KB EC-like block at 1MB and marker strings inside."""
    data = bytearray(b"\xff") * total
    rng = random.Random(7)
    ec = bytearray(rng.getrandbits(8) for _ in range(EC_SIZE))
    ec[: len(start)] = start
    ec[0x100:0x109] = b"IT8218VG "
    ec[0x200:0x206] = b"ITE8\x02\x00"
    data[EC_OFF : EC_OFF + EC_SIZE] = ec
    return bytes(data)


GOOD_START = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"


def _registry(tmp_path, patches, raw=None):
    path = tmp_path / "ec_patches.json"
    if raw is not None:
        path.write_bytes(raw)
    else:
        path.write_text(json.dumps({"patches": patches}))
    return str(path)


def _patch(key="p1", sig="5041535357", repl="5858585858", verified=True):
    return {
        "key": key,
        "vendor": "Test",
        "generation": "gen",
        "controller": "ITE",
        "description": "d",
        "signature_hex": sig,
        "patch_hex": repl,
        "verified": verified,
    }


def test_control_dump_is_found():
    assert ECPatcher().find_ec_region(_dump(GOOD_START)) == (EC_OFF, EC_SIZE)


@pytest.mark.parametrize(
    "start",
    [b"$CPD\x01\x02\x03\x04\x05", bytes(8), b"\x01\x00\x00\x00\x01\x00\x00\x00"],
    ids=["cpd", "zeros", "repeated-word"],
)
def test_non_ec_starts_are_not_reported_as_regions(start):
    """EC-1: $CPD (ME) and blank or repeated-word starts are refused, not extracted."""
    data = _dump(start)
    p = ECPatcher()
    assert p.find_ec_region(data) == (-1, -1)
    assert not p.analyze_ec(data).found


def test_auto_extract_message_says_region_is_unvalidated(tmp_path):
    """EC-1: a successful extraction must not claim the region is a verified EC image."""
    src = tmp_path / "dump.bin"
    src.write_bytes(_dump(GOOD_START))
    result = ECPatcher().extract_ec(str(src), str(tmp_path / "out.bin"))
    assert result.status == ECStatus.SUCCESS
    assert "not checked against an EC image format" in result.message


def test_negative_size_is_refused_and_writes_nothing(tmp_path):
    """EC-4: a negative size must not write a truncated file."""
    data = _dump(GOOD_START)
    offset, size, error = ECPatcher().resolve_region(data, 0, -5)
    assert (offset, size) == (-1, -1)
    assert "positive" in error
    src = tmp_path / "dump.bin"
    src.write_bytes(data)
    out = tmp_path / "out.bin"
    result = ECPatcher().extract_ec(str(src), str(out), 0, -5)
    assert result.status == ECStatus.ERROR
    assert not out.exists()


def test_size_larger_than_file_is_refused():
    offset, size, error = ECPatcher().resolve_region(b"\xff" * 0x1000, None, 0x40000)
    assert (offset, size) == (-1, -1)
    assert error


def test_non_numeric_size_returns_error_not_exception():
    """EC-12: a bad size is a returned message, not a ValueError."""
    offset, size, error = ECPatcher().resolve_region(_dump(GOOD_START), None, "abc")
    assert (offset, size) == (-1, -1)
    assert error


def test_apply_patch_refuses_input_as_output(tmp_path):
    """EC-2: an output path equal to the input must not modify the input in place."""
    path = _registry(tmp_path, [_patch(sig="504153535744", repl="585858585858")])
    target = tmp_path / "image.bin"
    original = b"xx" + b"PASSWD" + b"yy"
    target.write_bytes(original)
    result = ECPatcher(path).apply_patch(
        str(target), "p1", output_path=str(target), require_verified=False
    )
    assert result.status == ECStatus.ERROR
    assert target.read_bytes() == original


def test_apply_patch_does_not_overwrite_existing_default_output(tmp_path):
    """EC-2: the default output name must not replace an earlier patched file."""
    path = _registry(tmp_path, [_patch(sig="504153535744", repl="585858585858")])
    src = tmp_path / "image.bin"
    src.write_bytes(b"xx" + b"PASSWD" + b"yy")
    previous = tmp_path / "image_ecpatched.bin"
    previous.write_bytes(b"PRECIOUS")
    result = ECPatcher(path).apply_patch(str(src), "p1", require_verified=False)
    assert result.status == ECStatus.ERROR
    assert previous.read_bytes() == b"PRECIOUS"

    result = ECPatcher(path).apply_patch(str(src), "p1", require_verified=False, overwrite=True)
    assert result.status == ECStatus.SUCCESS
    assert previous.read_bytes() == b"xx" + b"XXXXXX" + b"yy"


def test_extract_refuses_existing_output_unless_overwrite(tmp_path):
    """EC-2: extract_ec must not replace a user file silently."""
    src = tmp_path / "dump.bin"
    src.write_bytes(_dump(GOOD_START))
    keep = tmp_path / "keep_ec.bin"
    keep.write_bytes(b"PRECIOUS")
    patcher = ECPatcher()
    result = patcher.extract_ec(str(src), str(keep))
    assert result.status == ECStatus.ERROR
    assert keep.read_bytes() == b"PRECIOUS"

    result = patcher.extract_ec(str(src), str(keep), overwrite=True)
    assert result.status == ECStatus.SUCCESS
    assert keep.read_bytes() == _dump(GOOD_START)[EC_OFF : EC_OFF + EC_SIZE]


def test_apply_patch_refuses_empty_signature(tmp_path):
    """EC-8: an empty signature must not report success with no change."""
    path = _registry(tmp_path, [_patch(sig="", repl="")])
    src = tmp_path / "image.bin"
    src.write_bytes(b"abc")
    result = ECPatcher(path).apply_patch(str(src), "p1", require_verified=False)
    assert result.status == ECStatus.ERROR
    assert not (tmp_path / "image_ecpatched.bin").exists()


def test_apply_patch_refuses_ambiguous_signature(tmp_path):
    """EC-8: a signature found twice is not patched at the first hit."""
    path = _registry(tmp_path, [_patch(sig="41", repl="58")])
    src = tmp_path / "image.bin"
    src.write_bytes(b"A..A..")
    result = ECPatcher(path).apply_patch(
        str(src), "p1", output_path=str(tmp_path / "out.bin"), require_verified=False
    )
    assert result.status == ECStatus.ERROR
    assert "2 places" in result.message
    assert not (tmp_path / "out.bin").exists()


def test_scan_patch_sites_missing_or_directory_raises_value_error(tmp_path):
    """EC-7: a bad path is a typed ValueError, not an OSError traceback."""
    patcher = ECPatcher()
    with pytest.raises(ValueError):
        patcher.scan_patch_sites(str(tmp_path / "missing.bin"))
    with pytest.raises(ValueError):
        patcher.scan_patch_sites(str(tmp_path))


def test_extract_bad_paths_return_error_status(tmp_path):
    """EC-7: missing input, directory input and unwritable output are ERROR results."""
    patcher = ECPatcher()
    missing = patcher.extract_ec(str(tmp_path / "nope.bin"), str(tmp_path / "out.bin"))
    assert missing.status == ECStatus.ERROR
    src = tmp_path / "dump.bin"
    src.write_bytes(_dump(GOOD_START))
    directory = patcher.extract_ec(str(tmp_path), str(tmp_path / "out2.bin"))
    assert directory.status == ECStatus.ERROR
    bad_out = patcher.extract_ec(str(src), str(tmp_path / "no_such_dir" / "out.bin"))
    assert bad_out.status == ECStatus.ERROR


def test_truncated_registry_is_reported_and_not_overwritten(tmp_path):
    """EC-6: a damaged registry is flagged, and install_patch must not replace it."""
    path = _registry(tmp_path, None, raw=b'{"patches": [{"key": "half')
    patcher = ECPatcher(path)
    assert patcher.load_error and "damaged" in patcher.load_error
    before = Path(path).read_bytes()
    with pytest.raises(ValueError):
        patcher.install_patch(
            ECPatch(
                key="new",
                vendor="v",
                generation="g",
                controller="ITE",
                description="d",
                signature_hex="41",
                patch_hex="42",
            )
        )
    assert Path(path).read_bytes() == before


@pytest.mark.parametrize(
    "raw",
    [b'{"patches": [5]}', b"null", b'"x"', b"\xff\xfe\x00bad"],
    ids=["non-dict-items", "null", "string", "non-utf8"],
)
def test_malformed_registry_does_not_crash(tmp_path, raw):
    """EC-6: the constructor must not raise on a malformed registry."""
    path = _registry(tmp_path, None, raw=raw)
    patcher = ECPatcher(path)
    assert isinstance(patcher.list_patches(), list)


def test_controller_label_needs_two_vendor_tokens():
    """EC-3: a lone 2-byte reporter token is not a controller label."""
    p = ECPatcher()
    assert p._controller_evidence(b"\x00\x80\x04\x00" * 4)[0] == ECController.UNKNOWN
    controller, tokens = p._controller_evidence(b"xx IT8218VG yy ITE8 zz")
    assert controller == ECController.ITE
    assert "IT8218" in tokens and "ITE" in tokens


def test_list_patches_controller_filter_matches_registry_family():
    """EC-11: ITE4532 and NPCE entries are not dropped by the controller filter."""
    p = ECPatcher()
    expected = [x for x in p.list_patches() if x.controller.upper().startswith("ITE")]
    assert expected
    assert p.list_patches(controller=ECController.ITE) == expected
    nuvoton = [x for x in p.list_patches() if x.controller.upper().startswith("NPC")]
    assert p.list_patches(controller=ECController.NUVOTON) == nuvoton


def test_default_output_path_for_extensionless_input(tmp_path):
    """EC-12: the default name stays in the input's folder when the input has no extension."""
    folder = tmp_path / "a.b"
    folder.mkdir()
    path = _registry(tmp_path, [_patch(sig="504153535744", repl="585858585858")])
    src = folder / "dump"
    src.write_bytes(b"xx" + b"PASSWD" + b"yy")
    result = ECPatcher(path).apply_patch(str(src), "p1", require_verified=False)
    assert result.status == ECStatus.SUCCESS
    assert result.output_path == str(folder / "dump_ecpatched.bin")


def test_region_apis_agree_on_one_file():
    """EC-9: find_ec_region, find_ec_region_end and end-anchored resolution agree."""
    data = _dump(GOOD_START)
    p = ECPatcher()
    offset, size = p.find_ec_region(data)
    assert (offset, size) == (EC_OFF, EC_SIZE)
    assert p.find_ec_region_end(data) == offset + size
    assert p.resolve_region(data, None, size)[:2] == (offset, size)


def test_dense_markers_are_scored_quickly():
    """EC-5: a dense run of short markers is scored in bounded time."""
    data = b"IT85" * 16384 + b"\xff" * 0x20000
    start = time.monotonic()
    ECPatcher().find_ec_region(data)
    assert time.monotonic() - start < 20
