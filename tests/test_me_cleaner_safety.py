"""ME cleaner: exact partition ranges, truncation point, overwrite refusal, descriptor layout."""

import struct

from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner, MeCleanResult


def _cleaner():
    return IntelMECleaner()


def test_partition_removal_zeroes_exactly_the_partition():
    data = bytearray(b"\x11" * 0x10000)
    entries = [(b"FTPR", 0x1000, 0x2000), (b"NFTP", 0x4000, 0x100)]
    removed = _cleaner()._remove_non_essential_partitions(
        data, 0, entries, (b"FTPR", 0x1000, 0x2000)
    )
    assert removed == 1
    assert data[0x4000:0x4100] == b"\xff" * 0x100
    assert data[0x4100] == 0x11 and data[0x3FFF] == 0x11  # neighbours untouched
    assert data[0x1000:0x3000] == b"\x11" * 0x2000  # FTPR untouched


def test_partition_overlapping_ftpr_is_never_removed():
    data = bytearray(b"\x22" * 0x10000)
    entries = [(b"FTPR", 0x1000, 0x2000), (b"XXXX", 0x2800, 0x100)]
    removed = _cleaner()._remove_non_essential_partitions(
        data, 0, entries, (b"FTPR", 0x1000, 0x2000)
    )
    assert removed == 0
    assert data[0x2800:0x2900] == b"\x22" * 0x100


def test_truncation_ends_after_ftpr_not_at_its_size():
    data = bytearray(b"\x33" * 0x40000)
    ftpr = (b"FTPR", 0x3000, 0x20000)
    _cleaner()._truncate_me(data, 0x0, [ftpr], ftpr)
    assert len(data) == 0x23000


def test_clean_refuses_output_over_input(tmp_path):
    src = tmp_path / "dump.bin"
    src.write_bytes(b"\xff" * 0x1000)
    report = _cleaner().clean(str(src), str(src))
    assert report.status == MeCleanResult.ERROR
    assert src.read_bytes() == b"\xff" * 0x1000


def test_flreg_is_read_from_the_frba_table(tmp_path):
    # Real layout: descriptor at 0x10, FRBA 0x40 from the start of the image (FLMAP0 at fd+4,
    # as ifdtool find_frba), ME entry = FRBA+8. All offsets are absolute.
    fd = 0x10
    data = bytearray(b"\xff" * 0x400000)
    data[fd : fd + 4] = b"\x5a\xa5\xf0\x0f"
    struct.pack_into("<I", data, fd + 0x04, 0x00040003)  # FRBA = 0x40
    frba = 0x40
    struct.pack_into("<I", data, frba + 0x08, 0x03FF0001)  # ME: base 1 page, limit 0x3FF
    data[0x1000:0x1010] = b"\x00" * 0x10  # the region is not blank
    me_start, me_end, _gen = _cleaner()._me_region_from_flreg(data, fd)
    assert me_start == 0x1000
    assert me_end == len(data)  # limit runs past the image: clamped to its size
