"""Regression tests for the ME cleaner findings in the Intel audit (H3-H6, M2, M6, M8, L1, L4).

Each image is synthetic. Partition offsets are relative to the ME region base, as in
me_cleaner; a table at 0x10 belongs to a standalone ME image with base 0.
"""

import struct

from bios_recovery.platforms.intel.me.me_cleaner import IntelMECleaner, MeCleanResult, MeGeneration

SIG = b"\x5a\xa5\xf0\x0f"


def _manifest(data, ftpr, version=(9, 0, 0, 1000)):
    data[ftpr : ftpr + 4] = b"$MN2"
    struct.pack_into("<HHHH", data, ftpr + 8, *version)


def _fpt(data, base, entries, header_version=0x20):
    data[base : base + 4] = b"$FPT"
    struct.pack_into("<I", data, base + 4, len(entries))
    data[base + 8] = header_version
    for i, (name, off, size) in enumerate(entries):
        e = base + 0x20 + i * 0x20
        data[e : e + 4] = name
        struct.pack_into("<II", data, e + 8, off, size)
    header = bytearray(data[base : base + 0x20])
    header[0x0B] = 0
    data[base + 0x0B] = (0x100 - sum(header)) & 0xFF


def _standalone(base=0, size=0x10000):
    """Standalone ME image: FTPR at 0x1000, a zero-offset entry, and an erasable NFTP."""
    data = bytearray(b"\xff" * size)
    _fpt(data, base, [(b"FTPR", 0x1000, 0x2000), (b"ROMB", 0, 0x100), (b"NFTP", 0x4000, 0x1000)])
    data[0x1000:0x3000] = b"\x55" * 0x2000
    data[0x4000:0x5000] = b"\x66" * 0x1000
    _manifest(data, 0x1000)
    return data


def _write(tmp_path, data, name="dump.bin"):
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return path


def test_zero_offset_partition_does_not_erase_fpt_header(tmp_path):
    src = _write(tmp_path, _standalone())
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), soft_disable=False)
    assert report.status == MeCleanResult.SUCCESS
    cleaned = out.read_bytes()
    assert cleaned[:4] == b"$FPT"
    assert cleaned[0x1010:0x3000] == b"\x55" * (0x3000 - 0x1010)


def test_standalone_table_at_0x10_uses_base_zero(tmp_path):
    data = bytearray(b"\xff" * 0x10000)
    _fpt(data, 0x10, [(b"FTPR", 0x1000, 0x2000), (b"NFTP", 0x4000, 0x3000)])
    data[0x1000:0x3000] = b"\x55" * 0x2000
    data[0x4000:0x7000] = b"\x66" * 0x3000
    _manifest(data, 0x1000)
    src = _write(tmp_path, data)
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), soft_disable=False)
    assert report.status == MeCleanResult.SUCCESS
    assert out.read_bytes()[0x4000:0x7000] == b"\xff" * 0x3000


def test_removed_partition_entry_is_dropped_and_checksum_fixed(tmp_path):
    src = _write(tmp_path, _standalone())
    out = tmp_path / "out.bin"
    IntelMECleaner().clean(str(src), str(out), soft_disable=False)
    cleaned = out.read_bytes()
    assert struct.unpack_from("<I", cleaned, 4)[0] == 2
    assert cleaned[0x20:0x24] == b"FTPR"
    assert cleaned[0x40:0x44] == b"ROMB"
    assert cleaned[0x60:0x80] == b"\xff" * 0x20
    assert sum(cleaned[0:0x20]) & 0xFF == 0


def test_unsupported_fpt_header_version_skips_removal(tmp_path):
    data = _standalone()
    data[8] = 0x21
    header = bytearray(data[0:0x20])
    header[0x0B] = 0
    data[0x0B] = (0x100 - sum(header)) & 0xFF
    src = _write(tmp_path, data)
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), soft_disable=False)
    assert report.partitions_removed == 0
    assert any("not supported" in m for m in report.messages)
    assert out.read_bytes()[0x4000:0x5000] == b"\x66" * 0x1000


def _cse_lt(size=0x10000):
    """CSME 11+ style region: $CPD present, no FTPR in the table."""
    data = bytearray(b"\xff" * size)
    _fpt(data, 0, [(b"NFTP", 0x1000, 0x1000)])
    data[0x1000:0x2000] = b"\x55" * 0x1000
    data[0x2000:0x2004] = b"$CPD"
    _manifest(data, 0x3000, version=(15, 0, 3, 1402))
    data[0x3000:0x3004] = b"$MN2"
    return data


def test_cse_lt_error_writes_nothing(tmp_path):
    src = _write(tmp_path, _cse_lt())
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), soft_disable=False)
    assert report.status == MeCleanResult.ERROR
    assert not out.exists()


def test_unset_flmap1_is_not_guessed_from_another_field():
    data = bytearray(b"\xff" * 0x400000)
    data[0x10:0x14] = SIG
    struct.pack_into("<I", data, 0x14, 0x00040000)  # FLMAP0: FRBA = 0x40
    struct.pack_into("<I", data, 0x18, 0x00000000)  # FLMAP1 unset
    struct.pack_into("<I", data, 0x24, 0x00200000)  # old fallback field: FPSBA = 0x200
    before = bytes(data[0x200:0x204]), bytes(data[0x4:0x8])
    cleaner = IntelMECleaner()
    assert cleaner._set_hap_bit(data, 0x1000, 0x2000, None, 15) is False
    assert cleaner._lock_me_descriptor(data, MeGeneration.GEN3) is False
    assert (bytes(data[0x200:0x204]), bytes(data[0x4:0x8])) == before


def test_declared_me_region_past_end_of_file_is_refused(tmp_path):
    size = 0x200000
    data = bytearray(b"\xff" * size)
    data[0x10:0x14] = SIG
    struct.pack_into("<I", data, 0x14, 0x00040000)
    struct.pack_into("<I", data, 0x18, 0x00000000)
    struct.pack_into("<I", data, 0x48, 0x03FF0001)  # FLREG2: ME 0x1000..0x3FFFFF (past EOF)
    _fpt(data, 0x1000, [(b"FTPR", 0x1000, 0x1000), (b"NFTP", 0x4000, 0x1000)])
    data[0x2000:0x3000] = b"\x55" * 0x1000
    data[0x5000:0x6000] = b"\x66" * 0x1000
    _manifest(data, 0x2000)
    src = _write(tmp_path, data)
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), soft_disable=False)
    assert report.status == MeCleanResult.ERROR
    assert not out.exists()


def test_no_fpt_with_content_is_not_already_clean():
    data = bytearray(b"\x55" * 0x10000)
    assert IntelMECleaner()._is_already_clean(data, 0, 0x10000) is False
    assert IntelMECleaner()._is_already_clean(bytearray(b"\xff" * 0x10000), 0, 0x10000) is True


def test_code_partition_means_generation_one():
    data = bytearray(b"\x55" * 0x10000)
    _fpt(data, 0, [(b"CODE", 0x1000, 0x1000)])
    assert IntelMECleaner()._detect_generation(data, 0, len(data)) == MeGeneration.GEN1


def test_no_descriptor_soft_disable_is_reported_not_applied(tmp_path):
    src = _write(tmp_path, _standalone())
    out = tmp_path / "out.bin"
    report = IntelMECleaner().clean(str(src), str(out), soft_disable=True)
    assert report.hap_bit_set is False
    assert any("no soft disable applied" in m for m in report.messages)


def test_directory_input_is_an_error_not_an_exception(tmp_path):
    report = IntelMECleaner().clean(str(tmp_path))
    assert report.status == MeCleanResult.ERROR
    assert IntelMECleaner().get_me_info(str(tmp_path))["found"] is False
