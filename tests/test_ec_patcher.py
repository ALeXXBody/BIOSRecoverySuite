"""Regression tests for the EC firmware analysis and patch engine."""

import os

from bios_recovery.engines.ec_patcher import ECController, ECPatcher, ECStatus
from tests.fixture_builder import build_ec_firmware


def test_ec_found_in_top_of_dump(ec_dump):
    patcher = ECPatcher()
    with open(ec_dump, "rb") as f:
        data = f.read()
    analysis = patcher.analyze_ec(data)

    assert analysis.found
    assert analysis.offset >= 0
    assert analysis.size >= 0x10000
    assert len(analysis.raw) > 0
    assert analysis.controller == ECController.ITE


def test_ec_controller_detection(ec_firmware):
    patcher = ECPatcher()
    analysis = patcher.analyze_ec(open(ec_firmware, "rb").read())
    assert analysis.controller == ECController.ITE
    assert "IT8587E" in analysis.raw[:0x20].decode("latin1")


def test_it8218_lenovo_15ahp9_style_detection(ec_dump):
    """Real-world case: Lenovo 15AHP9 with ITE IT8218VG EC.

    The 2-chip design keeps the EC image in the top of the main SPI dump;
    the analyzer must recognise the IT8218 signature family and the GUI
    extract step must produce a chip-writable image.
    """
    patcher = ECPatcher()
    with open(ec_dump, "rb") as f:
        data = f.read()
    analysis = patcher.analyze_ec(data)
    assert analysis.found, "EC image expected in the top of the dump"
    assert analysis.controller == ECController.ITE
    assert analysis.size >= 0x10000, "EC image must be at least one 64KB block"
    # 'IT8218' must now feed the controller classification
    assert any(sig == b"IT8218" for sig in patcher.CONTROLLER_SIGNATURES[ECController.ITE])
    assert patcher.extract_ec(ec_dump, ec_dump + ".ec.bin").status.name == "SUCCESS"


def test_password_flags_scanned(ec_dump):
    patcher = ECPatcher()
    analysis = patcher.analyze_ec(open(ec_dump, "rb").read())
    names = {f["name"] for f in analysis.password_flags}
    assert "PasswordStatus" in names
    assert "UnLock" in names


def test_kbc_config_detected(ec_dump):
    analysis = ECPatcher().analyze_ec(open(ec_dump, "rb").read())
    assert analysis.has_kbc_config


def test_checksum_valid(ec_firmware):
    analysis = ECPatcher().analyze_ec(open(ec_firmware, "rb").read())
    assert analysis.checksum_valid is True


def test_extract_ec_from_dump(ec_dump, tmp_path):
    out = str(tmp_path / "ec.bin")
    result = ECPatcher().extract_ec(ec_dump, out)
    assert result.status == ECStatus.SUCCESS
    assert os.path.exists(out)
    assert os.path.getsize(out) >= 0x10000


def test_patch_registry_loaded():
    patcher = ECPatcher()
    patches = patcher.list_patches()
    assert any(p.vendor.lower() == "lenovo" for p in patches)


def test_unverified_patch_refused(ec_firmware, tmp_path):
    patcher = ECPatcher()
    result = patcher.apply_patch(ec_firmware, "lenovo_t430_e147_gen3_disable_unlock_flag",
                                 require_verified=True)
    assert result.status == ECStatus.UNVERIFIED


def test_unverified_patch_forced(ec_firmware, tmp_path):
    out = str(tmp_path / "patched.bin")
    patcher = ECPatcher()
    result = patcher.apply_patch(
        ec_firmware,
        "lenovo_t430_e147_gen3_disable_unlock_flag",
        output_path=out,
        require_verified=False,
    )
    assert result.status == ECStatus.SUCCESS
    assert result.offset >= 0
    assert os.path.exists(out)
    with open(out, "rb") as f:
        patched = f.read()
    assert b"UnLock" not in patched


def test_missing_signature_reports_pattern_missing(intel_ifd, tmp_path):
    patcher = ECPatcher()
    result = patcher.apply_patch(
        intel_ifd,
        "lenovo_t430_e147_gen3_disable_unlock_flag",
        require_verified=False,
    )
    # An Intel flash-descriptor dump carries no EC 'UnLock' marker
    assert result.status == ECStatus.PATTERN_MISSING

def _make_spi_15ahp9_style(BIG: int, ec: bytes, noise: bytes | None,
                           noise_off: int | None) -> bytes:
    """Full Lenovo-style SPI: pseudorandom BIOS area, optional stray noise
    hit low in the image, real EC image in the TOP of the dump."""
    data = bytearray(bytes((i * 7 + 0x5B) & 0xFF for i in range(BIG)))
    if noise is not None:
        data[noise_off:noise_off + len(noise)] = noise
    start = BIG - len(ec)
    data[start:] = ec
    return bytes(data)


def test_noise_hit_in_bios_area_not_reported_as_ec():
    """Regression for a reported failure: Lenovo 15AHP9 32MB dump.

    A stray short ITE marker hit deep inside the BIOS area used to make the
    analyzer label everything from there to EOF as 'EC' (33MB extract).
    The EC must be found in the top of the dump instead, bounded in size.
    """
    BIG = 0x2000000  # 32MB, as the user's dump
    ec = build_ec_firmware()
    assert len(ec) == 0x40000

    # real dump: EC at top + a stray 2-byte ITE-family hit at 0x21000
    spi = _make_spi_15ahp9_style(BIG, ec, b"\x80\x04", 0x21000)
    analysis = ECPatcher().analyze_ec(spi)
    assert analysis.found
    assert analysis.offset >= BIG - 0x180000, f"offset {analysis.offset:#x} wrong"
    assert analysis.offset & 0xFFF == 0
    assert analysis.size <= 0x80000, f"size {analysis.size:#x} unbounded!"

    # extraction must write ONLY the EC region
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(spi)
        path = f.name
    out = "/tmp/ec_extract_regression.bin"
    try:
        result = ECPatcher().extract_ec(path, out)
        assert result.status == ECStatus.SUCCESS
        with open(out, "rb") as f:
            extracted = f.read()
        assert len(extracted) <= 0x80000, f"extracted {len(extracted)} bytes!"
        assert extracted == spi[analysis.offset:analysis.offset + analysis.size]
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)


def test_pure_noise_rejected():
    """A BIOS-only image with one lone short ITE-family hit must not be
    mislabeled as EC firmware."""
    data = bytearray(bytes((i * 7 + 0x5B) & 0xFF for i in range(0x100000)))
    data[0x21000:0x21002] = b"\x80\x04"
    analysis = ECPatcher().analyze_ec(bytes(data))
    assert not analysis.found, "lone noise hit must not count as EC"


# ---------------------------------------------------------------------------
# Region-boundary correctness + manual override (added after finding that the
# scorer anchored on a marker hit *inside* the image, producing offsets ~45KB
# into the EC instead of at its real start).
# ---------------------------------------------------------------------------

def _lenovo_15ahp9_style_dump(seed=1234, ec_size=0x40000, total=0x2000000):
    """32MB 2-chip SPI dump: EC firmware as one chip-sized block at the TOP,
    plus EC-ish strings scattered through the BIOS area (the DXE that talks to
    the EC really does contain them)."""
    import random
    random.seed(seed)
    data = bytearray(random.getrandbits(8) for _ in range(total))

    ec_off = total - ec_size
    ec = bytearray(random.getrandbits(8) for _ in range(ec_size))
    ec[0x0000:0x0004] = b"\xAA\x55\xAA\x55"
    ec[0x0100:0x0109] = b"IT8218VG "
    ec[0x0200:0x0206] = b"ITE8\x02\x00"
    ec[0x0700:0x0706] = b"ENE\x00\x01\x00"
    ec[0x0900:0x0904] = b"8218"
    data[ec_off:] = ec

    for off in (0x21000, 0x34000, 0x5A000, 0x9C000, 0x120000, 0x1A0000):
        data[off:off + 6] = b"ITE8\x02\x00"
    return bytes(data), ec_off


def test_region_starts_at_image_boundary_not_at_marker():
    """The reported offset must be the START of the EC image, not a signature
    hit somewhere inside it."""
    data, ec_off = _lenovo_15ahp9_style_dump()
    offset, size = ECPatcher().find_ec_region(data)
    assert offset == ec_off, f"offset 0x{offset:X} != image start 0x{ec_off:X}"
    assert size == 0x40000, f"size 0x{size:X} != 0x40000"


def test_region_size_is_chip_sized_not_rest_of_dump():
    """The original bug: extraction swallowed the entire 32MB dump."""
    data, ec_off = _lenovo_15ahp9_style_dump()
    analysis = ECPatcher().analyze_ec(data)
    assert analysis.found
    assert analysis.size <= 0x80000, f"extracted {analysis.size} bytes"
    assert analysis.size == 0x40000


def test_detection_survives_randomised_noise():
    """Random noise placement must not change the answer."""
    for seed in (1, 7, 99, 2024, 31337):
        data, ec_off = _lenovo_15ahp9_style_dump(seed=seed)
        offset, _size = ECPatcher().find_ec_region(data)
        assert offset == ec_off, f"seed {seed}: got 0x{offset:X}, want 0x{ec_off:X}"


def test_manual_override_is_honoured():
    """When auto-detect fails the user must be able to pin the region."""
    data = b"\xFF" * 0x100000          # nothing detectable at all
    analysis = ECPatcher().analyze_ec(data, offset=0x80000, size=0x40000)
    assert analysis.found
    assert analysis.offset == 0x80000
    assert analysis.size == 0x40000


def test_manual_override_past_eof_is_refused():
    data = b"\xFF" * 0x10000
    analysis = ECPatcher().analyze_ec(data, offset=0x8000, size=0x40000)
    assert not analysis.found
    assert "past the end" in analysis.message


def test_extract_with_override_writes_exact_size():
    import os
    import tempfile
    payload = bytes(range(256)) * 1024      # 256KB of identifiable data
    data = b"\xFF" * 0x10000 + payload

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        path = f.name
    out = "/tmp/ec_override_extract.bin"
    try:
        result = ECPatcher().extract_ec(path, out, offset=0x10000, size=0x40000)
        assert result.status == ECStatus.SUCCESS
        with open(out, "rb") as f:
            got = f.read()
        assert len(got) == 0x40000, f"wrote {len(got)} bytes"
        assert got == payload
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)


def test_extract_without_override_explains_how_to_proceed():
    """A not-found result must tell the user how to fix it, not just fail."""
    import os
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"\xFF" * 0x80000)
        path = f.name
    out = "/tmp/ec_nf.bin"
    try:
        result = ECPatcher().extract_ec(path, out)
        assert result.status == ECStatus.NOT_FOUND
        assert "manually" in result.message.lower()
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)
