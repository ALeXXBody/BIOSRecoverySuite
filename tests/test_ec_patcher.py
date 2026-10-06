"""Regression tests for the EC firmware analysis and patch engine."""

import os
import tempfile

import pytest

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
    hit low in the image, erased-flash gap, then the real EC image in the TOP
    of the dump.

    The 0xFF gap matters: in a real 2-chip image the region between the end of
    the BIOS and the start of the EC is unprogrammed flash, so it reads as
    0xFF. That gap is the only reliable delimiter of the region's start.
    """
    data = bytearray(bytes((i * 7 + 0x5B) & 0xFF for i in range(BIG)))
    if noise is not None:
        data[noise_off:noise_off + len(noise)] = noise
    start = BIG - len(ec)
    data[start:] = ec
    # Erase the 1MB below the EC region, the way a real image does.
    data[start - 0x100000:start] = b"\xFF" * 0x100000
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
    the EC really does contain them).

    The 1MB immediately below the EC region is erased (0xFF), as it is in a real
    image: the EC sits at the very top of the second chip and the flash below it
    was never programmed. That gap is what delimits the region start.
    """
    import random
    random.seed(seed)
    data = bytearray(random.getrandbits(8) for _ in range(total))

    ec_off = total - ec_size
    data[ec_off - 0x100000:ec_off] = b"\xFF" * 0x100000
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


# ---------------------------------------------------------------------------
# Regression: a 256KB chip was detected as 128KB and the wrong data extracted.
#
# Root cause: the region SIZE was inferred from where a marker hit sat inside
# the image ("smallest chip size that still contains the hit"). Real EC images
# put their identifying strings in the SECOND HALF, so a 256KB chip whose
# markers land at +0x20000 resolved to 128KB -- and a 128KB slice was written
# where 256KB of firmware belongs.
#
# The chip capacity is known hardware truth. That is what must drive the size;
# marker positions must never shrink it.
# ---------------------------------------------------------------------------

def _late_marker_dump(ec_size=0x40000, total=0x2000000, marker_at=0x20000):
    """32MB dump whose EC block sits at the top with its markers LATE in the
    image, and NO 0xFF padding separating it from the BIOS area (so there is no
    padding boundary to bound the start)."""
    import random
    random.seed(4242)
    data = bytearray(random.getrandbits(8) for _ in range(total))
    ec_off = total - ec_size
    # erased-flash gap below the EC region, as in a real 2-chip image
    data[ec_off - 0x100000:ec_off] = b"\xFF" * 0x100000
    ec = bytearray(random.getrandbits(8) for _ in range(ec_size))
    ec[0x0000:0x0004] = b"\xAA\x55\xAA\x55"
    ec[marker_at:marker_at + 9] = b"IT8218VG "
    ec[marker_at + 0x100:marker_at + 0x106] = b"ITE8\x02\x00"
    ec[marker_at + 0x300:marker_at + 0x304] = b"8218"
    data[ec_off:] = ec
    return bytes(data), ec_off


def test_late_markers_do_not_shrink_a_256k_chip_to_128k():
    """The exact reported failure: markers in the second half must not cause a
    256KB region to be reported (and extracted) as 128KB."""
    data, ec_off = _late_marker_dump()
    analysis = ECPatcher().analyze_ec(data)
    assert analysis.found
    assert analysis.size == 0x40000, (
        f"256KB chip reported as 0x{analysis.size:X} ({analysis.size} bytes)"
    )
    assert analysis.offset == ec_off


@pytest.mark.parametrize("marker_at", [0x18000, 0x20000, 0x28000, 0x30000])
def test_size_is_independent_of_marker_position(marker_at):
    """Whatever the marker offset, the answer must be the chip capacity."""
    data, ec_off = _late_marker_dump(marker_at=marker_at)
    analysis = ECPatcher().analyze_ec(data)
    assert analysis.found
    assert analysis.size == 0x40000, (
        f"marker at +0x{marker_at:X} gave size 0x{analysis.size:X}"
    )


def test_single_ff_block_inside_firmware_is_not_a_region_boundary():
    """A lone 4KB erased run inside firmware must not truncate the region.
    Real inter-region gaps are far larger than one block."""
    data, ec_off = _late_marker_dump()
    data = bytearray(data)
    # erase 4KB in the MIDDLE of the EC image
    data[ec_off + 0x10000:ec_off + 0x11000] = b"\xFF" * 0x1000
    analysis = ECPatcher().analyze_ec(bytes(data))
    assert analysis.found
    assert analysis.size == 0x40000, f"internal FF run truncated to 0x{analysis.size:X}"


def test_end_anchored_extraction_uses_chip_capacity():
    """Passing only the size must place the region at its detected end.

    This is the fix for the user: 256KB is a hardware fact, the region's end is
    reliably detectable, so the last 256KB before that end is the EC image.
    """
    data, ec_off = _late_marker_dump()
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        path = f.name
    out = "/tmp/ec_end_anchored.bin"
    try:
        result = ECPatcher().extract_ec(path, out, offset=None, size=0x40000)
        assert result.status == ECStatus.SUCCESS, result.message
        with open(out, "rb") as f:
            got = f.read()
        assert len(got) == 0x40000, f"wrote {len(got)} bytes, want 262144"
        assert got == data[ec_off:ec_off + 0x40000]
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)


def test_end_anchored_resolve_matches_manual_when_both_agree():
    """Sanity: end-anchoring with the right capacity reproduces the manual
    offset exactly, so the two modes cannot disagree."""
    data, ec_off = _late_marker_dump()
    p = ECPatcher()
    anchored = p.resolve_region(data, None, 0x40000)
    manual = p.resolve_region(data, ec_off, 0x40000)
    assert anchored == manual


def test_end_anchored_respects_0xff_terminated_region():
    """With a padding tail after the EC, the end is the padding boundary -- the
    extracted bytes must still be exactly the EC image, not the padding."""
    import random
    random.seed(7)
    total = 0x2000000
    ec_size = 0x40000
    data = bytearray(random.getrandbits(8) for _ in range(total))
    ec_off = 0x100000
    ec = bytearray(random.getrandbits(8) for _ in range(ec_size))
    ec[0x0000:0x0004] = b"\xAA\x55\xAA\x55"
    ec[0x0010:0x0019] = b"IT8218VG "
    data[ec_off:ec_off + ec_size] = ec
    data[ec_off + ec_size:] = b"\xFF" * (total - ec_off - ec_size)

    p = ECPatcher()
    offset, size, err = p.resolve_region(bytes(data), None, ec_size)
    assert err == ""
    assert size == ec_size
    assert offset == ec_off, f"anchored offset 0x{offset:X} != 0x{ec_off:X}"


def _layout_dump(ec_size, gap_before, marker_pos, total=0x2000000, seed=1234):
    import random
    random.seed(seed)
    d = bytearray(random.getrandbits(8) for _ in range(total))
    ec_off = total - ec_size
    if gap_before:
        d[ec_off - gap_before:ec_off] = b"\xFF" * gap_before
    ec = bytearray(random.getrandbits(8) for _ in range(ec_size))
    ec[0x0000:0x0004] = b"\xAA\x55\xAA\x55"
    ec[marker_pos:marker_pos + 9] = b"IT8218VG "
    ec[marker_pos + 0x100:marker_pos + 0x106] = b"ITE8\x02\x00"
    ec[marker_pos + 0x300:marker_pos + 0x304] = b"8218"
    d[ec_off:] = ec
    return bytes(d), ec_off


# Real SPI layouts: the EC sits at the top of the dump with erased flash below
# it, and the vendor may place the identifying strings anywhere in the image.
LAYOUTS = [
    ("256KB, 1MB gap, markers late", 0x40000, 0x100000, 0x20000),
    ("256KB, 1MB gap, markers at start", 0x40000, 0x100000, 0x0100),
    ("256KB, 64KB gap, markers late", 0x40000, 0x10000, 0x20000),
    ("256KB, 8KB gap, markers late", 0x40000, 0x2000, 0x20000),
    ("256KB, 1MB gap, markers at +0x38000", 0x40000, 0x100000, 0x38000),
    ("512KB, 1MB gap, markers late", 0x80000, 0x100000, 0x20000),
    ("512KB, 1MB gap, markers at +0x70000", 0x80000, 0x100000, 0x70000),
]


@pytest.mark.parametrize("label,ec_size,gap,mpos", LAYOUTS)
def test_auto_detect_across_real_layouts(label, ec_size, gap, mpos):
    data, ec_off = _layout_dump(ec_size, gap, mpos)
    analysis = ECPatcher().analyze_ec(data)
    assert analysis.found, f"{label}: not found"
    assert analysis.size == ec_size, f"{label}: got 0x{analysis.size:X}"
    assert analysis.offset == ec_off, f"{label}: offset 0x{analysis.offset:X}"


@pytest.mark.parametrize("label,ec_size,gap,mpos", LAYOUTS)
def test_end_anchored_is_exact_for_every_layout(label, ec_size, gap, mpos):
    """Whatever auto-detect thinks, asking for a capacity must yield exactly
    that many bytes of the correct region."""
    data, ec_off = _layout_dump(ec_size, gap, mpos)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        path = f.name
    out = "/tmp/ec_layout.bin"
    try:
        result = ECPatcher().extract_ec(path, out, offset=None, size=ec_size)
        assert result.status == ECStatus.SUCCESS, f"{label}: {result.message}"
        with open(out, "rb") as f:
            got = f.read()
        assert len(got) == ec_size, f"{label}: wrote {len(got)}"
        assert got == data[ec_off:ec_off + ec_size], f"{label}: wrong bytes"
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)


@pytest.mark.parametrize("ec_size", [0x40000, 0x80000])
def test_undelimitable_region_refuses_rather_than_guessing(ec_size):
    """With NO erased gap below the EC, the region start is not derivable from
    content. Reporting a size anyway is what wrote 128KB for a 256KB chip, so
    the analyzer must refuse and extract nothing."""
    data, ec_off = _layout_dump(ec_size, 0, 0x0100)
    assert ECPatcher().analyze_ec(data).found is False

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        path = f.name
    out = "/tmp/ec_undelimitable.bin"
    try:
        result = ECPatcher().extract_ec(path, out)
        assert result.status == ECStatus.NOT_FOUND
        assert not os.path.exists(out), "must not write a file when undelimitable"
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
        msg = result.message.lower()
        # the message must tell the user how to proceed, not just that it failed
        assert "manual region override" in msg
        assert "0x40000" in msg
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)


# ---------------------------------------------------------------------------
# Regression: reported start was thousands of bytes BEFORE the real EC start.
#
# Structural cause: the start was never read from the measured boundary; it
# was recomputed as ``blob_end - snapped_capacity``. Whenever the walk's blob
# was even one block longer than a chip capacity (a stray programmed byte
# directly above the region, a marker cluster whose blob overshot), the
# capacity snapped UP to the next chip size and the recomputed start was
# pushed BACKWARDS into the BIOS.
#
# The fix is structural and layout-independent: a measured boundary is never
# moved, and a capacity is only reported when start + capacity lands on
# another OBSERVED boundary. No offset in any of these tests is taken from a
# particular dump -- they model the *shape* of the layouts.
# ---------------------------------------------------------------------------


def _two_sided_dump(ec_size, total=0x400000, seed=99, tail=0):
    """Content, then an erased gap, the EC image, an optional stray non-FF
    `tail` directly above the region, then erased flash to EOF."""
    import random
    random.seed(seed)
    ec_off = 0x180000
    data = bytearray(random.getrandbits(8) for _ in range(total))
    data[ec_off - 0x100000:ec_off] = b"\xFF" * 0x100000
    ec = bytearray(random.getrandbits(8) for _ in range(ec_size))
    ec[0x0000:0x0004] = b"\xAA\x55\xAA\x55"
    ec[0x0100:0x0109] = b"IT8218VG "
    ec[0x0200:0x0206] = b"ITE8\x02\x00"
    ec[0x0900:0x0904] = b"8218"
    data[ec_off:ec_off + ec_size] = ec
    after = ec_off + ec_size
    if tail:
        data[after:after + tail] = bytes(
            (i * 13 + 3) & 0xFF for i in range(tail))
        after += tail
    data[after:] = b"\xFF" * (total - after)
    return bytes(data), ec_off


@pytest.mark.parametrize("ec_size", [0x20000, 0x40000, 0x80000])
def test_padding_on_both_sides_pins_region_exactly(ec_size):
    """With padding below AND above the region, both boundaries are observed:
    the answer must be the exact start and the exact chip capacity."""
    data, ec_off = _two_sided_dump(ec_size)
    offset, size = ECPatcher().find_ec_region(data)
    assert offset == ec_off, f"start 0x{offset:X} != measured boundary 0x{ec_off:X}"
    assert size == ec_size, f"size 0x{size:X} != capacity 0x{ec_size:X}"


def test_measured_start_is_never_recomputed_from_the_end():
    """A stray programmed byte directly above the region makes the walk's blob
    one block longer than the capacity. Recomputing start from blob_end then
    snapped the capacity up and shifted the start BACKWARDS into the BIOS --
    the reported failure. Now the measured start is either confirmed by a
    boundary at start + capacity, or the analyzer refuses; it may never be
    moved."""
    data, ec_off = _two_sided_dump(0x40000, tail=0x1000)
    p = ECPatcher()
    offset, size = p.find_ec_region(data)
    # may refuse (no capacity is justified), but must never answer a start
    # other than the measured boundary, nor a size other than the capacity
    assert offset in (-1, ec_off), f"start 0x{offset:X} moved off 0x{ec_off:X}"
    assert size in (-1, 0x40000), f"size 0x{size:X} is not the capacity"

    analysis = p.analyze_ec(data)
    assert not analysis.found, "an unjustified region must not be reported"

    # and nothing may be written on refusal
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(data)
        path = f.name
    out = "/tmp/ec_moved_start.bin"
    try:
        result = p.extract_ec(path, out)
        assert result.status == ECStatus.NOT_FOUND
        assert not os.path.exists(out)
    finally:
        os.unlink(path)
        if os.path.exists(out):
            os.unlink(out)


def test_region_whose_end_is_unobservable_refuses():
    """Padding below the region but content running on after it (no boundary
    within reach): the capacity cannot be justified by content, so auto-detect
    must refuse rather than guess -- and the end-anchored path must refuse too
    instead of reporting the search ceiling as an end."""
    import random
    random.seed(31337)
    total = 0x400000
    # deterministic pattern whose bytes always differ by 7, so it can never
    # contain any signature by accident (no phantom marker clusters)
    data = bytearray(((i * 7 + 0x5B) & 0xFF) for i in range(total))
    ec_size = 0x40000
    ec_off = 0x180000
    data[ec_off - 0x100000:ec_off] = b"\xFF" * 0x100000
    ec = bytearray(((i * 7 + 0x5B) & 0xFF) for i in range(ec_size))
    ec[0x0100:0x0109] = b"IT8218VG "
    ec[0x0200:0x0206] = b"ITE8\x02\x00"
    ec[0x0900:0x0904] = b"8218"
    data[ec_off:ec_off + ec_size] = ec
    # NOTE: no padding after the region -- content continues to EOF.

    p = ECPatcher()
    assert p.find_ec_region(bytes(data)) == (-1, -1)
    assert not p.analyze_ec(bytes(data)).found
    # the region end is equally underivable: no observed boundary follows the
    # cluster, so end-anchored mode must fail with an explanation, not return
    # whatever offset the search happened to stop at
    end = p.find_ec_region_end(bytes(data))
    assert end == -1, f"ceiling offset 0x{end:X} reported as a region end"
    offset, _size, err = p.resolve_region(bytes(data), None, 0x40000)
    assert offset == -1 and "end of the EC region" in err


# ---------------------------------------------------------------------------
# Structural quirks seen in real 2-chip dumps. These fixtures model the SHAPE
# of such images -- padding that stops just short of the region start, and an
# image 0xFF-padded out to its full chip capacity with the next region
# resuming right after it -- using only synthetic content. No offset or size
# here is taken from any particular dump.
# ---------------------------------------------------------------------------

_PATTERN_CYCLE = bytes(((i * 7 + 0x5B) & 0xFF) for i in range(256))


def _padded_tail_dump(total=0x800000, capacity=0x40000, usable=0x30000,
                      stray=2, pad=0x10000, next_lead_ff=0):
    """Mid-dump SPI image with a capacity-padded EC image and strays below it.

    * The padding below the region stops ``stray`` programmed bytes BEFORE
      the region's first byte, so no full 4KB 0xFF block sits directly under
      the start -- flash layouts are not always block-aligned.
    * The region's own tail is 0xFF-padded out to the full chip capacity and
      the next region's content resumes exactly at capacity end, so the
      region's real end is where that padding STOPS, while the block walk
      only ever sees the padding's start.
    """
    # The pattern's bytes always differ by 7, so it can never contain any
    # controller/KBC signature: the planted markers below are the only hits.
    data = bytearray(_PATTERN_CYCLE * (total // 256))
    ec_off = 0x300000
    # gap below the region, stopping `stray` bytes short of its start
    data[ec_off - stray - pad:ec_off - stray] = b"\xFF" * pad
    for i in range(stray):
        data[ec_off - stray + i] = 0x11 + i
    # the EC image: marker cluster near its start, tail padded to capacity
    ec = bytearray(_PATTERN_CYCLE * (capacity // 256))
    ec[0x0000:0x0004] = b"\xAA\x55\xAA\x55"
    ec[0x0100:0x0109] = b"IT8218VG "
    ec[0x0200:0x0206] = b"ITE8\x02\x00"
    ec[0x0900:0x0904] = b"8218"
    ec[usable:capacity] = b"\xFF" * (capacity - usable)
    data[ec_off:ec_off + capacity] = ec
    # the next region's content resumes at capacity end
    if next_lead_ff:
        data[ec_off + capacity:ec_off + capacity + next_lead_ff] = (
            b"\xFF" * next_lead_ff)
        data[ec_off + capacity + next_lead_ff] = 0x77
    else:
        data[ec_off + capacity] = 0x77
    return bytes(data), ec_off, capacity


def test_auto_detects_capacity_padded_region_mid_dump():
    """An image 0xFF-padded out to its capacity ends where the next region
    resumes, even though the forward walk stops at the padding's start."""
    for capacity, usable in ((0x20000, 0x18000), (0x40000, 0x30000),
                             (0x80000, 0x60000)):
        data, ec_off, cap = _padded_tail_dump(capacity=capacity, usable=usable)
        p = ECPatcher()
        off, size = p.find_ec_region(data)
        assert (off, size) == (ec_off, cap), f"capacity 0x{cap:X}"

        analysis = p.analyze_ec(data)
        assert analysis.found, f"capacity 0x{cap:X}"
        assert (analysis.offset, analysis.size) == (ec_off, cap)
        assert analysis.raw == data[ec_off:ec_off + cap]
        assert b"IT8218VG" in analysis.raw

        # end-anchored mode (capacity only) must land on the same start
        r_off, r_size, err = p.resolve_region(data, None, cap)
        assert err == "" and (r_off, r_size) == (ec_off, cap)


def test_strays_below_the_region_start_never_shift_the_answer():
    """Programmed bytes sitting between the padding and the region start must
    not drag the reported offset away from the region's first byte."""
    for stray in (0, 1, 2, 5):
        data, ec_off, capacity = _padded_tail_dump(stray=stray)
        off, size = ECPatcher().find_ec_region(data)
        assert (off, size) == (ec_off, capacity), f"stray={stray}"
        r_off, r_size, err = ECPatcher().resolve_region(data, None, capacity)
        assert err == "" and (r_off, r_size) == (ec_off, capacity), \
            f"stray={stray}"


def test_ff_led_next_region_is_refused_not_shifted():
    """Content that resumes with 0xFF bytes right after the capacity boundary
    makes the byte-level and block-level resume points disagree, straddling
    the true start by a few bytes. Refusing is the only correct answer: an
    extract shifted by even one byte would brick the EC."""
    data, ec_off, capacity = _padded_tail_dump(next_lead_ff=0x10)
    p = ECPatcher()
    off, size = p.find_ec_region(data)
    assert (off, size) == (-1, -1), f"shifted answer 0x{off:X}"
    assert not p.analyze_ec(data).found
    r_off, _r_size, err = p.resolve_region(data, None, capacity)
    assert r_off == -1 and err and "end of the EC region" in err
