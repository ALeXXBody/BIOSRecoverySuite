"""Inject Clean ME refuses blobs whose engine layout differs from the target.

Real-world failure this guards: a donor-style LT blob from a *different engine
generation* (FPT listing FTPR, e.g. CSME 16 tools) grafted over a CSME 15 LT
target produced a dead engine. The injector's job is a same-layout ME region
replacement; a layout mismatch is refused with the FIT round-trip guidance.
"""

import struct

from bios_recovery.platforms.intel.me.me_injector import MEInjector
from tests.fixture_builder import build_intel_ifd_image


def _with_fpt_rows(data: bytes, rows: list[tuple[bytes, int, int]]) -> bytearray:
    """Overwrite the target fixture's FPT rows with an explicit list."""
    blob = bytearray(data)
    me = 0x1000
    fpt = me + 0x10
    blob[fpt : fpt + 4] = b"$FPT"
    struct.pack_into("<I", blob, fpt + 4, len(rows))
    for i, (name, off, size) in enumerate(rows):
        e = blob[fpt + 0x20 + i * 0x20 : fpt + 0x20 + (i + 1) * 0x20]
        e[:4] = name.ljust(4, b"\x00")[:4]
        struct.pack_into("<II", e, 8, off, size)
        blob[fpt + 0x20 + i * 0x20 : fpt + 0x20 + (i + 1) * 0x20] = e
    # FPT checksum byte at +0x1B: header sum == 0 mod 256
    header = bytearray(blob[fpt : fpt + 0x20])
    header[0x1B] = 0
    blob[fpt + 0x1B] = (0x100 - sum(header)) & 0xFF
    return blob


def test_inject_refuses_a_foreign_layout(tmp_path):
    src = tmp_path / "bios.bin"
    src.write_bytes(build_intel_ifd_image())

    # A clean blob whose FPT lists partitions the target does not have
    # (CSME-16-style: FTPR listed with a different base).
    blob = bytearray(bytes((i * 11 + 5) & 0xFF for i in range(0x200000 - 0x1000)))
    fpt = 0x10
    blob[fpt : fpt + 4] = b"$FPT"
    struct.pack_into("<I", blob, fpt + 4, 3)
    for i, (name, off, size) in enumerate(
        [(b"FTPR", 0x2000, 0x125000), (b"MFS", 0x12B000, 0x64000), (b"NFTP", 0x18F000, 0x12C000)]
    ):
        blob[fpt + 0x20 + i * 0x20 : fpt + 0x20 + i * 0x20 + 4] = name
        struct.pack_into("<II", blob, fpt + 0x20 + i * 0x20 + 8, off, size)

    clean = tmp_path / "csme16_blob.bin"
    clean.write_bytes(bytes(blob))
    out = tmp_path / "mefixed.bin"

    report = MEInjector().inject(str(src), str(clean), out)
    assert not report["success"]
    assert "different engine layout" in report["message"]
    assert "Flash Image Tool" in report["message"]
    assert not out.exists()


def test_inject_accepts_a_same_layout_blob(tmp_path):
    src = tmp_path / "bios.bin"
    src.write_bytes(build_intel_ifd_image())

    # Same FPT rows as the target (FTPR/LOCL/ROMB/EFFS at the same offsets)
    blob = bytearray(bytes((i * 11 + 5) & 0xFF for i in range(0x200000 - 0x1000)))
    me, fpt = 0x1000, 0x10
    rows_len = 0x20 * 7
    blob[fpt : fpt + rows_len] = src.read_bytes()[me + fpt : me + fpt + rows_len]
    marker = 0x501C
    blob[marker : marker + 4] = b"$MN2"
    struct.pack_into("<HHHH", blob, marker + 8, 9, 5, 0, 0)

    clean = tmp_path / "clean_me.bin"
    clean.write_bytes(bytes(blob))
    out = tmp_path / "mefixed.bin"

    report = MEInjector().inject(str(src), str(clean), out)
    assert report["success"], report["message"]

    # descriptor untouched
    fixed = out.read_bytes()
    assert fixed[:0x1000] == src.read_bytes()[:0x1000]


def test_layout_helper_reports_the_participating_names():
    inj = MEInjector()
    tgt = [(b"FTPR", 0x4000, 0x1000), (b"LOCL", 0x8000, 0x1000)]
    cln = [(b"FTPR", 0x2000, 0x125000), (b"MFS", 0x12B000, 0x64000)]
    text = inj._layout_diff_names(tgt, cln)
    assert "FTPR,LOCL" in text and "FTPR,MFS" in text
