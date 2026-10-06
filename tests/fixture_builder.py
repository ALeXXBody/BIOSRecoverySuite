"""Synthetic-but-structurally-valid BIOS fixture generator for regression tests.

These fixtures are not real firmware. They contain correctly-formed headers,
flash descriptor region tables, FPT partition tables, firmware volume headers,
SMBIOS entry points/structures and NVRAM password variables so that every parser
in the suite can be exercised end-to-end deterministically.
"""

import os
import struct
import uuid


def _fill_pattern(data: bytearray, start: int, end: int) -> None:
    """Fill bytearray [start, end) with a deterministic 256-byte repeating pattern."""
    for i in range(start, min(end, len(data))):
        data[i] = (i * 7 + 0xA5) & 0xFF


def flreg(base: int, end: int) -> int:
    """Encode an Intel Flash Descriptor FLREG value from absolute addresses."""
    return (((end - 1) >> 12) << 16) | (base >> 12)


def make_fv_header(fv_size: int) -> bytes:
    """Build a valid EFI_FIRMWARE_VOLUME_HEADER (HeaderLength=0x48, rev 2)."""
    hdr = bytearray(0x48)
    hdr[0x00:0x10] = b"\x00" * 16
    hdr[0x10:0x20] = uuid.uuid4().bytes
    struct.pack_into("<Q", hdr, 0x20, fv_size)
    hdr[0x28:0x2C] = b"_FVH"
    struct.pack_into("<I", hdr, 0x2C, 0x4FEFF4FE)
    struct.pack_into("<H", hdr, 0x30, 0x48)
    hdr[0x34] = 0x00
    hdr[0x36] = 0x02
    struct.pack_into("<II", hdr, 0x37, 0x20000, fv_size // 0x20000)
    struct.pack_into("<II", hdr, 0x3F, 0xFFFFFFFF, 0xFFFFFFFF)
    return bytes(hdr)


def make_smbios_structures() -> tuple[bytes, int]:
    """Build a small SMBIOS structure table. Returns (data, structure_count)."""
    out = bytearray()
    count = 0

    def add_struct(struct_type: int, fixed: bytes, strings: list[bytes]) -> None:
        nonlocal count
        assert len(fixed) > 4
        hdr = struct.pack("<BBH", struct_type, len(fixed), count + 1)
        out.extend(hdr)
        out.extend(fixed[4:])
        for s in strings:
            out.extend(s)
            out.extend(b"\x00")
        if strings:
            out.extend(b"\x00")
        else:
            out.extend(b"\x00\x00")
        count += 1

    # Type 0 - BIOS Information (len 0x12, vendor/version/date string indexes)
    type0_fixed = bytearray(0x12)
    type0_fixed[0x00] = 0
    type0_fixed[0x01] = 0x12
    type0_fixed[0x04] = 1   # vendor string index
    type0_fixed[0x05] = 2   # version string index
    type0_fixed[0x06] = 3   # release date string index
    add_struct(0, bytes(type0_fixed),
               [b"American Megatrends Inc.", b"5.26", b"03/15/2020"])

    # Type 1 - System Information (len 0x19, UUID at fixed[0x08:0x18])
    type1_fixed = bytearray(0x19)
    type1_fixed[0x00] = 1
    type1_fixed[0x01] = 0x19
    struct.pack_into("<H", type1_fixed, 0x02, 0)
    type1_fixed[0x04:0x08] = bytes([1, 2, 3, 4])
    uuid_bytes = uuid.uuid4().bytes
    type1_fixed[0x08:0x18] = uuid_bytes
    add_struct(1, bytes(type1_fixed),
               [b"LENOVO", b"20HQCTO1WW", b"PF1ABC123", uuid_bytes.hex().upper().encode()])

    # Type 2 - Baseboard (len 0x08)
    add_struct(2, struct.pack("<BBHBBBBBB", 2, 0x08, 0, 1, 2, 3, 4, 5, 0),
               [b"LENOVO", b"20HQ", b"Notebook", b"L1NV7XB2", b"AT12345678"])

    # Type 3 - Chassis (len 0x09)
    add_struct(3, struct.pack("<BBHBBBBBB", 3, 0x09, 0, 1, 2, 0x00, 0x00, 0x00, 3),
               [b"LENOVO", b"None", b"CH12345678"])

    # Type 17 - Memory Device (len 0x1B)
    type17_fixed = bytearray(0x1B)
    struct.pack_into("<BBH", type17_fixed, 0, 17, 0x1B, 0)
    type17_fixed[0x04:0x19] = bytes([1, 2, 3, 4, 5]) + b"\x00" * (0x19 - 0x09)
    add_struct(17, bytes(type17_fixed),
               [b"DIMM0", b"BANK 0", b"Micron", b"SX0123456", b"A1B2C3D4", b"MTA8ATF1G64"])

    return bytes(out), count


def make_smbios_eps(table_addr: int, table_len: int, struct_count: int) -> bytes:
    eps = bytearray(0x1F)
    eps[0x00:0x04] = b"_SM_"
    eps[0x05] = 0x1F
    eps[0x06] = 2
    eps[0x07] = 7
    eps[0x0A] = 0
    eps[0x0B:0x10] = b"\x00" * 5
    eps[0x10:0x15] = b"_DMI_"
    struct.pack_into("<H", eps, 0x16, table_len)
    struct.pack_into("<I", eps, 0x18, table_addr)
    struct.pack_into("<H", eps, 0x1C, struct_count)
    eps[0x1E] = 0x27
    # intermediate checksum over bytes 0x05..0x1E, stored at 0x04
    eps[4] = (0x100 - (sum(eps[5:]) & 0xFF)) & 0xFF
    return bytes(eps)


def build_intel_ifd_image(size: int = 0x1000000) -> bytes:
    """Build a full Intel-flash-descriptor dump with ME, GbE and BIOS regions."""
    data = bytearray(0xFF for _ in range(size))

    fd = 0x0000
    me = 0x1000
    gbe = 0x400000
    bios = 0x401000
    me_size = gbe - me

    # Intel Flash Descriptor
    struct.pack_into("<I", data, fd + 0x00, 0x0FF0A55A)
    struct.pack_into("<I", data, fd + 0x10, 0x00100001)          # FLMAP0: FRBA=0x100, MSA=0x1000
    struct.pack_into("<I", data, fd + 0x14, 0x00200000)          # FLMAP1: FPSBA=0x200, FMBA=0
    struct.pack_into("<I", data, fd + 0x18, 0x00000000)          # FLMAP2

    frba = fd + 0x100
    struct.pack_into("<I", data, frba + 0x00, flreg(fd, fd + 0x1000))   # Descriptor
    struct.pack_into("<I", data, frba + 0x08, flreg(bios, size))        # BIOS
    struct.pack_into("<I", data, frba + 0x10, flreg(me, gbe))           # ME
    struct.pack_into("<I", data, frba + 0x18, flreg(gbe, gbe + 0x1000)) # GbE

    # PCH straps so HAP testing works (PCHSTRP0 at fpsba)
    fpsba = fd + 0x200
    struct.pack_into("<I", data, fpsba, 0x00000000)
    struct.pack_into("<I", data, fpsba + 0x28, 0x00000000)

    # ME region: deterministic pattern + FPT + version marker
    _fill_pattern(data, me, gbe)
    fpt = me + 0x10
    data[fpt:fpt + 4] = b"$FPT"
    struct.pack_into("<I", data, fpt + 0x04, 6)
    data[fpt + 0x20:fpt + 0x24] = b"FTPR"
    data[fpt + 0x28:fpt + 0x2C] = struct.pack("<I", 0x4000)
    data[fpt + 0x2C:fpt + 0x30] = struct.pack("<I", me_size - 0x4000)
    data[fpt + 0x40:fpt + 0x44] = b"LOCL"
    data[fpt + 0x48:fpt + 0x4C] = struct.pack("<I", 0x200000)
    data[fpt + 0x4C:fpt + 0x50] = struct.pack("<I", 0x100000)
    data[fpt + 0x60:fpt + 0x64] = b"ROMB"
    data[fpt + 0x68:fpt + 0x6C] = struct.pack("<I", 0x300000)
    data[fpt + 0x6C:fpt + 0x70] = struct.pack("<I", 0x80000)
    data[fpt + 0x80:fpt + 0x84] = b"EFFS"
    data[fpt + 0x88:fpt + 0x8C] = struct.pack("<I", 0x380000)
    data[fpt + 0x8C:fpt + 0x90] = struct.pack("<I", 0x200000)

    # FPT checksum (sum of 32-byte header == 0 mod 256)
    chk = (0x100 - sum(data[fpt:fpt + 0x20]) & 0xFF) & 0xFF
    data[fpt + 0x1B] = chk

    # FTPR partition manifest (real layout): $CPD at FTPR start, CPD entry
    # "FTPR.man" at +0x10 (name[12] + u32 offset at +0x0C) pointing at $MN2.
    cpd = me + 0x4000
    data[cpd:cpd + 4] = b"$CPD"
    struct.pack_into("<I", data, cpd + 0x04, 1)
    data[cpd + 0x10:cpd + 0x1C] = b"FTPR.man\x00\x00\x00\x00"
    struct.pack_into("<I", data, cpd + 0x1C, 0x30)  # MN2 offset relative to $CPD
    mn2 = cpd + 0x30
    data[mn2:mn2 + 4] = b"$MN2"
    # Manifest base = tag - 0x1C; version u16 x4 at base+0x24
    struct.pack_into("<HHHH", data, mn2 - 0x1C + 0x24, 12, 8, 0, 1852)

    # GbE region
    struct.pack_into("<I", data, gbe + 0x01, 0x10FBAA55)

    # BIOS region: a firmware volume
    bios_ptr = bios
    fv_size_1 = 0x80000
    data[bios_ptr:bios_ptr + 0x48] = make_fv_header(fv_size_1)
    _fill_pattern(data, bios_ptr + 0x48, bios_ptr + fv_size_1)

    # SMBIOS EPS + table
    smbios_table, struct_count = make_smbios_structures()
    table_addr = bios_ptr + fv_size_1
    table_len = len(smbios_table) + 2
    eps_addr = table_addr + table_len
    data[table_addr:eps_addr - 2] = smbios_table
    data[table_addr + len(smbios_table):table_addr + len(smbios_table) + 2] = b"\x00\x00"
    data[eps_addr:eps_addr + 0x1F] = make_smbios_eps(table_addr, table_len, struct_count)

    # AMI password variable (UTF-16LE "AMITSESetup") in a plausible NVRAM area
    pwd_var = b"A\x00M\x00I\x00T\x00S\x00E\x00S\x00e\x00t\x00u\x00p\x00"
    nvram = bios_ptr + 0x30000
    data[nvram:nvram + len(pwd_var)] = pwd_var
    data[nvram + len(pwd_var):nvram + len(pwd_var) + 12] = b"\x00" * 12

    return bytes(data)


def build_dell_pfs_image() -> bytes:
    """Build a small Dell PFS-style package with an embedded BIOS volume."""
    fv = bytearray(0x20000)
    fv[0:0x48] = make_fv_header(0x20000)
    _fill_pattern(fv, 0x48, 0x20000)

    payload = bytes(fv)
    pfs = bytearray(0x10)
    pfs[0x00:0x03] = b"PFS"
    struct.pack_into("<I", pfs, 0x04, len(payload) + 0x10)
    pfs.extend(payload)
    return bytes(pfs)


def build_ec_firmware() -> bytes:
    """Build a synthetic EC firmware blob (256KB, ITE-style, with password flags)."""
    ec = bytearray()
    for _idx in range(0x40000):
        ec.append(0x55 if _idx % 256 == 0 else 0xAA)
    ec[0x10:0x1C] = b"ITE\x00IT8587E\x00"
    ec[0x20000:0x20010] = b"KBC_CONFIG_V1\x00\x00\x00\x00"
    ec[0x30000:0x3000E] = b"PasswordStatus"
    ec[0x30010:0x30016] = b"UnLock"
    ec[0x30020:0x3002E] = b"Security-\x00\x00\x00\x00\x00"
    if len(ec) < 0x40000:
        ec.extend(b"\xFF" * (0x40000 - len(ec)))
    elif len(ec) > 0x40000:
        del ec[0x40000:]
    # 8-bit XOR checksum over image stored at last byte
    checksum = 0
    for _cidx in range(len(ec) - 1):
        checksum ^= ec[_cidx]
    ec[-1] = checksum
    return bytes(ec)


def build_ec_image_dump() -> bytes:
    """Build a 16MB dump with the EC firmware in the top 256KB (2-chip design)."""
    size = 0x1000000
    data = bytearray(0xFF for _ in range(size))
    ec = build_ec_firmware()
    data[size - len(ec):size] = ec
    return bytes(data)


# ---------------------------------------------------------------------------
# UEFI FV / FFS fixtures (for the UEFIPatch engine)
# ---------------------------------------------------------------------------

UEFI_PATCH_TARGET_GUID = "721C8B66-426C-4E86-8E99-3457C46AB0B9"   # SystemFormBrowserCoreDxe
UEFI_PATCH_OTHER_GUID = "79E0EDD7-9D1D-4F41-AE1A-F896169E5216"    # LenovoWmaPolicyDxe
ADV_PATTERN = bytes.fromhex("04320b483cc2e14abb16a73fadda475f")
ADV_REPLACEMENT = bytes.fromhex("778b1d826d24964e8e103467d56ab1ba")
WW_PATTERN = bytes.fromhex("C8390B747A")
TAMPER_MARKER = bytes.fromhex("4C4E564242534543FB")


def _ffs2_fv_header(fv_len: int) -> bytes:
    """Valid EFI_FIRMWARE_VOLUME_HEADER with the FFS2 file system GUID."""
    hdr = bytearray(0x48)
    hdr[0x10:0x20] = uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3").bytes_le
    struct.pack_into("<Q", hdr, 0x20, fv_len)
    hdr[0x28:0x2C] = b"_FVH"
    struct.pack_into("<I", hdr, 0x2C, 0x0004EFFF & ~0x00000800)  # clear erase-polarity bit
    struct.pack_into("<H", hdr, 0x30, 0x48)
    struct.pack_into("<H", hdr, 0x32, 0)              # checksum placeholder
    hdr[0x37] = 0x02                                  # revision
    struct.pack_into("<II", hdr, 0x38, fv_len // 0x1000, 0x1000)
    struct.pack_into("<II", hdr, 0x40, 0, 0)
    struct.pack_into("<H", hdr, 0x32, (0x10000 - sum(hdr)) & 0xFFFF)
    return bytes(hdr)


def _ffs_header(guid: str, ftype: int, attrs: int, body: bytes, state: int = 0x07,
                file_guid_override: str | None = None) -> bytes:
    size = 0x18 + len(body)
    hdr = bytearray(0x18)
    hdr[0:16] = uuid.UUID(file_guid_override or guid).bytes_le
    hdr[0x12] = ftype
    hdr[0x13] = attrs
    hdr[0x14] = size & 0xFF
    hdr[0x15] = (size >> 8) & 0xFF
    hdr[0x16] = (size >> 16) & 0xFF
    hdr[0x17] = state
    probe = bytearray(hdr)
    probe[0x10] = 0
    probe[0x11] = 0
    probe[0x17] = 0
    hdr[0x10] = (0x100 - (sum(probe) & 0xFF)) & 0xFF
    if attrs & 0x40:
        hdr[0x11] = (0x100 - (sum(body) & 0xFF)) & 0xFF
    else:
        hdr[0x11] = 0xAA
    return bytes(hdr) + body


def _section(stype: int, payload: bytes) -> bytes:
    total = 4 + len(payload)
    hdr = struct.pack("<I", total)[:3] + bytes([stype])
    return hdr + payload


def _pad_ffs(ffs: bytes, alignment: int = 8) -> bytes:
    pad = (-len(ffs)) % alignment
    return ffs + b"\xFF" * pad


def build_uefi_patch_image() -> bytes:
    """Small FV containing:
      * file A (LenovoWmaPolicyDxe GUID, type DRIVER, file-checksum attr) whose
        PE32 section sits inside a GUID-defined LZMA section and carries the
        advanced-menu pattern,
      * file B (type FREEFORM) with a raw PE32 section carrying the WWAN
        whitelist pattern + the LNVBBSEC tamper marker,
      * file C (type APPLICATION) as trailing sibling used to verify splicing.
    """
    import lzma as _lzma

    # file A: LZMA GUID-defined section wrapping a PE32 section
    pe_body_a = b"\x00" * 0x40 + ADV_PATTERN + b"\x00" * 0x20
    pe_sec_a = _section(0x10, pe_body_a)
    compressed = _lzma.compress(pe_sec_a, format=_lzma.FORMAT_ALONE,
                                filters=[{"id": _lzma.FILTER_LZMA1, "preset": 9,
                                          "dict_size": 1 << 24}])
    guid_sec_a = (uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF").bytes_le
                  + struct.pack("<HH", 0x18, 0x01) + compressed)
    lzma_sec = _section(0x02, guid_sec_a)
    file_a = _ffs_header(UEFI_PATCH_TARGET_GUID, 0x07, 0x40, lzma_sec)

    # file B: raw PE32 section with whitelist pattern + tamper marker
    pe_body_b = WW_PATTERN + b"\x11" * 0x10 + TAMPER_MARKER + b"\x22" * 0x08
    file_b = _ffs_header(UEFI_PATCH_OTHER_GUID, 0x15, 0x00, _section(0x10, pe_body_b))

    # file C: trailing sibling (APPLICATION) with unique filler
    file_c = _ffs_header("6F6D2D0C-C56A-4C4F-9E5A-2B3A0F97C2B1", 0x09, 0x00,
                         _section(0x19, b"DRIVER-C-PAYLOAD" * 4))

    fv_len = 0x10000
    body = _pad_ffs(file_a) + _pad_ffs(file_b) + _pad_ffs(file_c)
    assert len(body) + 0x48 <= fv_len
    fv = _ffs2_fv_header(fv_len) + body
    fv += b"\xFF" * (fv_len - len(fv))
    return fv


# real GUIDs from the badcaps autopatch driver set
AUTOpatch_BOOTOPTION_GUID = "E0746C42-D3F9-4F8B-B211-1410957B9FF5"
AUTOpatch_TRANSLATE_GUID = "826BCF56-BAC4-43F4-8EA1-8CDF0A121ABD"


def build_autopatch_fixture(dxe_dir: str | None = None) -> bytes:
    """Driver FV containing the real autopatch target FFS GUIDs, followed by a
    separate NVRAM volume FV whose header matches the shipped clean .vol (same
    prefix, size, checksum) but with different body content, so the NVRAM
    replace pass is exercisable."""
    filler = bytes(range(256)) * 3

    ffs_boot = _ffs_header(AUTOpatch_BOOTOPTION_GUID, 0x07, 0x00,
                           _section(0x10, filler[:600]))
    ffs_translate = _ffs_header(AUTOpatch_TRANSLATE_GUID, 0x07, 0x00,
                                _section(0x10, filler[:900]))
    body = _pad_ffs(ffs_boot) + _pad_ffs(ffs_translate)

    fv_len = 0x10000
    fv1 = _ffs2_fv_header(fv_len) + body
    fv1 += b"\xFF" * (fv_len - len(fv1))

    vol_path = os.path.join(dxe_dir or os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "bios_recovery", "patches", "dxe"),
        "NVRAM_EfiSystemNvDataFvGuid.vol")
    nvram = bytearray(open(vol_path, "rb").read())
    # alter body (keep 72-byte header) so a replace has a detectable effect
    nvram[0x48:0x148] = b"\x5A" * 0x100
    return fv1 + bytes(nvram)


def write_fixtures(outdir: str) -> dict[str, str]:
    """Write all fixtures to disk. Returns {name: path}."""
    os.makedirs(outdir, exist_ok=True)
    fixtures = {
        "intel_ifd.bin": build_intel_ifd_image(),
        "dell_pfs.bin": build_dell_pfs_image(),
        "ec_firmware.bin": build_ec_firmware(),
        "ec_dump.bin": build_ec_image_dump(),
        "uefi_patch.bin": build_uefi_patch_image(),
        "autopatch.bin": build_autopatch_fixture(),
    }
    paths = {}
    for name, data in fixtures.items():
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        paths[name] = path
    return paths


if __name__ == "__main__":
    import tempfile
    paths = write_fixtures(tempfile.mkdtemp())
    for name, path in paths.items():
        print(f"{name}: {path} ({os.path.getsize(path):,} bytes)")