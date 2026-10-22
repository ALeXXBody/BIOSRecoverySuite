"""AMI Aptio capsule handling.

Laptop and desktop vendors ship BIOS updates as AMI Aptio capsules (.CAP, .308,
.217 ...). The capsule is an EFI_CAPSULE_HEADER followed by two 16-bit fields,
RomImageOffset and RomLayoutOffset, and then the flash image. Burning that image
to the SPI chip performs the update without running the vendor's tool.

Layout (UEFI spec EFI_CAPSULE_HEADER, AMI extension as implemented by UEFITool):
  0x00  CapsuleGuid         AMI signed   4A3CA68B-7723-48FB-803D-578CC1FEC44D
                            AMI unsigned 14EEBB90-890A-43DB-AED1-5D3C4588A418
  0x10  HeaderSize          (not used to locate the image for AMI capsules)
  0x14  Flags
  0x18  CapsuleImageSize    whole capsule, including the header; must not exceed the file
  0x1C  RomImageOffset      u16: start of the flash image, from the capsule start
  0x1E  RomLayoutOffset     u16: module table used for the signature (not needed here)

The flash image is data[RomImageOffset:CapsuleImageSize].

The capsule image is *generic*: it carries a factory-default NVRAM/variables
store and generally omits the machine identity area, so the optional merge
here copies the dump's NVRAM/machine-identity FVs back in.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from bios_recovery.core.verified_write import write_verified

APTIO_SIGNED_CAPSULE_GUID_LE = bytes.fromhex("8ba63c4a2377fb48803d578cc1fec44d")
APTIO_UNSIGNED_CAPSULE_GUID_LE = bytes.fromhex("90bbee140a89db43aed15d3c4588a418")
APTIO_CAPSULE_GUID_LE = APTIO_SIGNED_CAPSULE_GUID_LE
APTIO_CAPSULE_GUIDS_LE = (APTIO_SIGNED_CAPSULE_GUID_LE, APTIO_UNSIGNED_CAPSULE_GUID_LE)
APTIO_CAPSULE_HEADER_SIZE = 0x20


def is_aptio_capsule_guid(head: bytes) -> bool:
    """True if the first 16 bytes of a file are one of the two AMI Aptio capsule GUIDs."""
    return bytes(head[:16]) in APTIO_CAPSULE_GUIDS_LE


@dataclass
class CapsuleInfo:
    success: bool
    header_size: int = 0        # RomImageOffset: where the flash image starts
    image_end: int = 0          # CapsuleImageSize: where the flash image ends
    image_size: int = 0
    image_sha256: str = ""
    flags_word: int = 0
    size_field: int = 0         # CapsuleImageSize as stored in the header
    messages: list = None
    output_path: str = ""

    def __post_init__(self):
        if self.messages is None:
            self.messages = []


def detect_capsule(data: bytes) -> CapsuleInfo:
    """Parse an AMI Aptio capsule header and validate it the way UEFITool does."""
    if len(data) < APTIO_CAPSULE_HEADER_SIZE:
        return CapsuleInfo(success=False, messages=["File too small for an Aptio capsule"])
    if not is_aptio_capsule_guid(data):
        return CapsuleInfo(success=False, messages=["Not an AMI Aptio capsule (GUID mismatch)"])

    messages = []
    flags_word = struct.unpack_from("<I", data, 0x14)[0]
    size_field = struct.unpack_from("<I", data, 0x18)[0]
    rom_image_offset = struct.unpack_from("<H", data, 0x1C)[0]

    if rom_image_offset == 0 or rom_image_offset > len(data) or rom_image_offset > size_field:
        messages.append(f"AMI capsule image offset {rom_image_offset:#x} is invalid")
        return CapsuleInfo(success=False, header_size=rom_image_offset,
                           size_field=size_field, messages=messages)
    if size_field > len(data):
        messages.append(
            f"AMI capsule image size {size_field:#x} is larger than the file "
            f"({len(data):#x} bytes): the file is truncated"
        )
        return CapsuleInfo(success=False, header_size=rom_image_offset,
                           size_field=size_field, messages=messages)
    if rom_image_offset == size_field:
        messages.append("AMI capsule contains no flash image (empty payload)")
        return CapsuleInfo(success=False, header_size=rom_image_offset,
                           size_field=size_field, messages=messages)
    if size_field < len(data):
        messages.append(
            f"{len(data) - size_field:#x} bytes follow the capsule image and are ignored"
        )

    image = data[rom_image_offset:size_field]
    image_size = len(image)
    image_sha256 = hashlib.sha256(image).hexdigest()

    if image_size % 0x1000 != 0:
        messages.append(f"Capsule image size {image_size:#x} not page-aligned")

    # A sane flash image is either blank-padded (0xFF) at the head, or contains
    # a recognizable structure at some point; something entirely zero is suspect.
    if image and set(image[:0x10000]) == {0x00}:
        messages.append("Capsule image head is all zeros - suspicious")

    return CapsuleInfo(
        success=True,
        header_size=rom_image_offset,
        image_end=size_field,
        image_size=image_size,
        image_sha256=image_sha256,
        flags_word=flags_word,
        size_field=size_field,
        messages=messages,
    )


def extract_flashable_image(
    input_path: str, output_path: str | None = None
) -> CapsuleInfo:
    """Strip the Aptio capsule header and write the bare flash image."""
    from bios_recovery.core.safety import SameFileError, ensure_distinct

    if output_path is None:
        output_path = input_path.rsplit(".", 1)[0] + "_flashable.bin"
    try:
        ensure_distinct(input_path, output_path)
    except SameFileError as exc:
        return CapsuleInfo(success=False, messages=[str(exc)])

    with open(input_path, "rb") as f:
        data = f.read()

    info = detect_capsule(data)
    if not info.success:
        return info

    image = data[info.header_size:info.image_end]
    write_verified(output_path, image)

    info.output_path = output_path
    return info


def _fv_list(blob: bytes) -> list[tuple[int, int]]:
    """Firmware volumes as (base, length), each with a verified header checksum."""
    from bios_recovery.core.bios_analyzer import BiosAnalyzer

    found = []
    pos = 0
    while True:
        i = blob.find(b"_FVH", pos)
        if i < 0:
            break
        pos = i + 1
        base = i - 0x28
        if base < 0:
            continue
        flen = BiosAnalyzer._valid_fv_length(blob, base)
        if flen:
            found.append((base, flen))
    return found


def restore_nvar_from_dump(
    capsule_image_path: str, dump_path: str, output_path: str
) -> CapsuleInfo:
    """Rebuild a flashable capsule image while preserving the dump's machine data.

    Real-world layout (verified on a genuine 32MB Acer/ASUS AMD-board dump):
      - FV boundaries are identical between the capsule image and the dump.
      - The dump carries an extra FV the capsule omitted (machine identity:
        MFG0 board serial, CNFG config data).
      - The NVRAM FVs hold NVAR records; the capsule's copies lack machine
        records (_DMI etc.).

    The merge copies a dump volume at or above 0x1000000 only when the capsule has a
    volume with the same bounds, or has no volume there and the range is erased.
    Any other dump volume is skipped with a message. The output is written only when
    bytes change and every volume of the capsule still parses afterwards. Variable
    records are not rewritten; a variable survives only if its dump volume is copied.
    """
    from bios_recovery.core.safety import SameFileError, ensure_distinct

    try:
        ensure_distinct(capsule_image_path, output_path)
        ensure_distinct(dump_path, output_path)
    except SameFileError as exc:
        return CapsuleInfo(success=False, messages=[str(exc)])
    with open(capsule_image_path, "rb") as f:
        image = bytearray(f.read())
    with open(dump_path, "rb") as f:
        dump = f.read()
    original = bytes(image)

    info = CapsuleInfo(success=True, messages=[])

    # --- 1) Region-level restore of NVRAM / machine FVs ---------------------
    dump_fvs = _fv_list(dump)
    cap_fvs = _fv_list(original)
    cap_set = set(cap_fvs)
    written: list[tuple[int, int]] = []

    def _overlaps(base: int, flen: int) -> bool:
        return any(base < b + n and b < base + flen for b, n in written)

    for base, flen in dump_fvs:
        if base < 0x1000000:
            continue  # never touch the pre-BIOS half from a merge
        if _overlaps(base, flen):
            info.messages.append(f"Skipped FV @0x{base:x}: overlaps a region already restored")
            continue
        if (base, flen) in cap_set and base < 0x1040000:
            image[base : base + flen] = dump[base : base + flen]
            written.append((base, flen))
            info.messages.append(f"Restored NVRAM FV @0x{base:x} (0x{flen:x} bytes) from the dump")
        elif (base, flen) not in cap_set and base + flen <= len(image):
            if any(b < base + flen and base < b + n for b, n in cap_fvs):
                info.messages.append(
                    f"Skipped FV @0x{base:x}: the capsule holds a different volume there"
                )
            elif set(image[base : base + flen]) != {0xFF}:
                info.messages.append(
                    f"Skipped FV @0x{base:x}: the capsule holds data there that is not a volume"
                )
            else:
                image[base : base + flen] = dump[base : base + flen]
                written.append((base, flen))
                info.messages.append(
                    f"Restored machine FV @0x{base:x} (0x{flen:x} bytes; erased in the capsule)"
                )

    # --- 2) Variable names that exist only in the dump -----------------------
    def nvar_names(blob: bytes) -> set:
        names = set()
        pos = 0
        while True:
            i = blob.find(b"NVAR", pos)
            if i < 0:
                break
            pos = i + 4
            total = int.from_bytes(blob[i + 4 : i + 6], "little")
            if total < 0x10 or i + total > len(blob):
                continue
            nm = blob[i + 11 : i + 0x40].split(b"\x00")[0]
            if nm and nm.isascii():
                names.add(nm)
        return names

    dump_names = nvar_names(dump)
    cap_names = nvar_names(original)
    only_dump = {n.decode(errors="replace") for n in (dump_names - cap_names) if len(n) >= 3}
    if only_dump:
        preview = ", ".join(sorted(only_dump)[:6])
        info.messages.append(
            f"{len(only_dump)} dump variable(s) are not in the capsule's store "
            f"(e.g. {preview}); they are kept only if their dump volume was restored above"
        )

    info.image_size = len(image)
    if bytes(image) == original:
        info.success = False
        info.messages.append("nothing to restore from the dump; no file written")
        return info
    if not set(cap_fvs) <= set(_fv_list(bytes(image))):
        info.success = False
        info.messages.append("merged image would lose a capsule volume; no file written")
        return info

    write_verified(output_path, bytes(image))
    info.output_path = output_path
    return info
