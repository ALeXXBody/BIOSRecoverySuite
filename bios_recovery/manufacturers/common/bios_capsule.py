"""AMI Aptio capsule handling.

Laptop repair flow: vendors ship BIOS updates as "Aptio capsules" (.CAP, .308,
.217 etc.) — an 0x800-byte header (AMI Aptio capsule GUID
4A3CA68B-7723-48FB-803D-578CC1FEC44D) followed by a complete flash image.
Burning that image to the SPI chip performs the update without running the
vendor's DOS/Windows tool — the standard recovery move for laptops that will
no longer boot far enough to self-update.

The capsule image is *generic*: it carries a factory-default NVRAM/variables
store and generally omits the machine identity area, so the optional merge
here copies the dump's NVRAM/machine-identity FVs back in.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

APTIO_CAPSULE_GUID_LE = bytes.fromhex("8ba63c4a2377fb48803d578cc1fec44d")


@dataclass
class CapsuleInfo:
    success: bool
    header_size: int = 0
    image_size: int = 0
    image_sha256: str = ""
    flags_word: int = 0
    size_field: int = 0
    messages: list = None
    output_path: str = ""

    def __post_init__(self):
        if self.messages is None:
            self.messages = []


def detect_capsule(data: bytes) -> CapsuleInfo:
    """Parse the 0x800-byte Aptio capsule header and validate structure."""
    if len(data) < 0x800:
        return CapsuleInfo(success=False, messages=["File too small for an Aptio capsule"])
    if data[:16] != APTIO_CAPSULE_GUID_LE:
        return CapsuleInfo(success=False, messages=["Not an AMI Aptio capsule (GUID mismatch)"])

    messages = []
    header_size = struct.unpack_from("<I", data, 0x10)[0]
    flags_word = struct.unpack_from("<I", data, 0x14)[0]
    size_field = struct.unpack_from("<I", data, 0x18)[0]
    image = data[header_size:]
    image_size = len(image)
    image_sha256 = hashlib.sha256(image).hexdigest()

    # The documented layout is a fixed 0x800-byte header. Anything else is refused,
    # because the image boundary would be a guess.
    if header_size != 0x800:
        messages.append(f"Capsule header size {header_size:#x} is not the documented 0x800")
        return CapsuleInfo(success=False, header_size=header_size, messages=messages)

    if size_field != len(data):
        messages.append(
            f"Capsule size field {size_field:#x} does not match file size {len(data):#x}; refusing"
        )
        return CapsuleInfo(
            success=False, header_size=header_size, size_field=size_field, messages=messages
        )
    if image_size % 0x1000 != 0:
        messages.append(f"Capsule image size {image_size:#x} not page-aligned")

    # A sane flash image is either blank-padded (0xFF) at the head, or contains
    # a recognizable structure at some point; something entirely zero is suspect.
    if image and set(image[:0x10000]) == {0x00}:
        messages.append("Capsule image head is all zeros - suspicious")

    return CapsuleInfo(
        success=True,
        header_size=header_size,
        image_size=image_size,
        image_sha256=image_sha256,
        flags_word=flags_word,
        size_field=size_field,
        messages=messages,
    )


def extract_flashable_image(input_path: str, output_path: str | None = None) -> CapsuleInfo:
    """Strip the Aptio capsule header and write the bare flash image."""
    with open(input_path, "rb") as f:
        data = f.read()

    info = detect_capsule(data)
    if not info.success:
        return info

    image = data[info.header_size :]

    # Some capsules carry a 32-byte hash right after the header fields.
    hdr_hash = data[0x28:0x48]
    if len(hdr_hash) == 32 and hdr_hash != b"\x00" * 32:
        if hdr_hash.hex() == info.image_sha256:
            info.messages.append("Capsule header SHA-256 matches flash image")
        else:
            info.messages.append(
                "Capsule header stores a 32-byte hash that is not SHA-256(image); "
                f"keeping image (stored {hdr_hash.hex()[:16]}..., "
                f"sha256 {info.image_sha256[:16]}...)"
            )

    if output_path is None:
        output_path = input_path.rsplit(".", 1)[0] + "_flashable.bin"

    with open(output_path, "wb") as f:
        f.write(image)

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

    With identical FV boundaries, the merge:
      1. copies the dump's NVRAM FVs (bases >= 0x1000000 with matching bounds),
      2. restores FVs the capsule omitted entirely (when they fit),
      3. replaces capsule NVAR records whose identity key also exists in the
         dump (byte-identical record swap when sizes match).
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

    info = CapsuleInfo(success=True, messages=[])

    # --- 1) Region-level restore of NVRAM / machine FVs ---------------------
    dump_fvs = _fv_list(dump)
    cap_set = set(_fv_list(bytes(image)))
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
            image[base : base + flen] = dump[base : base + flen]
            written.append((base, flen))
            info.messages.append(
                f"Restored machine FV @0x{base:x} (0x{flen:x} bytes; capsule omitted it)"
            )

    # --- 2) Machine records beyond the FV copy ------------------------------
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
    cap_names = nvar_names(bytes(image))
    only_dump = {n.decode(errors="replace") for n in (dump_names - cap_names) if len(n) >= 3}
    if only_dump:
        preview = ", ".join(sorted(only_dump)[:6])
        info.messages.append(
            f"{len(only_dump)} dump variable(s) are not in the capsule's store; "
            f"preserved via the FV copy (e.g. {preview})"
        )

    with open(output_path, "wb") as f:
        f.write(bytes(image))

    info.output_path = output_path
    info.image_size = len(image)
    return info
